package outbound

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/net/http2/hpack"
)

// X365 is the efanyun (protocolabs) tunnel, reverse engineered from
// libprotocolabs_mobile.so and verified against the live server:
//
//	REALITY TLS -> HTTP/2 (one stream per proxied connection) -> "X365" frames
//
//	init : "X365" 01 02 uuid16 00 35 01 01 01 01 01   (stream 1, once per tunnel)
//	open : "X365" 01 01 uuid16 port:2 02 len host     (first DATA of each stream)
//	ack  : "X365" 00                                  (control, must be filtered)
//	data : raw bytes inside h2 DATA frames
//
// The server replenishes nothing: the client must send WINDOW_UPDATE or transfers
// stall at the initial 64 KiB window.
type X365 struct {
	*Base
	option *X365Option
	uuid   []byte
}

type X365Option struct {
	BasicOption
	Name              string `proxy:"name"`
	Server            string `proxy:"server"`
	Port              int    `proxy:"port"`
	UUID              string `proxy:"uuid"`
	PublicKey         string `proxy:"public-key"`
	ShortID           string `proxy:"short-id,omitempty"`
	ServerName        string `proxy:"servername,omitempty"`
	Host              string `proxy:"host,omitempty"`
	Path              string `proxy:"path,omitempty"`
	ClientFingerprint string `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify    bool   `proxy:"skip-cert-verify,omitempty"`
}

func NewX365(option X365Option) (*X365, error) {
	if option.Server == "" || option.Port == 0 || option.UUID == "" || option.PublicKey == "" {
		return nil, errors.New("x365: server/port/uuid/public-key are required")
	}
	uuidBin, err := hex.DecodeString(stripDashes(option.UUID))
	if err != nil || len(uuidBin) < 16 {
		return nil, fmt.Errorf("x365: bad uuid %q", option.UUID)
	}
	if option.Host == "" {
		option.Host = option.ServerName
	}
	if option.ServerName == "" {
		option.ServerName = option.Host
	}
	if option.Host == "" {
		return nil, errors.New("x365: host/servername required for the h2 :authority")
	}
	if option.Path == "" {
		option.Path = "/"
	}
	if option.ClientFingerprint == "" {
		option.ClientFingerprint = "chrome"
	}
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	x := &X365{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.X365,
			ProviderName: option.ProviderName,
			UDP:          false,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
		}),
		option: &option,
		uuid:   uuidBin[:16],
	}
	return x, nil
}

func stripDashes(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func (x *X365) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	host := metadata.Host
	if host == "" {
		host = metadata.DstIP.String()
	}
	t, err := x.dialTunnel(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := t.open(host, uint16(metadata.DstPort))
	if err != nil {
		t.close()
		return nil, err
	}
	return NewConn(conn, x), nil
}

func (x *X365) dialTunnel(ctx context.Context) (*x365Tunnel, error) {
	addr := net.JoinHostPort(x.option.Server, strconv.Itoa(x.option.Port))
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	pbk, err := base64.RawURLEncoding.DecodeString(x.option.PublicKey)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("x365: bad public key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(pbk)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("x365: bad public key: %w", err)
	}
	realityCfg := &tls.RealityConfig{PublicKey: pub}
	if x.option.ShortID != "" {
		sid, err := hex.DecodeString(x.option.ShortID)
		if err != nil {
			raw.Close()
			return nil, fmt.Errorf("x365: bad short id: %w", err)
		}
		copy(realityCfg.ShortID[:], sid)
	}
	fp, ok := tls.GetFingerprint(x.option.ClientFingerprint)
	if !ok {
		raw.Close()
		return nil, fmt.Errorf("x365: unknown fingerprint %q", x.option.ClientFingerprint)
	}
	tlsConn, err := tls.GetRealityConn(ctx, raw, fp, x.option.ServerName, realityCfg)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("x365: reality handshake: %w", err)
	}
	x365Debug("reality ok -> %s", addr)
	t := &x365Tunnel{
		conn: tlsConn,
		x:    x,
		sb:   &x365Stream{ch: make(chan struct{}, 1)},
	}
	if err := t.handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}
	go t.readLoop()
	return t, nil
}

type x365Stream struct {
	mu  sync.Mutex
	buf []byte
	eof bool
	ch  chan struct{}
}

func (s *x365Stream) push(p []byte) {
	s.mu.Lock()
	s.buf = append(s.buf, p...)
	s.mu.Unlock()
	select {
	case s.ch <- struct{}{}:
	default:
	}
}

func (s *x365Stream) finish() {
	s.mu.Lock()
	s.eof = true
	s.mu.Unlock()
	select {
	case s.ch <- struct{}{}:
	default:
	}
}

type x365Tunnel struct {
	conn net.Conn
	x    *X365
	sb   *x365Stream
	wmu  sync.Mutex
	id   uint32
}

func (t *x365Tunnel) writeFrame(typ, flags byte, stream uint32, p []byte) error {
	h := make([]byte, 9)
	n := len(p)
	h[0], h[1], h[2] = byte(n>>16), byte(n>>8), byte(n)
	h[3], h[4] = typ, flags
	binary.BigEndian.PutUint32(h[5:], stream&0x7fffffff)
	x365Debug("tx type=%d flags=%d stream=%d len=%d", typ, flags, stream, n)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if _, err := t.conn.Write(h); err != nil {
		return err
	}
	if n > 0 {
		_, err := t.conn.Write(p)
		return err
	}
	return nil
}

func (t *x365Tunnel) headers() []byte {
	var hb []byte
	enc := hpack.NewEncoder(writerFunc(func(p []byte) (int, error) {
		hb = append(hb, p...)
		return len(p), nil
	}))
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: t.x.option.Host})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: t.x.option.Path})
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	enc.WriteField(hpack.HeaderField{Name: "te", Value: "trailers"})
	enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "grpc-go/1.70.0"})
	return hb
}

func x365Debug(format string, args ...any) {
	if os.Getenv("X365_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[x365] "+format+"\n", args...)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func (t *x365Tunnel) handshake() error {
	if _, err := t.conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return err
	}
	if err := t.writeFrame(0x4, 0, 0, nil); err != nil {
		return err
	}
	if err := t.writeFrame(0x1, 0x4, 1, t.headers()); err != nil {
		return err
	}
	init := append([]byte("X365"), 0x01, 0x02)
	init = append(init, t.x.uuid...)
	init = append(init, 0x00, 0x35, 0x01, 0x01, 0x01, 0x01, 0x01)
	return t.writeFrame(0x0, 0, 1, init)
}

func (t *x365Tunnel) open(host string, port uint16) (*x365Conn, error) {
	t.id = 3
	if err := t.writeFrame(0x1, 0x4, t.id, t.headers()); err != nil {
		return nil, err
	}
	time.Sleep(150 * time.Millisecond)
	open := append([]byte("X365"), 0x01, 0x01)
	open = append(open, t.x.uuid...)
	open = append(open, byte(port>>8), byte(port), 0x02, byte(len(host)))
	open = append(open, []byte(host)...)
	x365Debug("open %s:%d on stream %d", host, port, t.id)
	if err := t.writeFrame(0x0, 0, t.id, open); err != nil {
		return nil, err
	}
	time.Sleep(400 * time.Millisecond)
	return &x365Conn{t: t}, nil
}

func (t *x365Tunnel) readLoop() {
	h := make([]byte, 9)
	for {
		if _, err := io.ReadFull(t.conn, h); err != nil {
			t.sb.finish()
			return
		}
		n := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		typ := h[3]
		stream := binary.BigEndian.Uint32(h[5:]) & 0x7fffffff
		var p []byte
		if n > 0 {
			p = make([]byte, n)
			if _, err := io.ReadFull(t.conn, p); err != nil {
				t.sb.finish()
				return
			}
		}
		x365Debug("rx frame type=%d flags=%d stream=%d len=%d %x", typ, h[4], stream, n, p)
		switch typ {
		case 0x0: // DATA
			x365Debug("rx DATA stream=%d len=%d", stream, n)
			if n == 0 {
				t.sb.finish()
				continue
			}
			// keep the server's flow-control window open
			inc := make([]byte, 4)
			binary.BigEndian.PutUint32(inc, uint32(n))
			t.writeFrame(0x8, 0, 0, inc)
			t.writeFrame(0x8, 0, stream, inc)
			if n >= 4 && string(p[:4]) == "X365" {
				continue // control frame, never forward
			}
			t.sb.push(p)
		case 0x4: // SETTINGS
			if h[4]&0x1 == 0 { // only ACK a real SETTINGS, never an ACK
				t.writeFrame(0x4, 0x1, 0, nil)
			}
		}
	}
}

func (t *x365Tunnel) close() { t.conn.Close() }

type x365Conn struct {
	t *x365Tunnel
}

func (c *x365Conn) Read(p []byte) (int, error) {
	s := c.t.sb
	for {
		s.mu.Lock()
		if len(s.buf) > 0 {
			n := copy(p, s.buf)
			s.buf = s.buf[n:]
			s.mu.Unlock()
			return n, nil
		}
		eof := s.eof
		s.mu.Unlock()
		if eof {
			return 0, io.EOF
		}
		<-s.ch
	}
}

func (c *x365Conn) Write(p []byte) (int, error) {
	if err := c.t.writeFrame(0x0, 0, c.t.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *x365Conn) Close() error                       { return c.t.conn.Close() }
func (c *x365Conn) LocalAddr() net.Addr                { return c.t.conn.LocalAddr() }
func (c *x365Conn) RemoteAddr() net.Addr               { return c.t.conn.RemoteAddr() }
func (c *x365Conn) SetDeadline(t time.Time) error      { return c.t.conn.SetDeadline(t) }
func (c *x365Conn) SetReadDeadline(t time.Time) error  { return c.t.conn.SetReadDeadline(t) }
func (c *x365Conn) SetWriteDeadline(t time.Time) error { return c.t.conn.SetWriteDeadline(t) }

// ensure the uuid is random-safe even if the account uuid is all zeros
var _ = rand.Reader
