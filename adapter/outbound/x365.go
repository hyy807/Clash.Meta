package outbound

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"golang.org/x/net/http2/hpack"
)

// X365 is the efanyun (protocolabs) tunnel, reverse engineered from
// libprotocolabs_mobile.so and verified against the live node:
//
//	REALITY TLS -> HTTP/2 (one stream per proxied connection) -> "X365" frames
//
//	init : "X365" 01 02 uuid16 00 35 01 01 01 01 01   (stream 1, once per tunnel)
//	open : "X365" 01 01 uuid16 port:2 atyp addr       (first DATA of each stream)
//	ack  : "X365" 00                                  (control, filtered out)
//	data : raw bytes inside h2 DATA frames
//
// The REALITY handshake costs 1-3s, so one tunnel is shared by every proxied
// connection and each dial only opens a new h2 stream (that is what the vendor
// app does, and it keeps the latency checks inside their timeout).
type X365 struct {
	*Base
	option *X365Option
	uuid   []byte

	mu     sync.Mutex
	tunnel *x365Tunnel
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
	return &X365{
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
	}, nil
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
	for attempt := 0; attempt < 2; attempt++ {
		t, err := x.getTunnel(ctx)
		if err != nil {
			return nil, err
		}
		conn, err := t.open(host, uint16(metadata.DstPort))
		if err == nil {
			log.Debugln("[x365] %s dial %s:%d ok (stream %d)", x.Name(), host, metadata.DstPort, conn.id)
			return NewConn(conn, x), nil
		}
		log.Warnln("[x365] %s dial %s:%d failed: %s", x.Name(), host, metadata.DstPort, err)
		x.dropTunnel(t)
		if attempt == 1 {
			return nil, err
		}
	}
	return nil, errors.New("x365: dial failed")
}

func (x *X365) getTunnel(ctx context.Context) (*x365Tunnel, error) {
	x.mu.Lock()
	if x.tunnel != nil && x.tunnel.alive() {
		t := x.tunnel
		x.mu.Unlock()
		return t, nil
	}
	x.mu.Unlock()

	t, err := x.dialTunnel(ctx)
	if err != nil {
		return nil, err
	}

	x.mu.Lock()
	if x.tunnel != nil && x.tunnel.alive() {
		// another goroutine won the race
		old := x.tunnel
		x.mu.Unlock()
		t.close()
		return old, nil
	}
	x.tunnel = t
	x.mu.Unlock()
	return t, nil
}

func (x *X365) dropTunnel(t *x365Tunnel) {
	x.mu.Lock()
	if x.tunnel == t {
		x.tunnel = nil
	}
	x.mu.Unlock()
	t.close()
}

func (x *X365) dialTunnel(ctx context.Context) (*x365Tunnel, error) {
	pbk, err := base64.RawURLEncoding.DecodeString(x.option.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("x365: bad public key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(pbk)
	if err != nil {
		return nil, fmt.Errorf("x365: bad public key: %w", err)
	}
	realityCfg := &tls.RealityConfig{PublicKey: pub}
	if x.option.ShortID != "" {
		sid, err := hex.DecodeString(x.option.ShortID)
		if err != nil {
			return nil, fmt.Errorf("x365: bad short id: %w", err)
		}
		copy(realityCfg.ShortID[:], sid)
	}
	fp, ok := tls.GetFingerprint(x.option.ClientFingerprint)
	if !ok {
		return nil, fmt.Errorf("x365: unknown fingerprint %q", x.option.ClientFingerprint)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// honour interface / routing-mark / ip-stack preferences from the base option
	raw, err := dialer.DialContext(dialCtx, "tcp", x.Addr(), x.DialOptions()...)
	if err != nil {
		return nil, fmt.Errorf("x365: connect %s: %w", x.Addr(), err)
	}
	tlsConn, err := tls.GetRealityConn(dialCtx, raw, fp, x.option.ServerName, realityCfg)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("x365: reality handshake: %w", err)
	}
	x365Debug("reality ok -> %s", x.Addr())
	t := &x365Tunnel{
		conn:    tlsConn,
		x:       x,
		streams: map[uint32]*x365Stream{},
		nextID:  3,
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
	wmu  sync.Mutex

	mu      sync.Mutex
	streams map[uint32]*x365Stream
	nextID  uint32
	closed  bool
}

func (t *x365Tunnel) alive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.closed
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
	if err := t.conn.SetDeadline(time.Now().Add(10 * time.Second)); err == nil {
		defer t.conn.SetDeadline(time.Time{})
	}
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
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("x365: tunnel closed")
	}
	id := t.nextID
	t.nextID += 2
	sb := &x365Stream{ch: make(chan struct{}, 1)}
	t.streams[id] = sb
	t.mu.Unlock()

	if err := t.writeFrame(0x1, 0x4, id, t.headers()); err != nil {
		return nil, err
	}
	open := append([]byte("X365"), 0x01, 0x01)
	open = append(open, t.x.uuid...)
	open = append(open, byte(port>>8), byte(port))
	// address type: 0x01 = IPv4, 0x03 = IPv6, 0x02 = domain
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			open = append(open, 0x01)
			open = append(open, v4...)
		} else {
			open = append(open, 0x03)
			open = append(open, ip.To16()...)
		}
	} else {
		open = append(open, 0x02, byte(len(host)))
		open = append(open, []byte(host)...)
	}
	x365Debug("open %s:%d on stream %d", host, port, id)
	if err := t.writeFrame(0x0, 0, id, open); err != nil {
		return nil, err
	}
	return &x365Conn{t: t, id: id, sb: sb}, nil
}

func (t *x365Tunnel) readLoop() {
	h := make([]byte, 9)
	for {
		if _, err := io.ReadFull(t.conn, h); err != nil {
			t.shutdown()
			return
		}
		n := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		typ := h[3]
		stream := binary.BigEndian.Uint32(h[5:]) & 0x7fffffff
		var p []byte
		if n > 0 {
			p = make([]byte, n)
			if _, err := io.ReadFull(t.conn, p); err != nil {
				t.shutdown()
				return
			}
		}
		x365Debug("rx frame type=%d flags=%d stream=%d len=%d %x", typ, h[4], stream, n, p)
		switch typ {
		case 0x0: // DATA
			if n == 0 {
				t.streamEOF(stream)
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
			t.streamData(stream, p)
		case 0x4: // SETTINGS
			if h[4]&0x1 == 0 { // only ACK a real SETTINGS, never an ACK
				t.writeFrame(0x4, 0x1, 0, nil)
			}
		case 0x3: // RST_STREAM
			t.streamEOF(stream)
		case 0x7: // GOAWAY
			t.shutdown()
			return
		}
	}
}

func (t *x365Tunnel) streamData(id uint32, p []byte) {
	t.mu.Lock()
	sb := t.streams[id]
	t.mu.Unlock()
	if sb != nil {
		sb.push(p)
	}
}

func (t *x365Tunnel) streamEOF(id uint32) {
	t.mu.Lock()
	sb := t.streams[id]
	delete(t.streams, id)
	t.mu.Unlock()
	if sb != nil {
		sb.finish()
	}
}

func (t *x365Tunnel) shutdown() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	streams := t.streams
	t.streams = map[uint32]*x365Stream{}
	t.mu.Unlock()
	t.conn.Close()
	for _, sb := range streams {
		sb.finish()
	}
}

func (t *x365Tunnel) close() { t.shutdown() }

type x365Conn struct {
	t  *x365Tunnel
	id uint32
	sb *x365Stream

	dlMu     sync.Mutex
	deadline time.Time
}

func (c *x365Conn) setDeadline(t time.Time) {
	c.dlMu.Lock()
	c.deadline = t
	c.dlMu.Unlock()
	select {
	case c.sb.ch <- struct{}{}:
	default:
	}
}

func (c *x365Conn) Read(p []byte) (int, error) {
	s := c.sb
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
		c.dlMu.Lock()
		dl := c.deadline
		c.dlMu.Unlock()
		if dl.IsZero() {
			<-s.ch
			continue
		}
		d := time.Until(dl)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		select {
		case <-s.ch:
			timer.Stop()
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *x365Conn) Write(p []byte) (int, error) {
	if err := c.t.writeFrame(0x0, 0, c.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends only this h2 stream; the shared tunnel stays up for other dials.
func (c *x365Conn) Close() error {
	c.t.mu.Lock()
	delete(c.t.streams, c.id)
	c.t.mu.Unlock()
	return nil
}

func (c *x365Conn) LocalAddr() net.Addr                { return c.t.conn.LocalAddr() }
func (c *x365Conn) RemoteAddr() net.Addr               { return c.t.conn.RemoteAddr() }
func (c *x365Conn) SetDeadline(t time.Time) error      { c.setDeadline(t); return nil }
func (c *x365Conn) SetReadDeadline(t time.Time) error  { c.setDeadline(t); return nil }
func (c *x365Conn) SetWriteDeadline(t time.Time) error { return nil }
