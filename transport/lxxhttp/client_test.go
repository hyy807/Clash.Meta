package lxxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"
)

type testDialer struct{}

func (testDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (testDialer) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	return nil, io.EOF
}

var _ C.Dialer = testDialer{}

// newTestServer 起一个 h2 服务端: POST 收 obfs 上传流, GET 回 obfs 下行流.
func newTestServer(t *testing.T, obfsKey string) (*httptest.Server, chan []byte) {
	t.Helper()
	key := obfsDeriveKey(obfsKey)
	useObfs := obfsKey != ""
	received := make(chan []byte, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/stream/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var reader io.Reader = r.Body
			if useObfs {
				reader = newObfsReader(r.Body, key)
			}
			buf := make([]byte, 64)
			n, err := reader.Read(buf)
			if err != nil && n == 0 {
				t.Logf("upload read: %v", err)
			}
			received <- buf[:n]
		case http.MethodGet:
			if r.Header.Get("referer") == "" {
				t.Errorf("missing referer")
			}
			w.Header().Set("content-type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			var writer io.Writer = w
			if useObfs {
				writer = newObfsWriter(w, key)
			}
			_, _ = writer.Write([]byte("pong"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	})
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, received
}

func TestLXHTTPRoundTrip(t *testing.T) {
	const obfsKey = "test-obfs-key"
	server, received := newTestServer(t, obfsKey)

	client, err := NewClient(Config{
		Dialer:    testDialer{},
		Server:    server.Listener.Addr().String(),
		Path:      "/stream",
		ObfsKey:   obfsKey,
		TLSConfig: &vmess.TLSConfig{SkipCertVerify: true, Host: "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-received:
		if string(got) != "ping" {
			t.Fatalf("upload payload mismatch: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upload payload not received")
	}

	buf := make([]byte, 4)
	if _, err = io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("download payload mismatch: %q", buf)
	}
}

// 无 obfs 时也必须是原始字节流.
func TestLXHTTPPlainStream(t *testing.T) {
	server, received := newTestServer(t, "")
	client, err := NewClient(Config{
		Dialer:    testDialer{},
		Server:    server.Listener.Addr().String(),
		Path:      "/stream",
		TLSConfig: &vmess.TLSConfig{SkipCertVerify: true, Host: "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-received:
		if string(got) != "ping" {
			t.Fatalf("upload payload mismatch: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upload payload not received")
	}
}
