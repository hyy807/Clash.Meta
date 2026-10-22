package lxxhttp

// LightXtreme / 闪连 私有 XHTTP 客户端传输 (stream-up 模式) 的 mihomo 移植。
//
// 线上协议:
//   上行: POST https://<server><path>/<uuid4>   content-type: application/grpc
//         referer: https://<server><path>/?x_padding=XXXX...(重复 X)
//         body  = obfs 流 (见 obfs.go)，持续 DATA 帧
//   下行: GET  https://<download><dpath>/<uuid4>  同样的 referer 填充
//         响应 200 text/event-stream，body = 同一套 obfs 的裸字节流
//
// 上下行共用同一个 uuid4；TLS 一定是 h2 (ALPN)。

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"
)

const (
	defaultPaddingMin = 100
	defaultPaddingMax = 1000
	alpnH2            = "h2"
)

// Config 描述一条 lx-xhttp 传输。
type Config struct {
	Dialer         C.Dialer
	Server         string // host:port
	Path           string
	ObfsKey        string
	PaddingMin     int
	PaddingMax     int
	DownloadServer string // 可选, host:port
	DownloadPath   string // 可选
	TLSConfig      *vmess.TLSConfig
}

type Client struct {
	server       string
	download     string
	path         string
	downloadPath string
	obfsKey      []byte
	paddingMin   int
	paddingMax   int
	upload       *http2.Transport
	downloadHTTP *http2.Transport
	serverAddr   net.Addr
	closeOnce    sync.Once
}

// NewClient 构造 lx-xhttp 客户端。
func NewClient(config Config) (*Client, error) {
	if config.TLSConfig == nil {
		return nil, errors.New("lx-xhttp: TLS is required")
	}
	if config.Dialer == nil {
		return nil, errors.New("lx-xhttp: missing dialer")
	}
	if config.Server == "" {
		return nil, errors.New("lx-xhttp: missing server address")
	}
	host, _, err := net.SplitHostPort(config.Server)
	if err != nil {
		return nil, errors.New("lx-xhttp: invalid server address: " + err.Error())
	}
	client := &Client{
		server:       config.Server,
		download:     config.Server,
		path:         normalizePath(config.Path),
		downloadPath: normalizePath(config.Path),
		paddingMin:   defaultPaddingMin,
		paddingMax:   defaultPaddingMax,
	}
	if config.ObfsKey != "" {
		client.obfsKey = obfsDeriveKey(config.ObfsKey)
	}
	if config.PaddingMin > 0 && config.PaddingMax >= config.PaddingMin {
		client.paddingMin = config.PaddingMin
		client.paddingMax = config.PaddingMax
	}
	if config.DownloadServer != "" {
		client.download = config.DownloadServer
	}
	if config.DownloadPath != "" {
		client.downloadPath = normalizePath(config.DownloadPath)
	}
	client.serverAddr = &fakeAddr{network: "tcp", address: config.Server}

	uploadTLS := withHTTP2ALPN(config.TLSConfig, host)
	client.upload = newHTTP2Transport(config.Dialer, client.server, uploadTLS)

	if client.download != config.Server {
		dlHost, _, splitErr := net.SplitHostPort(client.download)
		if splitErr != nil {
			return nil, errors.New("lx-xhttp: invalid download server address: " + splitErr.Error())
		}
		client.downloadHTTP = newHTTP2Transport(config.Dialer, client.download, withHTTP2ALPN(config.TLSConfig, dlHost))
	} else {
		client.downloadHTTP = newHTTP2Transport(config.Dialer, client.server, uploadTLS)
	}
	return client, nil
}

// withHTTP2ALPN 保证 h2 协商，并可按 download 主机覆盖 SNI。
func withHTTP2ALPN(config *vmess.TLSConfig, serverName string) *vmess.TLSConfig {
	cloned := *config
	if serverName != "" {
		cloned.Host = serverName
	}
	nextProtos := make([]string, 0, len(config.NextProtos)+1)
	hasH2 := false
	for _, proto := range config.NextProtos {
		if proto == alpnH2 {
			hasH2 = true
		}
		nextProtos = append(nextProtos, proto)
	}
	if !hasH2 {
		nextProtos = append([]string{alpnH2}, nextProtos...)
	}
	cloned.NextProtos = nextProtos
	return &cloned
}

func newHTTP2Transport(dialer C.Dialer, server string, tlsConfig *vmess.TLSConfig) *http2.Transport {
	return &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			rawConn, err := dialer.DialContext(ctx, "tcp", server)
			if err != nil {
				return nil, err
			}
			tlsConn, err := vmess.StreamTLSConn(ctx, rawConn, tlsConfig)
			if err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimSuffix(path, "/")
}

func (c *Client) buildReferer(host string, path string) string {
	length := c.paddingMin
	if c.paddingMax > c.paddingMin {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(c.paddingMax-c.paddingMin+1)))
		if err == nil {
			length += int(n.Int64())
		}
	}
	return fmt.Sprintf("https://%s%s/?x_padding=%s", host, path, strings.Repeat("X", length))
}

func newSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

// DialContext 打开一条 lx-xhttp 双向流 (上行 POST + 下行 GET)。
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	sessionID, err := newSessionID()
	if err != nil {
		return nil, errors.New("lx-xhttp: generate session id: " + err.Error())
	}
	uploadURL := fmt.Sprintf("https://%s%s/%s", c.server, c.path, sessionID)
	downloadURL := fmt.Sprintf("https://%s%s/%s", c.download, c.downloadPath, sessionID)

	requestCtx, cancel := context.WithCancel(ctx)

	pipeReader, pipeWriter := io.Pipe()
	var uploadWriter io.Writer = pipeWriter
	if c.obfsKey != nil {
		uploadWriter = newObfsWriter(pipeWriter, c.obfsKey)
	}

	go func() {
		request, reqErr := http.NewRequestWithContext(requestCtx, http.MethodPost, uploadURL, pipeReader)
		if reqErr != nil {
			_ = pipeReader.CloseWithError(reqErr)
			return
		}
		request.Header.Set("content-type", "application/grpc")
		request.Header.Set("accept-encoding", "gzip")
		request.Header.Set("referer", c.buildReferer(c.server, c.path))
		response, roundErr := c.upload.RoundTrip(request)
		if roundErr != nil {
			_ = pipeReader.CloseWithError(roundErr)
			return
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}()

	downloadRequest, err := http.NewRequestWithContext(requestCtx, http.MethodGet, downloadURL, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	downloadRequest.Header.Set("accept-encoding", "gzip")
	downloadRequest.Header.Set("referer", c.buildReferer(c.download, c.downloadPath))
	downloadResponse, err := c.downloadHTTP.RoundTrip(downloadRequest)
	if err != nil {
		cancel()
		return nil, errors.New("lx-xhttp: open download stream: " + err.Error())
	}
	if downloadResponse.StatusCode != http.StatusOK {
		_ = downloadResponse.Body.Close()
		cancel()
		return nil, errors.New("lx-xhttp: unexpected download status: " + downloadResponse.Status)
	}

	var downloadReader io.Reader = downloadResponse.Body
	if c.obfsKey != nil {
		downloadReader = newObfsReader(downloadResponse.Body, c.obfsKey)
	}
	return &clientConn{
		reader:       downloadReader,
		writer:       uploadWriter,
		cancel:       cancel,
		pipeWriter:   pipeWriter,
		downloadBody: downloadResponse.Body,
		local:        fakeAddr{network: "tcp", address: "127.0.0.1:0"},
		remote:       c.serverAddr,
	}, nil
}

// Close 释放空闲连接。
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		if c.upload != nil {
			c.upload.CloseIdleConnections()
		}
		if c.downloadHTTP != nil {
			c.downloadHTTP.CloseIdleConnections()
		}
	})
	return nil
}

type clientConn struct {
	reader       io.Reader
	writer       io.Writer
	pipeWriter   *io.PipeWriter
	downloadBody io.Closer
	cancel       context.CancelFunc
	local        net.Addr
	remote       net.Addr
	closeOnce    sync.Once
}

func (c *clientConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *clientConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *clientConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		_ = c.pipeWriter.Close()
		_ = c.downloadBody.Close()
	})
	return nil
}

func (c *clientConn) LocalAddr() net.Addr                { return c.local }
func (c *clientConn) RemoteAddr() net.Addr               { return c.remote }
func (c *clientConn) SetDeadline(t time.Time) error      { return nil }
func (c *clientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *clientConn) SetWriteDeadline(t time.Time) error { return nil }

type fakeAddr struct {
	network string
	address string
}

func (a fakeAddr) Network() string { return a.network }
func (a fakeAddr) String() string  { return a.address }

// ParseServer 把 host:port 拆成 server/port 形式，供配置层复用。
func ParseServer(server string, port int) string {
	if port <= 0 {
		return server
	}
	if strings.Contains(server, ":") && !strings.HasPrefix(server, "[") {
		return "[" + server + "]:" + strconv.Itoa(port)
	}
	return net.JoinHostPort(server, strconv.Itoa(port))
}
