package outbound

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/anytls"
	"github.com/metacubex/mihomo/transport/lxxhttp"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type AnyTLS struct {
	*Base
	client   *anytls.Client
	option   *AnyTLSOption
	lxClient *lxxhttp.Client
}

type AnyTLSOption struct {
	BasicOption
	Name                     string           `proxy:"name"`
	Server                   string           `proxy:"server"`
	Port                     int              `proxy:"port"`
	Password                 string           `proxy:"password"`
	ALPN                     []string         `proxy:"alpn,omitempty"`
	SNI                      string           `proxy:"sni,omitempty"`
	ECHOpts                  ECHOptions       `proxy:"ech-opts,omitempty"`
	ShadowTLSOpts            ShadowTLSOptions `proxy:"shadow-tls-opts,omitempty"`
	RestlsOpts               RestlsOptions    `proxy:"restls-opts,omitempty"`
	JLSOpts                  JLSOptions       `proxy:"jls-opts,omitempty"`
	ClientFingerprint        string           `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify           bool             `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify           string           `proxy:"name-cert-verify,omitempty"`
	Fingerprint              string           `proxy:"fingerprint,omitempty"`
	Certificate              string           `proxy:"certificate,omitempty"`
	PrivateKey               string           `proxy:"private-key,omitempty"`
	UDP                      bool             `proxy:"udp,omitempty"`
	ClientMetadata           string           `proxy:"client-metadata,omitempty"`
	IdleSessionCheckInterval int              `proxy:"idle-session-check-interval,omitempty"`
	IdleSessionTimeout       int              `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession           int              `proxy:"min-idle-session,omitempty"`
	DisableReuse             bool             `proxy:"disable-reuse,omitempty"`
	// LightXtreme / 闪连: anytls 承载在私有 lx-xhttp 传输之上
	Transport LXHTTPOptions `proxy:"transport,omitempty"`
}

// LXHTTPOptions 闪连私有 XHTTP 传输配置。
type LXHTTPOptions struct {
	Type       string                `proxy:"type,omitempty"`
	Path       string                `proxy:"path,omitempty"`
	Mode       string                `proxy:"mode,omitempty"`
	ObfsKey    string                `proxy:"obfs-key,omitempty"`
	PaddingMin int                   `proxy:"padding-min,omitempty"`
	PaddingMax int                   `proxy:"padding-max,omitempty"`
	Download   LXHTTPDownloadOptions `proxy:"download,omitempty"`
}

type LXHTTPDownloadOptions struct {
	Server string `proxy:"server,omitempty"`
	Port   int    `proxy:"port,omitempty"`
	Path   string `proxy:"path,omitempty"`
}

func (o LXHTTPOptions) Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(o.Type)) {
	case "lx-xhttp", "xhttp", "lightxtreme", "闪电旋风劈":
		return true
	}
	return false
}

func (t *AnyTLS) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := t.client.CreateProxy(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(c, t), nil
}

func (t *AnyTLS) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	// create tcp
	c, err := t.client.CreateProxy(ctx, uot.RequestDestination(2))
	if err != nil {
		return nil, err
	}

	// create uot on tcp
	destination := M.SocksaddrFromNet(metadata.UDPAddr())
	return NewPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination})), t), nil
}

// SupportUOT implements C.ProxyAdapter
func (t *AnyTLS) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (t *AnyTLS) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (t *AnyTLS) Close() error {
	if t.lxClient != nil {
		_ = t.lxClient.Close()
	}
	return t.client.Close()
}

func NewAnyTLS(option AnyTLSOption) (*AnyTLS, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &AnyTLS{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.AnyTLS,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	singDialer := proxydialer.NewSingDialer(outbound.dialer)

	tOption := anytls.ClientConfig{
		Password:                 option.Password,
		Server:                   M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		Dialer:                   singDialer,
		ClientMetadata:           option.ClientMetadata,
		IdleSessionCheckInterval: time.Duration(option.IdleSessionCheckInterval) * time.Second,
		IdleSessionTimeout:       time.Duration(option.IdleSessionTimeout) * time.Second,
		MinIdleSession:           option.MinIdleSession,
		DisableReuse:             option.DisableReuse,
	}
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	shadowTLSConfig, err := option.ShadowTLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	restlsConfig, err := option.RestlsOpts.Parse(option.SNI, option.ClientFingerprint)
	if err != nil {
		return nil, err
	}
	jlsConfig, err := option.JLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	securityModes := make([]string, 0, 3)
	if shadowTLSConfig != nil {
		securityModes = append(securityModes, "ShadowTLS")
	}
	if restlsConfig != nil {
		securityModes = append(securityModes, "Restls")
	}
	if jlsConfig != nil {
		securityModes = append(securityModes, "JLS")
	}
	if len(securityModes) > 1 {
		return nil, errors.New("security modes are mutually exclusive: " + strings.Join(securityModes, ", "))
	}
	tlsConfig := &vmess.TLSConfig{
		Host:              option.SNI,
		SkipCertVerify:    option.SkipCertVerify,
		NameCertVerify:    option.NameCertVerify,
		NextProtos:        option.ALPN,
		FingerPrint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		ECH:               echConfig,
		ShadowTLS:         shadowTLSConfig,
		Restls:            restlsConfig,
		JLS:               jlsConfig,
	}
	if tlsConfig.Host == "" {
		tlsConfig.Host = option.Server
	}
	tOption.TLSConfig = tlsConfig

	// LightXtreme / 闪连: anytls 承载在私有 lx-xhttp 传输之上
	if option.Transport.Enabled() {
		lxConfig := lxxhttp.Config{
			Dialer:     outbound.dialer,
			Server:     addr,
			Path:       option.Transport.Path,
			ObfsKey:    option.Transport.ObfsKey,
			PaddingMin: option.Transport.PaddingMin,
			PaddingMax: option.Transport.PaddingMax,
			TLSConfig:  tlsConfig,
		}
		if download := option.Transport.Download; download.Server != "" {
			downloadPort := download.Port
			if downloadPort == 0 {
				downloadPort = option.Port
			}
			lxConfig.DownloadServer = net.JoinHostPort(download.Server, strconv.Itoa(downloadPort))
			lxConfig.DownloadPath = download.Path
		}
		lxClient, err := lxxhttp.NewClient(lxConfig)
		if err != nil {
			return nil, err
		}
		outbound.lxClient = lxClient
		tOption.Dial = lxClient.DialContext
	}

	client := anytls.NewClient(context.TODO(), tOption)
	outbound.client = client

	return outbound, nil
}
