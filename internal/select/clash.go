package selector

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"vpn-sub-manager/internal/model"
)

// clashProxy is the dedicated Clash.Meta proxy struct. No Extra/Raw field
// exists, so untrusted data cannot be emitted; transport/reality params are
// copied from the whitelisted Node.Extra keys into explicit fields.
type clashProxy struct {
	Name         string           `yaml:"name"`
	Type         string           `yaml:"type"`
	Server       string           `yaml:"server"`
	Port         int              `yaml:"port"`
	UUID         string           `yaml:"uuid,omitempty"`
	Password     string           `yaml:"password,omitempty"`
	Cipher       string           `yaml:"cipher,omitempty"`
	Method       string           `yaml:"method,omitempty"`
	Plugin       string           `yaml:"plugin,omitempty"`
	TLS          bool             `yaml:"tls,omitempty"`
	Token        string           `yaml:"token,omitempty"`
	PrivateKey   string           `yaml:"private-key,omitempty"`
	Network      string           `yaml:"network,omitempty"`
	ServerName   string           `yaml:"servername,omitempty"`
	Flow         string           `yaml:"flow,omitempty"`
	SNI          string           `yaml:"sni,omitempty"`
	Obfs         string           `yaml:"obfs,omitempty"`
	ObfsPassword string           `yaml:"obfs-password,omitempty"`
	ALPN                string            `yaml:"alpn,omitempty"`
	AllowInsecure       bool              `yaml:"allow-insecure,omitempty"`
	CongestionController string           `yaml:"congestion-controller,omitempty"`
	RealityOpts         *clashRealityOpts `yaml:"reality-opts,omitempty"`
	WSOpts              *clashWSOpts      `yaml:"ws-opts,omitempty"`
	GRPCOpts            *clashGRPCOpts    `yaml:"grpc-opts,omitempty"`
	HTTPOpts            *clashHTTPOpts    `yaml:"h2-opts,omitempty"`
	XHTTPOpts           *clashXHTTPOpts   `yaml:"xhttp-opts,omitempty"`
}

type clashRealityOpts struct {
	PBK string `yaml:"pbk"`
	SID string `yaml:"sid"`
	FP  string `yaml:"fp"`
}

type clashWSOpts struct {
	Path    string            `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

type clashGRPCOpts struct {
	GRPCServiceName string `yaml:"grpc-service-name,omitempty"`
	Authority       string `yaml:"authority,omitempty"`
	Mode            string `yaml:"mode,omitempty"`
}

type clashHTTPOpts struct {
	Path    string            `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

type clashXHTTPOpts struct {
	Path string `yaml:"path,omitempty"`
	Host string `yaml:"host,omitempty"`
	Mode string `yaml:"mode,omitempty"`
}

type clashGroup struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`
	URL      string   `yaml:"url,omitempty"`
	Interval int      `yaml:"interval,omitempty"`
}

type clashConfig struct {
	Name        string       `yaml:"name"`
	Proxies     []clashProxy `yaml:"proxies"`
	ProxyGroups []clashGroup `yaml:"proxy-groups"`
}

// ClashMeta builds a Clash.Meta YAML document: proxies[] plus a url-test
// proxy-group. Only explicit Node fields are emitted; Node.Extra/Node.Raw are
// dropped. The output is valid YAML parseable by gopkg.in/yaml.v3.
func ClashMeta(nodes []model.Node) ([]byte, error) {
	tags := nodeNames(nodes)
	proxies := make([]clashProxy, 0, len(nodes))
	for i, n := range nodes {
		proxies = append(proxies, clashProxyFor(n, tags[i]))
	}
	cfg := clashConfig{
		Name: "Sub Manager VPN",
		Proxies: proxies,
		ProxyGroups: []clashGroup{{
			Name:     "auto",
			Type:     "url-test",
			Proxies:  tags,
			URL:      "https://www.gstatic.com/generate_204",
			Interval: 300,
		}},
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("select: clash marshal: %w", err)
	}
	return b, nil
}

func clashProxyFor(n model.Node, name string) clashProxy {
	p := clashProxy{
		Name:   name,
		Type:   string(n.Protocol),
		Server: n.Host,
		Port:   n.Port,
	}
	net := transportNet(n)
	switch n.Protocol {
	case model.SchemeVMess:
		p.UUID = n.User
		p.Cipher = n.Encryption
		p.TLS = n.Security == "tls"
		p.Network = net
		p.ServerName = n.Extra["sni"]
		if alpn := n.Extra["alpn"]; alpn != "" {
			p.ALPN = alpn
		}
		switch net {
		case "ws":
			p.WSOpts = clashWSOptsFor(n)
		case "grpc":
			p.GRPCOpts = clashGRPCOptsFor(n)
		case "http", "h2":
			p.HTTPOpts = clashHTTPOptsFor(n)
		case "xhttp":
			p.XHTTPOpts = clashXHTTPOptsFor(n)
		}
	case model.SchemeVLESS:
		p.UUID = n.User
		p.TLS = n.Security == "tls" || n.Security == "reality"
		p.Network = net
		p.ServerName = n.Extra["sni"]
		if n.Flow != "" {
			p.Flow = n.Flow
		}
		if alpn := n.Extra["alpn"]; alpn != "" {
			p.ALPN = alpn
		}
		if n.Security == "reality" {
			p.RealityOpts = &clashRealityOpts{
				PBK: n.Extra["pbk"],
				SID: n.Extra["sid"],
				FP:  n.Extra["fp"],
			}
		}
		switch net {
		case "ws":
			p.WSOpts = clashWSOptsFor(n)
		case "grpc":
			p.GRPCOpts = clashGRPCOptsFor(n)
		case "http", "h2":
			p.HTTPOpts = clashHTTPOptsFor(n)
		case "xhttp":
			p.XHTTPOpts = clashXHTTPOptsFor(n)
		}
	case model.SchemeTrojan:
		p.Password = n.User
		p.TLS = n.Security == "tls"
		p.Network = net
		p.ServerName = n.Extra["sni"]
		if alpn := n.Extra["alpn"]; alpn != "" {
			p.ALPN = alpn
		}
		switch net {
		case "ws":
			p.WSOpts = clashWSOptsFor(n)
		case "grpc":
			p.GRPCOpts = clashGRPCOptsFor(n)
		case "http", "h2":
			p.HTTPOpts = clashHTTPOptsFor(n)
		case "xhttp":
			p.XHTTPOpts = clashXHTTPOptsFor(n)
		}
	case model.SchemeSS:
		p.Cipher = n.Encryption
		p.Password = n.User
		p.Plugin = n.Plugin
	case model.SchemeHysteria2:
		p.Password = n.User
		p.TLS = n.Security == "tls"
		p.SNI = n.Extra["sni"]
		if alpn := n.Extra["alpn"]; alpn != "" {
			p.ALPN = alpn
		}
		p.Obfs = n.Extra["obfs"]
		p.ObfsPassword = n.Extra["obfs-password"]
		if n.Extra["allow_insecure"] == "1" {
			p.AllowInsecure = true
		}
	case model.SchemeTUIC:
		p.UUID = n.User
		p.Password = n.User
		p.Token = n.User
		p.TLS = n.Security == "tls"
		p.SNI = n.Extra["sni"]
		if alpn := n.Extra["alpn"]; alpn != "" {
			p.ALPN = alpn
		}
		if cc := n.Extra["congestion_control"]; cc != "" {
			p.CongestionController = cc
		}
		if n.Extra["allow_insecure"] == "1" {
			p.AllowInsecure = true
		}
	case model.SchemeWireGuard:
		p.PrivateKey = n.User
	}
	return p
}

// clashWSOptsFor builds the Clash.Meta ws-opts block from whitelisted Extra keys.
func clashWSOptsFor(n model.Node) *clashWSOpts {
	o := &clashWSOpts{}
	if p := n.Extra["path"]; p != "" {
		o.Path = p
	}
	if h := n.Extra["host"]; h != "" {
		o.Headers = map[string]string{"Host": h}
	}
	return o
}

// clashHTTPOptsFor builds the Clash.Meta h2-opts block (HTTP/2 transport).
func clashHTTPOptsFor(n model.Node) *clashHTTPOpts {
	o := &clashHTTPOpts{}
	if p := n.Extra["path"]; p != "" {
		o.Path = p
	}
	if h := n.Extra["host"]; h != "" {
		o.Headers = map[string]string{"Host": h}
	}
	if o.Path == "" && o.Headers == nil {
		return nil
	}
	return o
}

// clashXHTTPOptsFor builds the Clash.Meta xhttp-opts block (splitHTTP transport).
func clashXHTTPOptsFor(n model.Node) *clashXHTTPOpts {
	o := &clashXHTTPOpts{}
	if p := n.Extra["path"]; p != "" {
		o.Path = p
	}
	if h := n.Extra["host"]; h != "" {
		o.Host = h
	}
	if m := n.Extra["mode"]; m != "" {
		o.Mode = m
	}
	if o.Path == "" && o.Host == "" && o.Mode == "" {
		return nil
	}
	return o
}

// clashGRPCOptsFor builds the Clash.Meta grpc-opts block with authority/mode.
func clashGRPCOptsFor(n model.Node) *clashGRPCOpts {
	o := &clashGRPCOpts{}
	if s := n.Extra["serviceName"]; s != "" {
		o.GRPCServiceName = s
	}
	if a := n.Extra["authority"]; a != "" {
		o.Authority = a
	}
	if m := n.Extra["mode"]; m != "" {
		o.Mode = m
	}
	if o.GRPCServiceName == "" && o.Authority == "" && o.Mode == "" {
		return nil
	}
	return o
}
