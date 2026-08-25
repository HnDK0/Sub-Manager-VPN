package selector

import (
	"encoding/json"
	"fmt"
	"strings"

	"vpn-sub-manager/internal/model"
)

// sbOutbound is the dedicated sing-box outbound struct. It deliberately omits
// any Extra/Raw field so model.Node is never serialized; transport/reality
// params are copied from the whitelisted Node.Extra keys into explicit fields.
type sbOutbound struct {
	Type       string        `json:"type"`
	Tag        string        `json:"tag"`
	Server     string        `json:"server"`
	ServerPort int           `json:"server_port"`
	UUID       string        `json:"uuid,omitempty"`
	Password   string        `json:"password,omitempty"`
	Method     string        `json:"method,omitempty"`
	Flow       string        `json:"flow,omitempty"`
	Plugin     string        `json:"plugin,omitempty"`
	TLS        *sbTLS        `json:"tls,omitempty"`
	Transport  *sbTransport  `json:"transport,omitempty"`
	Obfs              *sbObfs `json:"obfs,omitempty"`
	Token             string  `json:"token,omitempty"`
	PrivateKey        string  `json:"private_key,omitempty"`
	CongestionControl string  `json:"congestion_control,omitempty"`
	UDPRelayMode      string  `json:"udp_relay_mode,omitempty"`
}

// sbTLS carries the sing-box TLS/reality configuration. Reality params come
// from the whitelisted Node.Extra keys (pbk/sid/fp/sni).
type sbTLS struct {
	Enabled    bool       `json:"enabled"`
	ServerName string     `json:"server_name,omitempty"`
	ALPN       []string   `json:"alpn,omitempty"`
	UTLS       *sbUTLS    `json:"utls,omitempty"`
	Reality    *sbReality `json:"reality,omitempty"`
}

type sbUTLS struct {
	Fingerprint string `json:"fingerprint"`
}

type sbReality struct {
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

// sbTransport carries the per-network transport block (ws/grpc).
type sbTransport struct {
	Type        string            `json:"type"`
	Path        string            `json:"path,omitempty"`
	Host        []string          `json:"host,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
	Authority   string            `json:"authority,omitempty"`
	Mode        string            `json:"mode,omitempty"`
}

// sbObfs carries the hysteria2 obfs block.
type sbObfs struct {
	Type     string `json:"type"`
	Password string `json:"password,omitempty"`
}

type sbGroup struct {
	Type      string   `json:"type"`
	Tag       string   `json:"tag"`
	Outbounds []string `json:"outbounds"`
	URL       string   `json:"url,omitempty"`
	Interval  string   `json:"interval,omitempty"`
}

type sbConfig struct {
	Outbounds []interface{} `json:"outbounds"`
}

// SingBox builds a sing-box configuration: one outbound per node plus a
// urltest group selecting across them. Only explicit Node fields are emitted;
// Node.Extra/Node.Raw are never marshaled.
func SingBox(nodes []model.Node) ([]byte, error) {
	tags := nodeNames(nodes)
	out := make([]interface{}, 0, len(nodes)+1)
	for i, n := range nodes {
		out = append(out, sbOutboundFor(n, tags[i]))
	}
	out = append(out, sbGroup{
		Type:      "urltest",
		Tag:       "auto",
		Outbounds: tags,
		URL:       "https://www.gstatic.com/generate_204",
		Interval:  "300s",
	})

	b, err := json.MarshalIndent(sbConfig{Outbounds: out}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("select: singbox marshal: %w", err)
	}
	return b, nil
}

func sbOutboundFor(n model.Node, tag string) sbOutbound {
	o := sbOutbound{
		Type:       string(n.Protocol),
		Tag:        tag,
		Server:     n.Host,
		ServerPort: n.Port,
	}
	if n.Plugin != "" {
		o.Plugin = n.Plugin
	}
	net := transportNet(n)
	switch n.Protocol {
	case model.SchemeVMess:
		o.UUID = n.User
		o.Method = n.Encryption
		if n.Security == "tls" {
			o.TLS = sbTLSBlock(n, false)
		}
		if net != "tcp" {
			o.Transport = sbTransportFor(n, net)
		}
	case model.SchemeVLESS:
		o.UUID = n.User
		if n.Flow != "" {
			o.Flow = n.Flow
		}
		switch n.Security {
		case "reality":
			o.TLS = sbTLSBlock(n, true)
		case "tls":
			o.TLS = sbTLSBlock(n, false)
		}
		if net != "tcp" {
			o.Transport = sbTransportFor(n, net)
		}
	case model.SchemeTrojan:
		o.Password = n.User
		if n.Security == "tls" {
			o.TLS = sbTLSBlock(n, false)
		}
		if net != "tcp" {
			o.Transport = sbTransportFor(n, net)
		}
	case model.SchemeSS:
		o.Password = n.User
		o.Method = n.Encryption
	case model.SchemeHysteria2:
		o.Password = n.User
		if n.Security == "tls" {
			o.TLS = sbTLSBlock(n, false)
		}
		if obfs := n.Extra["obfs"]; obfs != "" {
			o.Obfs = &sbObfs{Type: obfs, Password: n.Extra["obfs-password"]}
		}
	case model.SchemeTUIC:
		o.UUID = n.User
		o.Password = n.User
		o.Token = n.User
		if n.Security == "tls" {
			o.TLS = sbTLSBlock(n, false)
		}
		o.CongestionControl = n.Extra["congestion_control"]
		o.UDPRelayMode = "native"
	case model.SchemeWireGuard:
		o.PrivateKey = n.User
	}
	return o
}

// sbTLSBlock builds the sing-box TLS block. reality enables the utls
// fingerprint and reality public_key/short_id; spider_x is intentionally NOT
// emitted (sing-box has no such field). ALPN is attached when present.
func sbTLSBlock(n model.Node, reality bool) *sbTLS {
	t := &sbTLS{Enabled: true, ServerName: n.Extra["sni"]}
	if alpn := n.Extra["alpn"]; alpn != "" {
		t.ALPN = strings.Split(alpn, ",")
	}
	if reality {
		t.UTLS = &sbUTLS{Fingerprint: firstNonEmpty(n.Extra["fp"], "chrome")}
		t.Reality = &sbReality{PublicKey: n.Extra["pbk"], ShortID: n.Extra["sid"]}
	}
	return t
}

// sbTransportFor builds the sing-box transport block for the given network.
func sbTransportFor(n model.Node, net string) *sbTransport {
	switch net {
	case "ws":
		t := &sbTransport{Type: "ws"}
		if p := n.Extra["path"]; p != "" {
			t.Path = p
		}
		if h := n.Extra["host"]; h != "" {
			t.Headers = map[string]string{"Host": h}
		}
		return t
	case "grpc":
		t := &sbTransport{Type: "grpc"}
		if s := n.Extra["serviceName"]; s != "" {
			t.ServiceName = s
		}
		if a := n.Extra["authority"]; a != "" {
			t.Authority = a
		}
		if m := n.Extra["mode"]; m != "" {
			t.Mode = m
		}
		return t
	case "http", "h2":
		t := &sbTransport{Type: "http"}
		if h := n.Extra["host"]; h != "" {
			t.Host = []string{h}
		}
		if p := n.Extra["path"]; p != "" {
			t.Path = p
		}
		return t
	case "xhttp":
		t := &sbTransport{Type: "httpupgrade"}
		if h := n.Extra["host"]; h != "" {
			t.Host = []string{h}
		}
		if p := n.Extra["path"]; p != "" {
			t.Path = p
		}
		return t
	}
	return nil
}

// firstNonEmpty returns the first non-empty string among vals.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
