package selector

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"vpn-sub-manager/internal/model"
)

// V2RayN builds a v2rayN-style subscription: each node's native URI joined by
// newlines and base64-encoded. An empty selection yields an empty string
// (never garbage). Extra/Raw are dropped; the benign SS Plugin obfs is
// serialized into the SS URI's ?plugin= param.
func V2RayN(nodes []model.Node) (string, error) {
	if len(nodes) == 0 {
		return "", nil
	}
	uris := make([]string, 0, len(nodes))
	names := nodeNames(nodes)
	for i, n := range nodes {
		u, err := nodeURI(n, names[i])
		if err != nil {
			return "", err
		}
		uris = append(uris, u)
	}
	raw := strings.Join(uris, "\n")
	return base64.StdEncoding.EncodeToString([]byte(raw)), nil
}

// NodeURI builds the v2rayN-style URI for a single node using its normalized
// display name. It is the exported form of nodeURI, used by the web layer so a
// user can copy one node's config into an external client to cross-check ping.
func NodeURI(n model.Node) (string, error) {
	return nodeURI(n, NormName(n))
}

func nodeURI(n model.Node, name string) (string, error) {
	switch n.Protocol {
	case model.SchemeVMess:
		return vmessURI(n, name), nil
	case model.SchemeVLESS, model.SchemeTrojan,
		model.SchemeHysteria2, model.SchemeTUIC, model.SchemeWireGuard:
		return simpleURI(n, name), nil
	case model.SchemeSS:
		return ssURI(n, name), nil
	default:
		return "", fmt.Errorf("select: unsupported protocol %q", n.Protocol)
	}
}

// vmessURI emits the vmess:// base64(JSON) form parse.go accepts. Only the
// explicit fields are written; transport extras (host/path/sni) come from the
// whitelisted Node.Extra keys. Ps carries the normalized display name.
func vmessURI(n model.Node, name string) string {
	v := vmessJSON{
		V:    "2",
		Ps:   name,
		Add:  n.Host,
		Port: strconv.Itoa(n.Port),
		ID:   n.User,
		Aid:  "0",
		Scy:  n.Encryption,
		Net:  transportNet(n),
		Type: "none",
		Host: n.Extra["host"],
		Path: n.Extra["path"],
		SNI:  n.Extra["sni"],
		TLS:  secureSecurity(n.Security),
	}
	b, _ := json.Marshal(v)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

// simpleURI covers vless/trojan/hysteria2/tuic/wireguard: userinfo@host:port
// with a security (and, for vless, encryption) query and a #name fragment.
// Transport/reality parameters are read from the whitelisted Node.Extra keys so
// every client gets a fully-connectable node across all transports.
func simpleURI(n model.Node, name string) string {
	q := url.Values{}
	net := transportNet(n)
	switch n.Protocol {
	case model.SchemeVLESS:
		// xray requires encryption=none for vless.
		q.Set("encryption", "none")
		if v := secureSecurity(n.Security); v != "" {
			q.Set("security", v)
		}
		q.Set("type", net)
		if n.Flow != "" {
			q.Set("flow", n.Flow)
		}
		// reality carries pbk/sid/fp/sni/spx; plain tls carries sni/fp/alpn.
		if n.Security == "reality" {
			addIf(q, "pbk", n.Extra["pbk"])
			addIf(q, "fp", n.Extra["fp"])
			addIf(q, "sid", n.Extra["sid"])
			addIf(q, "sni", n.Extra["sni"])
			addIf(q, "spx", n.Extra["spx"])
		} else {
			addIf(q, "sni", n.Extra["sni"])
			addIf(q, "fp", n.Extra["fp"])
			addIf(q, "alpn", n.Extra["alpn"])
		}
		addTransportParams(q, n)
	case model.SchemeTrojan:
		q.Set("security", "tls")
		addIf(q, "sni", n.Extra["sni"])
		addIf(q, "fp", n.Extra["fp"])
		addIf(q, "alpn", n.Extra["alpn"])
		q.Set("type", net)
		addTransportParams(q, n)
	case model.SchemeHysteria2:
		// hysteria2 has NO pbk (that is reality-VLESS-only).
		addIf(q, "sni", n.Extra["sni"])
		addIf(q, "alpn", n.Extra["alpn"])
		addIf(q, "obfs", n.Extra["obfs"])
		addIf(q, "obfs-password", n.Extra["obfs-password"])
		if n.Extra["allow_insecure"] == "1" {
			q.Set("insecure", "1")
		}
	case model.SchemeTUIC:
		// tuic has NO pbk (that is reality-VLESS-only).
		q.Set("security", "tls")
		addIf(q, "sni", n.Extra["sni"])
		addIf(q, "alpn", n.Extra["alpn"])
		addIf(q, "allow_insecure", n.Extra["allow_insecure"])
		addIf(q, "congestion_control", n.Extra["congestion_control"])
	}
	query := q.Encode()
	uri := fmt.Sprintf("%s://%s@%s:%d", n.Protocol, n.User, n.Host, n.Port)
	if query != "" {
		uri += "?" + query
	}
	if name != "" {
		uri += "#" + name
	}
	return uri
}

// addTransportParams emits the transport-specific query params for the node's
// network. tcp/quic carry no extra params; ws/grpc/http/xhttp each need their
// own set (grpc also carries authority+mode; xhttp adds mode).
func addTransportParams(q url.Values, n model.Node) {
	switch transportNet(n) {
	case "ws":
		addIf(q, "path", n.Extra["path"])
		addIf(q, "host", n.Extra["host"])
	case "grpc":
		addIf(q, "serviceName", n.Extra["serviceName"])
		addIf(q, "authority", n.Extra["authority"])
		addIf(q, "mode", n.Extra["mode"])
	case "http", "h2":
		addIf(q, "path", n.Extra["path"])
		addIf(q, "host", n.Extra["host"])
	case "xhttp":
		addIf(q, "path", n.Extra["path"])
		addIf(q, "host", n.Extra["host"])
		addIf(q, "mode", n.Extra["mode"])
	}
}

// transportNet returns the effective transport network for a node: n.Network,
// falling back to the parsed Extra["type"], defaulting to "tcp".
func transportNet(n model.Node) string {
	net := n.Network
	if net == "" {
		net = n.Extra["type"]
	}
	net = strings.ToLower(strings.TrimSpace(net))
	// Clash/sing-box/v2rayN can carry a literal "raw" network, meaning "no
	// transport / plain tcp". mihomo and the generators only understand "tcp",
	// so normalize raw->tcp to avoid emitting type=raw / network: raw /
	// transport.type: raw (which clients reject as an unknown transport).
	if net == "" || net == "raw" {
		net = "tcp"
	}
	return net
}

// addIf sets q[k]=v only when v is non-empty, so absent transport/reality
// params are omitted rather than emitted as empty values.
func addIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

// secureSecurity returns the security value to emit in a generated URI, or ""
// if s is missing or explicitly insecure ("none") so the output never
// advertises a plaintext/disabled transport. Filters drop such nodes upstream;
// this is defense-in-depth so a malformed node can never produce
// security=none / tls=none in the subscription.
func secureSecurity(s string) string {
	switch s {
	case "tls", "reality":
		return s
	}
	return ""
}

// ssURI emits the SIP002 form: base64(method:password)@host:port with an
// optional ?plugin= (the benign obfs validated at parse time).
func ssURI(n model.Node, name string) string {
	user := base64.StdEncoding.EncodeToString([]byte(n.Encryption + ":" + n.User))
	uri := fmt.Sprintf("ss://%s@%s:%d", user, n.Host, n.Port)
	if n.Plugin != "" {
		q := url.Values{}
		q.Set("plugin", n.Plugin)
		uri += "?" + q.Encode()
	}
	if name != "" {
		uri += "#" + name
	}
	return uri
}

// vmessJSON is the subset of the vmess schema parse.go reads back.
type vmessJSON struct {
	V    string `json:"v"`
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	ID   string `json:"id"`
	Aid  string `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
	SNI  string `json:"sni,omitempty"`
	TLS  string `json:"tls"`
}
