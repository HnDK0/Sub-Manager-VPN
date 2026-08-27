package parse

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"vpn-sub-manager/internal/model"
)

// ParseSubscription normalizes a raw subscription body into a flat list of
// model.Node. It handles three input shapes:
//
//  1. v2rayN base64: the whole body is base64 of newline-joined URIs.
//     If the body is not valid base64, it is treated as plain text of URIs.
//  2. Plain text: one URI per line.
//  3. Structured: Clash YAML (top-level `proxies:`) or sing-box JSON
//     (top-level `outbounds:`), best-effort mapped to Nodes.
//
// Unknown schemes are dropped (not an error). Parse errors on individual
// lines are skipped. The function only returns a non-nil error when a
// detected structured document fails to parse.
func ParseSubscription(body []byte) ([]model.Node, error) {
	text := decodeBody(body)
	trimmed := strings.TrimSpace(text)

	switch {
	case strings.HasPrefix(trimmed, "{"):
		return parseSingboxJSON([]byte(trimmed))
	case strings.Contains(trimmed, "proxies:"):
		return parseClashYAML([]byte(trimmed))
	default:
		return parseURIs(text), nil
	}
}

// decodeBody attempts base64 decoding (std / url-safe, padded / raw). If the
// body is not valid base64, the original text is returned unchanged.
func decodeBody(body []byte) string {
	if s, err := tryDecodeBase64(body); err == nil {
		return s
	}
	if s, ok := tryDecodePerLine(body); ok {
		return s
	}
	return string(body)
}

// tryDecodePerLine handles subscriptions where each line is an independent
// base64-encoded config (a common v2rayN layout). It base64-decodes every
// non-empty line and concatenates the decoded texts, joined by newlines. If no
// line decodes to text, ok is false and the caller falls back to the raw body.
func tryDecodePerLine(body []byte) (string, bool) {
	var sb strings.Builder
	found := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if s, err := tryDecodeBase64([]byte(line)); err == nil {
			sb.WriteString(s)
			sb.WriteString("\n")
			found = true
		}
	}
	if !found {
		return "", false
	}
	return sb.String(), true
}

func tryDecodeBase64(body []byte) (string, error) {
	// Join fields to tolerate wrapped/base64-with-newlines bodies.
	compact := strings.Join(strings.Fields(string(body)), "")
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, dec := range decoders {
		if b, err := dec(compact); err == nil && (isText(b) || strings.Contains(string(b), "://")) {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("not base64")
}

// isText reports whether b looks like decoded text rather than binary.
func isText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return true
}

// parseURIs splits plain text into lines and parses each as a URI.
func parseURIs(text string) []model.Node {
	var nodes []model.Node
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if n, ok := parseOne(line); ok {
			nodes = append(nodes, *n)
		}
	}
	return nodes
}

// parseOne parses a single URI. Returns ok=false for unknown/skipped schemes.
func parseOne(uri string) (*model.Node, bool) {
	scheme, userinfo, hostport, query, fragment, ok := splitURI(uri)
	if !ok {
		return nil, false
	}
	norm := normalizeScheme(scheme)
	if _, err := model.ParseScheme(norm); err != nil {
		return nil, false
	}
	var n *model.Node
	switch model.Scheme(norm) {
	case model.SchemeVMess:
		n = parseVMess(uri)
	case model.SchemeVLESS:
		n = parseVLESS(uri, userinfo, hostport, query, fragment)
	case model.SchemeTrojan:
		n = parseTrojan(uri, userinfo, hostport, query, fragment)
	case model.SchemeSS:
		n = parseSS(uri, userinfo, hostport, query, fragment)
	case model.SchemeHysteria2:
		n = parseHysteria2(uri, userinfo, hostport, query, fragment)
	case model.SchemeTUIC:
		n = parseTUIC(uri, userinfo, hostport, query, fragment)
	case model.SchemeWireGuard:
		n = parseWireGuard(uri, userinfo, hostport, query, fragment)
	default:
		return nil, false
	}
	if n == nil {
		return nil, false
	}
	return n, true
}

// normalizeScheme maps known aliases (hy2, amneziawg) to canonical schemes.
func normalizeScheme(s string) string {
	switch strings.ToLower(s) {
	case "hy2", "hysteria2":
		return "hysteria2"
	case "amneziawg", "wireguard":
		return "wireguard"
	default:
		return strings.ToLower(s)
	}
}

// splitURI extracts scheme/userinfo/hostport/query/fragment from a VPN URI.
// It is deliberately more lenient than net/url: userinfo may contain '/'
// (common in base64 SS/WireGuard keys) which net/url would misparse.
func splitURI(uri string) (scheme, userinfo, hostport, query, fragment string, ok bool) {
	i := strings.Index(uri, "://")
	if i < 0 {
		return "", "", "", "", "", false
	}
	scheme = uri[:i]
	rest := uri[i+3:]

	if h := strings.Index(rest, "#"); h >= 0 {
		fragment = rest[h+1:]
		rest = rest[:h]
	}
	if q := strings.Index(rest, "?"); q >= 0 {
		query = rest[q+1:]
		rest = rest[:q]
	}
	if a := strings.LastIndex(rest, "@"); a >= 0 {
		userinfo = rest[:a]
		hostport = rest[a+1:]
	} else {
		hostport = rest
	}
	return scheme, userinfo, hostport, query, fragment, true
}

// splitHostPort parses "host:port", tolerating IPv6 "[::1]:port".
func splitHostPort(hp string) (host string, port int) {
	if strings.HasPrefix(hp, "[") {
		if i := strings.Index(hp, "]"); i >= 0 {
			host = hp[1:i]
			rest := hp[i+1:]
			if strings.HasPrefix(rest, ":") {
				port, _ = strconv.Atoi(rest[1:])
			}
			return
		}
	}
	if i := strings.LastIndex(hp, ":"); i >= 0 {
		host = hp[:i]
		port, _ = strconv.Atoi(hp[i+1:])
		return
	}
	host = hp
	return
}

func tryB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, dec := range decoders {
		if b, err := dec(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not base64")
}

// ---------------------------------------------------------------------------
// vmess
// ---------------------------------------------------------------------------

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
	Host string `json:"host"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	Path string `json:"path"`
}

func parseVMess(uri string) *model.Node {
	payload := uri[len("vmess://"):]
	payload = strings.Split(payload, "#")[0]
	payload = strings.Split(payload, "?")[0]

	jsonBytes, err := tryB64(payload)
	if err != nil {
		jsonBytes = []byte(payload) // allow raw JSON
	}
	var v vmessJSON
	if err := json.Unmarshal(jsonBytes, &v); err != nil {
		return nil
	}
	port, _ := strconv.Atoi(v.Port)
	n := &model.Node{
		Protocol:   model.SchemeVMess,
		Host:       v.Add,
		Port:       port,
		User:       v.ID,
		Encryption: v.Scy,
		Name:       v.Ps,
		Raw:        uri,
	}
	if strings.EqualFold(v.TLS, "tls") {
		n.Security = "tls"
	}
	n.Network = v.Net
	// ponytail: capture ws/grpc/xhttp transport params into Extra so mihomo's
	// applyTransport can build ws-opts/grpc-opts. vmess:// JSON stores them in
	// host/path/type, but parseVMess never copied them — so vmess+ws probed with
	// an empty config and always returned dead. grpc encodes the service name in
	// `path`.
	if net := strings.ToLower(v.Net); net != "" && net != "tcp" {
		ex := map[string]string{}
		if v.Host != "" {
			ex["host"] = v.Host
		}
		if v.Path != "" {
			ex["path"] = v.Path
		}
		if v.Type != "" {
			ex["type"] = v.Type
		}
		if v.SNI != "" {
			ex["sni"] = v.SNI
		}
		if net == "grpc" && v.Path != "" {
			ex["serviceName"] = v.Path
		}
		n.Extra = ex
	}
	return n
}

// ---------------------------------------------------------------------------
// vless
// ---------------------------------------------------------------------------

func parseVLESS(uri, userinfo, hostport, query, fragment string) *model.Node {
	q, _ := url.ParseQuery(query)
	host, port := splitHostPort(hostport)
	n := &model.Node{
		Protocol:   model.SchemeVLESS,
		Host:       host,
		Port:       port,
		User:       userinfo,
		Encryption: q.Get("encryption"),
		Name:       fragment,
		Raw:        uri,
	}
	n.Security = q.Get("security")
	if n.Security == "" {
		n.Security = "none"
	}
	n.Flow = q.Get("flow")
	// ponytail: reality VLESS requires the xtls-rprx-vision flow; sources often
	// omit it, so default it here so every generator (v2rayn/singbox/clash) and
	// the web config endpoint emit a connectable node.
	if n.Security == "reality" && n.Flow == "" {
		n.Flow = "xtls-rprx-vision"
	}
	n.Network = q.Get("network")
	n.Extra = pickExtra(q, "type", "host", "path", "sni", "pbk", "sid", "fp", "spx", "serviceName", "alpn", "authority", "mode", "quicSecurity", "key", "allow_insecure", "congestion_control")
	return n
}

// ---------------------------------------------------------------------------
// trojan
// ---------------------------------------------------------------------------

func parseTrojan(uri, userinfo, hostport, query, fragment string) *model.Node {
	q, _ := url.ParseQuery(query)
	host, port := splitHostPort(hostport)
	n := &model.Node{
		Protocol: model.SchemeTrojan,
		Host:     host,
		Port:     port,
		User:     userinfo,
		Name:     fragment,
		Raw:      uri,
	}
	n.Security = q.Get("security")
	if n.Security == "" {
		n.Security = "tls"
	}
	// ponytail: capture the transport (ws/grpc/xhttp/h2) from the URI instead of
	// hardcoding tcp — trojan supports ws/grpc transports, and parsing them as tcp
	// (like the old vmess bug) made trojan+ws/grpc probe with an empty config and
	// always return dead.
	n.Network = q.Get("network")
	if n.Network == "" {
		n.Network = "tcp"
	}
	n.Extra = pickExtra(q, "type", "host", "path", "sni", "serviceName", "mode", "alpn", "authority", "allow_insecure", "congestion_control")
	return n
}

// ---------------------------------------------------------------------------
// ss (SIP002)
// ---------------------------------------------------------------------------

func parseSS(uri, userinfo, hostport, query, fragment string) *model.Node {
	q, _ := url.ParseQuery(query)
	host, port := splitHostPort(hostport)
	method, password := decodeSSUserinfo(userinfo)
	n := &model.Node{
		Protocol:   model.SchemeSS,
		Host:       host,
		Port:       port,
		User:       password,
		Encryption: method,
		Name:       fragment,
		Raw:        uri,
	}
	if plugin := q.Get("plugin"); plugin != "" {
		if isBenignPlugin(plugin) {
			n.Plugin = plugin
		} else {
			// exec present or unknown obfuscator: quarantine, do not set Plugin
			n.Extra = map[string]string{"plugin": plugin}
		}
	}
	return n
}

func decodeSSUserinfo(s string) (method, password string) {
	raw := s
	if b, err := tryB64(s); err == nil {
		raw = string(b)
	}
	if i := strings.Index(raw, ":"); i >= 0 {
		return raw[:i], raw[i+1:]
	}
	return raw, ""
}

// isBenignPlugin accepts only known, safe obfuscators and rejects any that
// carry an exec option (arbitrary command execution).
func isBenignPlugin(plugin string) bool {
	parts := strings.Split(plugin, ";")
	switch parts[0] {
	case "obfs-local", "obfs-http", "v2ray-plugin":
		for _, p := range parts[1:] {
			if strings.HasPrefix(strings.TrimSpace(p), "exec=") {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// hysteria2 / hy2
// ---------------------------------------------------------------------------

func parseHysteria2(uri, userinfo, hostport, query, fragment string) *model.Node {
	q, _ := url.ParseQuery(query)
	host, port := splitHostPort(hostport)
	n := &model.Node{
		Protocol: model.SchemeHysteria2,
		Host:     host,
		Port:     port,
		User:     userinfo,
		Name:     fragment,
		Raw:      uri,
	}
	n.Security = q.Get("security")
	if n.Security == "" {
		n.Security = "tls"
	}
	n.Network = "tcp"
	n.Extra = pickExtra(q, "sni", "obfs", "obfs-password", "pinSHA256", "insecure", "allow_insecure", "alpn", "congestion_control")
	if v, ok := n.Extra["insecure"]; ok && n.Extra["allow_insecure"] == "" {
		n.Extra["allow_insecure"] = v
	}
	return n
}

// ---------------------------------------------------------------------------
// tuic
// ---------------------------------------------------------------------------

func parseTUIC(uri, userinfo, hostport, query, fragment string) *model.Node {
	q, _ := url.ParseQuery(query)
	host, port := splitHostPort(hostport)
	n := &model.Node{
		Protocol: model.SchemeTUIC,
		Host:     host,
		Port:     port,
		User:     userinfo,
		Name:     fragment,
		Raw:      uri,
	}
	n.Security = q.Get("security")
	if n.Security == "" {
		n.Security = "tls"
	}
	n.Network = "tcp"
	n.Extra = pickExtra(q, "sni", "alpn", "allow_insecure", "congestion_control")
	return n
}

// ---------------------------------------------------------------------------
// wireguard / amneziawg
// ---------------------------------------------------------------------------

func parseWireGuard(uri, userinfo, hostport, query, fragment string) *model.Node {
	q, _ := url.ParseQuery(query)
	host, port := splitHostPort(hostport)
	n := &model.Node{
		Protocol: model.SchemeWireGuard,
		Host:     host,
		Port:     port,
		User:     userinfo,
		Name:     fragment,
		Raw:      uri,
	}
	// WireGuard provides its own transport encryption; no TLS layer.
	n.Extra = pickExtra(q, "privatekey", "peer-public-key", "public-key", "allowed-ips", "mtu", "reserved")
	return n
}

// pickExtra collects the named query params into Extra, returning nil if empty.
func pickExtra(q url.Values, keys ...string) map[string]string {
	extra := make(map[string]string)
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			extra[k] = v
		}
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
}

// ---------------------------------------------------------------------------
// Clash YAML
// ---------------------------------------------------------------------------

type clashProxy struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	Server     string `yaml:"server"`
	Port       int    `yaml:"port"`
	UUID       string `yaml:"uuid"`
	Password   string `yaml:"password"`
	Cipher     string `yaml:"cipher"`
	Method     string `yaml:"method"`
	Plugin     string `yaml:"plugin"`
	TLS        bool   `yaml:"tls"`
	SNI        string `yaml:"sni"`
	Network    string `yaml:"network"`
	Token      string `yaml:"token"`
	PrivateKey string `yaml:"private-key"`
}

type clashConfig struct {
	Proxies []clashProxy `yaml:"proxies"`
}

func parseClashYAML(data []byte) ([]model.Node, error) {
	var cfg clashConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	var nodes []model.Node
	for _, p := range cfg.Proxies {
		if n := clashToNode(p); n != nil {
			nodes = append(nodes, *n)
		}
	}
	return nodes, nil
}

func clashToNode(p clashProxy) *model.Node {
	scheme := strings.ToLower(p.Type)
	if _, err := model.ParseScheme(scheme); err != nil {
		return nil
	}
	n := &model.Node{
		Protocol: model.Scheme(scheme),
		Host:     p.Server,
		Port:     p.Port,
		Name:     p.Name,
		Network:  p.Network,
	}
	switch model.Scheme(scheme) {
	case model.SchemeVMess:
		n.User = p.UUID
		n.Encryption = p.Cipher
		if p.TLS {
			n.Security = "tls"
		}
	case model.SchemeVLESS:
		n.User = p.UUID
		if p.TLS {
			n.Security = "tls"
		} else {
			n.Security = "none"
		}
	case model.SchemeTrojan:
		n.User = p.Password
		if p.TLS {
			n.Security = "tls"
		} else {
			n.Security = "none"
		}
	case model.SchemeSS:
		n.User = p.Password
		n.Encryption = p.Cipher
		if p.Plugin != "" && isBenignPlugin(p.Plugin) {
			n.Plugin = p.Plugin
		}
	case model.SchemeHysteria2:
		n.User = p.Password
		n.Security = "tls"
	case model.SchemeTUIC:
		n.User = p.Token
		n.Security = "tls"
	case model.SchemeWireGuard:
		n.User = p.PrivateKey
	}
	return n
}

// ---------------------------------------------------------------------------
// sing-box JSON
// ---------------------------------------------------------------------------

type sbOutbound struct {
	Type       string          `json:"type"`
	Tag        string          `json:"tag"`
	Server     string          `json:"server"`
	ServerPort int             `json:"server_port"`
	UUID       string          `json:"uuid"`
	Password   string          `json:"password"`
	Method     string          `json:"method"`
	Plugin     string          `json:"plugin"`
	TLS        json.RawMessage `json:"tls"`
	Token      string          `json:"token"`
	PrivateKey string          `json:"private_key"`
}

type sbConfig struct {
	Outbounds []sbOutbound `json:"outbounds"`
}

func parseSingboxJSON(data []byte) ([]model.Node, error) {
	var cfg sbConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	var nodes []model.Node
	for _, o := range cfg.Outbounds {
		if n := sbToNode(o); n != nil {
			nodes = append(nodes, *n)
		}
	}
	return nodes, nil
}

func sbToNode(o sbOutbound) *model.Node {
	scheme := strings.ToLower(o.Type)
	if _, err := model.ParseScheme(scheme); err != nil {
		return nil
	}
	n := &model.Node{
		Protocol: model.Scheme(scheme),
		Host:     o.Server,
		Port:     o.ServerPort,
		Name:     o.Tag,
	}
	tlsOn := len(o.TLS) > 0 && string(o.TLS) != "null" && string(o.TLS) != "false"
	switch model.Scheme(scheme) {
	case model.SchemeVMess:
		n.User = o.UUID
		n.Encryption = o.Method
		if tlsOn {
			n.Security = "tls"
		}
	case model.SchemeVLESS:
		n.User = o.UUID
		if tlsOn {
			n.Security = "tls"
		} else {
			n.Security = "none"
		}
	case model.SchemeTrojan:
		n.User = o.Password
		if tlsOn {
			n.Security = "tls"
		} else {
			n.Security = "none"
		}
	case model.SchemeSS:
		n.User = o.Password
		n.Encryption = o.Method
		if o.Plugin != "" && isBenignPlugin(o.Plugin) {
			n.Plugin = o.Plugin
		}
	case model.SchemeHysteria2:
		n.User = o.Password
		n.Security = "tls"
	case model.SchemeTUIC:
		n.User = o.Token
		n.Security = "tls"
	case model.SchemeWireGuard:
		n.User = o.PrivateKey
	}
	return n
}
