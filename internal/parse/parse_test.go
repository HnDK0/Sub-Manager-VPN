package parse

import (
	"encoding/base64"
	"strings"
	"testing"

	"vpn-sub-manager/internal/model"
)

// buildVMess returns a vmess:// URI from a JSON payload (base64-encoded).
func buildVMess(t *testing.T, jsonStr string) string {
	t.Helper()
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(jsonStr))
}

func TestParseVMess(t *testing.T) {
	jsonStr := `{"v":"2","ps":"Example VMess","add":"1.2.3.4","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","type":"none","host":"example.com","tls":"tls","sni":"example.com","path":"/path"}`
	uri := buildVMess(t, jsonStr)
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != model.SchemeVMess {
		t.Errorf("Protocol = %q, want vmess", n.Protocol)
	}
	if n.Host != "1.2.3.4" {
		t.Errorf("Host = %q, want 1.2.3.4", n.Host)
	}
	if n.Port != 443 {
		t.Errorf("Port = %d, want 443", n.Port)
	}
	if n.User != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Errorf("User = %q", n.User)
	}
	if n.Encryption != "auto" {
		t.Errorf("Encryption = %q, want auto", n.Encryption)
	}
	if n.Security != "tls" {
		t.Errorf("Security = %q, want tls", n.Security)
	}
	if n.Name != "Example VMess" {
		t.Errorf("Name = %q, want Example VMess", n.Name)
	}
}

func TestParseVLESS(t *testing.T) {
	uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2Fpath&sni=example.com#MyVLESS"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != model.SchemeVLESS {
		t.Errorf("Protocol = %q, want vless", n.Protocol)
	}
	if n.Host != "example.com" || n.Port != 443 {
		t.Errorf("Host/Port = %q/%d, want example.com/443", n.Host, n.Port)
	}
	if n.User != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Errorf("User = %q", n.User)
	}
	if n.Encryption != "none" {
		t.Errorf("Encryption = %q, want none", n.Encryption)
	}
	if n.Security != "tls" {
		t.Errorf("Security = %q, want tls", n.Security)
	}
	if n.Name != "MyVLESS" {
		t.Errorf("Name = %q, want MyVLESS", n.Name)
	}
}

func TestParseTrojan(t *testing.T) {
	uri := "trojan://password123@example.com:443?security=tls&sni=example.com#MyTrojan"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != model.SchemeTrojan {
		t.Errorf("Protocol = %q, want trojan", n.Protocol)
	}
	if n.Host != "example.com" || n.Port != 443 {
		t.Errorf("Host/Port = %q/%d, want example.com/443", n.Host, n.Port)
	}
	if n.User != "password123" {
		t.Errorf("User = %q, want password123", n.User)
	}
	if n.Security != "tls" {
		t.Errorf("Security = %q, want tls", n.Security)
	}
}

func TestParseSS(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:password123"))
	uri := "ss://" + userinfo + "@example.com:8388#MySS"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != model.SchemeSS {
		t.Errorf("Protocol = %q, want ss", n.Protocol)
	}
	if n.Host != "example.com" || n.Port != 8388 {
		t.Errorf("Host/Port = %q/%d, want example.com/8388", n.Host, n.Port)
	}
	if n.User != "password123" {
		t.Errorf("User = %q, want password123", n.User)
	}
	if n.Encryption != "chacha20-ietf-poly1305" {
		t.Errorf("Encryption = %q, want chacha20-ietf-poly1305", n.Encryption)
	}
}

func TestParseSSPluginBenign(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:password123"))
	uri := "ss://" + userinfo + "@example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp#MySS"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Plugin != "obfs-local;obfs=http" {
		t.Errorf("Plugin = %q, want obfs-local;obfs=http", n.Plugin)
	}
	if n.Extra != nil {
		t.Errorf("Extra should be nil for benign plugin, got %v", n.Extra)
	}
}

func TestParseSSPluginExecRejected(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:password123"))
	// exec= present -> must NOT set Plugin, raw goes to Extra
	uri := "ss://" + userinfo + "@example.com:8388?plugin=v2ray-plugin%3Bobfs%3Dhttp%3Bexec%3D%2Fbin%2Fsh#MySS"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Plugin != "" {
		t.Errorf("Plugin should be empty when exec present, got %q", n.Plugin)
	}
	if n.Extra == nil || n.Extra["plugin"] == "" {
		t.Errorf("exec plugin should be quarantined into Extra, got %v", n.Extra)
	}
}

func TestParseHysteria2(t *testing.T) {
	uri := "hysteria2://user123@example.com:8443?sni=example.com#MyHy2"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != model.SchemeHysteria2 {
		t.Errorf("Protocol = %q, want hysteria2", n.Protocol)
	}
	if n.Host != "example.com" || n.Port != 8443 {
		t.Errorf("Host/Port = %q/%d, want example.com/8443", n.Host, n.Port)
	}
	if n.User != "user123" {
		t.Errorf("User = %q, want user123", n.User)
	}
	if n.Security != "tls" {
		t.Errorf("Security = %q, want tls", n.Security)
	}
}

func TestParseHy2Alias(t *testing.T) {
	uri := "hy2://user123@example.com:8443#Alias"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Protocol != model.SchemeHysteria2 {
		t.Fatalf("hy2 alias not normalized to hysteria2: %+v", nodes)
	}
}

func TestParseTUIC(t *testing.T) {
	uri := "tuic://token-abc@example.com:8443?security=tls#MyTUIC"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != model.SchemeTUIC {
		t.Errorf("Protocol = %q, want tuic", n.Protocol)
	}
	if n.Host != "example.com" || n.Port != 8443 {
		t.Errorf("Host/Port = %q/%d, want example.com/8443", n.Host, n.Port)
	}
	if n.User != "token-abc" {
		t.Errorf("User = %q, want token-abc", n.User)
	}
	if n.Security != "tls" {
		t.Errorf("Security = %q, want tls", n.Security)
	}
}

func TestParseWireGuard(t *testing.T) {
	uri := "wireguard://PRIVATEKEY@example.com:51820?public-key=PUB&allowed-ips=0.0.0.0/0#MyWG"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Protocol != model.SchemeWireGuard {
		t.Errorf("Protocol = %q, want wireguard", n.Protocol)
	}
	if n.Host != "example.com" || n.Port != 51820 {
		t.Errorf("Host/Port = %q/%d, want example.com/51820", n.Host, n.Port)
	}
	if n.User != "PRIVATEKEY" {
		t.Errorf("User = %q, want PRIVATEKEY", n.User)
	}
}

func TestParseAmneziaWGAlias(t *testing.T) {
	uri := "amneziawg://PRIVATEKEY@example.com:51820#AWG"
	nodes, err := ParseSubscription([]byte(uri))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Protocol != model.SchemeWireGuard {
		t.Fatalf("amneziawg alias not normalized to wireguard: %+v", nodes)
	}
}

func TestParseUnknownSchemeSkipped(t *testing.T) {
	// ssr is intentionally unsupported; must yield zero nodes, no panic.
	body := []byte("ssr://example.com:8388/?abc\nvmess://deadbeef")
	nodes, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("ssr line must be skipped, got %d nodes: %+v", len(nodes), nodes)
	}
}

func TestParseCorruptBase64NoPanic(t *testing.T) {
	// Not valid base64 -> treated as plain text -> line skipped, no panic.
	body := []byte("!!!corrupt base64 not valid!!!")
	nodes, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("corrupt input should yield 0 nodes, got %d", len(nodes))
	}
}

func TestParseBase64Body(t *testing.T) {
	// v2rayN format: base64 of newline-joined URIs.
	uris := []string{
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&security=tls#A",
		"trojan://pw@example.com:443#B",
	}
	raw := strings.Join(uris, "\n")
	body := []byte(base64.StdEncoding.EncodeToString([]byte(raw)))

	nodes, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes from base64 body, got %d", len(nodes))
	}
	if nodes[0].Protocol != model.SchemeVLESS || nodes[1].Protocol != model.SchemeTrojan {
		t.Fatalf("unexpected protocols: %+v", nodes)
	}
}

func TestParseClashYAML(t *testing.T) {
	yamlStr := `
proxies:
  - name: "vmess-node"
    type: vmess
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    cipher: auto
    tls: true
  - name: "ss-node"
    type: ss
    server: 5.6.7.8
    port: 8388
    cipher: aes-256-gcm
    password: pw123
  - name: "unsupported"
    type: socks5
    server: 9.9.9.9
    port: 1080
`
	nodes, err := ParseSubscription([]byte(yamlStr))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes (socks5 skipped), got %d: %+v", len(nodes), nodes)
	}
	if nodes[0].Protocol != model.SchemeVMess || nodes[0].Security != "tls" {
		t.Errorf("vmess node wrong: %+v", nodes[0])
	}
	if nodes[1].Protocol != model.SchemeSS || nodes[1].User != "pw123" {
		t.Errorf("ss node wrong: %+v", nodes[1])
	}
}

func TestParseSingboxJSON(t *testing.T) {
	jsonStr := `{
  "outbounds": [
    {"type":"trojan","tag":"t","server":"1.1.1.1","server_port":443,"password":"pw","tls":{"enabled":true}},
    {"type":"hysteria2","tag":"h","server":"2.2.2.2","server_port":8443,"password":"pw2"},
    {"type":"dns","tag":"dns"}
  ]
}`
	nodes, err := ParseSubscription([]byte(jsonStr))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes (dns skipped), got %d: %+v", len(nodes), nodes)
	}
	if nodes[0].Protocol != model.SchemeTrojan || nodes[0].Security != "tls" {
		t.Errorf("trojan node wrong: %+v", nodes[0])
	}
	if nodes[1].Protocol != model.SchemeHysteria2 || nodes[1].User != "pw2" {
		t.Errorf("hysteria2 node wrong: %+v", nodes[1])
	}
}
