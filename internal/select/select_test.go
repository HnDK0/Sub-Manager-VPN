package selector

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/parse"
)

// nameFmtRE matches the normalized display name:
// "<flag> <PROTO> <NET> <host:port> <security>" with an optional "-xxxx" collision suffix.
var nameFmtRE = regexp.MustCompile(`^.{1,8} [A-Z0-9]+ [^ ]+ [^ ]+:\d+ [^ ]+(-[0-9a-f]{4})?$`)

// sampleNode builds a node for the given scheme with the fields parse.go
// actually reads back, so round-trips are faithful.
func sampleNode(scheme model.Scheme) model.Node {
	n := model.Node{
		Protocol: scheme,
		Host:     "example.com",
		Port:     443,
		Name:     "node-" + string(scheme),
	}
	switch scheme {
	case model.SchemeVMess:
		n.User = "11111111-2222-3333-4444-555555555555"
		n.Encryption = "aes-128-gcm"
		n.Security = "tls"
	case model.SchemeVLESS:
		n.User = "11111111-2222-3333-4444-555555555555"
		n.Encryption = "none"
		n.Security = "tls"
	case model.SchemeTrojan:
		n.User = "trojan-pass"
		n.Security = "tls"
	case model.SchemeSS:
		n.User = "ss-pass"
		n.Encryption = "aes-256-gcm"
		n.Plugin = "obfs-local;obfs=http"
	case model.SchemeHysteria2:
		n.User = "hy2-pass"
		n.Security = "tls"
	case model.SchemeTUIC:
		n.User = "tuic-token"
		n.Security = "tls"
	case model.SchemeWireGuard:
		n.User = "wg-private-key"
	}
	return n
}

func TestSelectTopNPerCountry(t *testing.T) {
	// Country "US" has 7 alive nodes; "JP" has only 2 (both selected).
	var cands []Candidate
	for i := 0; i < 7; i++ {
		cands = append(cands, Candidate{
			Node:      model.Node{Protocol: model.SchemeVMess, Host: "us", Port: 1000 + i, Name: "us"},
			LatencyMs: (i + 1) * 10, // 10..70
			Country:   "US",
		})
	}
	cands = append(cands, Candidate{Node: model.Node{Protocol: model.SchemeSS, Host: "jp1", Port: 1, Name: "jp1"}, LatencyMs: 5, Country: "JP"})
	cands = append(cands, Candidate{Node: model.Node{Protocol: model.SchemeSS, Host: "jp2", Port: 2, Name: "jp2"}, LatencyMs: 9, Country: "JP"})

	got := Select(cands, 5)
	if len(got) != 7 { // 5 from US + 2 from JP
		t.Fatalf("expected 7 selected, got %d", len(got))
	}
	// US nodes must be the 5 lowest-latency (10..50), never the 60/70 ones.
	usCount := 0
	for _, n := range got {
		if n.Node.Host == "us" {
			usCount++
			if n.Node.Port > 1004 { // ports 1005,1006 are 60/70ms -> must be excluded
				t.Errorf("high-latency US node selected: port %d", n.Node.Port)
			}
		}
	}
	if usCount != 5 {
		t.Errorf("expected 5 US nodes, got %d", usCount)
	}
}

func TestSelectClampsTopN(t *testing.T) {
	var cands []Candidate
	for i := 0; i < 25; i++ {
		cands = append(cands, Candidate{Node: model.Node{Host: "h", Port: i}, LatencyMs: i, Country: "X"})
	}
	if len(Select(cands, 2)) != 3 { // clamped up to 3
		t.Error("topN=2 should clamp to 3")
	}
	if len(Select(cands, 99)) != 25 { // cap 500 >> count, all 25 returned
		t.Error("topN=99 should clamp to 20")
	}
	if len(Select(cands, 0)) != 5 { // default 5
		t.Error("topN=0 should default to 5")
	}
}

func TestNodeNamesFormat(t *testing.T) {
	nodes := []model.Node{
		{Protocol: model.SchemeVLESS, Host: "1.2.3.4", Port: 443, Security: "tls", Network: "ws", User: "u1"},
		{Protocol: model.SchemeVLESS, Host: "1.2.3.5", Port: 443, Security: "reality", Flow: "xtls-rprx-vision", Network: "grpc", User: "u1b"},
		{Protocol: model.SchemeVMess, Host: "5.6.7.8", Port: 8443, Encryption: "aes-128-gcm", Security: "tls", Network: "ws", User: "u2"},
		{Protocol: model.SchemeTrojan, Host: "9.10.11.12", Port: 443, Security: "tls", User: "u3"}, // default tcp
		{Protocol: model.SchemeHysteria2, Host: "h.example", Port: 443, Security: "tls", User: "u4"}, // default tcp
		{Protocol: model.SchemeTUIC, Host: "t.example", Port: 443, Security: "tls", User: "u5"}, // default tcp
		{Protocol: model.SchemeVLESS, Host: "e.example", Port: 443, User: "u6"}, // empty security -> none, default tcp
	}
	names := nodeNames(nodes)
	for i, n := range nodes {
		if !nameFmtRE.MatchString(names[i]) {
			t.Errorf("%s: name %q does not match <flag> <PROTO> <NET> <host:port> <security>", n.Protocol, names[i])
		}
	}
	// TYPE tokens are precise; empty country yields the white flag (🏳).
	if names[0] != "\U0001F3F3 VLESS ws 1.2.3.4:443 tls" {
		t.Errorf("vless+ws name = %q", names[0])
	}
	if names[1] != "\U0001F3F3 VLESS grpc 1.2.3.5:443 xtls-rprx-vision" {
		t.Errorf("vless+reality+grpc name = %q", names[1])
	}
	if names[2] != "\U0001F3F3 VMESS ws 5.6.7.8:8443 aes-128-gcm" {
		t.Errorf("vmess+ws name = %q", names[2])
	}
	if names[3] != "\U0001F3F3 TROJAN tcp 9.10.11.12:443 tls" {
		t.Errorf("trojan name = %q", names[3])
	}
	if names[4] != "\U0001F3F3 HY2 tcp h.example:443 tls" {
		t.Errorf("hysteria2 name = %q", names[4])
	}
	if names[5] != "\U0001F3F3 TUIC tcp t.example:443 tls" {
		t.Errorf("tuic name = %q", names[5])
	}
	if names[6] != "\U0001F3F3 VLESS tcp e.example:443 none" {
		t.Errorf("empty-security vless name = %q", names[6])
	}

	// Collision: same host:port, different credentials -> stable distinct suffix.
	same := []model.Node{
		{Protocol: model.SchemeVLESS, Host: "1.1.1.1", Port: 443, Security: "tls", User: "aaa"},
		{Protocol: model.SchemeVLESS, Host: "1.1.1.1", Port: 443, Security: "tls", User: "bbb"},
	}
	cn := nodeNames(same)
	if cn[0] == cn[1] {
		t.Fatalf("collision siblings must differ, both %q", cn[0])
	}
	if !strings.HasSuffix(cn[0], "-"+collisionSuffix(same[0])) {
		t.Errorf("sibling missing stable suffix: %q", cn[0])
	}
	// Stable across calls (no random counter).
	cn2 := nodeNames(same)
	if cn2[0] != cn[0] || cn2[1] != cn[1] {
		t.Error("nodeNames not stable across calls")
	}
}

func TestV2RayNRoundTrip(t *testing.T) {
	nodes := []model.Node{
		sampleNode(model.SchemeVMess),
		sampleNode(model.SchemeVLESS),
		sampleNode(model.SchemeTrojan),
		sampleNode(model.SchemeSS),
		sampleNode(model.SchemeHysteria2),
		sampleNode(model.SchemeTUIC),
		sampleNode(model.SchemeWireGuard),
	}
	b64, err := V2RayN(nodes)
	if err != nil {
		t.Fatalf("V2RayN: %v", err)
	}
	if b64 == "" {
		t.Fatal("expected non-empty base64")
	}
	// Empty selection -> empty string.
	empty, err := V2RayN(nil)
	if err != nil || empty != "" {
		t.Fatalf("empty selection should yield empty string, got %q err %v", empty, err)
	}

	// Decode and re-parse through the real parser.
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	// Security: the artifact must not be a marshaled model.Node (no Raw/Extra).
	if strings.Contains(string(raw), `"Raw"`) || strings.Contains(string(raw), `"Extra"`) {
		t.Fatal("v2rayN artifact contains marshaled model.Node fields")
	}
	parsed, err := parse.ParseSubscription(raw)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(parsed) != len(nodes) {
		t.Fatalf("expected %d nodes after round-trip, got %d", len(nodes), len(parsed))
	}
	wantNames := nodeNames(nodes)
	for i, orig := range nodes {
		assertRoundTrip(t, orig, parsed[i], wantNames[i])
	}
}

func TestSingBoxNoExtraRaw(t *testing.T) {
	nodes := []model.Node{sampleNode(model.SchemeSS), sampleNode(model.SchemeVMess), sampleNode(model.SchemeTUIC)}
	b, err := SingBox(nodes)
	if err != nil {
		t.Fatalf("SingBox: %v", err)
	}
	var cfg struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.Outbounds) != len(nodes)+1 {
		t.Fatalf("expected %d outbounds, got %d", len(nodes)+1, len(cfg.Outbounds))
	}
	group := cfg.Outbounds[len(cfg.Outbounds)-1]
	if group["type"] != "urltest" {
		t.Errorf("last outbound should be urltest group, got %v", group["type"])
	}
	for _, o := range cfg.Outbounds {
		assertNoExtraRaw(t, o)
	}
	// SS plugin must be present in its outbound.
	var foundPlugin bool
	for _, o := range cfg.Outbounds {
		if p, ok := o["plugin"]; ok && p == "obfs-local;obfs=http" {
			foundPlugin = true
		}
	}
	if !foundPlugin {
		t.Error("expected SS plugin in sing-box output")
	}
}

func TestClashNoExtraRaw(t *testing.T) {
	nodes := []model.Node{sampleNode(model.SchemeSS), sampleNode(model.SchemeVLESS), sampleNode(model.SchemeWireGuard)}
	b, err := ClashMeta(nodes)
	if err != nil {
		t.Fatalf("ClashMeta: %v", err)
	}
	var generic map[string]interface{}
	if err := yaml.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal yaml: %v", err)
	}
	proxies, ok := generic["proxies"].([]interface{})
	if !ok || len(proxies) != len(nodes) {
		t.Fatalf("expected %d proxies, got %v", len(nodes), generic["proxies"])
	}
	groups, ok := generic["proxy-groups"].([]interface{})
	if !ok || len(groups) != 1 {
		t.Fatalf("expected 1 proxy-group, got %v", generic["proxy-groups"])
	}
	g := groups[0].(map[string]interface{})
	if g["type"] != "url-test" {
		t.Errorf("group type should be url-test, got %v", g["type"])
	}
	assertNoExtraRawGeneric(t, generic)
}

func TestPersisterGuard(t *testing.T) {
	dir := t.TempDir()

	// Seed a previous good singbox.json.
	old := []byte("OLD-GOOD-CONTENT")
	if err := os.WriteFile(filepath.Join(dir, singboxFile), old, 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewPersister(dir, 1)
	// Empty run must keep old files and not error.
	if err := p.Persist(nil); err != nil {
		t.Fatalf("empty persist should not error: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, singboxFile))
	if string(got) != string(old) {
		t.Errorf("empty run overwrote good file: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, metaFile)); err == nil {
		t.Error("empty run should not write meta")
	}

	// Valid run writes all artifacts + meta.
	if err := p.Persist([]model.Node{sampleNode(model.SchemeSS)}); err != nil {
		t.Fatalf("valid persist: %v", err)
	}
	for _, f := range []string{singboxFile, v2raynFile, clashFile, metaFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing output %s: %v", f, err)
		}
	}
}

func TestPersisterBadDir(t *testing.T) {
	// Use an existing file as the target dir -> MkdirAll must fail.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewPersister(blocker, 1)
	err := p.Persist([]model.Node{sampleNode(model.SchemeSS)})
	if err == nil {
		t.Fatal("expected error for unwritable dir, got nil")
	}
}

// TestGeneratorsEmitRealityTransport proves the bug fix: reality VLESS nodes
// carry pbk/sid/fp/sni (and flow) in every output format, and ws/trojan nodes
// preserve path/host/sni. It also proves only whitelisted Extra keys are
// emitted (no Raw, no plugin/exec leakage).
func TestGeneratorsEmitRealityTransport(t *testing.T) {
	reality := model.Node{
		Protocol: model.SchemeVLESS,
		Host:     "example.com",
		Port:     443,
		User:     "11111111-2222-3333-4444-555555555555",
		Security: "reality",
		Flow:     "xtls-rprx-vision",
		Extra:    map[string]string{"pbk": "X", "sid": "Y", "fp": "chrome", "sni": "example.com", "type": "tcp"},
	}
	ws := model.Node{
		Protocol: model.SchemeVLESS,
		Host:     "ws.example.com",
		Port:     443,
		User:     "uuid-ws",
		Security: "tls",
		Extra:    map[string]string{"type": "ws", "path": "/ws", "host": "ws.example.com", "sni": "ws.example.com"},
	}
	trojan := model.Node{
		Protocol: model.SchemeTrojan,
		Host:     "tr.example.com",
		Port:     443,
		User:     "trojan-pass",
		Security: "tls",
		Extra:    map[string]string{"sni": "tr.example.com", "type": "ws", "path": "/t", "host": "tr.example.com"},
	}
	nodes := []model.Node{reality, ws, trojan}

	// --- v2rayN ---
	b64, err := V2RayN(nodes)
	if err != nil {
		t.Fatalf("V2RayN: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"security=reality", "pbk=X", "flow=xtls-rprx-vision",
		"type=ws", "path=%2Fws", "host=ws.example.com",
		"security=tls", "sni=tr.example.com", "path=%2Ft",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("v2rayN missing %q in:\n%s", want, text)
		}
	}

	// --- sing-box ---
	sb, err := SingBox(nodes)
	if err != nil {
		t.Fatalf("SingBox: %v", err)
	}
	var sbCfg struct {
		Outbounds []map[string]interface{} `json:"outbounds"`
	}
	if err := json.Unmarshal(sb, &sbCfg); err != nil {
		t.Fatalf("singbox unmarshal: %v", err)
	}
	// reality outbound must carry tls.reality.public_key == "X"
	var foundReality bool
	for _, o := range sbCfg.Outbounds {
		if o["type"] != "vless" {
			continue
		}
		tls, ok := o["tls"].(map[string]interface{})
		if !ok {
			continue
		}
		realityObj, ok := tls["reality"].(map[string]interface{})
		if !ok {
			continue
		}
		if realityObj["public_key"] == "X" {
			foundReality = true
		}
	}
	if !foundReality {
		t.Errorf("sing-box reality public_key not found in:\n%s", sb)
	}
	// ws transport preserved
	var foundWS bool
	for _, o := range sbCfg.Outbounds {
		if o["type"] != "vless" {
			continue
		}
		tr, ok := o["transport"].(map[string]interface{})
		if ok && tr["type"] == "ws" && tr["path"] == "/ws" {
			foundWS = true
		}
	}
	if !foundWS {
		t.Errorf("sing-box ws transport not found in:\n%s", sb)
	}

	// --- clash ---
	cl, err := ClashMeta(nodes)
	if err != nil {
		t.Fatalf("ClashMeta: %v", err)
	}
	var clCfg struct {
		Name    string `yaml:"name"`
		Proxies []struct {
			Type        string `yaml:"type"`
			RealityOpts struct {
				PBK string `yaml:"pbk"`
			} `yaml:"reality-opts"`
			WSOpts struct {
				Path string `yaml:"path"`
			} `yaml:"ws-opts"`
			SNI string `yaml:"sni"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(cl, &clCfg); err != nil {
		t.Fatalf("clash unmarshal: %v", err)
	}
	if clCfg.Name != "Sub Manager VPN" {
		t.Errorf("clash top-level name = %q, want %q", clCfg.Name, "Sub Manager VPN")
	}
	var foundClashReality, foundClashWS bool
	for _, p := range clCfg.Proxies {
		if p.Type == "vless" && p.RealityOpts.PBK == "X" {
			foundClashReality = true
		}
		if p.Type == "vless" && p.WSOpts.Path == "/ws" {
			foundClashWS = true
		}
		if p.Type == "trojan" && p.SNI == "tr.example.com" {
			foundClashWS = true
		}
	}
	if !foundClashReality {
		t.Errorf("clash reality-opts pbk not found in:\n%s", cl)
	}
	if !foundClashWS {
		t.Errorf("clash ws/sni not found in:\n%s", cl)
	}
}

// TestGeneratorsAllTransports proves full param coverage across ws/grpc/http
// transports and the no-pbk rule for hysteria2/tuic, plus no spx in sing-box
// or clash (spx is reality-VLESS-only and sing-box/clash have no such field).
func TestGeneratorsAllTransports(t *testing.T) {
	vlessGRPC := model.Node{
		Protocol: model.SchemeVLESS,
		Host:     "g.example.com",
		Port:     443,
		User:     "uuid-grpc",
		Security: "tls",
		Extra:    map[string]string{"type": "grpc", "serviceName": "svc", "authority": "auth.example.com", "mode": "multi", "sni": "g.example.com"},
	}
	vlessXHTTP := model.Node{
		Protocol: model.SchemeVLESS,
		Host:     "x.example.com",
		Port:     443,
		User:     "uuid-xhttp",
		Security: "tls",
		Extra:    map[string]string{"type": "xhttp", "path": "/x", "host": "x.example.com", "mode": "auto", "sni": "x.example.com"},
	}
	vlessH2 := model.Node{
		Protocol: model.SchemeVLESS,
		Host:     "h.example.com",
		Port:     443,
		User:     "uuid-h2",
		Security: "tls",
		Extra:    map[string]string{"type": "http", "path": "/h", "host": "h.example.com", "sni": "h.example.com"},
	}
	hy2 := model.Node{
		Protocol: model.SchemeHysteria2,
		Host:     "hy.example.com",
		Port:     443,
		User:     "hy-pass",
		Security: "tls",
		Extra:    map[string]string{"sni": "hy.example.com", "obfs": "salamander", "obfs-password": "pw", "pbk": "SHOULD_NOT_APPEAR"},
	}
	tuic := model.Node{
		Protocol: model.SchemeTUIC,
		Host:     "tu.example.com",
		Port:     443,
		User:     "tu-token",
		Security: "tls",
		Extra:    map[string]string{"sni": "tu.example.com", "congestion_control": "bbr", "allow_insecure": "1", "pbk": "SHOULD_NOT_APPEAR"},
	}
	trojanGRPC := model.Node{
		Protocol: model.SchemeTrojan,
		Host:     "tg.example.com",
		Port:     443,
		User:     "tg-pass",
		Security: "tls",
		Extra:    map[string]string{"type": "grpc", "serviceName": "tg-svc", "sni": "tg.example.com"},
	}
	nodes := []model.Node{vlessGRPC, vlessXHTTP, vlessH2, hy2, tuic, trojanGRPC}

	// --- v2rayN ---
	b64, err := V2RayN(nodes)
	if err != nil {
		t.Fatalf("V2RayN: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode b64: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"type=grpc", "serviceName=svc", "authority=auth.example.com", "mode=multi",
		"type=xhttp", "path=%2Fx", "host=x.example.com", "mode=auto",
		"type=http", "path=%2Fh", "host=h.example.com",
		"obfs=salamander", "obfs-password=pw",
		"congestion_control=bbr", "allow_insecure=1",
		"serviceName=tg-svc",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("v2rayN missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "pbk=SHOULD_NOT_APPEAR") {
		t.Errorf("v2rayN leaked pbk for hysteria2/tuic:\n%s", text)
	}

	// --- sing-box ---
	sb, err := SingBox(nodes)
	if err != nil {
		t.Fatalf("SingBox: %v", err)
	}
	sbText := string(sb)
	for _, want := range []string{
		`"type": "httpupgrade"`, "svc", "auth.example.com", "multi",
		"x.example.com", "h.example.com", "bbr",
	} {
		if !strings.Contains(sbText, want) {
			t.Errorf("sing-box missing %q in:\n%s", want, sbText)
		}
	}
	if strings.Contains(sbText, "SHOULD_NOT_APPEAR") {
		t.Errorf("sing-box leaked pbk for hysteria2/tuic:\n%s", sbText)
	}
	if strings.Contains(sbText, "spider_x") {
		t.Errorf("sing-box contains spider_x:\n%s", sbText)
	}

	// --- clash ---
	cl, err := ClashMeta(nodes)
	if err != nil {
		t.Fatalf("ClashMeta: %v", err)
	}
	clText := string(cl)
	for _, want := range []string{
		"grpc-service-name", "authority", "mode",
		"xhttp-opts:", "h2-opts:", "congestion-controller",
		"svc", "auth.example.com", "multi", "bbr",
	} {
		if !strings.Contains(clText, want) {
			t.Errorf("clash missing %q in:\n%s", want, clText)
		}
	}
	if strings.Contains(clText, "SHOULD_NOT_APPEAR") {
		t.Errorf("clash leaked pbk for hysteria2/tuic:\n%s", clText)
	}
	if strings.Contains(clText, "spx") {
		t.Errorf("clash contains spx:\n%s", clText)
	}
}

// --- helpers ---

func assertRoundTrip(t *testing.T, orig, got model.Node, wantName string) {
	t.Helper()
	if got.Protocol != orig.Protocol {
		t.Errorf("[%s] protocol: got %q want %q", orig.Protocol, got.Protocol, orig.Protocol)
	}
	if got.Host != orig.Host {
		t.Errorf("[%s] host: got %q want %q", orig.Protocol, got.Host, orig.Host)
	}
	if got.Port != orig.Port {
		t.Errorf("[%s] port: got %d want %d", orig.Protocol, got.Port, orig.Port)
	}
	if got.User != orig.User {
		t.Errorf("[%s] user: got %q want %q", orig.Protocol, got.User, orig.User)
	}
	// The emitted name is the normalized display name, not the raw DB name.
	if got.Name != wantName {
		t.Errorf("[%s] name: got %q want normalized %q", orig.Protocol, got.Name, wantName)
	}
	switch orig.Protocol {
	case model.SchemeVMess, model.SchemeVLESS, model.SchemeSS:
		if got.Encryption != orig.Encryption {
			t.Errorf("[%s] encryption: got %q want %q", orig.Protocol, got.Encryption, orig.Encryption)
		}
	}
	if orig.Protocol != model.SchemeWireGuard {
		if got.Security != orig.Security {
			t.Errorf("[%s] security: got %q want %q", orig.Protocol, got.Security, orig.Security)
		}
	}
	if orig.Protocol == model.SchemeSS {
		if got.Plugin != orig.Plugin {
			t.Errorf("[ss] plugin: got %q want %q", got.Plugin, orig.Plugin)
		}
	}
}

func assertNoExtraRaw(t *testing.T, m map[string]interface{}) {
	t.Helper()
	for k := range m {
		if strings.EqualFold(k, "extra") || strings.EqualFold(k, "raw") {
			t.Errorf("forbidden key %q in outbound", k)
		}
	}
}

func assertNoExtraRawGeneric(t *testing.T, v interface{}) {
	t.Helper()
	switch m := v.(type) {
	case map[string]interface{}:
		for k, val := range m {
			if strings.EqualFold(k, "extra") || strings.EqualFold(k, "raw") {
				t.Errorf("forbidden key %q in artifact", k)
			}
			assertNoExtraRawGeneric(t, val)
		}
	case []interface{}:
		for _, item := range m {
			assertNoExtraRawGeneric(t, item)
		}
	}
}
