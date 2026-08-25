package selector

import (
	"encoding/base64"
	"strings"
	"testing"

	"vpn-sub-manager/internal/model"
)

// TestGeneratedOutputHasNoInsecureMarkers proves by TEST that the three
// generators (sing-box, Clash.Meta, v2rayN) never emit insecure markers in
// their raw output — even when the filter stage is bypassed and deliberately
// malicious/insecure nodes reach the generators. This is belt-and-suspenders
// on top of secureSecurity and the per-scheme TLS guards.
//
// It does NOT run filter.Apply: we want to test the raw generator output.
func TestGeneratedOutputHasNoInsecureMarkers(t *testing.T) {
	// Insecure markers scanned case-insensitively in every format's text.
	markers := []string{
		"security=none",
		"skip-cert-verify",
		"tls=none",
		"allowinsecure",
		"insecure=1",
	}

	// All 5 kept schemes that carry a security field.
	schemes := []model.Scheme{
		model.SchemeVMess,
		model.SchemeVLESS,
		model.SchemeTrojan,
		model.SchemeHysteria2,
		model.SchemeTUIC,
	}

	// Build a node set covering, per scheme:
	//   - Security "none" (explicitly insecure)
	//   - Security "" (missing)
	//   - Security "tls" (valid)
	//   - Extra-laden nodes with skip-cert-verify / allowInsecure / tls.insecure
	var nodes []model.Node
	for _, s := range schemes {
		for _, sec := range []string{"none", "", "tls"} {
			nodes = append(nodes, insecureNode(s, sec, nil))
		}
		nodes = append(nodes, insecureNode(s, "tls", map[string]string{"skip-cert-verify": "true"}))
		nodes = append(nodes, insecureNode(s, "tls", map[string]string{"allowInsecure": "1"}))
		nodes = append(nodes, insecureNode(s, "tls", map[string]string{"tls.insecure": "true"}))
	}

	// --- sing-box (JSON) ---
	sb, err := SingBox(nodes)
	if err != nil {
		t.Fatalf("SingBox: %v", err)
	}
	scanForMarkers(t, "singbox", string(sb), markers)

	// --- clash (YAML) ---
	cl, err := ClashMeta(nodes)
	if err != nil {
		t.Fatalf("ClashMeta: %v", err)
	}
	scanForMarkers(t, "clash", string(cl), markers)

	// --- v2rayn (base64 -> decode before scanning) ---
	vn, err := V2RayN(nodes)
	if err != nil {
		t.Fatalf("V2RayN: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(vn)
	if err != nil {
		t.Fatalf("v2rayn base64 decode: %v", err)
	}
	scanForMarkers(t, "v2rayn", string(raw), markers)
}

// insecureNode builds a node for a scheme with the given security and optional
// Extra map. Credentials are filled so generation never errors on empty fields.
func insecureNode(s model.Scheme, sec string, extra map[string]string) model.Node {
	n := model.Node{
		Protocol: s,
		Host:     "example.com",
		Port:     443,
		Name:     string(s) + "-" + sec,
		Security: sec,
		Extra:    extra,
	}
	switch s {
	case model.SchemeVMess:
		n.User = "11111111-2222-3333-4444-555555555555"
		n.Encryption = "aes-128-gcm"
	case model.SchemeVLESS:
		n.User = "11111111-2222-3333-4444-555555555555"
		n.Encryption = "none"
	case model.SchemeTrojan:
		n.User = "trojan-pass"
	case model.SchemeHysteria2:
		n.User = "hy2-pass"
	case model.SchemeTUIC:
		n.User = "tuic-token"
	}
	return n
}

// scanForMarkers fails the test if any insecure marker appears in text.
func scanForMarkers(t *testing.T, format, text string, markers []string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, m := range markers {
		if strings.Contains(lower, strings.ToLower(m)) {
			t.Fatalf("%s output contains insecure marker %q", format, m)
		}
	}
}
