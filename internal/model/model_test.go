package model

import "testing"

func TestParseSchemeSupported(t *testing.T) {
	supported := []string{
		"vmess", "vless", "trojan", "ss", "hysteria2", "tuic", "wireguard",
	}
	for _, s := range supported {
		got, err := ParseScheme(s)
		if err != nil {
			t.Errorf("ParseScheme(%q) returned error: %v", s, err)
			continue
		}
		if got != Scheme(s) {
			t.Errorf("ParseScheme(%q) = %q, want %q", s, got, s)
		}
	}
}

func TestParseSchemeCaseInsensitive(t *testing.T) {
	cases := map[string]Scheme{
		"VMESS":     SchemeVMess,
		"Vless":     SchemeVLESS,
		"Trojan":    SchemeTrojan,
		"SS":        SchemeSS,
		"Hysteria2": SchemeHysteria2,
		"TUIC":      SchemeTUIC,
		"WireGuard": SchemeWireGuard,
	}
	for in, want := range cases {
		got, err := ParseScheme(in)
		if err != nil {
			t.Errorf("ParseScheme(%q) returned error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSchemeRejectsUnknown(t *testing.T) {
	rejected := []string{
		"ssr",     // legacy/risky, intentionally excluded
		"snell",   // legacy/risky, intentionally excluded
		"http",    // not a node scheme
		"garbage", // arbitrary unknown
		"", // empty
	}
	for _, s := range rejected {
		if _, err := ParseScheme(s); err == nil {
			t.Errorf("ParseScheme(%q) = nil error, want rejection", s)
		}
	}
}

func TestNodeFields(t *testing.T) {
	n := Node{
		Protocol:   SchemeVLESS,
		Host:       "example.com",
		Port:       443,
		Security:   "tls",
		Encryption: "none",
		User:       "uuid-1234",
		Extra:      map[string]string{"foo": "bar"},
		Plugin:     "obfs-local;obfs=http",
		Name:       "My Node",
		Raw:        "vless://uuid-1234@example.com:443",
		Source:     "https://sub.example.com",
	}
	if n.Protocol != SchemeVLESS || n.Host != "example.com" || n.Port != 443 {
		t.Errorf("Node fields not set as expected: %+v", n)
	}
	if n.Extra == nil {
		t.Errorf("Node.Extra should be initializable")
	}
}
