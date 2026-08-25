package netutil

import "testing"

func TestIsPublicLiteralIP(t *testing.T) {
	cases := []struct {
		host       string
		wantLit    bool
		wantPublic bool
	}{
		{"192.168.1.1", true, false},        // literal private IPv4
		{"10.0.0.5", true, false},           // literal private IPv4
		{"127.0.0.1", true, false},          // literal loopback
		{"169.254.169.254", true, false},    // cloud metadata
		{"8.8.8.8", true, true},             // literal public IPv4
		{"1.1.1.1", true, true},             // literal public IPv4
		{"::1", true, false},                // literal loopback IPv6
		{"fc00::1", true, false},            // literal ULA IPv6
		{"2606:4700::1111", true, true},     // literal public IPv6
		{"github.com", false, false},        // domain: no DNS
		{"raw.githubusercontent.com", false, false},
		{"example.com:8080", false, false},  // domain with port
		{"192.168.1.1:443", true, false},    // literal private with port
		{"8.8.8.8:443", true, true},         // literal public with port
	}
	for _, c := range cases {
		isLit, pub, err := IsPublicLiteralIP(c.host)
		if err != nil {
			t.Errorf("IsPublicLiteralIP(%q): unexpected err: %v", c.host, err)
			continue
		}
		if isLit != c.wantLit || pub != c.wantPublic {
			t.Errorf("IsPublicLiteralIP(%q) = (%v,%v); want (%v,%v)",
				c.host, isLit, pub, c.wantLit, c.wantPublic)
		}
	}
}
