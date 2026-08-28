package cdn

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/settings"
)

// seedRanges installs a fresh in-memory CF range set so tests never hit the
// network (loadCFRanges sees a fresh cache and returns it directly).
func seedRanges(t *testing.T, cidrs ...string) {
	t.Helper()
	ranges := make([]net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", c, err)
		}
		ranges = append(ranges, *ipnet)
	}
	cfMu.Lock()
	cfRanges = ranges
	cfLoadedAt = time.Now()
	cfMu.Unlock()
}

func TestIsCF(t *testing.T) {
	seedRanges(t, "203.0.113.0/24")
	if !isCF("203.0.113.5") {
		t.Fatal("expected 203.0.113.5 to be CF")
	}
	if isCF("198.51.100.9") {
		t.Fatal("expected 198.51.100.9 not to be CF")
	}
	if isCF("example.com") {
		t.Fatal("expected domain not to be CF")
	}
}

func TestResolveCDNIP(t *testing.T) {
	dir := t.TempDir()
	vwn := filepath.Join(dir, "connect_host")
	if err := os.WriteFile(vwn, []byte("\n\n198.51.100.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := resolveCDNIP(settings.Settings{CDNSource: "manual", CDNFallbackIP: "198.51.100.9"}); got != "198.51.100.9" {
		t.Fatalf("manual: got %q", got)
	}
	if got := resolveCDNIP(settings.Settings{CDNSource: "vwn", CDNVWNConfig: vwn}); got != "198.51.100.7" {
		t.Fatalf("vwn: got %q", got)
	}
	// vwn file missing -> fallback
	if got := resolveCDNIP(settings.Settings{CDNSource: "vwn", CDNVWNConfig: filepath.Join(dir, "nope"), CDNFallbackIP: "198.51.100.8"}); got != "198.51.100.8" {
		t.Fatalf("vwn fallback: got %q", got)
	}
	if got := resolveCDNIP(settings.Settings{CDNSource: "bogus"}); got != "" {
		t.Fatalf("bogus source: got %q", got)
	}
}

func TestRewrite(t *testing.T) {
	seedRanges(t, "203.0.113.0/24")

	// disabled -> unchanged
	in := []model.Node{{Host: "203.0.113.5", Extra: map[string]string{"host": "example.com"}}}
	out := Rewrite(in, settings.Settings{CDNEnabled: false})
	if out[0].Host != "203.0.113.5" {
		t.Fatal("disabled should not rewrite")
	}

	// CF host -> rewritten, sni set, ws host preserved, override applied
	in = []model.Node{{
		Host:   "203.0.113.5",
		Extra:  map[string]string{"host": "cf.example.com"},
	}}
	out = Rewrite(in, settings.Settings{
		CDNEnabled:    true,
		CDNSource:     "manual",
		CDNFallbackIP: "198.51.100.9",
		CDNOverrides:  map[string]string{"203.0.113.5": "198.51.100.10"},
	})
	n := out[0]
	if n.Host != "198.51.100.10" {
		t.Fatalf("override host: got %q", n.Host)
	}
	if n.Extra["sni"] != "203.0.113.5" {
		t.Fatalf("sni should be original host, got %q", n.Extra["sni"])
	}
	if n.Extra["host"] != "cf.example.com" {
		t.Fatalf("ws host header must be preserved, got %q", n.Extra["host"])
	}

	// domain host -> not rewritten
	in = []model.Node{{Host: "real.example.com"}}
	out = Rewrite(in, settings.Settings{CDNEnabled: true, CDNSource: "manual", CDNFallbackIP: "198.51.100.9"})
	if out[0].Host != "real.example.com" {
		t.Fatal("domain host must not be rewritten")
	}
}
