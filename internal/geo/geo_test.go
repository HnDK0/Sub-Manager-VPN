package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"

	"vpn-sub-manager/internal/model"
)

// stubManager wires injected lookup/resolve stubs onto an offline Manager.
func stubManager(lookup func(net.IP) (string, error), resolve func(context.Context, string) (net.IP, error)) *Manager {
	m := newOffline("")
	if lookup != nil {
		m.lookup = lookup
	}
	if resolve != nil {
		m.resolve = resolve
	}
	return m
}

func TestResolveCountryFallbackNoDB(t *testing.T) {
	// No DB, no stubs: an IP host with no lookup must fall back to "" (empty).
	m := newOffline("")
	n := &model.Node{Protocol: model.SchemeVMess, Host: "1.2.3.4", Port: 443, Name: "MyNode"}
	got, err := m.ResolveCountry(n)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("want fallback \"\", got %q", got)
	}
}

func TestResolveCountryDomainFallbackNoDB(t *testing.T) {
	// Domain host, no DB, resolve stub fails -> fallback to "", no panic.
	m := stubManager(nil, func(context.Context, string) (net.IP, error) {
		return nil, context.DeadlineExceeded
	})
	n := &model.Node{Protocol: model.SchemeTrojan, Host: "unreachable.example", Port: 443, Name: "FallbackName"}
	got, err := m.ResolveCountry(n)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("want fallback \"\", got %q", got)
	}
}

func TestResolveCountryViaInjectedLookup(t *testing.T) {
	// Literal IP host: lookup stub returns "US" directly.
	m := stubManager(func(ip net.IP) (string, error) {
		if !ip.Equal(net.ParseIP("1.2.3.4")) {
			t.Fatalf("lookup called with unexpected IP %v", ip)
		}
		return "US", nil
	}, nil)
	n := &model.Node{Protocol: model.SchemeVLESS, Host: "1.2.3.4", Port: 443, Name: "x"}
	got, err := m.ResolveCountry(n)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "US" {
		t.Fatalf("want US, got %q", got)
	}
}

func TestResolveDomainViaInjectedResolver(t *testing.T) {
	// Domain host: resolver stub returns an IP, lookup stub returns "DE".
	m := stubManager(func(ip net.IP) (string, error) {
		if !ip.Equal(net.ParseIP("9.9.9.9")) {
			t.Fatalf("lookup called with unexpected IP %v", ip)
		}
		return "DE", nil
	}, func(_ context.Context, host string) (net.IP, error) {
		if host != "domain.test" {
			t.Fatalf("resolve called with unexpected host %q", host)
		}
		return net.ParseIP("9.9.9.9"), nil
	})
	n := &model.Node{Protocol: model.SchemeSS, Host: "domain.test", Port: 8388, Name: "x"}
	got, err := m.ResolveCountry(n)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "DE" {
		t.Fatalf("want DE, got %q", got)
	}
}

func TestResolveCountryLookupMissFallsBack(t *testing.T) {
	// IP host, lookup returns empty -> fallback to "".
	m := stubManager(func(net.IP) (string, error) {
		return "", nil
	}, nil)
	n := &model.Node{Protocol: model.SchemeVMess, Host: "5.6.7.8", Port: 443, Name: "MissNode"}
	got, err := m.ResolveCountry(n)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("want fallback \"\", got %q", got)
	}
}

func TestSHA256File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	content := []byte("hello geo integrity")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sha256File(p)
	if err != nil {
		t.Fatalf("sha256File: %v", err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("sha256File = %q, want %q", got, want)
	}
	// Missing file must return an error.
	if _, err := sha256File(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestEnsureDBReDownloadsOnChecksumMismatch verifies that a corrupt mmdb whose
// cached .sha256 does not match is detected, removed, and (when the re-download
// is forced to fail) ensureDB degrades gracefully to (nil, false) without panic.
// Fully offline: downloadURL is pointed at a bogus URL.
func TestEnsureDBReDownloadsOnChecksumMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, dbName)

	// Corrupt database + a checksum of DIFFERENT content.
	if err := os.WriteFile(path, []byte("this is not a valid mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sha256", []byte("deadbeef"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Force the re-download to fail gracefully (offline / bogus URL).
	orig := downloadURL
	downloadURL = "http://127.0.0.1:0/geo/geolite2-country.mmdb"
	defer func() { downloadURL = orig }()

	r, ok := ensureDB(dir)
	if ok {
		t.Fatalf("ensureDB = (_, true), want (_, false) on failed re-download")
	}
	if r != nil {
		t.Fatalf("ensureDB returned non-nil reader: %v", r)
	}
	// Corrupt file must have been removed (detection happened, no panic).
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt mmdb should be removed, stat err = %v", err)
	}
}
