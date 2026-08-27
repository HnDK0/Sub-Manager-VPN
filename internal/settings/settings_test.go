package settings

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadMissingReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	s, existed, err := Load(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if existed {
		t.Fatal("expected existed=false for missing file")
	}
	d := Default()
	if s.Interval != d.Interval || s.TopN != d.TopN || s.DegradeMs != d.DegradeMs ||
		s.MinKeep != d.MinKeep {
		t.Fatalf("expected default, got %+v", s)
	}
	if len(s.ExcludeCountries) != 0 {
		t.Fatalf("expected no excluded countries by default, got %v", s.ExcludeCountries)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	in := Settings{
		StatePath: "/x/state.db",
		WebAddr:   "127.0.0.1:8090",
		WebToken:  "tok",
		WebSecret: "secretsecretsecretsecret1234",
		Interval:  "15m",
		TopN:      4,
	}
	if err := Save(p, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// No leftover temp file.
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should have been removed")
	}
	// Perms must be 0600 (enforced on POSIX; Windows uses ACLs and does not
	// synthesize a restrictive mode, so skip the assertion there).
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("expected 0600, got %v", fi.Mode().Perm())
		}
	}
	out, existed, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !existed {
		t.Fatal("expected existed=true")
	}
	if out.StatePath != in.StatePath || out.WebAddr != in.WebAddr || out.WebToken != in.WebToken ||
		out.WebSecret != in.WebSecret || out.Interval != in.Interval || out.TopN != in.TopN ||
		len(out.ExcludeCountries) != len(in.ExcludeCountries) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", in, out)
	}
}

func TestStoreUpdateValidation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	st, err := NewStore(p)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	// WebAddr set without token/secret must be rejected.
	if _, err := st.Update(Settings{WebAddr: "127.0.0.1:8090"}); err == nil {
		t.Fatal("expected validation error for web_addr without token/secret")
	}
	// Valid update applies and persists.
	good := Settings{WebAddr: "127.0.0.1:8090", WebToken: "t", WebSecret: "secretsecretsecretsecret1234"}
	got, err := st.Update(good)
	if err != nil {
		t.Fatalf("Update good: %v", err)
	}
	if got.WebAddr != good.WebAddr {
		t.Fatalf("update not applied: %+v", got)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("config not persisted: %v", err)
	}
	// Get reflects the update.
	if st.Get().WebAddr != good.WebAddr {
		t.Fatal("Get did not reflect update")
	}
}
