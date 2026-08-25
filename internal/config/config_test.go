package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestRegistry creates a Registry over a fresh temp-file sources list and
// returns it plus the file path (so it can be reopened to prove persistence).
func newTestRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sources.txt")
	reg, err := New(path)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	return reg, path
}

func TestAddSourcePersistsAndEnabled(t *testing.T) {
	reg, path := newTestRegistry(t)

	src, err := reg.AddSource("https://github.com/owner/repo")
	if err != nil {
		t.Fatalf("AddSource: %v", err)
	}
	if src.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if src.ID != "https://github.com/owner/repo" {
		t.Fatalf("expected ID == URL, got %q", src.ID)
	}
	if src.Kind != KindRepo {
		t.Fatalf("expected kind repo, got %q", src.Kind)
	}
	if !src.Enabled {
		t.Fatal("expected enabled by default")
	}

	// Reopen from the same file to prove persistence (no SQLite involved).
	reg2, err := New(path)
	if err != nil {
		t.Fatalf("config.New reopened: %v", err)
	}
	enabled, err := reg2.EnabledSources()
	if err != nil {
		t.Fatalf("EnabledSources: %v", err)
	}
	if len(enabled) != 1 || enabled[0].URL != "https://github.com/owner/repo" {
		t.Fatalf("expected 1 enabled source after reopen, got %+v", enabled)
	}
}

func TestAddSourceRejectsNonHTTPS(t *testing.T) {
	reg, _ := newTestRegistry(t)

	for _, bad := range []string{
		"http://github.com/owner/repo",
		"ftp://example.com/file",
		"not-a-url",
		"://broken",
	} {
		if _, err := reg.AddSource(bad); err == nil {
			t.Fatalf("expected error for %q, got nil", bad)
		}
	}

	// Nothing should have been persisted.
	all, err := reg.ListSources()
	if err != nil {
		t.Fatalf("ListSources: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected 0 sources after rejected adds, got %d", len(all))
	}
}

func TestAddSourceRejectsDuplicate(t *testing.T) {
	reg, _ := newTestRegistry(t)
	if _, err := reg.AddSource("https://github.com/owner/repo"); err != nil {
		t.Fatalf("AddSource: %v", err)
	}
	if _, err := reg.AddSource("https://github.com/owner/repo"); err == nil {
		t.Fatal("expected error adding duplicate source")
	}
}

func TestSetEnabledToggles(t *testing.T) {
	reg, _ := newTestRegistry(t)

	src, err := reg.AddSource("https://raw.githubusercontent.com/owner/repo/main/file.txt")
	if err != nil {
		t.Fatalf("AddSource: %v", err)
	}
	if src.Kind != KindRaw {
		t.Fatalf("expected kind raw, got %q", src.Kind)
	}

	if err := reg.SetEnabled(src.ID, false); err != nil {
		t.Fatalf("SetEnabled false: %v", err)
	}
	enabled, err := reg.EnabledSources()
	if err != nil {
		t.Fatalf("EnabledSources: %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("expected 0 enabled after disable, got %d", len(enabled))
	}

	if err := reg.SetEnabled(src.ID, true); err != nil {
		t.Fatalf("SetEnabled true: %v", err)
	}
	enabled, err = reg.EnabledSources()
	if err != nil {
		t.Fatalf("EnabledSources: %v", err)
	}
	if len(enabled) != 1 {
		t.Fatalf("expected 1 enabled after re-enable, got %d", len(enabled))
	}
}

func TestRemoveSource(t *testing.T) {
	reg, _ := newTestRegistry(t)

	src, err := reg.AddSource("https://github.com/owner/repo")
	if err != nil {
		t.Fatalf("AddSource: %v", err)
	}
	if err := reg.RemoveSource(src.ID); err != nil {
		t.Fatalf("RemoveSource: %v", err)
	}
	all, err := reg.ListSources()
	if err != nil {
		t.Fatalf("ListSources: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected 0 sources after remove, got %d", len(all))
	}

	// Removing a missing id is an error.
	if err := reg.RemoveSource(src.ID); err == nil {
		t.Fatal("expected error removing already-removed source")
	}
}

func TestEmptyRegistryHasNoEnabled(t *testing.T) {
	reg, _ := newTestRegistry(t)

	enabled, err := reg.EnabledSources()
	if err != nil {
		t.Fatalf("EnabledSources: %v", err)
	}
	if len(enabled) != 0 {
		t.Fatalf("expected 0 enabled sources on empty registry, got %d", len(enabled))
	}
}

func TestWriteIsAtomicAndDurable(t *testing.T) {
	reg, path := newTestRegistry(t)

	if _, err := reg.AddSource("https://github.com/owner/repo"); err != nil {
		t.Fatalf("AddSource: %v", err)
	}
	if _, err := reg.AddSource("https://raw.githubusercontent.com/owner/repo/main/x.txt"); err != nil {
		t.Fatalf("AddSource: %v", err)
	}

	// No leftover temp file from the atomic write.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("expected no leftover .tmp file after write")
	}

	// Target file is non-empty and contains both URLs (proves a valid source is
	// durably persisted, never left at the 0-byte state created by New).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sources file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty sources file after AddSource")
	}
	content := string(data)
	if !strings.Contains(content, "https://github.com/owner/repo") ||
		!strings.Contains(content, "https://raw.githubusercontent.com/owner/repo/main/x.txt") {
		t.Fatalf("sources file missing expected URLs: %q", content)
	}

	// Reopen and confirm both sources survived on disk.
	reopened, err := New(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	all, err := reopened.ListSources()
	if err != nil {
		t.Fatalf("ListSources: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 sources after reopen, got %d", len(all))
	}
}

func TestReplaceAllRoundTrip(t *testing.T) {
	reg, path := newTestRegistry(t)

	added, skipped, err := reg.ReplaceAll([]string{
		"https://github.com/a/repo",
		"http://insecure.example", // rejected
		"# comment line",          // ignored (not a URL)
		"https://raw.githubusercontent.com/b/c/main/x.txt",
	})
	if err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	if added != 2 || skipped != 1 {
		t.Fatalf("expected added=2 skipped=1, got added=%d skipped=%d", added, skipped)
	}

	// Disabled sources survive a rewrite as "# " lines and are excluded from
	// EnabledSources but kept in ListSources.
	if err := reg.SetEnabled("https://github.com/a/repo", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	enabled, err := reg.EnabledSources()
	if err != nil {
		t.Fatalf("EnabledSources: %v", err)
	}
	if len(enabled) != 1 {
		t.Fatalf("expected 1 enabled after disable, got %d", len(enabled))
	}

	// Reopen and confirm the disabled marker persisted in the file.
	reopened, err := New(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	all, err := reopened.ListSources()
	if err != nil {
		t.Fatalf("ListSources: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 sources after reopen, got %d", len(all))
	}
	disabledFound := false
	for _, s := range all {
		if s.URL == "https://github.com/a/repo" && !s.Enabled {
			disabledFound = true
		}
	}
	if !disabledFound {
		t.Fatal("expected https://github.com/a/repo to be disabled after reopen")
	}
}
