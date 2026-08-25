// Package config is the user source whitelist registry for vpn-sub-manager.
//
// This is the ONLY place subscription sources are stored. The fetch service
// reads from here and must never fetch a source the user did not add AND
// enable. No default or sample sources are ever seeded — an empty registry
// yields zero enabled sources, so a fetch fetches nothing by default (the
// "user whitelist only" guarantee).
//
// The registry is backed by a plain-text file (one source per line) rather
// than the shared SQLite state DB. This removes the SQLITE_BUSY lock that
// appeared when the TUI edited sources concurrently with the scheduler, and
// lets the user edit the file directly with `nano`. The file is re-read on
// every call, so external edits (nano) are reflected immediately.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpn-sub-manager/internal/netutil"
)

// Source kinds.
const (
	// KindRepo is a github.com repo or /tree/ URL resolved by the fetch service.
	KindRepo = "repo"
	// KindRaw is a direct raw file URL fetched as-is.
	KindRaw = "raw"
)

// Source is a user-managed subscription source.
type Source struct {
	ID      string    `json:"id"`      // stable identifier — the source URL itself
	URL     string    `json:"url"`     // the https source URL
	Kind    string    `json:"kind"`    // KindRepo or KindRaw
	Enabled bool      `json:"enabled"` // user toggle; only enabled sources are fetched
	AddedAt time.Time `json:"addedAt"` // when the user added it
}

// Registry is the user source whitelist, backed by a plain-text file.
type Registry struct {
	path string
}

// New constructs the registry over a plain-text sources file at path. The
// parent directory and the file are created if missing. The file is the sole
// store: no SQLite handle is opened, so editing sources never contends with
// the scheduler's state DB.
func New(path string) (*Registry, error) {
	if path == "" {
		return nil, errors.New("config: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("config: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("config: create file: %w", err)
	}
	f.Close()
	return &Registry{path: path}, nil
}

// detectKind inspects the URL to decide repo vs raw. A github.com host with at
// least an owner/repo path (repo root or /tree/...) is a repo; everything else
// (including raw.githubusercontent.com) is treated as a raw file URL.
func detectKind(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host != "github.com" {
		return KindRaw
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) >= 2 && parts[0] != "" {
		return KindRepo
	}
	return KindRaw
}

// isHTTPS reports whether rawURL parses as an https:// URL.
func isHTTPS(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && u.Scheme == "https"
}

// parseLine interprets one file line. It returns the source URL, whether it is
// enabled, and whether the line represents a source at all.
//
//	https://...            -> enabled source
//	# https://...          -> disabled source
//	# comment / blank      -> not a source (ignored)
func parseLine(line string) (url string, enabled bool, isSource bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", false, false
	}
	if strings.HasPrefix(trimmed, "#") {
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		if isHTTPS(rest) {
			return rest, false, true
		}
		return "", false, false // comment, not a source
	}
	if isHTTPS(trimmed) {
		return trimmed, true, true
	}
	return "", false, false // malformed line, ignore
}

// read parses the backing file into an ordered slice of sources. A missing file
// yields an empty slice (not an error).
func (r *Registry) read() ([]Source, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("config: read: %w", err)
	}
	var out []Source
	for _, line := range strings.Split(string(data), "\n") {
		u, enabled, ok := parseLine(line)
		if !ok {
			continue
		}
		out = append(out, Source{
			ID:      u,
			URL:     u,
			Kind:    detectKind(u),
			Enabled: enabled,
		})
	}
	return out, nil
}

// write rewrites the whole file from the given ordered sources. Enabled sources
// are written bare; disabled sources are prefixed with "# ".
//
// The write is atomic and durable: content goes to a temp file next to the
// target, is fsync'd, then renamed over the target. A crash or power-loss can
// therefore never leave sources.txt truncated/empty (which would silently drop
// every whitelisted source).
func (r *Registry) write(sources []Source) error {
	var b strings.Builder
	for _, s := range sources {
		if !s.Enabled {
			b.WriteString("# ")
		}
		b.WriteString(s.URL)
		b.WriteString("\n")
	}
	data := []byte(b.String())

	tmp := r.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("config: write temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("config: write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("config: sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: close temp: %w", err)
	}
	if err := os.Rename(tmp, r.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}

// AddSource validates the URL (must be a parseable https:// URL), appends it
// enabled by default, and returns the created Source. Non-https URLs and
// duplicates are rejected and never persisted.
func (r *Registry) AddSource(rawURL string) (*Source, error) {
	if !isHTTPS(rawURL) {
		return nil, fmt.Errorf("config: only https sources are allowed, got %q", rawURL)
	}
	if ok, err := netutil.IsPublicURL(rawURL); err != nil || !ok {
		return nil, fmt.Errorf("config: source host is not a public address: %s", rawURL)
	}
	existing, err := r.read()
	if err != nil {
		return nil, err
	}
	for _, s := range existing {
		if s.URL == rawURL {
			return nil, fmt.Errorf("config: source %q already exists", rawURL)
		}
	}
	src := Source{
		ID:      rawURL,
		URL:     rawURL,
		Kind:    detectKind(rawURL),
		Enabled: true,
		AddedAt: time.Now(),
	}
	existing = append(existing, src)
	if err := r.write(existing); err != nil {
		return nil, err
	}
	return &src, nil
}

// RemoveSource deletes the source with the given id (the URL). Removing a
// missing id is an error.
func (r *Registry) RemoveSource(id string) error {
	existing, err := r.read()
	if err != nil {
		return err
	}
	out := make([]Source, 0, len(existing))
	found := false
	for _, s := range existing {
		if s.ID == id {
			found = true
			continue
		}
		out = append(out, s)
	}
	if !found {
		return fmt.Errorf("config: source %q not found", id)
	}
	return r.write(out)
}

// SetEnabled toggles the enabled flag for the source with the given id (URL).
func (r *Registry) SetEnabled(id string, enabled bool) error {
	existing, err := r.read()
	if err != nil {
		return err
	}
	found := false
	for i := range existing {
		if existing[i].ID == id {
			existing[i].Enabled = enabled
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("config: source %q not found", id)
	}
	return r.write(existing)
}

// ListSources returns all sources, regardless of enabled state, in file order.
func (r *Registry) ListSources() ([]Source, error) {
	return r.read()
}

// EnabledSources returns only the enabled sources — what the fetch service
// should consume. An empty registry yields zero results.
func (r *Registry) EnabledSources() ([]Source, error) {
	all, err := r.read()
	if err != nil {
		return nil, err
	}
	out := make([]Source, 0, len(all))
	for _, s := range all {
		if s.Enabled {
			out = append(out, s)
		}
	}
	return out, nil
}

// ReplaceAll replaces the entire source list with the URLs in rawURLs. Each
// non-empty line is trimmed; only parseable https URLs are (re)inserted as
// enabled sources, everything else is counted as skipped. It returns how many
// sources were added and how many skipped.
func (r *Registry) ReplaceAll(rawURLs []string) (added, skipped int, err error) {
	var out []Source
	for _, raw := range rawURLs {
		raw = strings.TrimSpace(raw)
		// Blank lines and `#` comments are ignored (not counted as skipped).
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if !isHTTPS(raw) {
			skipped++
			continue
		}
		out = append(out, Source{
			ID:      raw,
			URL:     raw,
			Kind:    detectKind(raw),
			Enabled: true,
		})
		added++
	}
	if err := r.write(out); err != nil {
		return 0, 0, err
	}
	return added, skipped, nil
}
