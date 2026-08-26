// Package settings persists the app's runtime/entry parameters to a config.json
// file so they can be viewed and edited (e.g. via the web Settings zone). It is
// dependency-free: only the standard library. It deliberately does NOT touch the
// sources whitelist registry (that lives in package internal/config).
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Settings mirrors the runtime knobs persisted to config.json. JSON tags use
// snake_case so the on-disk file stays human-readable.
type Settings struct {
	StatePath        string   `json:"state_path"`
	SourcesPath      string   `json:"sources_path"`
	AssetsDir        string   `json:"assets_dir"`
	OutDir           string   `json:"out_dir"`
	Interval         string   `json:"interval"` // e.g. "2h"
	TopN             int      `json:"topn"`
	DegradeMs        int      `json:"degrade_ms"`
	MinKeep          int      `json:"minkeep"`
	ServeAddr        string   `json:"serve_addr"`
	ServeToken       string   `json:"serve_token"`
	WebAddr          string   `json:"web_addr"`
	WebToken         string   `json:"web_token"`
	WebSecret        string   `json:"web_secret"`
	CorpseCycles     int      `json:"corpse_cycles"`
	ProbeURL         string   `json:"probe_url"`
	SpeedTestURL     string   `json:"speed_test_url"`
	MinSpeedMbps     int      `json:"min_speed_mbps"`
	SpeedTestTopN    int      `json:"speed_test_topn"`
	ExcludeCountries []string `json:"exclude_countries"`
	ExcludeProtocols []string `json:"exclude_protocols"`
	Workers          int      `json:"workers"`
	SubValidityInterval string `json:"sub_validity_interval"` // e.g. "5m"
	SubPingInterval    string `json:"sub_ping_interval"`      // e.g. "30m"
	SubTopN            int    `json:"sub_topn"`               // 0 = use TopN
}

// Default returns the non-path defaults. Paths are left empty; the caller (main)
// fills them from the user config dir.
func Default() Settings {
	return Settings{
		Interval:     "2h",
		TopN:         5,
		DegradeMs:    0,
		MinKeep:      1,
		CorpseCycles: 5,
		Workers:      32,
		SubValidityInterval: "5m",
		SubPingInterval:    "30m",
	}
}

// Load reads config.json. A missing file yields Default() with existed=false and
// no error. A decode error is returned. When the file exists, every field is
// taken as-is (Save always writes the full object, so 0 is a real 0, not unset).
func Load(path string) (Settings, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), false, nil
		}
		return Settings{}, false, fmt.Errorf("read %s: %w", path, err)
	}
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{}, false, fmt.Errorf("decode %s: %w", path, err)
	}
	return s, true, nil
}

// Save writes settings atomically: marshal to path+".tmp", fsync, rename over
// path, chmod 0600. The temp file is removed on any error.
func Save(path string, s Settings) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create tmp %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write tmp %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync tmp %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", path, err)
	}
	// Enforce restrictive perms even if the umask loosened the create mode.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// Store is a concurrency-safe holder of the live Settings, backed by a file.
type Store struct {
	path string
	mu   sync.Mutex
	cur  Settings
}

// NewStore loads (or defaults) settings from path and returns a Store.
func NewStore(path string) (*Store, error) {
	s, _, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, cur: s}, nil
}

// Get returns the current Settings.
func (s *Store) Get() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Update replaces the stored settings with patch, validates, persists to disk,
// and returns the merged result. If WebAddr is set, WebToken must be non-empty
// and WebSecret must be >= 24 chars (mirrors the startup guard).
func (s *Store) Update(patch Settings) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if patch.WebAddr != "" {
		if patch.WebToken == "" {
			return Settings{}, fmt.Errorf("web_token is required when web_addr is set")
		}
		if len(patch.WebSecret) < 24 {
			return Settings{}, fmt.Errorf("web_secret must be at least 24 characters")
		}
	}

	if err := Save(s.path, patch); err != nil {
		return Settings{}, err
	}
	s.cur = patch
	return s.cur, nil
}
