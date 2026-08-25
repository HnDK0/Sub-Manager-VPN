// Package bans implements a small, persisted, concurrency-safe set of banned
// node hashes. The set is backed by a JSON file (bans.json) written atomically
// (temp file + rename) so a crash mid-write never leaves a corrupt file behind.
package bans

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Store is a persisted set of banned node hashes.
type Store struct {
	path string
	mu   sync.Mutex
	set  map[string]struct{}
}

type file struct {
	Banned []string `json:"banned"`
}

// New loads (or initializes) the ban set from path. A missing file yields an
// empty set with no error; a corrupt file is logged and treated as empty so the
// manager still starts.
func New(path string) *Store {
	s := &Store{path: path, set: make(map[string]struct{})}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("bans: read %s: %v (starting empty)", path, err)
		}
		return s
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("bans: parse %s: %v (starting empty)", path, err)
		return s
	}
	for _, h := range f.Banned {
		if h != "" {
			s.set[h] = struct{}{}
		}
	}
	return s
}

// Has reports whether hash is banned.
func (s *Store) Has(hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.set[hash]
	return ok
}

// Add bans hash and persists. It is idempotent.
func (s *Store) Add(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hash == "" {
		return nil
	}
	if _, ok := s.set[hash]; ok {
		return nil
	}
	s.set[hash] = struct{}{}
	return s.saveLocked()
}

// Remove unbans hash and persists. It is idempotent.
func (s *Store) Remove(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.set[hash]; !ok {
		return nil
	}
	delete(s.set, hash)
	return s.saveLocked()
}

// List returns a snapshot of all banned hashes.
func (s *Store) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.set))
	for h := range s.set {
		out = append(out, h)
	}
	return out
}

// saveLocked persists the current set atomically. Caller must hold mu.
func (s *Store) saveLocked() error {
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(file{Banned: s.List()}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
