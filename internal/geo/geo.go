// Package geo resolves a VPN node's host to an ISO country code using a
// locally-cached MaxMind GeoLite2-Country database. It is fully testable
// offline: the DNS resolver and the MMDB lookup are injectable function
// fields, and newOffline builds a Manager that never touches the network.
package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpn-sub-manager/internal/model"

	"github.com/oschwald/maxminddb-golang"
)

// dbName is the cached database file inside the assets directory.
const dbName = "GeoLite2-Country.mmdb"

// downloadURL is the direct release-asset URL for the GeoLite2 Country MMDB.
// sapics/geo-ip was deleted; its successor sapics/ip-location-db publishes the
// database under the moving "latest" release tag. The "latest" tag always points
// at the newest automated build, so this URL stays valid without an API lookup.
// ponytail: direct download avoids the GitHub API (rate limits + asset-name drift).
// var (not const) so tests can point it at a bogus URL for offline verification.
var downloadURL = "https://github.com/sapics/ip-location-db/releases/download/latest/geolite2-country.mmdb"

// Manager resolves node hosts to ISO country codes.
type Manager struct {
	mmdb *maxminddb.Reader
	// lookup maps an IP to an ISO country code. nil means "no database".
	lookup func(net.IP) (string, error)
	// resolve turns a domain into an IP using a BOUNDED, host-local resolver.
	resolve func(ctx context.Context, host string) (net.IP, error)
	// ctx bounds DNS resolution so a hanging resolver can never stall a cycle.
	ctx context.Context
}

// New builds a Manager, best-effort downloading the GeoLite2-Country database
// into assetsDir (skipped silently if already present or if the network is
// unavailable). The returned Manager always works: without a database it
// falls back to the node name on every lookup.
func New(assetsDir string) *Manager {
	m := &Manager{ctx: context.Background()}
	m.resolve = m.defaultResolve
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		log.Printf("geo: cannot create assets dir %s: %v", assetsDir, err)
	}
	if r, ok := ensureDB(assetsDir); ok {
		m.mmdb = r
		m.lookup = mmdbLookup(r)
	}
	return m
}

// newOffline builds a Manager that performs NO network access and has no
// database. Tests inject stubs for lookup/resolve to verify logic
// deterministically.
func newOffline(assetsDir string) *Manager {
	m := &Manager{ctx: context.Background()}
	m.resolve = m.defaultResolve
	return m
}

// Close releases the MMDB reader if one was loaded.
func (m *Manager) Close() error {
	if m.mmdb != nil {
		return m.mmdb.Close()
	}
	return nil
}

// defaultResolve resolves a host to an IP using the system's native resolver
// (net.DefaultResolver). It never routes through a VPN node: it dials the
// system-configured (local) DNS upstream only. A 5s overall timeout bounds
// the lookup so a stalled DNS socket cannot hang the scheduler cycle.
func (m *Manager) defaultResolve(ctx context.Context, host string) (net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("geo: no IP for %s", host)
	}
	return addrs[0].IP, nil
}

// ResolveCountry returns the ISO country code for a node's host.
//
// Priority:
//  1. host is a literal IP  -> MMDB lookup
//  2. host is a domain     -> bounded local DNS resolve, then MMDB lookup
//  3. ANY failure (no DB, unresolved, lookup miss) -> fallback to "" (empty
//     string), never the node name, so the country column is never polluted.
//
// It never panics and never crashes when the database is absent.
func (m *Manager) ResolveCountry(n *model.Node) (string, error) {
	host := n.Host
	ip := net.ParseIP(host)
	if ip == nil {
		// Domain: resolve via bounded local resolver.
		resolved, err := m.resolve(m.ctx, host)
		if err != nil {
			return "", nil // fallback
		}
		ip = resolved
	}
	if m.lookup == nil {
		return "", nil // no database
	}
	country, err := m.lookup(ip)
	if err != nil || country == "" {
		return "", nil // lookup miss
	}
	return country, nil
}

// mmdbLookup returns a lookup closure over an open MaxMind reader.
func mmdbLookup(r *maxminddb.Reader) func(net.IP) (string, error) {
	return func(ip net.IP) (string, error) {
		// The GeoLite2-Country build we download (sapics/ip-location-db) stores
		// the code FLAT as "country_code"; fall back to the nested standard
		// "country.iso_code" so we stay compatible if the DB layout changes.
		var rec struct {
			CountryCode string `maxminddb:"country_code"`
			Country     struct {
				IsoCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := r.Lookup(ip, &rec); err != nil {
			return "", err
		}
		if rec.CountryCode != "" {
			return rec.CountryCode, nil
		}
		return rec.Country.IsoCode, nil
	}
}

// ensureDB returns an open reader, downloading the database into assetsDir
// first if it is missing. On any failure it logs and returns (nil, false) so
// the Manager degrades to fallback mode.
func ensureDB(assetsDir string) (*maxminddb.Reader, bool) {
	path := filepath.Join(assetsDir, dbName)
	if _, err := os.Stat(path); err == nil {
		// Verify integrity against the cached checksum before trusting the file.
		if checksumOK(path) {
			r, err := maxminddb.Open(path)
			if err == nil {
				return r, true
			}
			log.Printf("geo: open existing %s failed: %v", path, err)
		} else {
			// Corruption/tampering detected: drop and re-download (best-effort).
			log.Printf("geo: checksum mismatch for %s, re-downloading", path)
			os.Remove(path)
			os.Remove(path + ".sha256")
		}
	}
	if err := fetchToFile(downloadURL, path); err != nil {
		log.Printf("geo: download failed: %v", err)
		return nil, false
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		log.Printf("geo: open downloaded db failed: %v", err)
		return nil, false
	}
	return r, true
}

// checksumOK reports whether path's cached "<path>.sha256" matches its contents.
// If no checksum file exists (first run / legacy install) it returns true so the
// caller opens the database as before (best-effort, no verification). Any read or
// compute error is treated as untrusted -> false, forcing a re-download.
func checksumOK(path string) bool {
	expected, err := os.ReadFile(path + ".sha256")
	if err != nil {
		if os.IsNotExist(err) {
			return true // nothing to verify against
		}
		return false // unreadable checksum -> cannot trust
	}
	got, err := sha256File(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(expected)) == got
}

// sha256File returns the hex-encoded sha256 of file contents.
func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// fetchToFile downloads url to path atomically: it streams into a temp file
// next to the target, fsyncs, then renames. On any error the temp file is
// removed, so a failed/interrupted download never leaves a corrupt (half-written)
// final file behind.
func fetchToFile(url, path string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download status %d", resp.StatusCode)
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	// ponytail: cleanup temp on any failure path; Close may also error on flush.
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	// ponytail: persist checksum so corruption/tampering between cycles is detected.
	if sum, err := sha256File(path); err == nil {
		if werr := os.WriteFile(path+".sha256", []byte(sum), 0o644); werr != nil {
			log.Printf("geo: write checksum %s.sha256 failed: %v", path, werr)
		}
	} else {
		log.Printf("geo: checksum %s failed: %v", path, err)
	}
	return nil
}
