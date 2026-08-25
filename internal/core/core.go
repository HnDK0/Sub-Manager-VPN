// Package core downloads and SHA256-verifies core VPN binaries (xray-core,
// sing-box) from official GitHub Releases and stores them locally.
//
// It is self-contained: it takes a store directory and does not depend on any
// config package. The GitHub API base URL is a field so tests can point it at
// an httptest server instead of the real network.
package core

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Manager downloads and verifies core binaries into StoreDir.
type Manager struct {
	// StoreDir is the local directory where verified binaries are extracted.
	StoreDir string
	// APIBase is the GitHub API base URL (default https://api.github.com).
	// Tests override this with an httptest server URL.
	APIBase string
	// Client is the HTTP client used for downloads. Defaults to http.DefaultClient.
	Client *http.Client
	// GOOS/GOARCH select the asset. They default to the running platform but
	// can be overridden (used by tests for determinism).
	GOOS   string
	GOARCH string
}

// New creates a Manager that stores binaries in storeDir.
func New(storeDir string) (*Manager, error) {
	if storeDir == "" {
		return nil, errors.New("core: storeDir is required")
	}
	return &Manager{
		StoreDir: storeDir,
		APIBase:  "https://api.github.com",
		Client:   http.DefaultClient,
		GOOS:     runtime.GOOS,
		GOARCH:   runtime.GOARCH,
	}, nil
}

// binSpec describes how to locate a binary's release asset for a given version.
type binSpec struct {
	repo  string // "owner/name" on GitHub
	asset func(version, goos, goarch string) string
}

// bins maps a logical binary name to its GitHub repo and asset-name builder.
var bins = map[string]binSpec{
	"xray": {
		repo: "XTLS/Xray-core",
		asset: func(_, goos, goarch string) string {
			return "Xray-" + goos + "-" + xrayArch(goarch) + ".zip"
		},
	},
	"sing-box": {
		repo: "SagerNet/sing-box",
		asset: func(version, goos, goarch string) string {
			return "sing-box-" + version + "-" + goos + "-" + goarch + ".zip"
		},
	},
}

// xrayArch maps a Go arch to xray's asset arch suffix.
func xrayArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "64"
	case "386":
		return "32"
	case "arm64":
		return "arm64"
	case "arm":
		return "arm32-v7"
	default:
		return goarch
	}
}

// exeName returns the on-disk executable name for a binary on the given OS.
func exeName(name, goos string) string {
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}

// ghAsset / ghRelease are the subset of the GitHub Releases API we consume.
type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
	TagName    string     `json:"tag_name"`
	Prerelease bool       `json:"prerelease"`
	Draft      bool       `json:"draft"`
	Assets     []ghAsset  `json:"assets"`
}

// isStable reports whether a release is a usable stable release: not a draft,
// not a prerelease, and not an alpha/beta/rc tag.
func isStable(r ghRelease) bool {
	if r.Draft || r.Prerelease {
		return false
	}
	lower := strings.ToLower(r.TagName)
	for _, bad := range []string{"alpha", "beta", "rc"} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	return true
}

func (m *Manager) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return http.DefaultClient
}

// latestRelease returns the first stable release for repo from the API.
func (m *Manager) latestRelease(repo string) (*ghRelease, error) {
	url := m.APIBase + "/repos/" + repo + "/releases"
	body, err := m.download(url)
	if err != nil {
		return nil, err
	}
	var releases []ghRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("core: decode releases for %s: %w", repo, err)
	}
	for _, r := range releases {
		if isStable(r) {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("core: no stable release found for %s", repo)
}

// Ensure downloads (if needed), SHA256-verifies, and extracts the named binary
// into StoreDir. On any checksum mismatch it returns an error and does not
// write or keep the binary.
func (m *Manager) Ensure(name string) error {
	spec, ok := bins[name]
	if !ok {
		return fmt.Errorf("core: unknown binary %q", name)
	}
	if _, err := m.BinaryPath(name); err == nil {
		return nil // already present and verified
	}
	rel, err := m.latestRelease(spec.repo)
	if err != nil {
		return err
	}

	wantAsset := spec.asset(rel.TagName, m.GOOS, m.GOARCH)
	exe := exeName(name, m.GOOS)

	var assetURL, sumURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case wantAsset:
			assetURL = a.BrowserDownloadURL
		case wantAsset + ".dgst":
			// Per-asset digest (xray-core style): "<ALGO> <hex>" lines.
			sumURL = a.BrowserDownloadURL
		case "checksums.txt":
			// Fallback for projects that publish a single checksums file.
			if sumURL == "" {
				sumURL = a.BrowserDownloadURL
			}
		}
	}
	if assetURL == "" {
		return fmt.Errorf("core: asset %s not found in release %s", wantAsset, rel.TagName)
	}
	if sumURL == "" {
		return fmt.Errorf("core: checksum file (.dgst or checksums.txt) not found in release %s", rel.TagName)
	}

	sumBody, err := m.download(sumURL)
	if err != nil {
		return err
	}
	expected, err := parseChecksum(sumBody, wantAsset)
	if err != nil {
		return err
	}

	assetBody, err := m.download(assetURL)
	if err != nil {
		return err
	}

	got := sha256.Sum256(assetBody)
	if !strings.EqualFold(hex.EncodeToString(got[:]), expected) {
		return fmt.Errorf("core: checksum mismatch for %s: got %s want %s", wantAsset, hex.EncodeToString(got[:]), expected)
	}

	if err := m.extractBinary(assetBody, exe); err != nil {
		return err
	}
	return nil
}

// BinaryPath returns the absolute path to the extracted binary if it is present.
func (m *Manager) BinaryPath(name string) (string, error) {
	exe := exeName(name, m.GOOS)
	dst := filepath.Join(m.StoreDir, exe)
	info, err := os.Stat(dst)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("core: binary %q not found in store (run Ensure first)", name)
		}
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("core: binary path %q is a directory", dst)
	}
	return dst, nil
}

// AllBinariesExist reports whether every named binary is present and verified
// in the store. Unknown names are treated as absent.
func (m *Manager) AllBinariesExist(names ...string) bool {
	for _, n := range names {
		if _, err := m.BinaryPath(n); err != nil {
			return false
		}
	}
	return true
}

// download fetches a URL and returns its full body.
func (m *Manager) download(url string) ([]byte, error) {
	// GitHub's API requires a User-Agent header or it returns 403; set one on
	// every request (harmless for the asset CDN too).
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("core: download %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "vpn-sub-manager")
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("core: download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("core: download %s: unexpected status %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// parseChecksum finds the SHA256 hex digest for asset in a checksum body.
// Accepts checksums.txt styles ("hash  filename" and "SHA256 (filename) =
// hash") as well as per-asset .dgst files whose lines are "<ALGO> <hex>" with
// no filename (e.g. "SHA256 <64-hex>").
func parseChecksum(data []byte, asset string) (string, error) {
	// First pass: checksums.txt style — a line containing both the asset name
	// and a 64-char hex digest.
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var hash, name string
		for _, f := range strings.Fields(line) {
			if isHex64(f) {
				hash = f
			}
			if f == asset {
				name = f
			}
		}
		if name == asset && hash != "" {
			return hash, nil
		}
	}
	// Second pass: .dgst style — "<ALGO>= <hex>" lines with no filename
	// (e.g. "SHA2-256= <64-hex>"). Among MD5/SHA1/SHA256/SHA512 only SHA256
	// yields a 64-char hex digest, so return the first 64-hex field found.
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, f := range strings.Fields(line) {
			if isHex64(f) {
				return f, nil
			}
		}
	}
	return "", fmt.Errorf("core: checksum entry for %s not found", asset)
}

// isHex64 reports whether s is a 64-char lowercase/uppercase hex string.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// extractBinary extracts the entry named exe from the zip bytes and writes it
// to StoreDir/exe. The entry may be nested in a subdirectory.
func (m *Manager) extractBinary(zipData []byte, exe string) error {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("core: invalid zip: %w", err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != exe {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(m.StoreDir, 0o755); err != nil {
			return err
		}
		dst := filepath.Join(m.StoreDir, exe)
		if err := os.WriteFile(dst, data, 0o755); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("core: binary %s not found inside zip", exe)
}
