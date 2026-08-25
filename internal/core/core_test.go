package core

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// dummyExe is the fake binary content stored inside the mock zip.
const dummyExe = "MZ dummy xray executable"

// buildZip creates an in-memory zip containing an xray.exe entry.
func buildZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("xray.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(dummyExe)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// startMockServer serves a mock GitHub Releases API plus the asset and
// checksums files. checksums is the body of checksums.txt (may be tampered).
func startMockServer(t *testing.T, zipData []byte, checksums string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var releaseJSON string
	mux.HandleFunc("/repos/XTLS/Xray-core/releases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(releaseJSON))
	})
	mux.HandleFunc("/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(checksums))
	})
	mux.HandleFunc("/Xray-windows-64.zip", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(zipData)
	})
	srv := httptest.NewServer(mux)
	releaseJSON = fmt.Sprintf(`[
	  {
	    "tag_name": "v1.8.0",
	    "prerelease": false,
	    "draft": false,
	    "assets": [
      {"name": "checksums.txt", "browser_download_url": "%s/checksums.txt"},
      {"name": "Xray-windows-64.zip", "browser_download_url": "%s/Xray-windows-64.zip"}
	    ]
	  },
	  {
	    "tag_name": "v1.9.0-beta.1",
	    "prerelease": true,
	    "draft": false,
	    "assets": []
	  }
	]`, srv.URL, srv.URL)
	return srv
}

func newTestManager(t *testing.T, srv *httptest.Server) *Manager {
	t.Helper()
	dir := t.TempDir()
	mgr, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mgr.APIBase = srv.URL
	mgr.GOOS = "windows"
	mgr.GOARCH = "amd64"
	return mgr
}

// TestEnsure_HappyPath verifies the manager downloads the matching asset,
// verifies its SHA256 against checksums.txt, and extracts the binary so that
// BinaryPath returns it with the correct content.
func TestEnsure_HappyPath(t *testing.T) {
	zipData := buildZip(t)
	sum := sha256.Sum256(zipData)
	checksums := fmt.Sprintf("%s  xray-windows-64.zip\n", hex.EncodeToString(sum[:]))

	srv := startMockServer(t, zipData, checksums)
	defer srv.Close()

	mgr := newTestManager(t, srv)
	if err := mgr.Ensure("xray"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	p, err := mgr.BinaryPath("xray")
	if err != nil {
		t.Fatalf("BinaryPath: %v", err)
	}
	if !strings.HasSuffix(p, "xray.exe") {
		t.Fatalf("BinaryPath returned %q, want ...xray.exe", p)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read extracted binary: %v", err)
	}
	if string(data) != dummyExe {
		t.Fatalf("extracted binary content = %q, want %q", string(data), dummyExe)
	}
}

// TestEnsure_TamperedChecksum verifies that a checksum mismatch yields an error
// and the binary is never written to the store.
func TestEnsure_TamperedChecksum(t *testing.T) {
	zipData := buildZip(t)
	// Wrong hash on purpose.
	checksums := "0000000000000000000000000000000000000000000000000000000000000000  xray-windows-64.zip\n"

	srv := startMockServer(t, zipData, checksums)
	defer srv.Close()

	mgr := newTestManager(t, srv)
	err := mgr.Ensure("xray")
	if err == nil {
		t.Fatal("Ensure returned nil; want checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Binary must not be present.
	if _, err := mgr.BinaryPath("xray"); err == nil {
		t.Fatal("BinaryPath succeeded after tampered checksum; binary should not be stored")
	}
	entries, _ := os.ReadDir(mgr.StoreDir)
	if len(entries) != 0 {
		t.Fatalf("store dir not empty after failure: %v", entries)
	}
}

// TestEnsure_UnknownBinary verifies an unknown name is rejected.
func TestEnsure_UnknownBinary(t *testing.T) {
	srv := startMockServer(t, buildZip(t), "")
	defer srv.Close()
	mgr := newTestManager(t, srv)
	if err := mgr.Ensure("not-a-binary"); err == nil {
		t.Fatal("Ensure accepted unknown binary name")
	}
}

// TestNew_EmptyStoreDir verifies New rejects an empty store directory.
func TestNew_EmptyStoreDir(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("New accepted empty storeDir")
	}
}
