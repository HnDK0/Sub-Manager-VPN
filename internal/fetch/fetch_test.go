package fetch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vpn-sub-manager/internal/config"
)

// newTestFetcher builds a Fetcher whose API/raw bases point at the given
// httptest servers, so no real network is touched.
func newTestFetcher(api, raw *httptest.Server) *Fetcher {
	f := NewFetcher(nil)
	f.apiBase = api.URL
	f.rawBase = raw.URL
	f.insecureOK = true // httptest mock servers are http; production default is false
	return f
}

func TestFetchRaw(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("vmess://example"))
	}))
	defer srv.Close()

	f := newTestFetcher(srv, srv)
	body, err := f.fetchRaw(context.Background(), srv.URL+"/sub.txt")
	if err != nil {
		t.Fatalf("fetchRaw: %v", err)
	}
	if string(body) != "vmess://example" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestFetchRawNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f := newTestFetcher(srv, srv)
	if _, err := f.fetchRaw(context.Background(), srv.URL+"/x"); err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestFetchRawHTTPRejected(t *testing.T) {
	f := NewFetcher(nil) // default: insecureOK=false
	if _, err := f.fetchRaw(context.Background(), "http://insecure.example/sub"); err == nil {
		t.Fatal("expected error for http url")
	}
}

func TestFetchRawKind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("v2rayN-body"))
	}))
	defer srv.Close()

	f := newTestFetcher(srv, srv)
	src := config.Source{ID: "1", URL: srv.URL + "/sub.txt", Kind: config.KindRaw, Enabled: true}
	out, err := f.Fetch(context.Background(), src)
	if err != nil {
		t.Fatalf("Fetch raw: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out))
	}
	if string(out[0].Body) != "v2rayN-body" {
		t.Fatalf("unexpected body: %q", out[0].Body)
	}
}

func TestFetchRepoKind(t *testing.T) {
	// Fake GitHub contents API: one candidate .txt file + a directory to skip.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries := []contentEntry{
			{Name: "subscription.txt", Path: "subscription.txt", Type: "file"},
			{Name: "assets", Path: "assets", Type: "dir"},
			{Name: "README.md", Path: "README.md", Type: "file"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer api.Close()

	// Raw endpoint serving the candidate file.
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/owner/repo/main/subscription.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("repo-sub-body"))
	}))
	defer raw.Close()

	f := newTestFetcher(api, raw)
	src := config.Source{ID: "2", URL: "https://github.com/owner/repo", Kind: config.KindRepo, Enabled: true}
	out, err := f.Fetch(context.Background(), src)
	if err != nil {
		t.Fatalf("Fetch repo: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(out), out)
	}
	if string(out[0].Body) != "repo-sub-body" {
		t.Fatalf("unexpected body: %q", out[0].Body)
	}
	if out[0].URL != raw.URL+"/owner/repo/main/subscription.txt" {
		t.Fatalf("unexpected url: %q", out[0].URL)
	}
}

func TestFetchRepoFallbackMaster(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ref") == "main" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		entries := []contentEntry{
			{Name: "sub.yaml", Path: "sub.yaml", Type: "file"},
		}
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer api.Close()

	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/owner/repo/master/sub.yaml" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("master-body"))
	}))
	defer raw.Close()

	f := newTestFetcher(api, raw)
	src := config.Source{ID: "3", URL: "https://github.com/owner/repo", Kind: config.KindRepo, Enabled: true}
	out, err := f.Fetch(context.Background(), src)
	if err != nil {
		t.Fatalf("Fetch repo fallback: %v", err)
	}
	if len(out) != 1 || string(out[0].Body) != "master-body" {
		t.Fatalf("unexpected result: %+v", out)
	}
}

func TestFetchHTTPURLRejected(t *testing.T) {
	f := NewFetcher(nil) // default: insecureOK=false
	src := config.Source{ID: "4", URL: "http://insecure.example/sub", Kind: config.KindRaw, Enabled: true}
	if _, err := f.Fetch(context.Background(), src); err == nil {
		t.Fatal("expected error for http source url")
	}
}

func TestFetchConditionalNotModified(t *testing.T) {
	const etag = `"v1"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("vmess://example"))
	}))
	defer srv.Close()

	f := newTestFetcher(srv, srv)
	src := config.Source{ID: "1", URL: srv.URL + "/sub.txt", Kind: config.KindRaw, Enabled: true}

	// First call: full body + ETag, not modified=false.
	fs, notMod, err := f.FetchConditional(context.Background(), src, "", "")
	if err != nil {
		t.Fatalf("first FetchConditional: %v", err)
	}
	if notMod {
		t.Fatal("expected first call to be modified")
	}
	if len(fs) != 1 || string(fs[0].Body) != "vmess://example" || fs[0].ETag != etag {
		t.Fatalf("unexpected first result: %+v", fs)
	}

	// Second call with the ETag: 304, NotModified, empty body.
	fs2, notMod2, err := f.FetchConditional(context.Background(), src, fs[0].ETag, "")
	if err != nil {
		t.Fatalf("second FetchConditional: %v", err)
	}
	if !notMod2 {
		t.Fatal("expected second call to be not-modified")
	}
	if len(fs2) != 1 || !fs2[0].NotModified || len(fs2[0].Body) != 0 {
		t.Fatalf("unexpected 304 result: %+v", fs2)
	}
}

func TestFetchRepoSubpathRecursive(t *testing.T) {
	// Path-aware fake GitHub contents API: a subdirectory tree with candidates
	// nested two levels deep, plus a non-candidate file at root to ignore.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		var entries []contentEntry
		switch {
		case p == "/repos/owner/repo/contents":
			entries = []contentEntry{
				{Name: "githubmirror", Path: "githubmirror", Type: "dir"},
				{Name: "notes.md", Path: "notes.md", Type: "file"},
			}
		case p == "/repos/owner/repo/contents/githubmirror":
			entries = []contentEntry{
				{Name: "sub1.txt", Path: "githubmirror/sub1.txt", Type: "file"},
				{Name: "nested", Path: "githubmirror/nested", Type: "dir"},
			}
		case p == "/repos/owner/repo/contents/githubmirror/nested":
			entries = []contentEntry{
				{Name: "sub2.yaml", Path: "githubmirror/nested/sub2.yaml", Type: "file"},
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer api.Close()

	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/main/githubmirror/sub1.txt":
			_, _ = w.Write([]byte("body1"))
		case "/owner/repo/main/githubmirror/nested/sub2.yaml":
			_, _ = w.Write([]byte("body2"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer raw.Close()

	f := newTestFetcher(api, raw)
	src := config.Source{ID: "5", URL: "https://github.com/owner/repo/tree/main/githubmirror", Kind: config.KindRepo, Enabled: true}
	out, err := f.Fetch(context.Background(), src)
	if err != nil {
		t.Fatalf("Fetch repo subpath: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 nested candidates, got %d: %+v", len(out), out)
	}
	bodies := map[string]bool{}
	for _, o := range out {
		bodies[string(o.Body)] = true
	}
	if !bodies["body1"] || !bodies["body2"] {
		t.Fatalf("missing expected bodies: %+v", bodies)
	}
}

func TestFetchRepoSubpathIgnoredAtRoot(t *testing.T) {
	// Bare repo URL: only root-level candidates are fetched; a non-candidate
	// root file is skipped and directories are recursed (guarded against the
	// identical-entries mock returning the same listing for sub-paths).
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries := []contentEntry{
			{Name: "subscription.txt", Path: "subscription.txt", Type: "file"},
			{Name: "assets", Path: "assets", Type: "dir"},
			{Name: "README.md", Path: "README.md", Type: "file"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer api.Close()

	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/owner/repo/main/subscription.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("repo-sub-body"))
	}))
	defer raw.Close()

	f := newTestFetcher(api, raw)
	src := config.Source{ID: "6", URL: "https://github.com/owner/repo", Kind: config.KindRepo, Enabled: true}
	out, err := f.Fetch(context.Background(), src)
	if err != nil {
		t.Fatalf("Fetch repo: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(out), out)
	}
	if string(out[0].Body) != "repo-sub-body" {
		t.Fatalf("unexpected body: %q", out[0].Body)
	}
}
