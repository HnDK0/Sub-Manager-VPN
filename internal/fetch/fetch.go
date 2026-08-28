// Package fetch resolves whitelisted source URLs and fetches raw subscription
// bodies over HTTPS only. It is the read side of the user whitelist: it never
// adds, removes, or persists sources — it only turns a config.Source into the
// raw bytes the rest of the pipeline consumes.
package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vpn-sub-manager/internal/config"
	"vpn-sub-manager/internal/netutil"
)

// FetchedSource is a single resolved subscription body.
type FetchedSource struct {
	URL  string
	Body []byte

	// ETag / LastModified are the validation headers returned by the server
	// (empty if the server sent none). They let the scheduler issue a
	// conditional GET on the next cycle so an unchanged source is not
	// re-downloaded.
	ETag         string
	LastModified string

	// NotModified is true for a 304 response: the body is unchanged since the
	// last fetch, so Body is empty and the caller should reuse prior data.
	NotModified bool
}

// Fetcher resolves and downloads whitelisted sources.
type Fetcher struct {
	reg     *config.Registry
	apiBase string // GitHub contents API base (default https://api.github.com)
	rawBase string // raw.githubusercontent.com base
	client  *http.Client

	// insecureOK relaxes the HTTPS-only guard. It is false in production so a
	// non-https URL is always rejected; tests set it to allow httptest (http)
	// mock servers. The default Fetcher never sets this.
	insecureOK bool
}

// NewFetcher builds a Fetcher over the given registry. The registry is kept for
// API symmetry; Fetch consumes only the passed config.Source.
func NewFetcher(reg *config.Registry) *Fetcher {
	return &Fetcher{
		reg:     reg,
		apiBase: "https://api.github.com",
		rawBase: "https://raw.githubusercontent.com",
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Fetch resolves src and returns the raw subscription bodies.
func (f *Fetcher) Fetch(ctx context.Context, src config.Source) ([]FetchedSource, error) {
	if src.Kind == config.KindRepo {
		// A github.com "raw view" URL (github.com/owner/repo/raw/branch/path)
		// is not a repo root — fetch it directly as a raw file instead of
		// going through the contents API.
		if rawURL, ok := githubRawView(src.URL); ok {
			return f.fetchRawURL(ctx, rawURL)
		}
		return f.fetchRepo(ctx, src.URL)
	}
	// raw (default)
	return f.fetchRawURL(ctx, src.URL)
}

// FetchConditional is like Fetch but sends the prior validation headers so an
// unchanged source returns 304 (NotModified) instead of a fresh body. It
// returns the fetched sources plus a bool that is true only when EVERY source
// came back NotModified. Repo sources (multiple files) are always fetched
// unconditionally (allNotModified is false) because per-file caching is out of
// scope for the common single-file case.
func (f *Fetcher) FetchConditional(ctx context.Context, src config.Source, etag, lastModified string) ([]FetchedSource, bool, error) {
	if src.Kind == config.KindRepo {
		fs, err := f.fetchRepo(ctx, src.URL)
		if err != nil {
			return nil, false, err
		}
		return fs, false, nil
	}
	fs, err := f.fetchRawConditional(ctx, src.URL, etag, lastModified)
	if err != nil {
		return nil, false, err
	}
	return fs, len(fs) > 0 && fs[0].NotModified, nil
}

// fetchRawConditional GETs url with conditional headers. A 304 yields a
// NotModified FetchedSource with no body; a 2xx returns the body plus the
// server's validation headers for the next cycle.
func (f *Fetcher) fetchRawConditional(ctx context.Context, rawURL, etag, lastModified string) ([]FetchedSource, error) {
	if err := f.assertHTTPS(rawURL); err != nil {
		return nil, err
	}
	if err := f.assertSafeHost(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch: build request: %w", err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: get %q: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		// Unchanged: keep the prior validation headers so the caller can reuse
		// its cached parse and re-issue the same conditional next time.
		return []FetchedSource{{
			URL:          rawURL,
			NotModified:  true,
			ETag:         etag,
			LastModified: lastModified,
		}}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &httpError{URL: rawURL, Status: resp.StatusCode}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetch: read body %q: %w", rawURL, err)
	}
	return []FetchedSource{{
		URL:          rawURL,
		Body:         body,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}}, nil
}

// githubRawView converts a github.com "raw view" URL
// (https://github.com/owner/repo/raw/branch/path) into its direct raw form
// (https://raw.githubusercontent.com/owner/repo/branch/path), which can be
// downloaded without the GitHub contents API. Returns ok=false for any URL
// that is not such a raw-view link.
func githubRawView(u string) (string, bool) {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host != "github.com" {
		return "", false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 5 || parts[2] != "raw" {
		return "", false
	}
	owner, repo, branch := parts[0], parts[1], parts[3]
	rest := strings.Join(parts[4:], "/")
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, branch, rest), true
}

// fetchRawURL asserts the URL is https, downloads it, and wraps it as a single
// FetchedSource.
func (f *Fetcher) fetchRawURL(ctx context.Context, rawURL string) ([]FetchedSource, error) {
	if err := f.assertHTTPS(rawURL); err != nil {
		return nil, err
	}
	if err := f.assertSafeHost(rawURL); err != nil {
		return nil, err
	}
	body, err := f.fetchRaw(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	return []FetchedSource{{URL: rawURL, Body: body}}, nil
}

// fetchRepo resolves a github.com/owner/repo URL via the contents API and
// downloads every candidate subscription file. It honors a /tree/<branch>/<path>
// sub-path from the URL and recurses into directories, so a source can point at
// a subdirectory (e.g. githubmirror/) instead of the whole repository.
func (f *Fetcher) fetchRepo(ctx context.Context, rawURL string) ([]FetchedSource, error) {
	owner, repo, branch, subPath, err := parseRepoPath(rawURL)
	if err != nil {
		return nil, err
	}

	var out []FetchedSource
	seen := map[string]bool{}    // dedupe files by path
	visited := map[string]bool{} // cycle guard for directories
	queue := []string{subPath}
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		if visited[path] {
			continue
		}
		visited[path] = true

		branchUsed, entries, err := f.listContents(ctx, owner, repo, path, branch)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Type == "dir" {
				queue = append(queue, e.Path)
				continue
			}
			if e.Type != "file" {
				continue
			}
			if !isCandidate(e.Name) || seen[e.Path] {
				continue
			}
			seen[e.Path] = true
			raw := fmt.Sprintf("%s/%s/%s/%s/%s", f.rawBase, owner, repo, branchUsed, escapePath(e.Path))
			if err := f.assertHTTPS(raw); err != nil {
				return nil, err
			}
			if err := f.assertSafeHost(raw); err != nil {
				return nil, err
			}
			body, err := f.fetchRaw(ctx, raw)
			if err != nil {
				return nil, err
			}
			out = append(out, FetchedSource{URL: raw, Body: body})
		}
	}
	return out, nil
}

// listContents queries the contents API for a given repo path, trying the
// hinted branch first (if any) then "main" and "master" as fallbacks. It
// returns the branch that actually resolved so callers can build the matching
// raw URL. per_page=1000 avoids silently missing files beyond the API default
// of 30.
func (f *Fetcher) listContents(ctx context.Context, owner, repo, path, branchHint string) (string, []contentEntry, error) {
	branches := []string{"main", "master"}
	if branchHint != "" {
		branches = []string{branchHint, "main", "master"}
	}
	for _, branch := range branches {
		u := fmt.Sprintf("%s/repos/%s/%s/contents", f.apiBase, owner, repo)
		if path != "" {
			u += "/" + escapePath(path)
		}
		u += fmt.Sprintf("?ref=%s&per_page=1000", branch)
		if err := f.assertHTTPS(u); err != nil {
			return "", nil, err
		}
		body, err := f.fetchRaw(ctx, u)
		if err != nil {
			var he *httpError
			if errors.As(err, &he) && he.Status == http.StatusNotFound {
				continue // try fallback branch / path
			}
			return "", nil, err
		}
		var entries []contentEntry
		if err := json.Unmarshal(body, &entries); err != nil {
			return "", nil, fmt.Errorf("fetch: decode contents json: %w", err)
		}
		return branch, entries, nil
	}
	return "", nil, fmt.Errorf("fetch: repo %s/%s path %q not found on %v", owner, repo, path, branches)
}

// contentEntry is the subset of the GitHub contents API object we use.
type contentEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"` // "file" or "dir"
}

// isCandidate reports whether a file name looks like a subscription file.
func isCandidate(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".txt"),
		strings.HasSuffix(lower, ".yaml"),
		strings.HasSuffix(lower, ".yml"),
		strings.HasSuffix(lower, ".json"):
		return true
	}
	return strings.Contains(lower, "sub") ||
		strings.Contains(lower, "subscribe") ||
		strings.Contains(lower, "subscription")
}

// parseRepoPath extracts owner, repo, an explicit branch ("" when the URL is a
// bare repo root), and the sub-path ("" for the root) from a github.com URL.
// Both bare repo URLs and /tree/<branch>/<path> URLs are supported so a user
// can point a source at a subdirectory instead of the whole repository.
func parseRepoPath(rawURL string) (owner, repo, branch, subPath string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "", "", fmt.Errorf("fetch: invalid repo url %q: %w", rawURL, err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", "", fmt.Errorf("fetch: not a owner/repo url: %q", rawURL)
	}
	owner, repo = parts[0], parts[1]
	if len(parts) >= 4 && parts[2] == "tree" {
		branch = parts[3]
		subPath = strings.Join(parts[4:], "/")
	}
	return owner, repo, branch, subPath, nil
}

// escapePath URL-escapes each "/" segment of p without touching the slashes,
// so directory/file names with spaces or special chars resolve correctly.
func escapePath(p string) string {
	if p == "" {
		return ""
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// fetchRaw GETs url and returns the body. HTTPS only; non-2xx is an error.
func (f *Fetcher) fetchRaw(ctx context.Context, rawURL string) ([]byte, error) {
	if err := f.assertHTTPS(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch: build request: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: get %q: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &httpError{URL: rawURL, Status: resp.StatusCode}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetch: read body %q: %w", rawURL, err)
	}
	return body, nil
}

// assertHTTPS rejects any non-https URL unless insecureOK is set (tests only).
func (f *Fetcher) assertHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("fetch: invalid url %q: %w", rawURL, err)
	}
	if u.Scheme != "https" && !f.insecureOK {
		return fmt.Errorf("fetch: refusing non-https url: %q", rawURL)
	}
	return nil
}

// assertSafeHost rejects any URL whose host resolves to a non-public address
// (SSRF guard). It is skipped entirely when insecureOK is set, so httptest
// (127.0.0.1) mock servers used by tests still pass.
func (f *Fetcher) assertSafeHost(rawURL string) error {
	if f.insecureOK {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("fetch: invalid url %q: %w", rawURL, err)
	}
	// Reject only literal non-public IPs (private/loopback/link-local/metadata).
	// Domains are allowed without DNS resolution: a live lookup here is both
	// fragile (odd resolvers, mixed public/private answers) and useless against
	// DNS rebinding — the connect-time resolution happens immediately after.
	isLiteral, public, err := netutil.IsPublicLiteralIP(u.Hostname())
	if err != nil {
		return fmt.Errorf("fetch: refusing non-public host: %s", u.Hostname())
	}
	if isLiteral && !public {
		return fmt.Errorf("fetch: refusing non-public host: %s", u.Hostname())
	}
	return nil
}

// httpError carries the status code for non-2xx responses.
type httpError struct {
	URL    string
	Status int
}

func (e *httpError) Error() string {
	return fmt.Sprintf("fetch: %q returned status %d", e.URL, e.Status)
}
