package serve

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNginxSnippet(t *testing.T) {
	c := NewController(t.TempDir(), "127.0.0.1:18080", "secret")
	target := "http://127.0.0.1:18080/s/secret/"
	s := c.NginxSnippet(target, "/vpn-sub")
	if !strings.Contains(s, "location") {
		t.Fatalf("snippet missing 'location': %q", s)
	}
	if !strings.Contains(s, target) {
		t.Fatalf("snippet missing target %q: %q", target, s)
	}
}

func TestStatusLocalURL(t *testing.T) {
	dir := t.TempDir()
	c := NewController(dir, "127.0.0.1:18080", "tok")
	st := c.Status()
	if st.LocalURL != "http://127.0.0.1:18080/s/tok/" {
		t.Fatalf("LocalURL = %q, want http://127.0.0.1:18080/s/tok/", st.LocalURL)
	}
	if st.Token != "tok" {
		t.Fatalf("Token = %q", st.Token)
	}
	if st.ListenAddr != "127.0.0.1:18080" {
		t.Fatalf("ListenAddr = %q", st.ListenAddr)
	}

	c2 := NewController(dir, "127.0.0.1:18080", "")
	if got := c2.Status().LocalURL; got != "http://127.0.0.1:18080/" {
		t.Fatalf("no-token LocalURL = %q", got)
	}
}

func TestDetectHTTPDNoPanic(t *testing.T) {
	c := NewController(t.TempDir(), "127.0.0.1:18080", "")
	// must not panic; we do not assume nginx/caddy/apache is present
	_ = c.DetectHTTPD()
}

func TestServeHealthz(t *testing.T) {
	dir := t.TempDir()
	c := NewController(dir, "127.0.0.1:18099", "")
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	// Start returns before the listener is bound; poll until the server is
	// ready or the deadline expires.
	var resp *http.Response
	var err error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://127.0.0.1:18099/healthz")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /healthz after retries: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d", resp.StatusCode)
	}
}
