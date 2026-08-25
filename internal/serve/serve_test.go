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

func TestParseNginxServersIn(t *testing.T) {
	src := `
http {
    server {
        server_name example.com www.example.com;
        location /s/tok/ {
            proxy_pass http://127.0.0.1:18080/s/tok/;
        }
        location = /healthz { proxy_pass http://127.0.0.1:18080/healthz; }
    }
    server {
        server_name _;
        listen 80 default_server;
        location /admin/ {
            proxy_pass http://127.0.0.1:8090/admin/;
        }
    }
}
`
	servers := parseNginxServersIn(src)
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}
	var sub, admin *NginxServer
	for i := range servers {
		if len(servers[i].Names) > 0 && servers[i].Names[0] == "example.com" {
			sub = &servers[i]
		}
		if len(servers[i].Names) == 0 {
			admin = &servers[i]
		}
	}
	if sub == nil {
		t.Fatalf("subscription server not found")
	}
	if got := sub.LocProxy["/s/tok/"]; got != "127.0.0.1:18080" {
		t.Fatalf("sub proxy target = %q, want 127.0.0.1:18080", got)
	}
	if got := sub.LocProxy["/healthz"]; got != "127.0.0.1:18080" {
		t.Fatalf("healthz proxy target = %q, want 127.0.0.1:18080", got)
	}
	if admin == nil {
		t.Fatalf("admin server (no names) not found")
	}
	if got := admin.LocProxy["/admin/"]; got != "127.0.0.1:8090" {
		t.Fatalf("admin proxy target = %q, want 127.0.0.1:8090", got)
	}
}

func TestParseNginxServersLocalhost(t *testing.T) {
	src := `
server {
    server_name vpn.example.com;
    location /s/tok/ {
        proxy_pass http://localhost:18080/s/tok/;
    }
}
`
	servers := parseNginxServersIn(src)
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if got := servers[0].LocProxy["/s/tok/"]; got != "127.0.0.1:18080" {
		t.Fatalf("localhost proxy target = %q, want 127.0.0.1:18080", got)
	}
}

func TestParseNginxServersNoPanic(t *testing.T) {
	c := NewController(t.TempDir(), "127.0.0.1:18080", "")
	// On non-Linux (no /etc/nginx) this returns nil; must not panic.
	_ = c.ParseNginxServers()
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
