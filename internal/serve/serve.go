package serve

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// HTTPDInfo describes a detected reverse-proxy / web server on the host.
type HTTPDInfo struct {
	Name         string // "nginx" | "caddy" | "apache"
	BinPath      string // resolved binary path, "" if not installed
	Running      bool   // true if a process is currently running
	ConfigDir    string // primary config dir, e.g. /etc/nginx
	SitesEnabled string // dir where a snippet can be dropped, e.g. /etc/nginx/sites-enabled
}

// Status is a point-in-time view of the subscription HTTP server.
type Status struct {
	Running    bool
	ListenAddr string // e.g. "127.0.0.1:18080"
	Token      string // secret path token, "" if none
	LocalURL   string // base URL form "http://<listen>/s/<token>/" (no token -> "http://<listen>/")
	ExternalIP string // first non-loopback IPv4, "" if none
}

// Controller bundles the HTTP server and host HTTPD detection.
type Controller struct {
	outDir  string
	addr    string
	token   string
	mu      sync.Mutex
	server  *http.Server
	running bool
}

// NewController builds a controller. outDir is the dir containing singbox.json etc.
// addr is the listen address "host:port". token gates all routes under /s/<token>/ when non-empty.
func NewController(outDir, addr, token string) *Controller {
	return &Controller{outDir: outDir, addr: addr, token: token}
}

// Start launches the HTTP server in a goroutine and returns immediately.
// It is a NO-OP when addr == "" (Status.Running stays false).
func (c *Controller) Start(ctx context.Context) error {
	if c.addr == "" {
		return nil
	}
	srv := &http.Server{
		Addr:    c.addr,
		Handler: c,
	}
	c.mu.Lock()
	c.server = srv
	c.running = true
	c.mu.Unlock()

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// background serve error; surface via running flag only
		}
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()
	return nil
}

// Stop gracefully shuts the HTTP server down.
func (c *Controller) Stop() error {
	c.mu.Lock()
	srv := c.server
	c.mu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	c.mu.Lock()
	c.running = false
	c.mu.Unlock()
	return err
}

// Status returns a current snapshot of the server.
func (c *Controller) Status() Status {
	c.mu.Lock()
	running := c.running
	c.mu.Unlock()

	local := "http://" + c.addr + "/"
	if c.token != "" {
		local = "http://" + c.addr + "/s/" + c.token + "/"
	}
	return Status{
		Running:    running,
		ListenAddr: c.addr,
		Token:      c.token,
		LocalURL:   local,
		ExternalIP: externalIP(),
	}
}

// ListFiles returns the base names of the regular files in outDir, sorted
// lexicographically. If outDir cannot be read it returns nil.
func (c *Controller) ListFiles() []string {
	entries, err := os.ReadDir(c.outDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// Read returns the contents of the named file inside outDir. It rejects path
// traversal: the name must not be absolute and must not escape outDir (neither
// directly via ".." nor after cleaning/joining).
func (c *Controller) Read(name string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("serve: empty name")
	}
	if filepath.IsAbs(name) {
		return nil, fmt.Errorf("serve: absolute path not allowed: %q", name)
	}
	if strings.Contains(filepath.Clean(name), "..") {
		return nil, fmt.Errorf("serve: path traversal not allowed: %q", name)
	}
	p := filepath.Join(c.outDir, name)
	base := filepath.Clean(c.outDir)
	if p != base && !strings.HasPrefix(p, base+string(os.PathSeparator)) {
		return nil, fmt.Errorf("serve: path escapes out dir: %q", name)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ServeHTTP implements http.Handler.
func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
		return
	}

	if c.token != "" {
		prefix := "/s/" + c.token + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		rel := strings.TrimPrefix(r.URL.Path, prefix)
		if rel == "" {
			c.listFiles(w, r)
			return
		}
		c.serveFile(w, r, rel)
		return
	}

	// no token: serve directly under root
	if r.URL.Path == "/" {
		c.listFiles(w, r)
		return
	}
	c.serveFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
}

// profileTitle is the name Hiddify/Happ show after importing a subscription.
// It is sent via the Profile-Title HTTP header (highest precedence in the
// clients' naming hierarchy) and via Content-Disposition filename.
const profileTitle = "Sub Manager VPN"

func (c *Controller) serveFile(w http.ResponseWriter, r *http.Request, name string) {
	name = filepath.Base(name)
	if name == "" || name == "." || name == "/" {
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(c.outDir, name)
	base := filepath.Clean(c.outDir)
	if p != base && !strings.HasPrefix(p, base+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// ponytail: name via header so Hiddify/Happ show a real profile title.
	w.Header().Set("Profile-Title", profileTitle)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Type", contentType(name))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (c *Controller) listFiles(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(c.outDir)
	if err != nil {
		http.Error(w, "cannot list directory", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		io.WriteString(w, e.Name()+"\n")
	}
}

func contentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		return "application/json"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".yaml", ".yml":
		return "text/yaml"
	default:
		return "application/octet-stream"
	}
}

// NginxSnippet returns an nginx location block reverse-proxying path to target.
// Used for the subscription server (static files, no long-lived streaming).
func (c *Controller) NginxSnippet(target, path string) string {
	return fmt.Sprintf(`location %s {
    proxy_pass %s;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
`, path, target)
}

// AdminNginxSnippet returns an nginx location block for the admin web UI.
// The UI streams live status/events over SSE, so the proxy must disable
// buffering and keep the connection open (long read timeout).
func (c *Controller) AdminNginxSnippet(target, path string) string {
	return fmt.Sprintf(`location %s {
    proxy_pass %s;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    # SSE (live status/events): keep the stream unbuffered.
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 1d;
}
`, path, target)
}

// externalIP returns the first up, non-loopback, global-unicast IPv4.
func externalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil && ip4.IsGlobalUnicast() {
				return ip4.String()
			}
		}
	}
	return ""
}
