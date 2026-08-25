package serve

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type httpdDef struct {
	name         string
	configDir    string
	sitesEnabled string
	binNames     []string // binary names to locate on disk
	procNames    []string // process-name candidates for the "running" check
}

// ponytail: Linux defaults only; the host target is Ubuntu.
var httpdDefs = []httpdDef{
	{"nginx", "/etc/nginx", "/etc/nginx/sites-enabled", []string{"nginx"}, []string{"nginx"}},
	{"caddy", "/etc/caddy", "/etc/caddy", []string{"caddy"}, []string{"caddy"}},
	{"apache", "/etc/apache2", "/etc/apache2/sites-enabled", []string{"apache2", "apache", "httpd"}, []string{"apache2", "apache", "httpd"}},
}

// findBin resolves a binary by name. It first tries PATH (exec.LookPath) for
// each candidate, then falls back to the common sbin/bin directories so a
// systemd --user service with a minimal PATH (where nginx lives in
// /usr/sbin) is still detected. Returns the first absolute path found, else "".
func findBin(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil && p != "" {
			return p
		}
	}
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		for _, n := range names {
			p := filepath.Join(dir, n)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}
	return ""
}

// DetectHTTPD scans for nginx/caddy/apache and returns info for those installed.
// It never panics; a failed exec is treated as not running.
func (c *Controller) DetectHTTPD() []HTTPDInfo {
	var out []HTTPDInfo
	for _, d := range httpdDefs {
		bin := findBin(d.binNames...)
		if bin == "" {
			continue
		}
		info := HTTPDInfo{
			Name:         d.name,
			BinPath:      bin,
			ConfigDir:    d.configDir,
			SitesEnabled: d.sitesEnabled,
			Running:      isProcessRunning(d.procNames...),
		}
		out = append(out, info)
	}
	return out
}

// isProcessRunning reports whether any of the given process names is running.
// It tries pgrep -x for each candidate, then falls back to scanning /proc/*/comm.
func isProcessRunning(names ...string) bool {
	if _, err := exec.LookPath("pgrep"); err == nil {
		for _, name := range names {
			if err := exec.Command("pgrep", "-x", name).Run(); err == nil {
				return true
			}
		}
		return false
	}
	// fallback: scan /proc/*/comm
	for _, p := range globProcComm() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(data))
		for _, name := range names {
			if comm == name {
				return true
			}
		}
	}
	return false
}

func globProcComm() []string {
	matches, err := filepath.Glob("/proc/*/comm")
	if err != nil {
		return nil
	}
	return matches
}

// NginxServer is a parsed nginx `server { ... }` block: the server_name tokens
// and a map of location path -> proxy_pass target (host:port).
type NginxServer struct {
	Names    []string
	LocProxy map[string]string
}

var (
	reServerName = regexp.MustCompile(`server_name\s+([^;]*);`)
	reProxyPass  = regexp.MustCompile(`proxy_pass\s+(\S+);`)
)

// ParseNginxServers reads the standard nginx config locations
// (/etc/nginx/nginx.conf plus *.conf under conf.d/ and sites-enabled/) and
// extracts every server block's server_name and location proxy_pass targets.
// It is defensive: missing/unreadable files or parse failures yield an empty
// slice rather than an error or panic. On non-Linux hosts (no /etc/nginx) it
// simply returns nil.
func (c *Controller) ParseNginxServers() []NginxServer {
	var servers []NginxServer
	sources := []string{"/etc/nginx/nginx.conf"}
	sources = append(sources, globConfDir("/etc/nginx/conf.d")...)
	sources = append(sources, globConfDir("/etc/nginx/sites-enabled")...)
	for _, f := range sources {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		servers = append(servers, parseNginxServersIn(string(data))...)
	}
	return servers
}

func globConfDir(dir string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, "*.conf"))
	if err != nil {
		return nil
	}
	return matches
}

// parseNginxServersIn extracts server blocks from a single config blob.
func parseNginxServersIn(src string) []NginxServer {
	var servers []NginxServer
	i := 0
	n := len(src)
	for i < n {
		idx := strings.Index(src[i:], "server")
		if idx < 0 {
			break
		}
		pos := i + idx
		if !isTokenBoundary(at(src, pos-1)) || !isTokenBoundary(at(src, pos+len("server"))) {
			i = pos + len("server")
			continue
		}
		open := strings.Index(src[pos+len("server"):], "{")
		if open < 0 {
			break
		}
		bracePos := pos + len("server") + open
		end := matchBrace(src, bracePos)
		if end < 0 {
			break
		}
		if srv := parseServerBlock(src[bracePos+1 : end]); srv != nil {
			servers = append(servers, *srv)
		}
		i = end + 1
	}
	return servers
}

// parseServerBlock parses the body of a `server { ... }` block.
func parseServerBlock(block string) *NginxServer {
	srv := &NginxServer{LocProxy: map[string]string{}}
	for _, m := range reServerName.FindAllStringSubmatch(block, -1) {
		for _, tok := range strings.Fields(m[1]) {
			t := strings.Trim(tok, `"'`)
			if t == "" || t == "_" || t == "default_server" {
				continue
			}
			srv.Names = append(srv.Names, t)
		}
	}
	i := 0
	for i < len(block) {
		idx := strings.Index(block[i:], "location")
		if idx < 0 {
			break
		}
		pos := i + idx
		if !isTokenBoundary(at(block, pos-1)) || !isTokenBoundary(at(block, pos+len("location"))) {
			i = pos + len("location")
			continue
		}
		rest := block[pos+len("location"):]
		open := strings.Index(rest, "{")
		if open < 0 {
			break
		}
		head := strings.TrimSpace(rest[:open])
		path := locationPath(head)
		bracePos := pos + len("location") + open
		end := matchBrace(block, bracePos)
		if end < 0 {
			break
		}
		if path != "" {
			if pp := proxyPassTarget(block[bracePos+1 : end]); pp != "" {
				srv.LocProxy[path] = pp
			}
		}
		i = end + 1
	}
	if len(srv.Names) == 0 && len(srv.LocProxy) == 0 {
		return nil
	}
	return srv
}

// locationPath returns the path of a location directive, stripping an optional
// modifier (=, ~, ~*, ^~).
func locationPath(head string) string {
	fields := strings.Fields(head)
	if len(fields) == 0 {
		return ""
	}
	switch fields[0] {
	case "=", "~", "~*", "^~":
		if len(fields) > 1 {
			return fields[1]
		}
		return ""
	}
	return fields[0]
}

// proxyPassTarget extracts host:port from a proxy_pass directive, stripping the
// scheme and any trailing path/query.
func proxyPassTarget(block string) string {
	m := reProxyPass.FindStringSubmatch(block)
	if m == nil {
		return ""
	}
	target := strings.Trim(m[1], `"'`)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	if slash := strings.Index(target, "/"); slash >= 0 {
		target = target[:slash]
	}
	if hash := strings.Index(target, "#"); hash >= 0 {
		target = target[:hash]
	}
	return target
}

// matchBrace returns the index of the '}' that closes the '{' at open, or -1.
func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func at(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return ' ' // treat out-of-range as a boundary
	}
	return s[i]
}

func isTokenBoundary(b byte) bool {
	if b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '{' || b == '}' || b == ';' || b == '(' || b == ')' || b == '#' {
		return true
	}
	// identifiers may contain letters, digits, '-', '_', '.', '/', ':'
	if b == '_' || b == '-' || b == '.' || b == '/' || b == ':' {
		return false
	}
	return !isIdentByte(b)
}

func isIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
