package serve

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type httpdDef struct {
	name         string
	configDir    string
	sitesEnabled string
}

// ponytail: Linux defaults only; the host target is Ubuntu.
var httpdDefs = []httpdDef{
	{"nginx", "/etc/nginx", "/etc/nginx/sites-enabled"},
	{"caddy", "/etc/caddy", "/etc/caddy"},
	{"apache", "/etc/apache2", "/etc/apache2/sites-enabled"},
}

// DetectHTTPD scans for nginx/caddy/apache and returns info for those installed.
// It never panics; a failed exec is treated as not running.
func (c *Controller) DetectHTTPD() []HTTPDInfo {
	var out []HTTPDInfo
	for _, d := range httpdDefs {
		bin, err := exec.LookPath(d.name)
		if err != nil || bin == "" {
			continue
		}
		info := HTTPDInfo{
			Name:         d.name,
			BinPath:      bin,
			ConfigDir:    d.configDir,
			SitesEnabled: d.sitesEnabled,
			Running:      isProcessRunning(d.name),
		}
		out = append(out, info)
	}
	return out
}

func isProcessRunning(name string) bool {
	if _, err := exec.LookPath("pgrep"); err == nil {
		if err := exec.Command("pgrep", "-x", name).Run(); err == nil {
			return true
		}
		return false
	}
	// fallback: scan /proc/*/comm
	for _, p := range globProcComm() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == name {
			return true
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
