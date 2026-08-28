// Package cdn rewrites VPN nodes whose server IP falls inside Cloudflare's
// published IP ranges, swapping the IP for a working CDN edge IP (e.g. one
// scanned by the companion VWNpy tool) while preserving SNI and ws/gRPC Host
// headers so TLS validation still succeeds.
//
// It is dependency-free beyond the standard library and the model/settings
// packages. On any upstream failure it degrades safely: nodes are returned
// unchanged rather than broken.
package cdn

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/settings"
)

const (
	cfV4URL         = "https://www.cloudflare.com/ips-v4"
	cfV6URL         = "https://www.cloudflare.com/ips-v6"
	cfCacheTTL      = 24 * time.Hour
	defaultVWNConfig = "/usr/local/etc/xray/connect_host"
)

var (
	cfMu       sync.Mutex
	cfRanges   []net.IPNet
	cfLoadedAt time.Time
)

// loadCFRanges returns the cached Cloudflare CIDR list, refreshing it from the
// network when older than cfCacheTTL. On a hard failure it keeps a stale cache
// if one exists, otherwise returns nil (callers then skip rewriting).
func loadCFRanges() []net.IPNet {
	cfMu.Lock()
	defer cfMu.Unlock()
	if time.Since(cfLoadedAt) < cfCacheTTL && len(cfRanges) > 0 {
		return cfRanges
	}
	ranges, err := fetchCFRanges()
	if err != nil {
		if len(cfRanges) > 0 {
			log.Printf("cdn: refresh CF ranges failed, using cached: %v", err)
			return cfRanges
		}
		log.Printf("cdn: load CF ranges failed: %v (CDN rewrite disabled)", err)
		return nil
	}
	cfRanges = ranges
	cfLoadedAt = time.Now()
	return cfRanges
}

// fetchCFRanges downloads both Cloudflare IP list endpoints and parses each
// non-blank line into a net.IPNet.
func fetchCFRanges() ([]net.IPNet, error) {
	out := make([]net.IPNet, 0, 256)
	client := &http.Client{Timeout: 15 * time.Second}
	for _, u := range []string{cfV4URL, cfV6URL} {
		resp, err := client.Get(u)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("%s returned %d", u, resp.StatusCode)
		}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
			out = append(out, *ipnet)
		}
		resp.Body.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// isCF reports whether ipStr is an IP inside a Cloudflare range. Domains (which
// fail to parse as an IP) are never considered CF hosts.
func isCF(ipStr string) bool {
	ranges := loadCFRanges()
	if len(ranges) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, ipnet := range ranges {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveCDNIP returns the working CDN edge IP per the configured source.
//   - "vwn": first non-empty line of the VWNpy connect_host file (default path
//     when CDNVWNConfig is empty); falls back to CDNFallbackIP when the file is
//     missing/empty.
//   - "manual": CDNFallbackIP.
//   - anything else: "" (no rewrite target).
func resolveCDNIP(s settings.Settings) string {
	switch s.CDNSource {
	case "vwn":
		path := s.CDNVWNConfig
		if path == "" {
			path = defaultVWNConfig
		}
		if ip := readFirstLine(path); ip != "" {
			return ip
		}
		return s.CDNFallbackIP
	case "manual":
		return s.CDNFallbackIP
	default:
		return ""
	}
}

// readFirstLine returns the first non-empty, trimmed line of the file at path,
// or "" if the file is missing or empty.
func readFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

// Rewrite returns nodes with any Cloudflare-range server IP replaced by the
// working CDN edge IP. SNI (Extra["sni"]) is set to the original Host when
// absent so certificate validation still passes; the ws/gRPC Host header
// (Extra["host"]) is deliberately left untouched. Per-host overrides take
// precedence over the auto-resolved IP. When CDNEnabled is false, or no target
// IP can be resolved, nodes are returned unchanged.
func Rewrite(nodes []model.Node, s settings.Settings) []model.Node {
	if !s.CDNEnabled {
		return nodes
	}
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if isCF(n.Host) {
			target := resolveCDNIP(s)
			if target != "" {
				// Copy Extra so we never mutate the caller's shared map.
				if n.Extra == nil {
					n.Extra = map[string]string{}
				} else {
					cp := make(map[string]string, len(n.Extra)+1)
					for k, v := range n.Extra {
						cp[k] = v
					}
					n.Extra = cp
				}
				if n.Extra["sni"] == "" {
					n.Extra["sni"] = n.Host
				}
				// Keep n.Extra["host"] (ws/gRPC HTTP Host) as the original domain.
				if ov, ok := s.CDNOverrides[n.Host]; ok {
					target = ov
				} else if ov, ok := s.CDNOverrides[n.Extra["sni"]]; ok {
					target = ov
				}
				if target != "" {
					n.Host = target
				}
			}
		}
		out = append(out, n)
	}
	return out
}
