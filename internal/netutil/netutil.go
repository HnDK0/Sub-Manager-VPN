// Package netutil provides SSRF guards: helpers to decide whether a host or
// URL points at a public, routable address (and therefore is safe to fetch
// from) versus a private/loopback/link-local/metadata/reserved address that
// must never be reached from a subscription source.
package netutil

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"
)

// resolveTimeout bounds DNS resolution so a malicious/odd domain cannot make it
// block indefinitely.
const resolveTimeout = 5 * time.Second

// IsPublicHost reports whether host (with optional port) resolves to a public,
// global-unicast address. A literal IP is checked directly; a domain is
// resolved and ALL resolved IPs must be public. Loopback, private (RFC1918 /
// RFC4193 ULA), link-local, cloud metadata (169.254.169.254), multicast, and
// unspecified addresses are rejected. On resolution error (false, err) is
// returned.
func IsPublicHost(host string) (bool, error) {
	// Strip optional port. net.SplitHostPort handles bracketed IPv6 literals
	// and host:port; a bare host (no port) returns an error we ignore.
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}

	if ip := net.ParseIP(hostOnly); ip != nil {
		return isPublicIP(ip), nil
	}

	// Domain: resolve with a bounded timeout.
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostOnly)
	if err != nil {
		return false, fmt.Errorf("netutil: resolve %q: %w", hostOnly, err)
	}
	if len(addrs) == 0 {
		return false, fmt.Errorf("netutil: no addresses for %q", hostOnly)
	}
	for _, a := range addrs {
		if !isPublicIP(a.IP) {
			return false, nil
		}
	}
	return true, nil
}

// IsPublicURL reports whether rawURL is an https:// URL whose host is public.
func IsPublicURL(rawURL string) (bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, fmt.Errorf("netutil: parse url %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return false, nil
	}
	return IsPublicHost(u.Hostname())
}

// ResolveAndCheckPublic resolves host (with optional port) and returns the first
// public IP plus a bool. For a literal IP it returns (ip, isPublicIP(ip), nil).
// For a domain it resolves via the same bounded resolver; if resolution fails it
// returns (nil, false, err); if ANY resolved IP is non-public it returns
// (nil, false, nil); otherwise it returns (addrs[0].IP, true, nil). The caller
// should pin the returned IP before connecting to close the DNS-rebinding TOCTOU
// window between validation and connect-time resolution.
func ResolveAndCheckPublic(host string) (net.IP, bool, error) {
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}
	if ip := net.ParseIP(hostOnly); ip != nil {
		return ip, isPublicIP(ip), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostOnly)
	if err != nil {
		return nil, false, fmt.Errorf("netutil: resolve %q: %w", hostOnly, err)
	}
	if len(addrs) == 0 {
		return nil, false, fmt.Errorf("netutil: no addresses for %q", hostOnly)
	}
	for _, a := range addrs {
		if !isPublicIP(a.IP) {
			return nil, false, nil
		}
	}
	return addrs[0].IP, true, nil
}

// isPublicIP reports whether ip is a global-unicast public address. It returns
// false for loopback, private (RFC1918 / RFC4193 ULA), link-local, the cloud
// metadata IP 169.254.169.254, multicast, and unspecified addresses.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Normalize to 4-byte form when possible for the IPv4 checks below.
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0: // unspecified 0.0.0.0/8
			return false
		case v4[0] == 127: // loopback 127.0.0.0/8
			return false
		case v4[0] == 10: // private 10.0.0.0/8
			return false
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31: // private 172.16.0.0/12
			return false
		case v4[0] == 192 && v4[1] == 168: // private 192.168.0.0/16
			return false
		case v4[0] == 169 && v4[1] == 254: // link-local 169.254.0.0/16 (incl. metadata)
			return false
		case v4[0] >= 224 && v4[0] <= 239: // multicast 224.0.0.0/4
			return false
		case v4[0] >= 240: // reserved 240.0.0.0/4
			return false
		}
		return true
	}

	// IPv6.
	switch {
	case ip.IsLoopback(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsMulticast(), ip.IsUnspecified():
		return false
	case ip[0]&0xfe == 0xfc: // ULA fc00::/7
		return false
	}
	return ip.IsGlobalUnicast()
}
