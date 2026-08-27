package mihomo

import (
	"fmt"
	"strings"

	"vpn-sub-manager/internal/model"
)

// nodeHash mirrors state.nodeHash so proxy names are stable and match DB keys.
func nodeHash(n *model.Node) string {
	sum := sha256Sum(fmt.Sprintf("%s|%s|%d|%s|%s|%s", n.Protocol, n.Host, n.Port, n.User, n.Security, n.Encryption))
	return sum
}

// extra reads a benign, allow-listed key from Node.Extra. Dangerous keys
// (allow_insecure, skip-cert-verify, dialer-proxy, plugin) are NEVER read.
func extra(n model.Node, key string) string {
	if n.Extra == nil {
		return ""
	}
	return n.Extra[key]
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildProxyYAML converts a normalized Node into a clash-meta proxy map using
// ONLY known fields plus the strict Extra allow-list. It never reads
// allow_insecure / skip-cert-verify / dialer-proxy / plugin.
func buildProxyYAML(n model.Node) map[string]any {
	name := nodeHash(&n)
	base := map[string]any{
		"name":   name,
		"server": n.Host,
		"port":   n.Port,
	}
	net := n.Network
	if net == "" {
		net = "tcp"
	}
	alpn := splitList(extra(n, "alpn"))
	fp := extra(n, "fp")
	sni := extra(n, "sni")
	if sni == "" {
		sni = n.Host
	}

	switch n.Protocol {
	case model.SchemeVLESS:
		base["type"] = "vless"
		base["uuid"] = n.User
		if n.Flow != "" {
			base["flow"] = n.Flow
		}
		base["network"] = net
		if n.Security == "reality" {
			base["tls"] = true
		} else if n.Security == "tls" {
			// Strict cert verification: reject self-signed / mismatched certs so
			// a node that only "works" with allow_insecure is NOT marked alive.
			base["tls"] = map[string]any{"enabled": true, "skip-cert-verify": false}
		}
		if n.Security == "reality" {
			ro := map[string]any{}
			if pbk := extra(n, "pbk"); pbk != "" {
				ro["public-key"] = pbk
			}
			if sid := extra(n, "sid"); sid != "" {
				ro["short-id"] = sid
			}
			if spx := extra(n, "spx"); spx != "" {
				ro["spider-x"] = spx
			}
			base["reality-opts"] = ro
			// xray/sing-box default client-fingerprint to chrome; match it so
			// the probe exercises the same TLS fingerprint the client will use.
			if fp == "" {
				fp = "chrome"
			}
		}
		if fp != "" {
			base["client-fingerprint"] = fp
		}
		base["servername"] = sni
		applyTransport(base, net, n)
		if len(alpn) > 0 {
			base["alpn"] = alpn
		}

	case model.SchemeVMess:
		base["type"] = "vmess"
		base["uuid"] = n.User
		base["alterId"] = 0
		cipher := n.Encryption
		if cipher == "" {
			cipher = "auto"
		}
		base["cipher"] = cipher
		base["network"] = net
		if n.Security == "tls" {
			base["tls"] = map[string]any{"enabled": true, "skip-cert-verify": false}
		}
		if fp != "" {
			base["client-fingerprint"] = fp
		}
		base["servername"] = sni
		applyTransport(base, net, n)
		if len(alpn) > 0 {
			base["alpn"] = alpn
		}

	case model.SchemeTrojan:
		base["type"] = "trojan"
		base["password"] = n.User
		base["network"] = net
		base["sni"] = sni
		// Trojan is always TLS; verify the cert strictly.
		base["tls"] = map[string]any{"enabled": true, "skip-cert-verify": false}
		if fp != "" {
			base["client-fingerprint"] = fp
		}
		applyTransport(base, net, n)
		if len(alpn) > 0 {
			base["alpn"] = alpn
		}

	case model.SchemeHysteria2:
		base["type"] = "hysteria2"
		base["password"] = n.User
		if obfs := extra(n, "obfs"); obfs != "" {
			base["obfs"] = obfs
		}
		if op := extra(n, "obfs-password"); op != "" {
			base["obfs-password"] = op
		}
		base["sni"] = sni
		if fp != "" {
			base["fingerprint"] = fp
		}
		if len(alpn) > 0 {
			base["alpn"] = alpn
		}

	case model.SchemeTUIC:
		base["type"] = "tuic"
		base["uuid"] = n.User
		base["password"] = n.User
		base["sni"] = sni
		if fp != "" {
			base["fingerprint"] = fp
		}
		if cc := extra(n, "congestion_control"); cc != "" {
			base["congestion-controller"] = cc
		}
		if len(alpn) > 0 {
			base["alpn"] = alpn
		}

	case model.SchemeSS:
		// Shadowsocks: only AEAD ciphers reach here — filter.DropUnsupported
		// already rejected non-AEAD SS and DropMalware rejected any plugin — so
		// cipher+password are sufficient and safe to emit. Without this case the
		// proxy map had no "type", mihomo rejected it, the probe failed, and SS
		// nodes were silently dropped as dead (never appeared in alive).
		base["type"] = "ss"
		base["cipher"] = n.Encryption
		base["password"] = n.User
	}
	return base
}

// applyTransport attaches ws-opts / grpc-opts for ws / grpc networks.
func applyTransport(base map[string]any, net string, n model.Node) {
	switch net {
	case "ws":
		ws := map[string]any{}
		if p := extra(n, "path"); p != "" {
			ws["path"] = p
		}
		if h := extra(n, "host"); h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		base["ws-opts"] = ws
	case "grpc":
		grpc := map[string]any{}
		if svc := extra(n, "serviceName"); svc != "" {
			grpc["grpc-service-name"] = svc
		}
		base["grpc-opts"] = grpc
	case "xhttp":
		x := map[string]any{}
		if p := extra(n, "path"); p != "" {
			x["path"] = p
		}
		if h := extra(n, "host"); h != "" {
			x["host"] = h
		}
		if m := extra(n, "mode"); m != "" {
			x["mode"] = m
		}
		base["xhttp-opts"] = x
	case "http":
		h := map[string]any{}
		if p := extra(n, "path"); p != "" {
			h["path"] = p
		}
		if ho := extra(n, "host"); ho != "" {
			h["headers"] = map[string]any{"Host": ho}
		}
		base["http-opts"] = h
	case "h2":
		h2 := map[string]any{}
		if p := extra(n, "path"); p != "" {
			h2["path"] = p
		}
		if ho := extra(n, "host"); ho != "" {
			h2["headers"] = map[string]any{"Host": ho}
		}
		base["h2-opts"] = h2
	}
}
