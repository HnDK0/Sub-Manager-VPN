// Package select turns alive, latency-measured nodes into a small, safe set of
// subscription artifacts (sing-box JSON, v2rayN base64, Clash.Meta YAML) and
// persists them to disk.
//
// Security boundary: generators NEVER marshal model.Node. They build dedicated
// output structs / URI strings from explicit, validated Node fields only, so
// the untrusted Node.Extra and Node.Raw values can never leak into a
// generated subscription.
package selector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"vpn-sub-manager/internal/model"
)

// Candidate is a single alive node plus the inputs the selector needs: its
// measured latency and the country it was resolved to (geo resolution +
// state country column, supplied by the scheduler).
type Candidate struct {
	Node      model.Node
	LatencyMs int
	Country   string
	Hash      string
}

// Select ranks alive nodes per country by latency and returns the top TopN
// from each country merged together. A country with fewer than TopN alive
// nodes contributes ALL of its nodes (never padded with dead ones). TopN is
// clamped to the supported range [3,500]; a non-positive value defaults to 5.
func Select(cands []Candidate, topN int) []Candidate {
	if topN <= 0 {
		topN = 5
	}
	if topN < 3 {
		topN = 3
	}
	if topN > 500 {
		topN = 500
	}

	byCountry := make(map[string][]Candidate)
	for _, c := range cands {
		byCountry[c.Country] = append(byCountry[c.Country], c)
	}

	countries := make([]string, 0, len(byCountry))
	for k := range byCountry {
		countries = append(countries, k)
	}
	sort.Strings(countries)

	var out []Candidate
	for _, country := range countries {
		group := byCountry[country]
		sort.SliceStable(group, func(i, j int) bool {
			return group[i].LatencyMs < group[j].LatencyMs
		})
		limit := topN
		if len(group) < limit {
			limit = len(group)
		}
		for _, c := range group[:limit] {
			out = append(out, c)
		}
	}
	return out
}

// nodeNames returns the normalized display name for each node. Names follow the
// uniform scheme:
//
//	<flag> <PROTO> <NET> <host:port> <security>
//
// <flag> is the unicode flag emoji for the resolved country (🏳 when geo is
// unavailable), <PROTO> is the uppercase protocol (VLESS/VMess/Trojan/HY2/TUIC),
// <NET> is the transport type (tcp/ws/grpc/mkcp/xhttp/..., default tcp), and
// <security> is the REAL encryption/cipher (see securityLabel). Nodes sharing a
// host:port (same endpoint, different credentials) get a STABLE short hash suffix
// derived from their credential so the name is reproducible across cycles; a
// final numeric guard prevents duplicate outbound tags / proxy names.
// model.Node.Name (the raw, DB-stored name used for dead-node tracking) is never
// read here.
func nodeNames(nodes []model.Node) []string {
	// Count host:port groups to decide which nodes need a collision suffix.
	groupSize := make(map[string]int)
	for _, n := range nodes {
		groupSize[hostPort(n)]++
	}
	seen := make(map[string]int)
	out := make([]string, len(nodes))
	for i, n := range nodes {
		name := baseName(n)
		if groupSize[hostPort(n)] > 1 {
			name += "-" + collisionSuffix(n)
		}
		if c, ok := seen[name]; ok {
			seen[name] = c + 1
			name = fmt.Sprintf("%s-%d", name, c+1)
		} else {
			seen[name] = 1
		}
		out[i] = name
	}
	return out
}

func hostPort(n model.Node) string {
	return n.Host + ":" + strconv.Itoa(n.Port)
}

func baseName(n model.Node) string {
	return fmt.Sprintf("%s %s %s %s %s", flagEmoji(n.Country), typeLabel(n.Protocol), netLabel(n), hostPort(n), securityLabel(n))
}

// NormName returns the normalized display name for a node, following the
// uniform scheme:
//
//	<flag> <PROTO> <NET> <host:port> <security>
//
// It is the single-node form of baseName (no collision suffix) and is what the
// state layer persists as the node's display name. model.Node.Name (the raw,
// DB-stored name used for dead-node tracking) is never read here.
func NormName(n model.Node) string {
	return baseName(n)
}

// typeLabel maps a protocol to its uppercase display token.
func typeLabel(p model.Scheme) string {
	switch p {
	case model.SchemeVMess:
		return "VMESS"
	case model.SchemeVLESS:
		return "VLESS"
	case model.SchemeTrojan:
		return "TROJAN"
	case model.SchemeHysteria2:
		return "HY2"
	case model.SchemeTUIC:
		return "TUIC"
	default:
		return strings.ToUpper(string(p))
	}
}

// netLabel returns the transport/network token for the display name (the 3rd
// segment). An empty Network defaults to "tcp" (the common case for Trojan/
// Hysteria2/TUIC and bare VLESS/VMess).
func netLabel(n model.Node) string {
	if n.Network != "" {
		return n.Network
	}
	return "tcp"
}

// securityLabel returns the REAL encryption/cipher token for the display name
// (the 4th segment). "reality" is a VLESS security MODE, not a cipher — for
// reality nodes the cipher is the VLESS flow (xtls-rprx-vision), falling back to
// "reality" only when Flow is empty. VMess shows its inner Encryption (default
// aes-128-gcm); Trojan/Hysteria2/TUIC always run over TLS.
func securityLabel(n model.Node) string {
	switch n.Protocol {
	case model.SchemeVLESS:
		switch n.Security {
		case "reality":
			if n.Flow != "" {
				return n.Flow
			}
			return "reality"
		case "tls":
			return "tls"
		case "none", "":
			return "none"
		default:
			return n.Security
		}
	case model.SchemeVMess:
		if n.Encryption != "" {
			return n.Encryption
		}
		return "aes-128-gcm"
	case model.SchemeTrojan, model.SchemeHysteria2, model.SchemeTUIC:
		return "tls"
	default:
		if n.Security != "" {
			return n.Security
		}
		return "---"
	}
}

// flagEmoji returns the unicode flag for a 2-letter ISO country code, built from
// regional indicator symbols. Empty or non-2-letter codes yield the white flag
// (🏳) as a clean fallback (no raw garbage).
func flagEmoji(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return "\U0001F3F3" // 🏳 white flag
	}
	const base = rune(0x1F1E6) // regional indicator 'A'
	return string([]rune{base + rune(code[0]-'A'), base + rune(code[1]-'A')})
}

// collisionSuffix returns the first 4 hex chars of sha256(credential): a stable
// per-node discriminator for same-host:port siblings (no random counter).
func collisionSuffix(n model.Node) string {
	sum := sha256.Sum256([]byte(n.User))
	return hex.EncodeToString(sum[:])[:4]
}
