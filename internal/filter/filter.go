package filter

import (
	"strings"

	"vpn-sub-manager/internal/model"
)

// dedupSep is a separator that cannot appear in any node field, so a simple
// string join is a safe composite key.
const dedupSep = "\x00"

// key returns the dedup key for a node: Protocol|Network|Host|Port|User|
// Security|Encryption. Security/Encryption are included so a host:port listed
// both as secure and insecure survives dedup as two distinct configs
// (DropInsecure then keeps the secure one) instead of the insecure twin
// shadowing the secure one. Network is included so the same endpoint advertised
// over multiple transports (e.g. ws and grpc) is kept as distinct configs
// rather than collapsed into one.
func key(n model.Node) string {
	return string(n.Protocol) + dedupSep + n.Network + dedupSep + n.Host + dedupSep +
		itoa(n.Port) + dedupSep + n.User + dedupSep + n.Security + dedupSep + n.Encryption
}

// itoa avoids importing strconv for one int.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// Dedup removes nodes that share the same Protocol|Host|Port|User key, keeping
// the first occurrence (and its Source). Name/Source differences do not count.
func Dedup(nodes []model.Node) []model.Node {
	seen := make(map[string]struct{}, len(nodes))
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		k := key(n)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, n)
	}
	return out
}

// open reports whether a node is an open (no-authentication) proxy that must
// be rejected. Only VMess/VLESS/Trojan/SS carry their credential in User; for
// those an empty User means no auth. Hysteria2/TUIC/WireGuard (and any other)
// are NOT enforced here — their secret may live in Extra, and a false drop is
// worse than a false keep.
func open(n model.Node) bool {
	switch n.Protocol {
	case model.SchemeVMess, model.SchemeVLESS, model.SchemeTrojan, model.SchemeSS:
		return strings.TrimSpace(n.User) == ""
	}
	return false
}

// DropOpen removes open (no-authentication) proxies. It runs after Dedup and
// before DropInsecure so the ordering is Dedup -> DropOpen -> DropInsecure ->
// DropMalware.
func DropOpen(nodes []model.Node) []model.Node {
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if open(n) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// isTruthy reports whether a cert-skip value is enabled.
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// isPlainForward reports whether the protocol is a plain (unencrypted) forward
// proxy that should never appear in a secure subscription.
func isPlainForward(proto model.Scheme, extra map[string]string) bool {
	switch strings.ToLower(string(proto)) {
	case "socks", "http", "https":
		return true
	}
	for _, k := range []string{"protocol", "scheme"} {
		if v, ok := extra[k]; ok {
			switch strings.ToLower(v) {
			case "socks", "http", "https":
				return true
			}
		}
	}
	return false
}

// DropInsecure removes nodes that are plaintext or skip certificate
// verification. VLESS must use tls/reality; VMess/Trojan must use TLS;
// Hysteria2/TUIC drop only on security=none. (Shadowsocks/WireGuard are
// already removed upstream by DropUnsupported.)
func DropInsecure(nodes []model.Node) []model.Node {
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		drop := false
		if isPlainForward(n.Protocol, n.Extra) {
			drop = true
		}
		switch n.Protocol {
		case model.SchemeVLESS:
			// VLESS MUST use TLS (tls) or REALITY. security=none or absent is
			// plaintext -> drop. encryption=none is the normal VLESS default.
			if n.Security != "tls" && n.Security != "reality" {
				drop = true
			}
			// A reality node with no public key (pbk) is not valid reality: the
			// probe would disable reality and fall back to plain TLS, falsely
			// passing a node the client rejects. Drop it here.
			if n.Security == "reality" && strings.TrimSpace(n.Extra["pbk"]) == "" {
				drop = true
			}
			// VLESS flow (xtls-rprx-vision / xtls-rprx-origin) requires reality
			// security. A flow set with plain tls (or none) is invalid and the
			// client fails the handshake -> drop before it can reach a probe.
			if n.Flow != "" && n.Security != "reality" {
				drop = true
			}
	case model.SchemeVMess, model.SchemeTrojan:
			// These are plaintext-capable without TLS transport.
			if n.Security != "tls" {
				drop = true
			}
		case model.SchemeHysteria2, model.SchemeTUIC:
			// Always TLS by protocol, but security=none is a misconfiguration
			// (no transport security) -> drop.
			if n.Security == "none" {
				drop = true
			}
		}
		// Cert-skip indicators in Extra (hysteria2/tuic excluded above).
		if !drop && hasCertSkip(n.Extra) {
			drop = true
		}
		if !drop {
			out = append(out, n)
		}
	}
	return out
}

// hasCertSkip reports whether Extra requests skipping certificate verification.
func hasCertSkip(extra map[string]string) bool {
	if extra == nil {
		return false
	}
	for _, k := range []string{"insecure", "allow_insecure", "skip-cert-verify"} {
		if v, ok := extra[k]; ok && isTruthy(v) {
			return true
		}
	}
	return false
}

// malwareKeys are Extra keys that are dangerous regardless of value.
var malwareKeys = map[string]struct{}{
	"exec":            {},
	"command":         {},
	"script":          {},
	"outbound-hijack": {},
	"route":           {},
}

// DropMalware removes nodes whose Extra map carries execution/hijack
// indicators. Scope is limited to Extra to avoid false positives on benign
// Clash/sing-box routing fields. Benign unknown Extra fields are kept.
func DropMalware(nodes []model.Node) []model.Node {
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if isMalwareExtra(n.Extra) || isMalwarePlugin(n.Plugin) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// isMalwarePlugin inspects the SS plugin string. Any non-empty plugin is
// rejected: simple-obfs is DPI-bypassable/deprecated and v2ray-plugin can
// tunnel arbitrary traffic (an injection surface). Only bare AEAD SS (no
// plugin) is accepted.
func isMalwarePlugin(plugin string) bool {
	return strings.TrimSpace(plugin) != ""
}

// isMalwareExtra inspects only the Extra map for malware indicators.
func isMalwareExtra(extra map[string]string) bool {
	if extra == nil {
		return false
	}
	for k, v := range extra {
		lk := strings.ToLower(k)
		if _, ok := malwareKeys[lk]; ok {
			return true
		}
		// ssconf is only malware when it carries an exec/script payload; a
		// plain ssconf:// config link is benign.
		if lk == "ssconf" && malwareValue(v) {
			return true
		}
		// Any other key with a dangerous value is rejected.
		if malwareValue(v) {
			return true
		}
	}
	return false
}

// malwareValue reports whether a value looks like an execution payload.
//
// It is intentionally narrow. Bare shell metacharacters (& ; |) appear in
// benign params — VLESS ws path="/?ed=2048&v=1", Hysteria2 obfs-password — and
// must NOT trip it. The dangerous *keys* (exec/command/script/outbound-hijack/
// route) are already rejected by isMalwareExtra before this runs, so this only
// guards non-dangerous keys and ssconf values against actual execution payloads.
func malwareValue(v string) bool {
	lower := strings.ToLower(v)
	// Clear execution tokens.
	for _, tok := range []string{"exec ", "command ", "script"} {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	// Command substitution / backtick execution.
	if strings.Contains(lower, "$(") || strings.Contains(lower, "`") {
		return true
	}
	// Command chaining (&&) — a genuine shell sequence, not a benign separator.
	if strings.Contains(lower, "&&") {
		return true
	}
	// Executable/script payloads by extension.
	for _, ext := range []string{".sh", ".exe", ".bat", ".ps1", ".dll", ".py"} {
		if strings.Contains(lower, ext) {
			return true
		}
	}
	// ssconf:// (or any http(s)://) link carrying a script/executable payload.
	if strings.Contains(lower, "ssconf://") ||
		strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		if strings.Contains(lower, "script") || strings.Contains(lower, ".sh") ||
			strings.Contains(lower, ".exe") {
			return true
		}
	}
	return false
}

// broken reports whether a node is missing required fields and would yield a
// non-functional subscription entry. Host/Port are mandatory for every scheme;
// User (the credential) is mandatory for the schemes whose parser populates it
// (vmess/vless/trojan/ss/hysteria2/tuic); SS additionally needs a cipher.
func broken(n model.Node) bool {
	if strings.TrimSpace(n.Host) == "" || n.Port <= 0 {
		return true
	}
	switch n.Protocol {
	case model.SchemeVMess, model.SchemeVLESS, model.SchemeTrojan,
		model.SchemeHysteria2, model.SchemeTUIC:
		if strings.TrimSpace(n.User) == "" {
			return true
		}
	case model.SchemeSS:
		if strings.TrimSpace(n.User) == "" || strings.TrimSpace(n.Encryption) == "" {
			return true
		}
	}
	return false
}

// DropBroken removes nodes that lack required fields so only functional,
// non-empty configs reach generation. Final safety net after trust/security filters.
func DropBroken(nodes []model.Node) []model.Node {
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if !broken(n) {
			out = append(out, n)
		}
	}
	return out
}

// safeSSCiphers is the allowlist of Shadowsocks ciphers we re-enable. Only AEAD
// methods are accepted; stream/non-AEAD ciphers (cfb/ctr/rc4/chacha20 non-ietf/
// salsa20/tea/speck/plain/none) and the non-recommended aes-192-gcm are rejected
// because they are weak or fingerprintable. 2022-blake3-* are the current SIP022
// standard and safe.
var safeSSCiphers = map[string]bool{
	"aes-256-gcm":                    true,
	"aes-128-gcm":                    true,
	"chacha20-ietf-poly1305":         true,
	"xchacha20-ietf-poly1305":        true,
	"2022-blake3-aes-256-gcm":        true,
	"2022-blake3-aes-128-gcm":        true,
	"2022-blake3-chacha20-poly1305":  true,
}

// isSafeSS reports whether an SS cipher is an accepted AEAD method.
func isSafeSS(cipher string) bool {
	return safeSSCiphers[strings.ToLower(strings.TrimSpace(cipher))]
}

// DropUnsupported removes nodes whose protocol is outside the strict allowlist.
// WireGuard (SchemeWireGuard) is still cut — its handshake is trivially
// recognizable. Shadowsocks (SchemeSS) is RE-ENABLED but only for AEAD ciphers
// (see isSafeSS); non-AEAD SS is dropped because it is weak/fingerprintable.
// Kept: vmess/vless/trojan/hysteria2/tuic + AEAD SS.
func DropUnsupported(nodes []model.Node) []model.Node {
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		switch n.Protocol {
		case model.SchemeWireGuard:
			continue
		case model.SchemeSS:
			if !isSafeSS(n.Encryption) {
				continue
			}
		}
		out = append(out, n)
	}
	return out
}

// Apply runs Dedup -> DropBroken -> DropUnsupported -> DropOpen -> DropInsecure -> DropMalware in order.
func Apply(nodes []model.Node) []model.Node {
	nodes = Dedup(nodes)
	nodes = DropBroken(nodes)
	nodes = DropUnsupported(nodes)
	nodes = DropOpen(nodes)
	nodes = DropInsecure(nodes)
	nodes = DropMalware(nodes)
	return nodes
}
