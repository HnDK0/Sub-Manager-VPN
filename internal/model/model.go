package model

import (
	"fmt"
	"strings"
)

// Scheme is the URI scheme / protocol of a VPN node.
// Only the 7 supported schemes are valid; ssr/snell and any unknown
// scheme are intentionally rejected (see ParseScheme).
type Scheme string

const (
	SchemeVMess     Scheme = "vmess"
	SchemeVLESS     Scheme = "vless"
	SchemeTrojan    Scheme = "trojan"
	SchemeSS        Scheme = "ss"
	SchemeHysteria2 Scheme = "hysteria2"
	SchemeTUIC      Scheme = "tuic"
	SchemeWireGuard Scheme = "wireguard"
)

// supportedSchemes is the canonical allow-list. ssr/snell are deliberately
// excluded as legacy/risky protocols.
var supportedSchemes = map[Scheme]struct{}{
	SchemeVMess:     {},
	SchemeVLESS:     {},
	SchemeTrojan:    {},
	SchemeSS:        {},
	SchemeHysteria2: {},
	SchemeTUIC:      {},
	SchemeWireGuard: {},
}

// ParseScheme lowercases the input and returns the matching Scheme, or an
// error if it is not one of the 7 supported schemes. Unknown schemes
// (ssr, snell, http, garbage, ...) are rejected.
func ParseScheme(s string) (Scheme, error) {
	norm := Scheme(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := supportedSchemes[norm]; !ok {
		return "", fmt.Errorf("unsupported scheme %q", s)
	}
	return norm, nil
}

// Node is the normalized representation of a single VPN subscription node.
// Fields are intentionally flat and typed so later tasks (parsing, filtering,
// generation) can rely on stable names.
//
// Security model: untrusted/unknown parsed fields are quarantined into
// Extra and Raw. Generators (Task 10) must DROP Extra and never emit Raw —
// only the explicit, validated fields below are safe to output.
type Node struct {
	Protocol   Scheme            // URI scheme (vmess/vless/trojan/ss/hysteria2/tuic/wireguard)
	Host       string            // server hostname or IP
	Port       int               // server port
	Security   string            // transport security mode, e.g. "tls"/"reality"/"none"
	Encryption string            // inner encryption, e.g. vmess aes-128-gcm or ss method
	Flow       string            // vless flow, e.g. "xtls-rprx-vision" (reality)
	Network    string            // transport type, e.g. "tcp"/"ws"/"grpc"/"mkcp"/"xhttp"
	User       string            // uuid / username / password
	Extra      map[string]string // non-mapped fields; DROPPED at generation (security)
	Plugin     string            // SS plugin; rejected by DropMalware (injection surface) — only bare AEAD SS kept
	Name       string            // human-friendly node name
	Raw        string            // original URI (quarantined, never emitted)
	Source     string            // source URL/id the node came from
	Country    string            // resolved ISO country code (geo); used in output naming, empty => "XX"
}
