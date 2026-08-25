package test

import (
	"fmt"

	"vpn-sub-manager/internal/model"
)

// nodeXrayOutbound builds an xray outbound object that routes traffic THROUGH
// the given node, so probes measure real node→internet latency/speed instead of
// host→internet. It mirrors the field handling used by the v2rayN generator in
// internal/select and additionally reads the transport/reality parameters that
// the parser stores in Node.Extra (pbk/sid/fp/spx/sni/host/path/type) so that
// reality, tls and ws nodes can actually bind and tunnel. The five kept
// protocols are supported; an unsupported protocol yields a clear error so the
// node is skipped rather than mis-tested.
//
// Reading Node.Extra here is safe: it is our own parsed node (not a subscription
// output) and contains only benign transport/reality config (no exec/script).
func nodeXrayOutbound(n model.Node) (map[string]any, error) {
	network := n.Network
	if network == "" {
		network = "tcp"
	}
	transport := transportSettings(n, network)
	switch n.Protocol {
	case model.SchemeVLESS:
		user := map[string]any{"id": n.User, "encryption": "none", "level": 0}
		if n.Flow != "" {
			user["flow"] = n.Flow
		}
		return map[string]any{
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []map[string]any{
					{"address": n.Host, "port": n.Port, "users": []map[string]any{user}},
				},
			},
			"streamSettings": streamSettings(n, network, transport),
		}, nil
	case model.SchemeVMess:
		enc := n.Encryption
		if enc == "" {
			enc = "aes-128-gcm"
		}
		return map[string]any{
			"protocol": "vmess",
			"settings": map[string]any{
				"vnext": []map[string]any{
					{"address": n.Host, "port": n.Port, "users": []map[string]any{
						{"id": n.User, "security": enc, "level": 0},
					}},
				},
			},
			"streamSettings": streamSettings(n, network, transport),
		}, nil
	case model.SchemeTrojan:
		return map[string]any{
			"protocol": "trojan",
			"settings": map[string]any{
				"servers": []map[string]any{
					{"address": n.Host, "port": n.Port, "password": n.User, "level": 0},
				},
			},
			"streamSettings": streamSettings(n, network, transport),
		}, nil
	case model.SchemeHysteria2:
		return map[string]any{
			"protocol": "hysteria2",
			"settings": map[string]any{
				"servers": []map[string]any{
					{"address": n.Host, "port": n.Port, "password": n.User, "level": 0},
				},
			},
			"streamSettings": streamSettings(n, network, transport),
		}, nil
	case model.SchemeTUIC:
		return map[string]any{
			"protocol": "tuic",
			"settings": map[string]any{
				"servers": []map[string]any{
					{"address": n.Host, "port": n.Port, "uuid": n.User, "password": n.User, "level": 0},
				},
			},
			"streamSettings": streamSettings(n, network, transport),
		}, nil
	default:
		return nil, fmt.Errorf("test: unsupported protocol %q for node outbound", n.Protocol)
	}
}

// transportSettings returns the per-network transport block (ws/grpc) when the
// parser captured the needed parameters; nil for tcp.
func transportSettings(n model.Node, network string) map[string]any {
	switch network {
	case "ws":
		ws := map[string]any{}
		if p := n.Extra["path"]; p != "" {
			ws["path"] = p
		}
		if h := n.Extra["host"]; h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		if len(ws) == 0 {
			return nil
		}
		return ws
	case "grpc":
		if svc := n.Extra["serviceName"]; svc != "" {
			return map[string]any{"serviceName": svc}
		}
		return nil
	}
	return nil
}

// streamSettings builds the xray streamSettings. For "reality"/"tls" it emits the
// matching settings block built from Node.Extra (reality: pbk/sid/sni/fp/spx;
// tls: sni). Plaintext/"none" yields no security block (the filters reject
// insecure nodes upstream, so this is defense-in-depth).
func streamSettings(n model.Node, network string, transport map[string]any) map[string]any {
	ss := map[string]any{"network": network}
	if transport != nil {
		ss[network+"Settings"] = transport
	}
	switch n.Security {
	case "reality":
		rs := map[string]any{
			"show":         false,
			"publicKey":    n.Extra["pbk"],
			"shortId":      n.Extra["sid"],
			"serverName":   firstNonEmpty(n.Extra["sni"], n.Host),
			"fingerprint":  firstNonEmpty(n.Extra["fp"], "chrome"),
		}
		if spx := n.Extra["spx"]; spx != "" {
			rs["spiderX"] = spx
		}
		ss["security"] = "reality"
		ss["realitySettings"] = rs
		return ss
	case "tls":
		ts := map[string]any{}
		if sni := firstNonEmpty(n.Extra["sni"], n.Host); sni != "" {
			ts["serverName"] = sni
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = ts
		return ss
	}
	return ss
}

// firstNonEmpty returns the first non-empty string among vals.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
