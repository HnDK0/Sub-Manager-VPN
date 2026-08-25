package selector

import (
	"encoding/base64"
	"strings"
	"testing"

	"vpn-sub-manager/internal/model"
)

// TestV2RayNSanitizesInsecureSecurity proves the generators never emit
// security=none / tls=none even if a malformed node reaches them. Filters drop
// such nodes upstream; this is defense-in-depth.
func TestV2RayNSanitizesInsecureSecurity(t *testing.T) {
	cases := []model.Node{
		{Protocol: model.SchemeVMess, Name: "vm", Host: "h", Port: 443, User: "u", Security: "none"},
		{Protocol: model.SchemeVLESS, Name: "vl", Host: "h", Port: 443, User: "u", Security: "none"},
		{Protocol: model.SchemeTrojan, Name: "tr", Host: "h", Port: 443, User: "u", Security: "none"},
		{Protocol: model.SchemeHysteria2, Name: "h2", Host: "h", Port: 443, User: "u", Security: "none"},
		{Protocol: model.SchemeTUIC, Name: "tu", Host: "h", Port: 443, User: "u", Security: "none"},
	}
	for _, n := range cases {
		uri, err := nodeURI(n, nodeNames([]model.Node{n})[0])
		if err != nil {
			t.Fatalf("nodeURI(%s): %v", n.Protocol, err)
		}
		if n.Protocol == model.SchemeVMess {
			dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "vmess://"))
			if err != nil {
				t.Fatalf("vmess decode: %v", err)
			}
			if strings.Contains(string(dec), `"tls":"none"`) {
				t.Fatalf("vmess emitted insecure tls: %s", dec)
			}
		} else if strings.Contains(uri, "security=none") {
			t.Fatalf("%s emitted insecure security: %s", n.Protocol, uri)
		}
	}

	// Secure values are preserved.
	vl := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "tls"}
	if uri, _ := nodeURI(vl, nodeNames([]model.Node{vl})[0]); !strings.Contains(uri, "security=tls") {
		t.Fatalf("vless tls not preserved: %s", uri)
	}
	vm := model.Node{Protocol: model.SchemeVMess, Host: "h", Port: 443, User: "u", Security: "tls"}
	vmURI, _ := nodeURI(vm, nodeNames([]model.Node{vm})[0])
	dec, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(vmURI, "vmess://"))
	if !strings.Contains(string(dec), `"tls":"tls"`) {
		t.Fatalf("vmess tls not preserved: %s", dec)
	}
	rl := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "reality"}
	if uri, _ := nodeURI(rl, nodeNames([]model.Node{rl})[0]); !strings.Contains(uri, "security=reality") {
		t.Fatalf("vless reality not preserved: %s", uri)
	}
}
