package mihomo

import (
	"testing"

	"vpn-sub-manager/internal/model"
)

// TestBuildProxyYAMLTransports ensures every supported transport network
// (ws/grpc/xhttp/http/h2) gets its clash-meta transport opts block, with the
// path/host read from the whitelisted Node.Extra. Before the fix, applyTransport
// only handled ws/grpc, so xhttp/http/h2 nodes were pinged without their
// path/host and were wrongly marked dead.
func TestBuildProxyYAMLTransports(t *testing.T) {
	cases := []struct {
		net     string
		extra   map[string]string
		wantKey string
		wantPath string
		wantHost string
	}{
		{"ws", map[string]string{"path": "/w", "host": "ws.example.com"}, "ws-opts", "/w", "ws.example.com"},
		{"grpc", map[string]string{"serviceName": "svc"}, "grpc-opts", "", ""},
		{"xhttp", map[string]string{"path": "/x", "host": "x.example.com", "mode": "auto"}, "xhttp-opts", "/x", "x.example.com"},
		{"http", map[string]string{"path": "/p", "host": "h.example.com"}, "http-opts", "/p", "h.example.com"},
		{"h2", map[string]string{"path": "/p2", "host": "h2.example.com"}, "h2-opts", "/p2", "h2.example.com"},
	}
	for _, c := range cases {
		n := model.Node{
			Protocol: model.SchemeVLESS, Host: "1.2.3.4", Port: 443,
			Security: "tls", Network: c.net, User: "uuid", Extra: c.extra,
		}
		y := buildProxyYAML(n)
		if y["network"] != c.net {
			t.Fatalf("%s: network = %v, want %q", c.net, y["network"], c.net)
		}
		opts, ok := y[c.wantKey].(map[string]any)
		if !ok || opts == nil {
			t.Fatalf("%s: %s missing (got %v)", c.net, c.wantKey, y[c.wantKey])
		}
		if c.wantPath != "" {
			if opts["path"] != c.wantPath {
				t.Fatalf("%s: %s.path = %v, want %q", c.net, c.wantKey, opts["path"], c.wantPath)
			}
		}
		// host retrieval differs: xhttp uses a direct "host" field, others headers.Host.
		if c.wantHost != "" {
			if c.net == "xhttp" {
				if opts["host"] != c.wantHost {
					t.Fatalf("xhttp: host = %v, want %q", opts["host"], c.wantHost)
				}
			} else {
				hdr, _ := opts["headers"].(map[string]any)
				if hdr == nil || hdr["Host"] != c.wantHost {
					t.Fatalf("%s: headers.Host = %v, want %q", c.net, hdr["Host"], c.wantHost)
				}
			}
		}
	}
}
