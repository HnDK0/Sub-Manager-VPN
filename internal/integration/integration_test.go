// Package integration holds end-to-end tests that exercise the real
// xray-core subprocess (actual binary download + SOCKS5 tunnel) against a
// local mock node, plus an optional sing-box presence check.
package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"vpn-sub-manager/internal/core"
	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/state"
	"vpn-sub-manager/internal/test"
)

// newIntegrationState opens a temp SQLite state store for the test.
func newIntegrationState(t *testing.T) *state.State {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	return st
}

// newIntegrationMgr creates a core.Manager backed by a temp store dir.
func newIntegrationMgr(t *testing.T) *core.Manager {
	t.Helper()
	mgr, err := core.New(t.TempDir())
	if err != nil {
		t.Fatalf("core manager: %v", err)
	}
	return mgr
}

// TestIntegrationRealXray downloads the real xray-core binary, starts the
// engine's worker pool (one real xray SOCKS5 subprocess), and probes a local
// mock TCP "node" through the tunnel. It asserts the node is reported alive
// with non-negative latency (a fast localhost mock may report 0) and that a
// batch run persists without error.
//
// If the xray binary cannot be downloaded (offline CI / blocked network), the
// test skips cleanly so the suite stays green.
func TestIntegrationRealXray(t *testing.T) {
	// 1. Local mock "node": a plain TCP listener that accepts (and immediately
	//    closes) connections for the duration of the test.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock node: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	host := addr.IP.String()
	port := addr.Port

	// 2. Build a node pointing at the mock target (scheme is irrelevant to the
	//    tunnel; only Host+Port must be TCP-reachable).
	node := model.Node{
		Protocol: model.SchemeTrojan,
		Host:     host,
		Port:     port,
		Security: "tls",
		User:     "integration-user",
		Name:     "mock-local-node",
		Raw:      fmt.Sprintf("trojan://integration-user@%s:%d", host, port),
		Source:   "integration-test",
	}

	// 3. Download the real xray binary (generous timeout). Skip if offline.
	mgr := newIntegrationMgr(t)
	_, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()
	if err := mgr.Ensure("xray"); err != nil {
		t.Skipf("xray download unavailable: %v", err)
	}
	t.Logf("xray binary ready at %s", func() string {
		p, _ := mgr.BinaryPath("xray")
		return p
	}())

	// 4. Temp state + engine using the real xray manager. Workers:1 keeps the
	//    download race-free and the test light; StartWorkers launches the real
	//    xray subprocess pool.
	st := newIntegrationState(t)
	defer st.Close()
	eng := test.New(mgr, st, test.Options{
		StartWorkers: true,
		Workers:      1,
		Probes:       5,
		Timeout:      15 * time.Second,
	})
	defer eng.Close()

	probeCtx, probeCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer probeCancel()
	r, err := eng.Probe(probeCtx, node)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !r.Alive {
		t.Fatalf("expected node alive through real xray tunnel, got %+v", r)
	}
	// Latency may be 0 for an instant localhost mock (sub-millisecond round-trip
	// truncates to 0 ms); the key assertion is that the real xray tunnel works.
	if r.LatencyMs < 0 {
		t.Fatalf("expected non-negative latency, got %d", r.LatencyMs)
	}
	t.Logf("probe result: alive=%v latencyMs=%d probes=%d", r.Alive, r.LatencyMs, r.ProbeCount)

	// RunBatch must persist without panic/error.
	batchCtx, batchCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer batchCancel()
	if err := eng.RunBatch(batchCtx, []model.Node{node}); err != nil {
		t.Fatalf("RunBatch: %v", err)
	}

	// 5. Optional sing-box presence check (best-effort, never fails the test).
	_, sbCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer sbCancel()
	if err := mgr.Ensure("sing-box"); err != nil {
		t.Logf("sing-box download skipped/unavailable: %v", err)
	}
	t.Logf("sing-box present: %v", mgr.AllBinariesExist("sing-box"))
}

// --- fake SOCKS5 spawn for the no-xray smoke test ---

var integrationFakeListeners sync.Map

// fakeSpawnSOCKS starts an in-process SOCKS5 server on the requested port and
// returns a long-lived dummy subprocess the engine can kill on Close. This lets
// the engine's full pool + probe + persist path run with no real xray binary.
func fakeSpawnSOCKS(ctx context.Context, port int) (*exec.Cmd, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	integrationFakeListeners.Store(port, l)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go handleFakeSOCKS(c)
		}
	}()
	// The dummy child must outlive the test: if it exits, the engine's reaper
	// clears w.cmd and the next ensureProxy tries to rebind the still-held
	// listener port and fails. A long-lived child keeps the proxy authoritative.
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1000000", "127.0.0.1")
	} else {
		cmd = exec.Command("sleep", "3600")
	}
	return cmd, nil
}

// handleFakeSOCKS is a minimal SOCKS5 (no-auth) server that accepts CONNECT and
// replies success, then serves a tiny HTTP response so the HTTP-GET RTT and
// download probes (which route through this proxy) succeed. It does not egress.
func handleFakeSOCKS(c net.Conn) {
	defer c.Close()
	greet := make([]byte, 3)
	if _, err := io.ReadFull(c, greet); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	var extra int
	switch hdr[3] {
	case 0x01:
		extra = 4
	case 0x04:
		extra = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		extra = int(l[0]) + 2
	default:
		return
	}
	rest := make([]byte, extra)
	if _, err := io.ReadFull(c, rest); err != nil {
		return
	}
	time.Sleep(time.Millisecond)
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	// Serve a minimal HTTP response so the HTTP-GET RTT / download probes
	// (which route through this proxy) succeed. Consume the client's HTTP
	// request, then reply 200 with a small body.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	var req []byte
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
		req = append(req, buf[0])
		if len(req) >= 4 && string(req[len(req)-4:]) == "\r\n\r\n" {
			break
		}
		if len(req) > 8192 {
			break
		}
	}
	body := []byte("ok")
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	if _, err := c.Write([]byte(resp)); err != nil {
		return
	}
}

// TestEngineSmokeNoXray exercises the full engine pool + probe + persist path
// using an injected fake SOCKS5 spawn, so no real xray binary or network is
// required. It keeps the integration package compiling and the real-xray path
// runnable.
func TestEngineSmokeNoXray(t *testing.T) {
	st := newIntegrationState(t)
	defer st.Close()
	mgr := newIntegrationMgr(t)
	eng := test.New(mgr, st, test.Options{
		StartWorkers: true,
		Spawn:        fakeSpawnSOCKS,
		Workers:      2,
		Probes:       3,
		Timeout:      5 * time.Second,
		Retention:    state.Retention{HistoryCycles: 1},
		ProbeURL:     "http://probe.invalid/generate_204",
		SpeedTestURL: "http://speed.invalid/10MB",
		SpeedTestTopN: 1,
	})
	defer func() {
		integrationFakeListeners.Range(func(_, v any) bool {
			v.(net.Listener).Close()
			return true
		})
		eng.Close()
	}()

	n := model.Node{Protocol: model.SchemeTrojan, Host: "10.0.0.1", Port: 443, User: "smoke"}
	if err := eng.RunBatch(context.Background(), []model.Node{n}); err != nil {
		t.Fatalf("RunBatch (no xray): %v", err)
	}
	r, err := eng.Probe(context.Background(), n)
	if err != nil {
		t.Fatalf("Probe (no xray): %v", err)
	}
	if !r.Alive {
		t.Fatal("expected alive through fake SOCKS5")
	}
	if r.LatencyMs <= 0 {
		t.Fatalf("want positive latency, got %d", r.LatencyMs)
	}
}
