package test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpn-sub-manager/internal/core"
	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/state"
)

// fakeSpawnPing returns a short-lived child process (ping) so the reaper test
// can prove it waits on and cleans up an exiting subprocess without any real
// xray binary or network.
func fakeSpawnPing(ctx context.Context, port int) (*exec.Cmd, error) {
	if runtime.GOOS == "windows" {
		return exec.Command("ping", "-n", "1", "127.0.0.1"), nil
	}
	return exec.Command("ping", "-c", "1", "127.0.0.1"), nil
}

// fakeListeners tracks in-process SOCKS5 servers started by fakeSpawnSOCKS so
// tests can close them.
var fakeListeners sync.Map

// fakeSpawnSOCKS starts a real (in-process) SOCKS5 server on the requested port
// and returns a long-lived dummy subprocess the engine can kill on Close. This
// lets RunBatch exercise the full pool + probe + persist path with no xray.
func fakeSpawnSOCKS(ctx context.Context, port int) (*exec.Cmd, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	fakeListeners.Store(port, l)
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
	// Small deterministic delay so the probe measures a non-zero latency.
	time.Sleep(time.Millisecond)
	// success reply: ver, rep=success, rsv, atyp=IPv4, 0.0.0.0:0
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	// Serve a minimal HTTP response so the HTTP-GET RTT / download probes
	// (which route through this proxy) succeed. Consume the client's HTTP
	// request, then reply 200 with a small body.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
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

// startFakeSOCKS5 starts an in-process SOCKS5 server on an ephemeral port and
// returns its address, registering cleanup on t.
func startFakeSOCKS5(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	fakeListeners.Store(port, l)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go handleFakeSOCKS(c)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func newTestState(t *testing.T) *state.State {
	t.Helper()
	st, err := state.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	return st
}

func newTestMgr(t *testing.T) *core.Manager {
	t.Helper()
	mgr, err := core.New(t.TempDir())
	if err != nil {
		t.Fatalf("core manager: %v", err)
	}
	return mgr
}

// TestPersistAndPrune verifies the classify/persist path writes a node, its
// result, and a history sample, and that state.Prune enforces retention. No
// xray or network is involved.
func TestPersistAndPrune(t *testing.T) {
	st := newTestState(t)
	defer st.Close()
	e := New(newTestMgr(t), st, Options{StartWorkers: false})
	defer e.Close()

	n := model.Node{Protocol: model.SchemeVMess, Host: "1.2.3.4", Port: 443, User: "u1"}
	r := Result{Alive: true, LatencyMs: 42, ProbeCount: 3}
	cycle := 1
	if err := e.persist(context.Background(), n, r, cycle); err != nil {
		t.Fatalf("persist: %v", err)
	}

	id, err := st.NodeID(nodeHash(n))
	if err != nil {
		t.Fatalf("node id: %v", err)
	}

	var rc, hc int
	if err := st.DB().QueryRow("SELECT count(*) FROM results WHERE node_id = ?", id).Scan(&rc); err != nil {
		t.Fatal(err)
	}
	if rc != 1 {
		t.Fatalf("want 1 result row, got %d", rc)
	}
	if err := st.DB().QueryRow("SELECT count(*) FROM history WHERE node_id = ?", id).Scan(&hc); err != nil {
		t.Fatal(err)
	}
	if hc != 1 {
		t.Fatalf("want 1 history row, got %d", hc)
	}

	// Add more history samples across cycles, then prune to keep only the last 1.
	for c := 2; c <= 4; c++ {
		if err := st.AddHistory(id, 10*c, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Prune(state.Retention{HistoryCycles: 1}, 4); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if err := st.DB().QueryRow("SELECT count(*) FROM history WHERE node_id = ?", id).Scan(&hc); err != nil {
		t.Fatal(err)
	}
	if hc != 1 {
		t.Fatalf("after prune want 1 history row, got %d", hc)
	}
}

// TestWorkerReaper proves the reaper waits on and reaps an exiting child
// process (a short-lived ping) so no zombie is left behind.
func TestWorkerReaper(t *testing.T) {
	st := newTestState(t)
	defer st.Close()
	e := New(newTestMgr(t), st, Options{StartWorkers: false, Spawn: fakeSpawnPing, Workers: 1})
	defer e.Close()

	w := e.newWorker(0)
	if err := w.ensureProxy(); err != nil {
		t.Fatalf("ensureProxy: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&w.reapCount) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if atomic.LoadInt32(&w.reapCount) == 0 {
		t.Fatal("reaper did not reap the exited child process")
	}
	w.mu.Lock()
	cmd := w.cmd
	w.mu.Unlock()
	if cmd != nil {
		t.Fatal("expected worker cmd to be cleared after reap")
	}
}

// TestProbeThroughFakeProxy exercises the real SOCKS5 client + aggregation by
// probing through an in-process fake SOCKS5 server. No xray, no network.
func TestProbeThroughFakeProxy(t *testing.T) {
	st := newTestState(t)
	defer st.Close()
	e := New(newTestMgr(t), st, Options{StartWorkers: false, Probes: 3, Timeout: 2 * time.Second, ProbeURL: "http://probe.invalid/generate_204", SpeedTestURL: "http://speed.invalid/10MB", SpeedTestTopN: 1})
	defer e.Close()

	addr := startFakeSOCKS5(t)
	n := model.Node{Protocol: model.SchemeVLESS, Host: "example.com", Port: 443, User: "u2"}
	r, err := e.probeThrough(addr, n, context.Background())
	if err != nil {
		t.Fatalf("probeThrough: %v", err)
	}
	if !r.Alive {
		t.Fatal("expected alive through fake proxy")
	}
	if r.ProbeCount != 3 {
		t.Fatalf("want 3 probes, got %d", r.ProbeCount)
	}
	if r.LatencyMs <= 0 {
		t.Fatalf("want positive latency, got %d", r.LatencyMs)
	}
}

// TestRunBatch exercises the full pool: workers run fake SOCKS5 backends, nodes
// are probed and persisted, and the batch prunes. No xray, no network.
func TestRunBatch(t *testing.T) {
	st := newTestState(t)
	defer st.Close()
	e := New(newTestMgr(t), st, Options{
		StartWorkers: true,
		Spawn:        fakeSpawnSOCKS,
		Workers:      2,
		Probes:       2,
		Timeout:      2 * time.Second,
		Retention:    state.Retention{HistoryCycles: 1},
		ProbeURL:     "http://probe.invalid/generate_204",
		SpeedTestURL: "http://speed.invalid/10MB",
		SpeedTestTopN: 1,
	})
	defer func() {
		fakeListeners.Range(func(_, v any) bool {
			v.(net.Listener).Close()
			return true
		})
		e.Close()
	}()

	nodes := []model.Node{
		{Protocol: model.SchemeTrojan, Host: "10.0.0.1", Port: 443, User: "a"},
		{Protocol: model.SchemeVLESS, Host: "10.0.0.2", Port: 443, User: "b", Security: "tls"},
	}
	if err := e.RunBatch(context.Background(), nodes); err != nil {
		t.Fatalf("RunBatch: %v", err)
	}

	var total int
	if err := st.DB().QueryRow("SELECT count(*) FROM results").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != len(nodes) {
		t.Fatalf("want %d result rows, got %d", len(nodes), total)
	}
}
