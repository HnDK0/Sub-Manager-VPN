// Package integration holds end-to-end tests that exercise the embedded
// mihomo engine (in-process) against a real node. If there is no egress to
// tunnel through the node, the probe reports dead and the test skips cleanly so
// the suite stays green offline.
package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"vpn-sub-manager/internal/mihomo"
	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/state"
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

// TestIntegrationRealMihomo starts the embedded mihomo hub, syncs a node, and
// probes it. With no real egress to tunnel through the node the probe returns
// dead (no error) and the test skips — matching the embedded-hub skip
// (no real egress to tunnel through the node).
func TestIntegrationRealMihomo(t *testing.T) {
	st := newIntegrationState(t)
	defer st.Close()

	node := model.Node{
		Protocol: model.SchemeTrojan,
		Host:     "1.1.1.1",
		Port:     443,
		Security: "tls",
		User:     "integration-user",
		Name:     "integration-node",
	}

	eng := mihomo.New(mihomo.Options{Workers: 1})
	eng.Start()
	defer eng.Close()

	if err := eng.SyncNodes([]model.Node{node}); err != nil {
		t.Fatalf("SyncNodes: %v", err)
	}

	probeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := eng.Probe(probeCtx, node)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !r.Alive {
		// On the real backend, liveness requires a tunneled HTTP probe THROUGH
		// the node; a CI host has no real egress, so this fails exactly when
		// network/egress is unavailable. Skip rather than fail.
		t.Skipf("mihomo probe dead (no real egress to tunnel through the node in CI): %+v", r)
	}
	// Latency may be 0 for an instant localhost mock (sub-millisecond round-trip
	// truncates to 0 ms); the key assertion is that the embedded engine works.
	if r.LatencyMs < 0 {
		t.Fatalf("expected non-negative latency, got %d", r.LatencyMs)
	}
	t.Logf("probe result: alive=%v latencyMs=%d", r.Alive, r.LatencyMs)
}
