package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"vpn-sub-manager/internal/config"
	"vpn-sub-manager/internal/mihomo"
	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/scheduler"
)

// fakeEngine is a no-op probe engine for wiring tests: no mihomo subprocess, no network.
type fakeEngine struct{}

func (fakeEngine) Start() {}

func (fakeEngine) Probe(ctx context.Context, n model.Node) (mihomo.Result, error) {
	return mihomo.Result{}, nil
}

func (fakeEngine) SyncNodes(nodes []model.Node) error { return nil }

func (fakeEngine) Close() error { return nil }

// TestRunWiringNoHang proves the wiring returns without hanging and does not
// leave a subprocess when the context is cancelled. It uses a pre-cancelled
// context and skipUI=true so the UI never blocks on a terminal, and overrides
// the scheduler's FetchFn/ProbeFn/GeoFn with nil-safe no-ops so NO network or
// mihomo runs. Because ProbeFn is a no-op, the engine never spawns a subprocess,
// so there is nothing to leak on shutdown.
func TestRunWiringNoHang(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		StatePath:   filepath.Join(dir, "state.db"),
		SourcesPath: filepath.Join(dir, "sources.txt"),
		AssetsDir:   filepath.Join(dir, "assets"),
		OutDir:      filepath.Join(dir, "out"),
		Interval:    30 * time.Minute,
		TopN:        5,
		DegradeMs:   0,
		MinKeep:     1,
	}
	schedCfg := scheduler.Config{
		StatePath:   cfg.StatePath,
		SourcesPath: cfg.SourcesPath,
		AssetsDir:   cfg.AssetsDir,
		OutDir:      cfg.OutDir,
		Interval:    cfg.Interval,
		TopN:        cfg.TopN,
		DegradeMs:   cfg.DegradeMs,
		MinKeep:     cfg.MinKeep,
	}

	sch, err := scheduler.New(schedCfg)
	if err != nil {
		t.Fatalf("scheduler.New: %v", err)
	}
	// Use a fake engine so no mihomo subprocess is spawned.
	sch.SetEngine(fakeEngine{})
	// Override with no-ops: zero network, zero mihomo.
	sch.FetchFn = func(ctx context.Context, src config.Source) ([]model.Node, error) {
		return nil, nil
	}
	sch.ProbeFn = func(ctx context.Context, nodes []model.Node) (map[string]mihomo.Result, error) {
		return nil, nil
	}
	sch.GeoFn = func(n model.Node) string { return "?" }

	// Pre-cancel so runInner skips the UI and goes straight to the
	// scheduler-wait shutdown path.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- runInner(ctx, cfg, sch, true, filepath.Join(dir, "config.json")) }()

	select {
	case err := <-done:
		// context.Canceled is the expected scheduler return on shutdown.
		t.Logf("runInner returned: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("runInner did not return within 2s (possible hang / zombie)")
	}
}
