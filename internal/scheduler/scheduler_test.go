package scheduler

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpn-sub-manager/internal/config"
	"vpn-sub-manager/internal/geo"
	"vpn-sub-manager/internal/mihomo"
	"vpn-sub-manager/internal/model"
	selector "vpn-sub-manager/internal/select"
)

// TestMain swaps the production geo constructor for an offline variant so the
// whole package runs without network. The probe engine is injected per-test via
// SetEngine (a fake that records Close), so no mihomo subprocess is spawned.
func TestMain(m *testing.M) {
	geoNew = func(string) *geo.Manager { return &geo.Manager{} }
	os.Exit(m.Run())
}

// fakeEngine records Close so tests can assert the scheduler tears it down.
type fakeEngine struct {
	mu       sync.Mutex
	closed   bool
	lastSync []model.Node
}

func (f *fakeEngine) Probe(ctx context.Context, n model.Node) (mihomo.Result, error) {
	return mihomo.Result{}, nil
}

func (f *fakeEngine) Start() {}

func (f *fakeEngine) SyncNodes(nodes []model.Node) error {
	f.mu.Lock()
	f.lastSync = append([]model.Node(nil), nodes...)
	f.mu.Unlock()
	return nil
}

func (f *fakeEngine) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeEngine) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// withTestScheduler builds a Scheduler with a fake engine (recording Close) so
// no mihomo is spawned. The real engine is closed on cleanup.
func withTestScheduler(t *testing.T, cfg Config) (*Scheduler, *fakeEngine) {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	real := s.engine
	fake := &fakeEngine{}
	s.engine = fake
	t.Cleanup(func() { _ = real.Close() })
	return s, fake
}

func enabledSource(t *testing.T, s *Scheduler) {
	t.Helper()
	if _, err := s.reg.AddSource("https://example.com/sub"); err != nil {
		t.Fatalf("add source: %v", err)
	}
}

func TestRunTickerFires(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		StatePath:   filepath.Join(dir, "state.db"),
		SourcesPath: filepath.Join(dir, "sources.txt"),
		AssetsDir:   filepath.Join(dir, "assets"),
		OutDir:      filepath.Join(dir, "out"),
		Interval:    20 * time.Millisecond,
		TopN:        5,
		MinKeep:     1,
	}
	s, fake := withTestScheduler(t, cfg)
	enabledSource(t, s)

	var cycles int32
	cycleCh := make(chan struct{}, 16)
	s.FetchFn = func(ctx context.Context, src config.Source) ([]model.Node, error) {
		atomic.AddInt32(&cycles, 1)
		select {
		case cycleCh <- struct{}{}:
		default:
		}
		return []model.Node{
			{Protocol: model.SchemeVLESS, Host: "alive.example.com", Port: 443, User: "u1", Security: "tls"},
			{Protocol: model.SchemeVLESS, Host: "dead.example.com", Port: 443, User: "u2", Security: "tls"},
		}, nil
	}
	s.GeoFn = func(n model.Node) string { return "US" }
	s.ProbeFn = func(ctx context.Context, nodes []model.Node) (map[string]mihomo.Result, error) {
		out := make(map[string]mihomo.Result)
		for _, n := range nodes {
			out[nodeHash(&n)] = mihomo.Result{Alive: n.Host == "alive.example.com", LatencyMs: 10}
		}
		return out, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Wait for the ticker to actually drive a second cycle (deterministic: we
	// block on real cycle signals, not a fixed sleep, so a slow first Cycle on
	// a loaded machine can't cause a false failure).
	got := 0
	timeout := time.After(5 * time.Second)
	for got < 2 {
		select {
		case <-cycleCh:
			got++
		case <-timeout:
			t.Fatalf("expected at least 2 cycles within 5s, got %d", got)
		}
	}
	cancel()
	<-done

	if atomic.LoadInt32(&cycles) < 2 {
		t.Fatalf("expected at least 2 cycles, got %d", atomic.LoadInt32(&cycles))
	}
	if !fake.isClosed() {
		t.Fatalf("expected engine.Close to be called on Stop")
	}
}

func TestCyclePersists(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		StatePath:   filepath.Join(dir, "state.db"),
		SourcesPath: filepath.Join(dir, "sources.txt"),
		AssetsDir:   filepath.Join(dir, "assets"),
		OutDir:      filepath.Join(dir, "out"),
		TopN:        5,
		MinKeep:     1,
	}
	s, _ := withTestScheduler(t, cfg)
	enabledSource(t, s)
	defer s.Stop()

	s.FetchFn = func(ctx context.Context, src config.Source) ([]model.Node, error) {
		return []model.Node{
			{Protocol: model.SchemeVLESS, Host: "node-a.example.com", Port: 443, User: "u1", Security: "tls", Name: "A"},
			{Protocol: model.SchemeVLESS, Host: "node-b.example.com", Port: 443, User: "u2", Security: "tls", Name: "B"},
		}, nil
	}
	s.GeoFn = func(n model.Node) string { return "US" }
	s.ProbeFn = func(ctx context.Context, nodes []model.Node) (map[string]mihomo.Result, error) {
		out := make(map[string]mihomo.Result)
		for _, n := range nodes {
			h := nodeHash(&n)
			out[h] = mihomo.Result{Alive: true, LatencyMs: 10}
			// emulate defaultProbe: persist so cands (read from LatestResult) see them
			if id, e := s.st.NodeID(h); e == nil {
				_ = s.st.RecordResult(id, true, 10, 0, 1)
			}
		}
		return out, nil
	}

	if err := s.Cycle(context.Background()); err != nil {
		t.Fatalf("Cycle: %v", err)
	}

	for _, name := range []string{"singbox.json", "v2rayn.txt", "clash.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, "out", name)); err != nil {
			t.Fatalf("output %s missing: %v", name, err)
		}
	}

	sb, err := os.ReadFile(filepath.Join(dir, "out", "singbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sb), "node-a.example.com") || !strings.Contains(string(sb), "node-b.example.com") {
		t.Fatalf("singbox.json missing hosts: %s", sb)
	}

	cl, err := os.ReadFile(filepath.Join(dir, "out", "clash.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cl), "node-a.example.com") || !strings.Contains(string(cl), "node-b.example.com") {
		t.Fatalf("clash.yaml missing hosts: %s", cl)
	}

	vn, err := os.ReadFile(filepath.Join(dir, "out", "v2rayn.txt"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(vn)))
	if err != nil {
		t.Fatalf("v2rayn not base64: %v", err)
	}
	if !strings.Contains(string(dec), "node-a.example.com") || !strings.Contains(string(dec), "node-b.example.com") {
		t.Fatalf("v2rayn missing hosts: %s", dec)
	}

	var host string
	if err := s.st.DB().QueryRow("SELECT host FROM nodes WHERE host = ?", "node-a.example.com").Scan(&host); err != nil {
		t.Fatalf("node not in state: %v", err)
	}
	if host != "node-a.example.com" {
		t.Fatalf("unexpected host %q", host)
	}
}

func TestDegradeSwap(t *testing.T) {
	mk := func(host string, lat int) selector.Candidate {
		return selector.Candidate{
			Node:      model.Node{Protocol: model.SchemeVLESS, Host: host, Port: 443, User: "u", Security: "tls"},
			LatencyMs: lat,
			Country:   "US",
		}
	}
	cands := []selector.Candidate{
		mk("degraded.example.com", 1000),
		mk("ok1.example.com", 10),
		mk("ok2.example.com", 10),
		mk("better.example.com", 5),
		mk("better2.example.com", 5),
	}
	selected := []selector.Candidate{cands[0], cands[1], cands[2]}

	got := applyDegrade(selected, cands, 0)

	for _, n := range got {
		if n.Node.Host == "degraded.example.com" {
			t.Fatalf("degraded node still selected: %v", got)
		}
	}
	found := false
	for _, n := range got {
		if n.Node.Host == "better.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected swap to better.example.com, got %v", got)
	}
}

func TestDegradeNoSwapWhenHealthy(t *testing.T) {
	mk := func(host string, lat int) selector.Candidate {
		return selector.Candidate{
			Node:      model.Node{Protocol: model.SchemeVLESS, Host: host, Port: 443, User: "u", Security: "tls"},
			LatencyMs: lat,
			Country:   "US",
		}
	}
	cands := []selector.Candidate{mk("a.example.com", 10), mk("b.example.com", 10), mk("c.example.com", 10)}
	selected := []selector.Candidate{cands[0], cands[1], cands[2]}

	got := applyDegrade(selected, cands, 0)
	if len(got) != len(selected) {
		t.Fatalf("expected %d nodes, got %d", len(selected), len(got))
	}
	for i, n := range got {
		if n.Node.Host != selected[i].Node.Host {
			t.Fatalf("selection changed: got %v want %v", got, selected)
		}
	}
}

// TestCorpseStillProbed documents variant A: nodes dead for many consecutive
// cycles are still probed every cycle (no corpse-skipping), so the subscription
// pool can never silently starve. A fresh node and a long-dead node are both
// probed.
func TestCorpseStillProbed(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		StatePath:   filepath.Join(dir, "state.db"),
		SourcesPath: filepath.Join(dir, "sources.txt"),
		AssetsDir:   filepath.Join(dir, "assets"),
		OutDir:      filepath.Join(dir, "out"),
		TopN:        5,
		MinKeep:     1,
	}
	s, _ := withTestScheduler(t, cfg)
	enabledSource(t, s)
	defer s.Stop()

	corpse := model.Node{Protocol: model.SchemeVLESS, Host: "corpse.example.com", Port: 443, User: "u0", Security: "tls"}
	live := model.Node{Protocol: model.SchemeVLESS, Host: "live.example.com", Port: 443, User: "u1", Security: "tls"}

	// Seed the corpse into state with 5 consecutive dead results.
	hash := nodeHash(&corpse)
	if err := s.st.UpsertNode(&corpse, 0); err != nil {
		t.Fatalf("upsert corpse: %v", err)
	}
	id, err := s.st.NodeID(hash)
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	for i := 1; i <= 5; i++ {
		if err := s.st.RecordResult(id, false, 0, 0, i); err != nil {
			t.Fatalf("record dead: %v", err)
		}
	}

	var probed int32
	s.FetchFn = func(ctx context.Context, src config.Source) ([]model.Node, error) {
		return []model.Node{corpse, live}, nil
	}
	s.GeoFn = func(n model.Node) string { return "US" }
	s.ProbeFn = func(ctx context.Context, nodes []model.Node) (map[string]mihomo.Result, error) {
		for range nodes {
			atomic.AddInt32(&probed, 1)
		}
		out := make(map[string]mihomo.Result)
		for _, n := range nodes {
			out[nodeHash(&n)] = mihomo.Result{Alive: n.Host == "live.example.com", LatencyMs: 10}
		}
		return out, nil
	}

	if err := s.Cycle(context.Background()); err != nil {
		t.Fatalf("Cycle: %v", err)
	}

	if got := atomic.LoadInt32(&probed); got != 2 {
		t.Fatalf("expected both nodes probed (variant A: no corpse-skip), got %d probes", got)
	}
}

// TestDualPoolSeedAndReplace verifies the two core F4 invariants:
//  1. SeedSubscription populates out/ immediately (first-boot gap closed).
//  2. ReplaceRoutine hands the FULL union to SyncNodes, never a partial set
//     that would wipe other proxies (oracle CRITICAL).
func TestDualPoolSeedAndReplace(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		StatePath:   filepath.Join(dir, "state.db"),
		SourcesPath: filepath.Join(dir, "sources.txt"),
		AssetsDir:   filepath.Join(dir, "assets"),
		OutDir:      filepath.Join(dir, "out"),
		TopN:        5,
		SubTopN:     5,
		MinKeep:     1,
	}
	s, fake := withTestScheduler(t, cfg)
	enabledSource(t, s)
	defer s.Stop()

	s.FetchFn = func(ctx context.Context, src config.Source) ([]model.Node, error) {
		return []model.Node{
			{Protocol: model.SchemeVLESS, Host: "node-a.example.com", Port: 443, User: "u1", Security: "tls", Name: "A"},
			{Protocol: model.SchemeVLESS, Host: "node-b.example.com", Port: 443, User: "u2", Security: "tls", Name: "B"},
			{Protocol: model.SchemeVLESS, Host: "node-d.example.com", Port: 443, User: "u4", Security: "tls", Name: "D"},
			{Protocol: model.SchemeVLESS, Host: "node-c.example.com", Port: 443, User: "u3", Security: "tls", Name: "C"},
		}, nil
	}
	s.GeoFn = func(n model.Node) string {
		if n.Host == "node-c.example.com" {
			return "DE"
		}
		return "US"
	}
	s.ProbeFn = func(ctx context.Context, nodes []model.Node) (map[string]mihomo.Result, error) {
		out := make(map[string]mihomo.Result)
		for _, n := range nodes {
			h := nodeHash(&n)
			out[h] = mihomo.Result{Alive: true, LatencyMs: 10}
			// emulate defaultProbe: persist so cands (read from LatestResult) see them
			if id, e := s.st.NodeID(h); e == nil {
				_ = s.st.RecordResult(id, true, 10, 0, 1)
			}
		}
		return out, nil
	}

	if err := s.Cycle(context.Background()); err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	if err := s.SeedSubscription(); err != nil {
		t.Fatalf("SeedSubscription: %v", err)
	}

	// (1) first-boot populate: out/ must contain all seeded hosts.
	sb, err := os.ReadFile(filepath.Join(dir, "out", "singbox.json"))
	if err != nil {
		t.Fatalf("read singbox: %v", err)
	}
	for _, h := range []string{"node-a.example.com", "node-b.example.com", "node-c.example.com", "node-d.example.com"} {
		if !strings.Contains(string(sb), h) {
			t.Fatalf("singbox.json missing seeded host %s: %s", h, sb)
		}
	}

	// Pick a US subscription member to replace.
	subs, err := s.st.ListSubscription()
	if err != nil {
		t.Fatalf("list subscription: %v", err)
	}
	var deadHash string
	for _, r := range subs {
		n, e := s.st.NodeByHash(r.NodeID)
		if e == nil && n.Country == "US" {
			deadHash = r.NodeID
			break
		}
	}
	if deadHash == "" {
		t.Fatalf("no US subscription member found")
	}

	fake.mu.Lock()
	fake.lastSync = nil
	fake.mu.Unlock()

	if err := s.ReplaceRoutine(deadHash); err != nil {
		t.Fatalf("ReplaceRoutine: %v", err)
	}

	// (2) full-union non-wipe: SyncNodes must have received EVERY common node,
	// including node-d which is NOT a subscription member.
	fake.mu.Lock()
	got := append([]model.Node(nil), fake.lastSync...)
	fake.mu.Unlock()
	if len(got) == 0 {
		t.Fatalf("SyncNodes was never called by ReplaceRoutine")
	}
	hasD := false
	for _, n := range got {
		if n.Host == "node-d.example.com" {
			hasD = true
		}
	}
	if !hasD {
		hosts := make([]string, 0, len(got))
		for _, n := range got {
			hosts = append(hosts, n.Host)
		}
		t.Fatalf("ReplaceRoutine passed a PARTIAL set to SyncNodes (missing node-d); got %v", hosts)
	}
}
