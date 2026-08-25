// Package scheduler orchestrates the full 24/7 refresh pipeline for
// vpn-sub-manager: it loads enabled sources, fetches/parses/filters them,
// resolves geo, upserts into state, probes latency, selects the best nodes per
// country, swaps out degraded nodes, and persists the three subscription
// outputs (sing-box / v2rayN / Clash.Meta) to disk.
//
// It is driven entirely in-process via time.Ticker (no external cron). Every
// external dependency (fetch, probe, geo) is reachable through an injectable
// function field so the whole cycle is unit-testable without network or xray.
package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"vpn-sub-manager/internal/config"
	"vpn-sub-manager/internal/core"
	"vpn-sub-manager/internal/fetch"
	"vpn-sub-manager/internal/filter"
	"vpn-sub-manager/internal/geo"
	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/parse"
	selector "vpn-sub-manager/internal/select"
	"vpn-sub-manager/internal/state"
	"vpn-sub-manager/internal/test"
)

// Config configures a Scheduler. Zero values for Interval/TopN/DegradeMs fall
// back to sane defaults in New.
type Config struct {
	StatePath   string
	SourcesPath string // plain-text sources whitelist (separate from state DB)
	AssetsDir   string
	CoreDir     string
	OutDir      string

	Interval  time.Duration
	TopN      int
	DegradeMs int
	MinKeep   int
	// CorpseCycles is the number of consecutive dead cycles after which a node
	// is treated as a corpse and skipped on the next ping to save budget. Zero
	// defaults to 5; a non-positive value disables corpse-skipping entirely.
	CorpseCycles int
	// ProbeURL is fetched (HTTP GET) through the proxy egress to measure real
	// RTT. Empty uses the engine default (gstatic generate_204).
	ProbeURL string
	// SpeedTestURL is downloaded through the proxy egress to measure throughput.
	// Empty disables speed measurement.
	SpeedTestURL string
	// MinSpeedMbps, when > 0, is the throughput floor for the speed brake:
	// nodes slower than this are dropped from selection.
	MinSpeedMbps int
	// SpeedTestTopN caps how many MB are downloaded for the speed sample.
	SpeedTestTopN int
	// IsBanned reports whether a node hash is banned and must be excluded from
	// selection (so it never reaches a subscription). Nil disables banning.
	IsBanned func(hash string) bool
}

// ProbeEngine is the subset of the test engine the scheduler depends on. It is
// an interface (not the concrete type) so tests can supply a fake that records
// Close without spawning xray or downloading cores. Start launches the worker
// pool (a no-op for fakes).
type ProbeEngine interface {
	Start()
	Probe(ctx context.Context, n model.Node) (test.Result, error)
	Close() error
}

// Phase enumerates the pipeline stages surfaced to the TUI as live progress.
type Phase int

const (
	PhaseIdle Phase = iota
	PhaseFetch
	PhaseGeo
	PhaseProbe
	PhaseSelect
	PhasePersist
	PhaseDone
)

func (p Phase) String() string {
	switch p {
	case PhaseFetch:
		return "fetch"
	case PhaseGeo:
		return "geo/upsert"
	case PhaseProbe:
		return "probe"
	case PhaseSelect:
		return "select"
	case PhasePersist:
		return "persist"
	case PhaseDone:
		return "idle"
	default:
		return "idle"
	}
}

// Snapshot is a point-in-time view of the scheduler, polled by the TUI to show
// live progress without starting anything itself.
type Snapshot struct {
	Running       bool
	Cycle         int
	Phase         Phase
	SourceTotal   int
	SourceDone    int
	NodesFetched  int
	NodesUpserted int
	NodesAlive    int
	StartedAt     time.Time
	LastCycleDur  time.Duration
	LastError     string

	// Filter-stage counters, populated during parseFetched. They are cumulative
	// across all sources within a single cycle.
	Parsed             int // nodes parsed before any filter pass
	DedupKept          int // nodes surviving Dedup
	DroppedUnsupported int // dropped by DropUnsupported
	DroppedInsecure    int // dropped by DropInsecure
	DroppedBroken      int // dropped by DropBroken
	DroppedMalware     int // dropped by DropMalware
	Kept               int // nodes surviving all filter passes

	// Probe-phase progress, populated during the probe stage.
	ProbeTotal int // nodes scheduled for probing this cycle
	ProbeDone  int // nodes whose probe has completed this cycle
}

// engineNew and geoNew are the production constructors, kept as package-level
// vars so tests can swap in offline/no-xray variants before calling New.
var (
	engineNew = func(mgr *core.Manager, st *state.State, opts test.Options) *test.Engine {
		return test.New(mgr, st, opts)
	}
	geoNew = geo.New
)

// Scheduler runs the refresh pipeline on a ticker.
type Scheduler struct {
	cfg Config
	st  *state.State
	mgr *core.Manager
	reg *config.Registry
	geo *geo.Manager

	engine    ProbeEngine
	fetcher   *fetch.Fetcher
	persister *selector.Persister

	// Injectable function fields. Defaults wire the real implementations;
	// tests replace them with deterministic fakes.
	FetchFn func(ctx context.Context, src config.Source) ([]model.Node, error)
	ProbeFn func(ctx context.Context, nodes []model.Node) (map[string]test.Result, error)
	GeoFn   func(n model.Node) string

	ctx    context.Context
	cancel context.CancelFunc

	ticker  *time.Ticker
	stopMu  sync.Mutex
	stopped bool

	statusMu sync.RWMutex
	status   Snapshot
	cycleReq chan struct{}

	// parseCache holds the last parsed nodes per source URL so an unchanged
	// source (304 or identical body hash) is reused without re-parsing. It is
	// in-memory only: on a cold start we re-fetch once and repopulate it.
	cacheMu    sync.Mutex
	parseCache map[string][]model.Node
}

// New builds a Scheduler: it opens state, creates the core manager, the test
// engine, the geo manager, and the output persister. Defaults: Interval 30m,
// TopN 5, DegradeMs 0 (only the 2x-median rule is used when 0).
func New(cfg Config) (*Scheduler, error) {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Minute
	}
	if cfg.TopN <= 0 {
		cfg.TopN = 5
	}
	if cfg.DegradeMs < 0 {
		cfg.DegradeMs = 0
	}
	if cfg.CorpseCycles == 0 {
		cfg.CorpseCycles = 5
	}

	st, err := state.Open(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("scheduler: open state: %w", err)
	}
	mgr, err := core.New(cfg.CoreDir)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("scheduler: core manager: %w", err)
	}
	reg, err := config.New(cfg.SourcesPath)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("scheduler: config registry: %w", err)
	}
	geoMgr := geoNew(cfg.AssetsDir)
	engine := engineNew(mgr, st, test.Options{
		ProbeURL:      cfg.ProbeURL,
		SpeedTestURL:  cfg.SpeedTestURL,
		MinSpeedMbps:  cfg.MinSpeedMbps,
		SpeedTestTopN: cfg.SpeedTestTopN,
	})

	persister := selector.NewPersister(cfg.OutDir, cfg.MinKeep)
	persister.Log = func(msg string) { log.Print(msg) }

	s := &Scheduler{
		cfg:       cfg,
		st:        st,
		mgr:       mgr,
		reg:       reg,
		geo:       geoMgr,
		engine:    engine,
		fetcher:   fetch.NewFetcher(reg),
		persister: persister,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.cycleReq = make(chan struct{}, 1)
	s.parseCache = make(map[string][]model.Node)
	s.status.Running = false

	s.FetchFn = s.defaultFetch
	s.ProbeFn = s.defaultProbe
	s.GeoFn = func(n model.Node) string {
		c, _ := geoMgr.ResolveCountry(&n)
		return c
	}
	return s, nil
}

// SetEngine replaces the probe engine. Tests use it to inject a fake that
// avoids spawning xray or downloading cores.
func (s *Scheduler) SetEngine(e ProbeEngine) {
	s.engine = e
}

// WithSpeed marks a context for on-demand throughput sampling. The background
// cycle never calls this, so automatic probes stay latency-only.
func (s *Scheduler) WithSpeed(ctx context.Context) context.Context {
	return test.WithSpeed(ctx)
}

// defaultFetch fetches, parses and filters one enabled source into nodes.
// To keep load minimal it reuses the prior parse when the source is unchanged:
// a conditional GET (ETag / Last-Modified) yields 304, or a matching body hash
// covers servers that send no validation headers. On a cold start (no cache)
// or for servers that always re-send, it falls back to a full fetch + parse.
func (s *Scheduler) defaultFetch(ctx context.Context, src config.Source) ([]model.Node, error) {
	baseMeta, haveMeta := s.st.GetSourceMeta(src.URL)
	if haveMeta && (baseMeta.ETag != "" || baseMeta.LastModified != "") {
		fetched, notMod, err := s.fetcher.FetchConditional(ctx, src, baseMeta.ETag, baseMeta.LastModified)
		if err != nil {
			return nil, err
		}
		if notMod {
			if cached, ok := s.cachedNodes(src.URL); ok {
				log.Printf("scheduler: %s unchanged (304), reusing %d nodes", src.URL, len(cached))
				return cached, nil
			}
			// 304 but nothing cached (process restarted) -> full fetch below.
		} else {
			// 200: maybe the body is identical despite no 304 (no ETag server).
			if haveMeta && baseMeta.BodySHA != "" && len(fetched) == 1 && !fetched[0].NotModified {
				if shaHex(fetched[0].Body) == baseMeta.BodySHA {
					if cached, ok := s.cachedNodes(src.URL); ok {
						log.Printf("scheduler: %s body unchanged, reusing %d nodes", src.URL, len(cached))
						return cached, nil
					}
				}
			}
			nodes := s.parseFetched(fetched)
			s.setCache(src.URL, nodes)
			s.st.SetSourceMeta(src.URL, sourceMetaFrom(fetched))
			return nodes, nil
		}
	}

	// No prior meta, 304 without cache, or a repo source: full fetch + parse.
	fetched, err := s.fetcher.Fetch(ctx, src)
	if err != nil {
		return nil, err
	}
	// Even without validation headers, skip the parse if the body is unchanged.
	if haveMeta && baseMeta.BodySHA != "" && len(fetched) == 1 {
		if shaHex(fetched[0].Body) == baseMeta.BodySHA {
			if cached, ok := s.cachedNodes(src.URL); ok {
				return cached, nil
			}
		}
	}
	nodes := s.parseFetched(fetched)
	s.setCache(src.URL, nodes)
	s.st.SetSourceMeta(src.URL, sourceMetaFrom(fetched))
	return nodes, nil
}

// parseFetched parses and filters every fetched body, skipping ones that fail
// so a single bad file does not abort the whole source. It also records the
// per-stage filter counters into the live snapshot (expanding filter.Apply
// inline so each pass can be measured without changing any signatures).
func (s *Scheduler) parseFetched(fetched []fetch.FetchedSource) []model.Node {
	var nodes []model.Node
	for _, fs := range fetched {
		if fs.NotModified {
			continue
		}
		parsed, err := parse.ParseSubscription(fs.Body)
		if err != nil {
			log.Printf("scheduler: parse %s failed: %v", fs.URL, err)
			continue
		}
		s.setStatus(func(st *Snapshot) { st.Parsed += len(parsed) })

		// ponytail: mirror filter.Apply's order (Dedup -> DropBroken ->
		// DropUnsupported -> DropOpen -> DropInsecure -> DropMalware) so each
		// drop count is measured; DropOpen has no counter field.
		cur := filter.Dedup(parsed)
		s.setStatus(func(st *Snapshot) { st.DedupKept += len(cur) })

		next := filter.DropBroken(cur)
		s.setStatus(func(st *Snapshot) { st.DroppedBroken += len(cur) - len(next) })
		cur = next

		next = filter.DropUnsupported(cur)
		s.setStatus(func(st *Snapshot) { st.DroppedUnsupported += len(cur) - len(next) })
		cur = next

		cur = filter.DropOpen(cur) // no counter field

		next = filter.DropInsecure(cur)
		s.setStatus(func(st *Snapshot) { st.DroppedInsecure += len(cur) - len(next) })
		cur = next

		next = filter.DropMalware(cur)
		s.setStatus(func(st *Snapshot) { st.DroppedMalware += len(cur) - len(next) })
		cur = next

		s.setStatus(func(st *Snapshot) { st.Kept += len(cur) })
		nodes = append(nodes, cur...)
	}
	return nodes
}

// cachedNodes returns the cached parse for url, if present.
func (s *Scheduler) cachedNodes(url string) ([]model.Node, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	n, ok := s.parseCache[url]
	return n, ok
}

// setCache stores the parsed nodes for url.
func (s *Scheduler) setCache(url string, nodes []model.Node) {
	s.cacheMu.Lock()
	s.parseCache[url] = nodes
	s.cacheMu.Unlock()
}

// shaHex returns the hex SHA-256 of b.
func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sourceMetaFrom derives the validation headers to persist from a fetch result
// (single-file sources only; repos are always re-fetched).
func sourceMetaFrom(fetched []fetch.FetchedSource) state.SourceMeta {
	if len(fetched) != 1 || fetched[0].NotModified {
		return state.SourceMeta{}
	}
	return state.SourceMeta{
		ETag:         fetched[0].ETag,
		LastModified: fetched[0].LastModified,
		BodySHA:      shaHex(fetched[0].Body),
	}
}

// defaultProbe probes every node through the engine and returns results keyed
// by node hash.
func (s *Scheduler) defaultProbe(ctx context.Context, nodes []model.Node) (map[string]test.Result, error) {
	s.setStatus(func(st *Snapshot) { st.ProbeTotal = len(nodes); st.ProbeDone = 0 })
	out := make(map[string]test.Result, len(nodes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n model.Node) {
			defer wg.Done()
			r, err := s.engine.Probe(ctx, n)
			if err != nil {
				// Infra failure (pool down / ctx cancelled): drop this node this
				// cycle instead of stalling the whole batch. ponytail: next cycle recovers it.
				return
			}
			mu.Lock()
			out[nodeHash(&n)] = r
			mu.Unlock()
			s.setStatus(func(st *Snapshot) { st.ProbeDone++ }) // ponytail: live probe progress for the UI
		}(n)
	}
	wg.Wait()
	return out, nil
}

// CachedNodes returns the union of all nodes currently held in the parse cache
// across every source. It is read-only and safe for concurrent use. Returns nil
// when the cache is empty.
func (s *Scheduler) CachedNodes() []model.Node {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	var out []model.Node
	for _, ns := range s.parseCache {
		out = append(out, ns...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ProbeNodes probes the given nodes through the configured ProbeFn and returns
// the results keyed exactly as ProbeFn produces them (no re-keying). It is a
// thin, exported wrapper so external callers (e.g. a web UI) can reuse the
// scheduler's probe path without touching internal fields.
func (s *Scheduler) ProbeNodes(ctx context.Context, nodes []model.Node) (map[string]test.Result, error) {
	return s.ProbeFn(ctx, nodes)
}

// filterCorpses drops nodes that have been dead for at least CorpseCycles
// consecutive cycles (corpses), so the scheduler stops wasting ping budget on
// nodes that are effectively gone. New nodes (no results yet) are always
// probed, and the threshold can be disabled via a non-positive CorpseCycles.
func (s *Scheduler) filterCorpses(nodes []model.Node) []model.Node {
	if s.cfg.CorpseCycles <= 0 {
		return nodes
	}
	out := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		id, err := s.st.NodeID(nodeHash(&n))
		if err != nil {
			// Unknown node — always probe it.
			out = append(out, n)
			continue
		}
		streak, err := s.st.ConsecutiveDead(id)
		if err != nil || streak < s.cfg.CorpseCycles {
			out = append(out, n)
			continue
		}
		log.Printf("scheduler: skipping corpse node %s:%d (dead %d cycles)", n.Host, n.Port, streak)
	}
	return out
}

// Run executes one Cycle immediately, then repeats on every ticker tick until
// ctx is cancelled. It always calls Stop on the way out.
func (s *Scheduler) Run(ctx context.Context) error {
	s.stopMu.Lock()
	s.ticker = time.NewTicker(s.cfg.Interval)
	s.stopped = false
	s.stopMu.Unlock()

	s.engine.Start()
	s.setStatus(func(st *Snapshot) { st.Running = true })

	if err := s.Cycle(ctx); err != nil {
		log.Printf("scheduler: initial cycle failed: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			s.Stop()
			return ctx.Err()
		case <-s.ctx.Done():
			s.Stop()
			return nil
		case <-s.cycleReq:
			if err := s.Cycle(ctx); err != nil {
				log.Printf("scheduler: manual cycle failed: %v", err)
			}
		case <-s.ticker.C:
			if err := s.Cycle(ctx); err != nil {
				log.Printf("scheduler: cycle failed: %v", err)
			}
		}
	}
}

// Status returns a point-in-time snapshot of the pipeline for the TUI.
func (s *Scheduler) Status() Snapshot {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.status
}

// setStatus mutates the live snapshot under the status lock.
func (s *Scheduler) setStatus(fn func(*Snapshot)) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	fn(&s.status)
}

// RequestCycle asks the scheduler to run a cycle immediately, bypassing the
// next ticker tick. Non-blocking and safe to call from the TUI.
func (s *Scheduler) RequestCycle() {
	select {
	case s.cycleReq <- struct{}{}:
	default:
	}
}

// Cycle runs the full pipeline once. It is safe to call directly (unit tests
// do exactly that).
func (s *Scheduler) Cycle(ctx context.Context) error {
	cycle, err := s.st.IncrementCycle()
	if err != nil {
		return fmt.Errorf("scheduler: increment cycle: %w", err)
	}

	sources, err := s.reg.EnabledSources()
	if err != nil {
		return fmt.Errorf("scheduler: enabled sources: %w", err)
	}

	start := time.Now()
	// ponytail: single status update per phase; TUI polls this snapshot.
	s.setStatus(func(st *Snapshot) {
		st.Cycle = cycle
		st.Phase = PhaseFetch
		st.SourceTotal = len(sources)
		st.SourceDone = 0
		st.NodesFetched = 0
		st.NodesUpserted = 0
		st.NodesAlive = 0
		st.Parsed = 0
		st.DedupKept = 0
		st.DroppedUnsupported = 0
		st.DroppedInsecure = 0
		st.DroppedBroken = 0
		st.DroppedMalware = 0
		st.Kept = 0
		st.StartedAt = start
		st.LastError = ""
	})

	var nodes []model.Node
	for _, src := range sources {
		fetched, err := s.FetchFn(ctx, src)
		if err != nil {
			// One bad source must not abort the whole cycle.
			log.Printf("scheduler: fetch source %s failed: %v", src.URL, err)
			s.setStatus(func(st *Snapshot) { st.SourceDone++ })
			continue
		}
		nodes = append(nodes, fetched...)
		s.setStatus(func(st *Snapshot) {
			st.SourceDone++
			st.NodesFetched += len(fetched)
		})
	}

	// Skip nodes dead for many consecutive cycles (corpses) to save ping budget.
	nodes = s.filterCorpses(nodes)

	// Geo-resolve + upsert each remaining node into state.
	s.setStatus(func(st *Snapshot) { st.Phase = PhaseGeo })
	type enriched struct {
		n       model.Node
		country string
		hash    string
	}
	var enrichedNodes []enriched
	upserted := 0
	for _, n := range nodes {
		country := s.GeoFn(n)
		n.Country = country
		hash := nodeHash(&n)
		if err := s.st.UpsertNodeWithCountry(n, country); err != nil {
			return fmt.Errorf("scheduler: upsert node: %w", err)
		}
		enrichedNodes = append(enrichedNodes, enriched{n: n, country: country, hash: hash})
		upserted++
		if upserted%500 == 0 {
			u := upserted
			s.setStatus(func(st *Snapshot) { st.NodesUpserted = u })
		}
	}
	s.setStatus(func(st *Snapshot) { st.NodesUpserted = upserted })

	// Probe batch.
	s.setStatus(func(st *Snapshot) { st.Phase = PhaseProbe })
	results, err := s.ProbeFn(ctx, nodes)
	if err != nil {
		return fmt.Errorf("scheduler: probe: %w", err)
	}

	// Persist probe results so history, retention pruning, and consecutive-dead
	// tracking stay accurate across cycles (a single engine.Probe does not write
	// to state on its own).
	for _, en := range enrichedNodes {
		r, ok := results[en.hash]
		if !ok {
			continue
		}
		id, err := s.st.NodeID(en.hash)
		if err != nil {
			continue
		}
		if err := s.st.RecordResult(id, r.Alive, int(r.LatencyMs), int(r.SpeedKbps), cycle); err != nil {
			log.Printf("scheduler: record result: %v", err)
		}
		if err := s.st.AddHistory(id, int(r.LatencyMs), cycle); err != nil {
			log.Printf("scheduler: add history: %v", err)
		}
	}

	// Enforce bounded retention so results/history/nodes don't grow unbounded
	// under continuous 24/7 operation. A prune error must not abort the cycle.
	if err := s.st.Prune(state.DefaultRetention(), cycle); err != nil {
		log.Printf("[scheduler] prune: %v", err)
	}

	// Build candidates from alive nodes only. Banned nodes are dropped here so
	// they can never reach a generated subscription. The min-speed brake drops
	// nodes whose measured throughput is below the configured floor.
	var cands []selector.Candidate
	floorKbps := s.cfg.MinSpeedMbps * 1000
	for _, en := range enrichedNodes {
		r, ok := results[en.hash]
		if !ok || !r.Alive {
			continue
		}
		if s.cfg.IsBanned != nil && s.cfg.IsBanned(en.hash) {
			continue
		}
		if floorKbps > 0 && r.SpeedKbps < int64(floorKbps) {
			continue
		}
		cands = append(cands, selector.Candidate{
			Node:      en.n,
			LatencyMs: int(r.LatencyMs),
			Country:   en.country,
		})
	}

	s.setStatus(func(st *Snapshot) {
		st.NodesAlive = len(cands)
		st.Phase = PhaseSelect
	})
	selected := selector.Select(cands, s.cfg.TopN)
	selected = applyDegrade(selected, cands, s.cfg.DegradeMs)

	s.setStatus(func(st *Snapshot) { st.Phase = PhasePersist })
	if err := s.persister.Persist(selected); err != nil {
		return fmt.Errorf("scheduler: persist: %w", err)
	}

	log.Printf("scheduler: cycle %d done: %d sources, %d nodes, %d selected",
		cycle, len(sources), len(nodes), len(selected))
	s.setStatus(func(st *Snapshot) {
		st.Phase = PhaseDone
		st.LastCycleDur = time.Since(start)
	})
	return nil
}

// Stop cleanly shuts the scheduler down: it cancels the internal context,
// stops the ticker, and closes the test engine (killing any xray subprocess)
// and the geo manager. It is safe to call multiple times and before Run.
func (s *Scheduler) Stop() {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	s.setStatus(func(st *Snapshot) { st.Running = false })

	if s.cancel != nil {
		s.cancel()
	}
	if s.ticker != nil {
		s.ticker.Stop()
	}
	if s.engine != nil {
		_ = s.engine.Close()
	}
	if s.geo != nil {
		_ = s.geo.Close()
	}
	if s.st != nil {
		_ = s.st.Close()
	}
}

// nodeHash replicates state.nodeHash (sha256 of
// protocol|host|port|user|security|encryption) so the scheduler can key probe
// results and lookups without modifying state. Keep in sync with internal/state.
func nodeHash(n *model.Node) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|%s|%s", n.Protocol, n.Host, n.Port, n.User, n.Security, n.Encryption)))
	return hex.EncodeToString(sum[:])
}
