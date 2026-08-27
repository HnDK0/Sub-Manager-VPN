// Package scheduler orchestrates the full 24/7 refresh pipeline for
// vpn-sub-manager: it loads enabled sources, fetches/parses/filters them,
// resolves geo, upserts into state, probes latency, selects the best nodes per
// country, swaps out degraded nodes, and persists the three subscription
// outputs (sing-box / v2rayN / Clash.Meta) to disk.
//
// It is driven entirely in-process via time.Ticker (no external cron). Every
// external dependency (fetch, probe, geo) is reachable through an injectable
// function field so the whole cycle is unit-testable without network or
// spawning the embedded hub.
package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"vpn-sub-manager/internal/config"
	"vpn-sub-manager/internal/fetch"
	"vpn-sub-manager/internal/filter"
	"vpn-sub-manager/internal/geo"
	"vpn-sub-manager/internal/mihomo"
	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/parse"
	selector "vpn-sub-manager/internal/select"
	"vpn-sub-manager/internal/state"
)

// Config configures a Scheduler. Zero values for Interval/TopN/DegradeMs fall
// back to sane defaults in New.
type Config struct {
	StatePath   string
	SourcesPath string // plain-text sources whitelist (separate from state DB)
	AssetsDir   string
	OutDir      string

	Interval  time.Duration
	TopN      int
	DegradeMs int
	MinKeep   int
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
	// ExcludeCountries holds 2-letter ISO codes whose nodes are dropped from
	// selection (e.g. a user in RU typically does not want RU exit nodes).
	ExcludeCountries []string
	// ExcludeProtocols holds scheme strings (vmess/vless/trojan/hysteria2/tuic)
	// whose nodes are skipped entirely (no probe, never selected).
	ExcludeProtocols []string
	// Workers is the in-process probe-concurrency semaphore: it bounds
	// concurrent Latency/Speed calls inside the embedded mihomo engine.
	// Clamped to [16, 512]; 0 defaults to 350. Bounded — never unbounded.
	Workers int
	// ProbeTimeoutMs bounds each URLTest (ms); 0 defaults to 2000 inside engine.
	ProbeTimeoutMs int
	// MaxPingMs drops nodes with latency above this from the subscription
	// membership (0 = no cap). Applied at reconcile so only good-ping VPNs
	// reach the served subscription.
	MaxPingMs int

	// SubValidityInterval drives the SubValidity timer: aliveness (latency) of
	// each subscription member. 0 defaults to 5m.
	SubValidityInterval time.Duration
	// SubPingInterval drives the SubPing timer: latency refresh for labels/
	// ordering of subscription members. 0 defaults to 30m.
	SubPingInterval time.Duration
	// SubTopN caps subscription output members per country. 0 defaults to TopN.
	SubTopN int

	// IsBanned reports whether a node hash is banned and must be excluded from
	// selection (so it never reaches a subscription). Nil disables banning.
	IsBanned func(hash string) bool
}

// ProbeEngine is the subset of the embedded mihomo engine the scheduler depends
// on. It is an interface (not the concrete type) so tests can supply a fake
// that records Close without spawning the embedded hub or downloading cores.
// Start launches
// the embedded hub (a no-op for fakes).
type ProbeEngine interface {
	Start()
	SyncNodes(nodes []model.Node) error
	Probe(ctx context.Context, n model.Node) (mihomo.Result, error)
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
	AliveCount int // nodes whose probe returned alive this cycle
	DeadCount  int // nodes whose probe returned dead this cycle

	// Geo-phase progress, populated during the geo/upsert stage.
	NodesGeoTotal int // nodes scheduled for geo resolution this cycle
	NodesGeoDone  int // nodes whose geo resolution completed this cycle
}

// engineNew and geoNew are the production constructors, kept as package-level
// vars so tests can swap in offline/no-core variants before calling New.
var (
	engineNew = func(opts mihomo.Options) *mihomo.Controller {
		return mihomo.New(opts)
	}
	geoNew = geo.New
)

// Scheduler runs the refresh pipeline on a ticker.
type Scheduler struct {
	cfg Config
	st  *state.State
	reg *config.Registry
	geo *geo.Manager

	engine    ProbeEngine
	fetcher   *fetch.Fetcher
	persister *selector.Persister

	// Injectable function fields. Defaults wire the real implementations;
	// tests replace them with deterministic fakes.
	FetchFn func(ctx context.Context, src config.Source) ([]model.Node, error)
	ProbeFn func(ctx context.Context, nodes []model.Node) (map[string]mihomo.Result, error)
	GeoFn   func(n model.Node) string

	// curCycle is the cycle number of the currently running cycle. defaultProbe
	// reads it to tag live result rows as they are persisted during the probe.
	curCycle int

	ctx    context.Context
	cancel context.CancelFunc

	// cycleCtx is the context for the currently running cycle, separate from
	// the shutdown context (s.ctx). StopCycle cancels it to abort the running
	// cycle without tearing down the process or the ticker.
	cycleMu     sync.Mutex
	cycleCtx    context.Context
	cycleCancel context.CancelFunc

	// Three timers, each with its own derived context + WaitGroup so Stop can
	// wait for all of them cleanly.
	commonTimer *time.Ticker
	validTimer  *time.Ticker
	pingTimer   *time.Ticker
	timerWG     sync.WaitGroup
	stopMu      sync.Mutex
	stopped     bool

	statusMu sync.RWMutex
	status   Snapshot
	cycleReq chan struct{}

	// parseCache holds the last parsed nodes per source URL so an unchanged
	// source (304 or identical body hash) is reused without re-parsing. It is
	// in-memory only: on a cold start we re-fetch once and repopulate it.
	cacheMu    sync.Mutex
	parseCache map[string][]model.Node
}

// New builds a Scheduler: it opens state, creates the embedded mihomo engine,
// the geo manager, and the output persister. Defaults: Interval 2h, TopN 5,
// DegradeMs 0 (only the 2x-median rule is used when 0).
func New(cfg Config) (*Scheduler, error) {
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Hour
	}
	if cfg.TopN <= 0 {
		cfg.TopN = 5
	}
	if cfg.DegradeMs < 0 {
		cfg.DegradeMs = 0
	}
	if cfg.Workers <= 0 || cfg.Workers < 16 {
		cfg.Workers = 350
	}
	if cfg.Workers > 512 {
		cfg.Workers = 512
	}
	if cfg.SubValidityInterval <= 0 {
		cfg.SubValidityInterval = 5 * time.Minute
	}
	if cfg.SubPingInterval <= 0 {
		cfg.SubPingInterval = 30 * time.Minute
	}
	if cfg.SubTopN <= 0 {
		cfg.SubTopN = cfg.TopN
	}

	st, err := state.Open(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("scheduler: open state: %w", err)
	}
	reg, err := config.New(cfg.SourcesPath)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("scheduler: config registry: %w", err)
	}
	geoMgr := geoNew(cfg.AssetsDir)
	engine := engineNew(mihomo.Options{
		ProbeURL:       cfg.ProbeURL,
		SpeedTestURL:   cfg.SpeedTestURL,
		MinSpeedMbps:   cfg.MinSpeedMbps,
		SpeedTestTopN:  cfg.SpeedTestTopN,
		Workers:        cfg.Workers,
		ProbeTimeoutMs: cfg.ProbeTimeoutMs,
	})

	persister := selector.NewPersister(cfg.OutDir, cfg.MinKeep)
	persister.Log = func(msg string) { log.Print(msg) }

	s := &Scheduler{
		cfg:       cfg,
		st:        st,
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
// avoids spawning the embedded hub or downloading cores.
func (s *Scheduler) SetEngine(e ProbeEngine) {
	s.engine = e
}

// WithSpeed marks a context for on-demand throughput sampling. The background
// cycle never calls this, so automatic probes stay latency-only.
func (s *Scheduler) WithSpeed(ctx context.Context) context.Context {
	return mihomo.WithSpeed(ctx)
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
func (s *Scheduler) defaultProbe(ctx context.Context, nodes []model.Node) (map[string]mihomo.Result, error) {
	s.setStatus(func(st *Snapshot) { st.ProbeTotal = len(nodes); st.ProbeDone = 0 })
	out := make(map[string]mihomo.Result, len(nodes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	// Honor -workers: bound concurrent probes through the engine. The embedded
	// mihomo hub parallelizes URLTest, so this is the real concurrency knob.
	workers := s.cfg.Workers
	// Mirror engine.New's clamp: a stale persisted `workers` (e.g. the old
	// default 4 written to config.json on first run) must not silently kneecap
	// concurrency. Anything below 16 is treated as "use the 350 default";
	// above 512 is capped to the RAM/network-safe ceiling.
	if workers < 16 || workers > 512 {
		workers = 350
	}
	log.Printf("scheduler: probe concurrency = %d (cfg.Workers=%d)", workers, s.cfg.Workers)
	sem := make(chan struct{}, workers)
	for _, n := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(n model.Node) {
			defer wg.Done()
			defer func() { <-sem }()
			r, err := s.engine.Probe(ctx, n)
			if err != nil {
				// Infra failure (pool down): drop this node this cycle instead
				// of stalling the whole batch. ponytail: next cycle recovers it.
				return
			}
			// ponytail: a cancelled cycle must not advance the progress counter
			// or record aborted probes — only nodes that actually finished before
			// StopCycle are counted/kept; the rest stay unrecorded.
			if ctx.Err() != nil {
				return
			}
			mu.Lock()
			out[nodeHash(&n)] = r
			// ponytail: live pool update — persist each result as it finishes so
			// the Nodes table (nodeViews joins the latest results row) refreshes
			// row-by-row during the probe instead of only at cycle end.
			if id, derr := s.st.NodeID(nodeHash(&n)); derr == nil {
				_ = s.st.RecordResult(id, r.Alive, int(r.LatencyMs), int(r.SpeedKbps), s.curCycle)
				_ = s.st.AddHistory(id, int(r.LatencyMs), s.curCycle)
			}
			mu.Unlock()
			s.setStatus(func(st *Snapshot) {
				st.ProbeDone++ // ponytail: live probe progress for the UI
				if r.Alive {
					st.AliveCount++
				} else {
					st.DeadCount++
				}
			})
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
func (s *Scheduler) ProbeNodes(ctx context.Context, nodes []model.Node) (map[string]mihomo.Result, error) {
	return s.ProbeFn(ctx, nodes)
}

// Run executes one Cycle immediately, then repeats on three independent timers
// until ctx is cancelled: CommonScan (Interval), SubValidity (SubValidityInterval),
// and SubPing (SubPingInterval). It always calls Stop on the way out.
func (s *Scheduler) Run(ctx context.Context) error {
	s.stopMu.Lock()
	s.commonTimer = time.NewTicker(s.cfg.Interval)
	s.validTimer = time.NewTicker(s.cfg.SubValidityInterval)
	s.pingTimer = time.NewTicker(s.cfg.SubPingInterval)
	s.stopped = false
	s.stopMu.Unlock()

	s.engine.Start()
	s.setStatus(func(st *Snapshot) { st.Running = true })

	// FIX A: boot rehydration — load every persisted common node into the engine
	// and rebuild out/ from the persisted subscription table on EVERY start, so a
	// restart does not lose progress (valid nodes / served files). Runs before the
	// grace-skip below because the in-memory engine and out/ are lost on restart.
	if all, err := s.fullUnion(nil); err == nil && len(all) > 0 {
		if err := s.engine.SyncNodes(all); err != nil {
			log.Printf("scheduler: boot sync nodes: %v", err)
		}
	}
	if err := s.regenerateSubs(); err != nil {
		log.Printf("scheduler: boot regenerate subs: %v", err)
	}

	// Skip the immediate startup cycle if a successful cycle completed recently
	// (within the interval, or 1h if interval is zero). Avoids redundant work
	// right after a restart.
	grace := s.cfg.Interval
	if grace <= 0 {
		grace = time.Hour
	}
	if last, ok, err := s.st.LastSuccess(); err == nil && ok && time.Since(last) < grace {
		log.Printf("scheduler: skipping immediate startup cycle (last successful %v ago, within %v)", time.Since(last), grace)
	} else {
		if err := s.Cycle(ctx); err != nil {
			log.Printf("scheduler: initial cycle failed: %v", err)
		}
	}

	// SubValidity timer: aliveness of each subscription member.
	s.timerWG.Add(1)
	go func() {
		defer s.timerWG.Done()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-s.validTimer.C:
				if err := s.SubValidity(s.ctx); err != nil {
					log.Printf("scheduler: sub-validity failed: %v", err)
				}
			}
		}
	}()
	// SubPing timer: latency refresh for labels/ordering.
	s.timerWG.Add(1)
	go func() {
		defer s.timerWG.Done()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-s.pingTimer.C:
				if err := s.SubPing(s.ctx); err != nil {
					log.Printf("scheduler: sub-ping failed: %v", err)
				}
			}
		}
	}()

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
		case <-s.commonTimer.C:
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

// StopCycle cancels the currently running cycle's context so the cycle function
// returns early (it checks cycleCtx.Err() and bails cleanly). It does NOT shut
// down the process or the ticker — only the in-flight cycle is aborted. Safe to
// call when no cycle is running (it is a no-op then).
func (s *Scheduler) StopCycle() {
	s.cycleMu.Lock()
	defer s.cycleMu.Unlock()
	if s.cycleCancel != nil {
		s.cycleCancel()
	}
}

// Cycle runs the full pipeline once. It is safe to call directly (unit tests
// do exactly that). The cycle runs under a dedicated cycleCtx (a child of the
// passed ctx) so it can be aborted independently via StopCycle without killing
// the process or the ticker.
func (s *Scheduler) Cycle(ctx context.Context) error {
	// ponytail: derive a fresh, cancellable context per cycle so StopCycle can
	// abort just this cycle. cycleCtx is a child of ctx, so cancelling it never
	// cancels the shutdown context.
	s.cycleMu.Lock()
	s.cycleCtx, s.cycleCancel = context.WithCancel(ctx)
	cctx := s.cycleCtx
	s.cycleMu.Unlock()
	defer func() {
		s.cycleMu.Lock()
		if s.cycleCancel != nil {
			s.cycleCancel()
			s.cycleCancel = nil
		}
		s.cycleMu.Unlock()
	}()

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
		st.AliveCount = 0
		st.DeadCount = 0
		st.NodesGeoTotal = 0
		st.NodesGeoDone = 0
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
	s.curCycle = cycle

	var nodes []model.Node
	for _, src := range sources {
		fetched, err := s.FetchFn(cctx, src)
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

	// Geo-resolve + upsert each node into state.
	s.setStatus(func(st *Snapshot) {
		st.Phase = PhaseGeo
		st.NodesGeoTotal = len(nodes)
		st.NodesGeoDone = 0
	})
	type enriched struct {
		n       model.Node
		country string
		hash    string
	}
	// ponytail: GeoFn (DNS + mmdb) is the slow part, so resolve countries in a
	// bounded worker pool. SQLite allows only one writer, so the cheap upsert is
	// done serially afterward — parallelism targets the geo lookup, not the DB.
	countries := make([]string, len(nodes))
	var geoWg sync.WaitGroup
	sem := make(chan struct{}, 32)
	var geoMu sync.Mutex
	var geoErr error
	for i := range nodes {
		if cctx.Err() != nil {
			break
		}
		geoWg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer geoWg.Done()
			defer func() { <-sem }()
			countries[i] = s.GeoFn(nodes[i])
			s.setStatus(func(st *Snapshot) { st.NodesGeoDone++ })
		}(i)
	}
	geoWg.Wait()
	if cctx.Err() != nil {
		return nil // ponytail: clean bail on cycle cancellation (no spurious error log)
	}
	var enrichedNodes []enriched
	for i, n := range nodes {
		n.Country = countries[i]
		hash := nodeHash(&n)
		if err := s.st.UpsertNodeWithCountry(n, countries[i]); err != nil {
			geoMu.Lock()
			if geoErr == nil {
				geoErr = err
			}
			geoMu.Unlock()
			break
		}
		enrichedNodes = append(enrichedNodes, enriched{n: n, country: countries[i], hash: hash})
	}
	if geoErr != nil {
		return fmt.Errorf("scheduler: upsert node: %w", geoErr)
	}
	s.setStatus(func(st *Snapshot) { st.NodesUpserted = len(nodes) })

	// Build skip sets for excluded countries/protocols so we don't waste probe
	// budget on nodes that can never reach a subscription. Country is already
	// resolved (GeoFn ran above), so both filters are known here.
	exclude := make(map[string]bool, len(s.cfg.ExcludeCountries))
	for _, c := range s.cfg.ExcludeCountries {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			exclude[c] = true
		}
	}
	skipProto := make(map[string]bool, len(s.cfg.ExcludeProtocols))
	for _, p := range s.cfg.ExcludeProtocols {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			skipProto[p] = true
		}
	}

	// Probe batch: skip excluded countries/protocols. enrichedNodes still
	// derives from the full node set (for upsert/history), but results are only
	// produced for the filtered slice, so skipped nodes never reach selection.
	s.setStatus(func(st *Snapshot) { st.Phase = PhaseProbe })

	// One engine reload for the whole batch, then a bounded fan-out probe.
	// Previously this was split into a "valid-first" pass + a second pass, each
	// with its own mihomo config reload (two full rebuilds per cycle). A single
	// reload + one ProbeFn call is enough: every node — alive or new — is
	// re-measured each cycle, so corpses in the valid set are still caught. The
	// reload is required so the per-node Probe hot path finds every node already
	// present and skips EnsureNode (which would otherwise reload config under the
	// write lock, serializing the pool back to ~1-by-1).
	probeNodes := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		if exclude[strings.ToUpper(n.Country)] || skipProto[strings.ToLower(string(n.Protocol))] {
			continue
		}
		probeNodes = append(probeNodes, n)
	}

	if len(probeNodes) > 0 {
		if err := s.engine.SyncNodes(probeNodes); err != nil {
			log.Printf("scheduler: sync nodes: %v", err)
		}
		if _, e := s.ProbeFn(cctx, probeNodes); e != nil {
			return fmt.Errorf("scheduler: probe: %w", e)
		}
	}

	// ponytail: probe results are now persisted live inside defaultProbe, as
	// each node finishes probing (not batched at cycle end). The 'results' and
	// 'history' rows feed nodeViews(), so the Nodes pool refreshes row-by-row.

	// ponytail: if the cycle was stopped mid-probe, keep the already-collected
	// results (recorded above) but DO NOT run selection/reconcile/regenerate —
	// an empty `selected` would wipe the existing subscription. The next cycle
	// recovers the unprobed nodes.
	if cctx.Err() != nil {
		return nil
	}

	// Enforce bounded retention so results/history/nodes don't grow unbounded
	// under continuous 24/7 operation. A prune error must not abort the cycle.
	if err := s.st.Prune(state.DefaultRetention(), cycle); err != nil {
		log.Printf("[scheduler] prune: %v", err)
	}

	// Build candidates from alive nodes only. Banned nodes are dropped here so
	// they can never reach a generated subscription. The min-speed brake drops
	// nodes whose measured throughput is below the configured floor.
	// Drop nodes whose resolved country is in the exclude list so they can
	// never reach a generated subscription (safety net; they were already
	// skipped at probe time above).
	// Build candidates from the persisted latest measurement. A node keeps its
	// last-known liveness if this cycle's probe errored, so a transient infra
	// blip can't silently drop it from the subscription.
	var cands []selector.Candidate
	floorKbps := s.cfg.MinSpeedMbps * 1000
	for _, en := range enrichedNodes {
		if s.cfg.IsBanned != nil && s.cfg.IsBanned(en.hash) {
			continue
		}
		if exclude[strings.ToUpper(en.country)] {
			continue
		}
		id, e := s.st.NodeID(en.hash)
		if e != nil {
			continue
		}
		lr, e2 := s.st.LatestResult(id)
		if e2 != nil || !lr.Alive {
			continue
		}
		if floorKbps > 0 && lr.SpeedKbps < floorKbps {
			continue
		}
		cands = append(cands, selector.Candidate{
			Node:      en.n,
			LatencyMs: lr.LatencyMs,
			Country:   en.country,
		})
	}

	s.setStatus(func(st *Snapshot) {
		st.NodesAlive = len(cands)
		st.Phase = PhaseSelect
	})
	selected := selector.Select(cands, s.cfg.TopN)
	selected = applyDegrade(selected, cands, s.cfg.DegradeMs)

	// FIX C: reconcile the subscription table to exactly the best selection so a
	// freshly-probed good node actually enters the served subscription (not only
	// via death-replacement). Banned nodes are skipped, so manual UI removals
	// stick; banned members are naturally absent from selected and get removed.
	// Member identity uses ListSubscription().NodeID (the real node hash) because
	// SubscriptionMemberNodes() does not expose Security/Encryption, which
	// nodeHash depends on.
	members, err := s.st.ListSubscription()
	if err != nil {
		log.Printf("scheduler: reconcile list subscription: %v", err)
	} else {
		selSet := make(map[string]bool, len(selected))
		for _, c := range selected {
			h := nodeHash(&c.Node)
			if s.cfg.IsBanned != nil && s.cfg.IsBanned(h) {
				continue
			}
			if s.cfg.MaxPingMs > 0 && c.LatencyMs > s.cfg.MaxPingMs {
				continue
			}
			selSet[h] = true
			if err := s.st.AddSubscription(h); err != nil {
				log.Printf("scheduler: reconcile add %s: %v", h, err)
			}
		}
		// Only prune members when we actually have a selection. An empty
		// selection (all probed nodes dead this cycle) must NOT wipe the
		// subscription — keep the last-known-good set (MinKeep semantics).
		if len(selected) > 0 {
			for _, m := range members {
				if !selSet[m.NodeID] {
					if err := s.st.RemoveSubscription(m.NodeID); err != nil {
						log.Printf("scheduler: reconcile remove %s: %v", m.NodeID, err)
					}
				}
			}
		}
	}

	s.setStatus(func(st *Snapshot) { st.Phase = PhasePersist })
	// Single writer to out/: regenerateSubs gathers the current subscription
	// set (which may be empty on first boot) and persists it. The common pool
	// is internal-only and never written to out/ directly.
	if err := s.regenerateSubs(); err != nil {
		return fmt.Errorf("scheduler: regenerate subs: %w", err)
	}

	// On first boot with an empty subscription, auto-seed from the common pool.
	if members, _ := s.st.ListSubscription(); len(members) == 0 {
		if err := s.SeedSubscription(); err != nil {
			log.Printf("scheduler: seed subscription: %v", err)
		}
	}

	log.Printf("scheduler: cycle %d done: %d sources, %d nodes, %d selected",
		cycle, len(sources), len(nodes), len(selected))
	if err := s.st.SetLastSuccess(time.Now()); err != nil {
		log.Printf("scheduler: record last success: %v", err)
	}
	s.setStatus(func(st *Snapshot) {
		st.Phase = PhaseDone
		st.LastCycleDur = time.Since(start)
	})
	return nil
}

// regenerateSubs is THE ONLY writer to out/. It gathers the alive, non-banned
// subscription members (optionally capped per country by SubTopN) and persists
// them through the existing three generators (untouched). Banned members are
// excluded from the served output.
func (s *Scheduler) regenerateSubs() error {
	members, err := s.st.SubscriptionMemberNodes()
	if err != nil {
		return fmt.Errorf("subscription members: %w", err)
	}
	var cands []selector.Candidate
	for _, n := range members {
		h := nodeHash(&n)
		if s.cfg.IsBanned != nil && s.cfg.IsBanned(h) {
			continue
		}
		// Use the latest stored latency for ordering/labels when available.
		lat := 0
		if id, e := s.st.NodeID(h); e == nil {
			if r, e2 := s.st.LatestResult(id); e2 == nil {
				lat = r.LatencyMs
			}
		}
		cands = append(cands, selector.Candidate{Node: n, LatencyMs: lat, Country: n.Country})
	}
	// Cap per country by SubTopN (best latency first).
	cands = capPerCountry(cands, s.cfg.SubTopN)
	nodes := make([]model.Node, 0, len(cands))
	for _, c := range cands {
		nodes = append(nodes, c.Node)
	}
	if err := s.persister.Persist(nodes); err != nil {
		return fmt.Errorf("persist subscription: %w", err)
	}
	return nil
}

// RegenerateSubs exposes regenerateSubs for the web layer so a manual
// add/remove of a subscription member takes effect in out/ immediately.
func (s *Scheduler) RegenerateSubs() error {
	return s.regenerateSubs()
}

// capPerCountry keeps at most topN candidates per country, ordered by latency
// (lowest first; 0 latency treated as worst).
func capPerCountry(cands []selector.Candidate, topN int) []selector.Candidate {
	if topN <= 0 {
		return cands
	}
	byCountry := make(map[string][]selector.Candidate)
	var order []string
	for _, c := range cands {
		k := c.Country
		if _, ok := byCountry[k]; !ok {
			order = append(order, k)
		}
		byCountry[k] = append(byCountry[k], c)
	}
	out := make([]selector.Candidate, 0, len(cands))
	for _, k := range order {
		grp := byCountry[k]
		sort.SliceStable(grp, func(i, j int) bool {
			if grp[i].LatencyMs == 0 && grp[j].LatencyMs == 0 {
				return false
			}
			if grp[i].LatencyMs == 0 {
				return false
			}
			if grp[j].LatencyMs == 0 {
				return true
			}
			return grp[i].LatencyMs < grp[j].LatencyMs
		})
		if len(grp) > topN {
			grp = grp[:topN]
		}
		out = append(out, grp...)
	}
	return out
}

// SeedSubscription populates the subscription from the common pool: for each
// country, build candidates from common nodes + their latest results latency,
// select the best per TopN, and add them. It then regenerates out/ immediately
// so the freshly-seeded subscription is written on first boot (closing the
// first-boot gap where out/ would otherwise stay empty until the next tick).
func (s *Scheduler) SeedSubscription() error {
	common, err := s.st.ListNodes()
	if err != nil {
		return fmt.Errorf("list common nodes: %w", err)
	}
	byCountry := make(map[string][]selector.Candidate)
	for _, nr := range common {
		if !nr.Alive {
			continue
		}
		if s.cfg.IsBanned != nil && s.cfg.IsBanned(nr.Hash) {
			continue
		}
		byCountry[nr.Country] = append(byCountry[nr.Country], selector.Candidate{
			Node:      model.Node{Protocol: model.Scheme(nr.Protocol), Host: nr.Host, Port: nr.Port, Name: nr.Name, Country: nr.Country, User: nr.Name},
			LatencyMs: nr.LatencyMs,
			Country:   nr.Country,
			Hash:      nr.Hash,
		})
	}
	for _, cands := range byCountry {
		best := selector.Select(cands, s.cfg.TopN)
		for _, c := range best {
			h := c.Hash
			if err := s.st.AddSubscription(h); err != nil {
				log.Printf("scheduler: seed add subscription %s: %v", h, err)
			}
		}
	}
	return s.regenerateSubs()
}

// SubValidity checks each subscription member's aliveness via mihomo latency and
// replaces any dead member immediately (ReplaceRoutine). It runs on its own
// timer context, independent of the common scan.
//
// Probes are fanned out across workers (mirroring defaultProbe): the engine is
// pre-synced with the member set so Probe takes the fast URLTest path instead of
// the EnsureNode write-lock reload. Goroutines only probe + append to a guarded
// slice; all DB/out writes (SetSubValidChecked, ReplaceRoutine) happen serially
// after wg.Wait.
func (s *Scheduler) SubValidity(ctx context.Context) error {
	members, err := s.st.ListSubscription()
	if err != nil {
		return fmt.Errorf("list subscription: %w", err)
	}
	// Resolve nodes serially; drop orphaned rows (DB write) up front.
	type probeItem struct {
		m    state.SubscriptionRow
		node model.Node
	}
	var items []probeItem
	for _, m := range members {
		n, e := s.st.NodeByHash(m.NodeID)
		if e != nil {
			// Orphaned row (node pruned): drop it.
			_ = s.st.RemoveSubscription(m.NodeID)
			continue
		}
		items = append(items, probeItem{m: m, node: n})
	}
	if len(items) == 0 {
		return nil
	}
	// Pre-sync the exact set we are about to probe so Probe stays on the
	// concurrent URLTest path (no per-node EnsureNode reload thrash).
	nodes := make([]model.Node, len(items))
	for i, it := range items {
		nodes[i] = it.node
	}
	if err := s.engine.SyncNodes(nodes); err != nil {
		log.Printf("scheduler: subvalidity sync nodes: %v", err)
	}
	workers := s.cfg.Workers
	if workers <= 0 {
		workers = 32
	}
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	type probeResult struct {
		m    state.SubscriptionRow
		res  mihomo.Result
		perr error
	}
	results := make([]probeResult, 0, len(items))
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it probeItem) {
			defer wg.Done()
			defer func() { <-sem }()
			r, e := s.engine.Probe(ctx, it.node)
			if e != nil {
				// Infra failure: record, don't swallow silently.
				log.Printf("scheduler: subvalidity probe %s: %v", it.m.NodeID, e)
				mu.Lock()
				results = append(results, probeResult{m: it.m, perr: e})
				mu.Unlock()
				return
			}
			mu.Lock()
			results = append(results, probeResult{m: it.m, res: r})
			mu.Unlock()
		}(it)
	}
	wg.Wait()
	// Serial post-processing: DB writes + ReplaceRoutine must stay serial.
	for _, pr := range results {
		if pr.perr != nil {
			continue
		}
		if err := s.st.SetSubValidChecked(pr.m.NodeID, time.Now().Unix()); err != nil {
			log.Printf("scheduler: set sub valid checked %s: %v", pr.m.NodeID, err)
		}
		if !pr.res.Alive {
			if err := s.ReplaceRoutine(pr.m.NodeID); err != nil {
				log.Printf("scheduler: replace routine %s: %v", pr.m.NodeID, err)
			}
		}
	}
	return nil
}

// SubPing refreshes latency for each subscription member and regenerates out/
// when ordering may have changed. It runs on its own timer context.
//
// Probes are fanned out across workers (mirroring defaultProbe): the engine is
// pre-synced with the member set so Probe takes the fast URLTest path. Goroutines
// only probe + append to a guarded slice; SetSubPing and the single regenerateSubs
// call happen serially after wg.Wait.
func (s *Scheduler) SubPing(ctx context.Context) error {
	members, err := s.st.ListSubscription()
	if err != nil {
		return fmt.Errorf("list subscription: %w", err)
	}
	type probeItem struct {
		m    state.SubscriptionRow
		node model.Node
	}
	var items []probeItem
	changed := false
	for _, m := range members {
		n, e := s.st.NodeByHash(m.NodeID)
		if e != nil {
			_ = s.st.RemoveSubscription(m.NodeID)
			changed = true
			continue
		}
		items = append(items, probeItem{m: m, node: n})
	}
	if len(items) == 0 {
		if changed {
			if err := s.regenerateSubs(); err != nil {
				return fmt.Errorf("regenerate subs: %w", err)
			}
		}
		return nil
	}
	nodes := make([]model.Node, len(items))
	for i, it := range items {
		nodes[i] = it.node
	}
	if err := s.engine.SyncNodes(nodes); err != nil {
		log.Printf("scheduler: subping sync nodes: %v", err)
	}
	workers := s.cfg.Workers
	if workers <= 0 {
		workers = 32
	}
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	type probeResult struct {
		m    state.SubscriptionRow
		res  mihomo.Result
		perr error
	}
	results := make([]probeResult, 0, len(items))
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it probeItem) {
			defer wg.Done()
			defer func() { <-sem }()
			r, e := s.engine.Probe(ctx, it.node)
			if e != nil {
				log.Printf("scheduler: subping probe %s: %v", it.m.NodeID, e)
				mu.Lock()
				results = append(results, probeResult{m: it.m, perr: e})
				mu.Unlock()
				return
			}
			mu.Lock()
			results = append(results, probeResult{m: it.m, res: r})
			mu.Unlock()
		}(it)
	}
	wg.Wait()
	// Serial post-processing: SetSubPing + single regenerateSubs at the end.
	for _, pr := range results {
		if pr.perr != nil {
			continue
		}
		if e := s.st.SetSubPing(pr.m.NodeID, int(pr.res.LatencyMs), time.Now().Unix()); e != nil {
			log.Printf("scheduler: set sub ping %s: %v", pr.m.NodeID, e)
		}
		changed = true
	}
	if changed {
		if err := s.regenerateSubs(); err != nil {
			return fmt.Errorf("regenerate subs: %w", err)
		}
	}
	return nil
}

// ReplaceRoutine swaps a dead subscription member for a fresh, same-country
// common node. It queries common alive, non-banned, same-country nodes (applying
// ExcludeCountries/ExcludeProtocols), orders by stored latency, takes top-K (5),
// calls SyncNodes with the FULL current union (never a partial set that would
// wipe other proxies), fresh-pings each, swaps the first alive in, and
// regenerates out/ immediately. If none available, it removes the dead member.
func (s *Scheduler) ReplaceRoutine(deadHash string) error {
	dead, err := s.st.NodeByHash(deadHash)
	if err != nil {
		_ = s.st.RemoveSubscription(deadHash)
		return nil
	}
	cands, err := s.st.CommonAliveSameCountry(dead.Country, s.cfg.ExcludeCountries, s.cfg.ExcludeProtocols)
	if err != nil {
		return fmt.Errorf("common same-country: %w", err)
	}
	// Order by stored latency (best first).
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].LatencyMs == 0 && cands[j].LatencyMs == 0 {
			return false
		}
		if cands[i].LatencyMs == 0 {
			return false
		}
		if cands[j].LatencyMs == 0 {
			return true
		}
		return cands[i].LatencyMs < cands[j].LatencyMs
	})
	if len(cands) > 5 {
		cands = cands[:5]
	}

	// Build the FULL union: common alive ∪ subscription members ∪ candidates,
	// so SyncNodes never drops a subscription member or other proxy.
	union, err := s.fullUnion(cands)
	if err != nil {
		return fmt.Errorf("full union: %w", err)
	}
	if err := s.engine.SyncNodes(union); err != nil {
		return fmt.Errorf("sync nodes: %w", err)
	}

	// Fresh-ping each candidate; swap the first alive in.
	for _, c := range cands {
		res, e := s.engine.Probe(context.Background(), c.Node)
		if e != nil {
			continue
		}
		if res.Alive {
			h := nodeHash(&c.Node)
			if s.cfg.IsBanned != nil && s.cfg.IsBanned(h) {
				continue
			}
			if err := s.st.AddSubscription(h); err != nil {
				log.Printf("scheduler: replace add %s: %v", h, err)
			}
			_ = s.st.RemoveSubscription(deadHash)
			if err := s.regenerateSubs(); err != nil {
				return fmt.Errorf("regenerate subs: %w", err)
			}
			return nil
		}
	}
	// None alive: drop the dead member so it is excluded from output.
	_ = s.st.RemoveSubscription(deadHash)
	return s.regenerateSubs()
}

// fullUnion returns the complete node set to hand to SyncNodes: every common
// alive node, every current subscription member, plus the given candidates.
// This guarantees subscription ⊆ synced set, so a reload never wipes a member.
func (s *Scheduler) fullUnion(extra []selector.Candidate) ([]model.Node, error) {
	seen := make(map[string]bool)
	var out []model.Node
	add := func(n model.Node) {
		h := nodeHash(&n)
		if seen[h] {
			return
		}
		seen[h] = true
		out = append(out, n)
	}
	common, err := s.st.ListNodes()
	if err != nil {
		return nil, err
	}
	for _, nr := range common {
		if !nr.Alive {
			continue
		}
		add(model.Node{Protocol: model.Scheme(nr.Protocol), Host: nr.Host, Port: nr.Port, Name: nr.Name, Country: nr.Country, User: nr.Name})
	}
	members, err := s.st.SubscriptionMemberNodes()
	if err != nil {
		return nil, err
	}
	for _, n := range members {
		add(n)
	}
	for _, c := range extra {
		add(c.Node)
	}
	return out, nil
}

// SubStatus returns a per-pool status snapshot for the web UI.
func (s *Scheduler) SubStatus() map[string]any {
	members, _ := s.st.ListSubscription()
	alive := 0
	for _, m := range members {
		id, err := s.st.NodeID(m.NodeID)
		if err != nil {
			continue
		}
		if r, err := s.st.LatestResult(id); err == nil && r.Alive {
			alive++
		}
	}
	return map[string]any{
		"subscriptionMembers": len(members),
		"subscriptionAlive":   alive,
	}
}

// Stop cleanly shuts the scheduler down: it cancels the internal context,
// stops the three timers, waits for their goroutines, and closes the embedded
// mihomo engine and the geo manager. It is safe to call multiple times and
// before Run.
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
	if s.commonTimer != nil {
		s.commonTimer.Stop()
	}
	if s.validTimer != nil {
		s.validTimer.Stop()
	}
	if s.pingTimer != nil {
		s.pingTimer.Stop()
	}
	// Wait for the SubValidity/SubPing goroutines to observe ctx cancellation.
	s.timerWG.Wait()
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
