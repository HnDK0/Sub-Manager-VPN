// Package test implements the ping-through-proxy test engine for
// vpn-sub-manager. It spawns real xray-core subprocesses (obtained from
// core.Manager) configured as SOCKS5 proxies on per-worker ephemeral ports,
// routes probes through them to measure a model.Node's liveness and latency,
// classifies the node alive/dead, and persists the result + history into the
// SQLite state store.
//
// The engine is built for 24/7 operation: a worker pool keeps a persistent
// xray process per worker, a reaper waits on each child so no zombie is left
// behind, and crashed proxies are recovered. Close (and context cancellation)
// kill every spawned subprocess.
package test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"vpn-sub-manager/internal/core"
	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/state"
)

// proxyReadyTimeout bounds how long ensureProxy waits for the real xray backend
// to bind its SOCKS5 port before giving up and rescheduling the worker.
const proxyReadyTimeout = 5 * time.Second

// Result is the outcome of probing a single node.
type Result struct {
	Alive      bool  // true if at least one probe succeeded
	LatencyMs  int64 // median latency (ms) over successful HTTP probes (fallback: direct TCP connect)
	SpeedKbps  int64 // measured throughput (kbps); 0 if not measured
	ProbeCount int   // number of probes attempted
}

// Options configures an Engine.
type Options struct {
	// Workers is the size of the worker pool (each owns one xray process).
	// Defaults to 8 when <= 0.
	Workers int
	// Probes is how many times each node is probed. Defaults to 3.
	Probes int
	// Timeout is the per-probe dial timeout. Defaults to 5s.
	Timeout time.Duration
	// Retention is passed to state.Prune after each batch. Defaults to
	// state.DefaultRetention().
	Retention state.Retention
	// Spawn overrides how a SOCKS5 backend process is launched. In production
	// it is nil and xray is used. Tests inject a fake here so no real binary
	// or network is required.
	Spawn func(ctx context.Context, port int) (*exec.Cmd, error)
	// StartWorkers launches the worker pool in New. Tests set this false to
	// exercise pieces (persist, reaper) without a running pool.
	StartWorkers bool

	// ProbeURL is fetched (HTTP GET) through the node's SOCKS5 proxy to measure
	// real end-to-end RTT. Defaults to a public generate_204 endpoint.
	ProbeURL string
	// SpeedTestURL is downloaded through the proxy to measure throughput.
	// Defaults to a public 10MB file. Empty disables speed measurement.
	SpeedTestURL string
	// MinSpeedMbps, when > 0, is the throughput floor used by the scheduler's
	// speed brake (nodes slower than this are dropped from selection).
	MinSpeedMbps int
	// SpeedTestTopN caps how many MB are downloaded for the speed sample
	// (adaptive early-exit may stop sooner). Defaults to 1 (MB).
	SpeedTestTopN int
}

// speedCtxKey marks a probe context that should also sample throughput (speed)
// on top of latency. The background 24/7 cycle never sets this, so automatic
// probes stay latency-only and never burn traffic on every node every cycle;
// only on-demand manual tests (test.WithSpeed) enable throughput sampling.
type speedCtxKey struct{}

// WithSpeed returns a context that requests throughput sampling during probing.
func WithSpeed(ctx context.Context) context.Context {
	return context.WithValue(ctx, speedCtxKey{}, true)
}

// speedWanted reports whether the probe context requests throughput sampling.
func speedWanted(ctx context.Context) bool {
	v, _ := ctx.Value(speedCtxKey{}).(bool)
	return v
}

// Engine probes nodes through per-worker SOCKS5 proxies and persists results.
type Engine struct {
	mgr  *core.Manager
	st   *state.State
	opts Options

	spawn func(ctx context.Context, port int) (*exec.Cmd, error)

	jobs    chan probeJob
	workers []*worker
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc

	mu          sync.Mutex
	closed      bool
	started     bool
	realBackend bool // true only for the production xray spawn (injected fakes are false)
	tempDir     string
}

// probeJob is a unit of work dispatched to the pool.
type probeJob struct {
	node model.Node
	ctx  context.Context
	resp chan probeOutcome
}

type probeOutcome struct {
	r   Result
	err error
}

// worker owns one persistent SOCKS5 backend process on a fixed ephemeral port.
type worker struct {
	eng       *Engine
	id        int
	port      int
	stop      chan struct{}
	mu        sync.Mutex
	cmd       *exec.Cmd
	proxyAddr string
	reapCount int32 // atomic: how many times the reaper reaped an exit

	// reaping is true while a goroutine owns the Wait on the current cmd
	// (set by reap, or by kill when reap is not yet waiting). killed is true
	// once Process.Kill has been issued for the current cmd. Both are guarded
	// by mu and reset when a fresh backend is spawned, so the Kill+Wait+nil
	// lifecycle runs exactly once with no double Kill and no nil deref.
	reaping bool
	killed  bool
}

// New creates an Engine. If opts.StartWorkers is true the worker pool (and its
// xray processes) is started immediately.
func New(mgr *core.Manager, st *state.State, opts Options) *Engine {
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.Probes <= 0 {
		opts.Probes = 3
	}
	if opts.Timeout <= 0 {
		// ponytail: a node slower than 2s to answer a tunneled probe is already
		// a "shit server" per operator policy; fail it fast so dead/slow nodes
		// stop tying up workers.
		opts.Timeout = 2 * time.Second
	}
	if opts.Retention == (state.Retention{}) {
		opts.Retention = state.DefaultRetention()
	}
	if opts.ProbeURL == "" {
		opts.ProbeURL = "https://www.gstatic.com/generate_204"
	}
	if opts.SpeedTestURL == "" {
		opts.SpeedTestURL = "http://speedtest.selectel.ru/10MB"
	}
	if opts.SpeedTestTopN <= 0 {
		opts.SpeedTestTopN = 1
	}
	dir, _ := os.MkdirTemp("", "submgr-test-*")
	e := &Engine{
		mgr:     mgr,
		st:      st,
		opts:    opts,
		jobs:    make(chan probeJob, opts.Workers),
		tempDir: dir,
	}
	if opts.Spawn == nil {
		e.spawn = e.spawnXray
	} else {
		e.spawn = opts.Spawn
	}
	e.realBackend = (opts.Spawn == nil)
	if opts.StartWorkers {
		e.Start()
	}
	return e
}

// Start launches the worker pool (idempotent). The scheduler calls it when the
// pipeline begins; tests may skip it or supply a fake probeEngine.
func (e *Engine) Start() {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started = true
	e.mu.Unlock()
	e.start()
}

// start launches the worker pool.
func (e *Engine) start() {
	e.ctx, e.cancel = context.WithCancel(context.Background())
	for i := 0; i < e.opts.Workers; i++ {
		w := e.newWorker(i)
		e.workers = append(e.workers, w)
		e.wg.Add(1)
		go w.run()
	}
}

func (e *Engine) newWorker(id int) *worker {
	return &worker{eng: e, id: id, port: e.freePort(), stop: make(chan struct{})}
}

// freePort binds a listener to grab a free ephemeral port, then releases it so
// the backend can own it. There is a small TOCTOU window; acceptable here.
func (e *Engine) freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Probe probes a single node through the pool and returns its Result.
func (e *Engine) Probe(ctx context.Context, n model.Node) (Result, error) {
	job := probeJob{node: n, ctx: ctx, resp: make(chan probeOutcome, 1)}
	select {
	case e.jobs <- job:
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	select {
	case o := <-job.resp:
		return o.r, o.err
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

// RunBatch probes every node through the pool, persists each result, and prunes
// to the retention policy. It advances the cycle counter once for the batch.
func (e *Engine) RunBatch(ctx context.Context, nodes []model.Node) error {
	cycle, err := e.st.IncrementCycle()
	if err != nil {
		return fmt.Errorf("test: increment cycle: %w", err)
	}
	results := make([]Result, len(nodes))
	errs := make([]error, len(nodes))
	var wg sync.WaitGroup
	for i := range nodes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := e.Probe(ctx, nodes[i])
			results[i], errs[i] = r, err
		}(i)
	}
	wg.Wait()

	for i, n := range nodes {
		if errs[i] != nil {
			// Infra failure (e.g. pool not running): skip persistence for this
			// node this cycle rather than crashing the whole batch.
			continue
		}
		if err := e.persist(ctx, n, results[i], cycle); err != nil {
			return fmt.Errorf("test: persist node %s: %w", n.Host, err)
		}
	}
	if err := e.st.Prune(e.opts.Retention, cycle); err != nil {
		return fmt.Errorf("test: prune: %w", err)
	}
	return nil
}

// persist classifies (already done in Result) and writes the node, its result,
// and a history sample into state.
func (e *Engine) persist(ctx context.Context, n model.Node, r Result, cycle int) error {
	if err := e.st.UpsertNode(&n, cycle); err != nil {
		return err
	}
	id, err := e.st.NodeID(nodeHash(n))
	if err != nil {
		return err
	}
	if err := e.st.RecordResult(id, r.Alive, int(r.LatencyMs), int(r.SpeedKbps), cycle); err != nil {
		return err
	}
	if err := e.st.AddHistory(id, int(r.LatencyMs), cycle); err != nil {
		return err
	}
	return nil
}

// Close stops the pool and kills every spawned subprocess, then removes temp
// config files. It is safe to call more than once.
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()

	if e.cancel != nil {
		e.cancel()
	}
	for _, w := range e.workers {
		w.kill()
	}
	e.wg.Wait()
	if e.tempDir != "" {
		os.RemoveAll(e.tempDir)
	}
	return nil
}

// --- worker ---

func (w *worker) run() {
	defer w.eng.wg.Done()
	for {
		if err := w.ensureProxy(); err != nil {
			select {
			case <-w.eng.ctx.Done():
				return
			default:
			}
			select {
			case <-w.eng.ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}
		select {
		case job := <-w.eng.jobs:
			w.handle(job)
		case <-w.eng.ctx.Done():
			w.kill()
			return
		}
	}
}

func (w *worker) handle(job probeJob) {
	r, err := w.probe(job)
	job.resp <- probeOutcome{r: r, err: err}
}

// probe ensures a backend is running, (re)configures it with the current node's
// outbound on the real xray path, then measures through it.
func (w *worker) probe(job probeJob) (Result, error) {
	if err := w.ensureProxy(); err != nil {
		// Backend unavailable: treat as dead rather than dropping the node.
		return Result{Alive: false, ProbeCount: w.eng.opts.Probes}, nil
	}
	if w.eng.realBackend {
		// Real xray path: the worker's proxy must route through THIS node, so
		// (re)configure the backend with the node's outbound before probing.
		if err := w.configureForNode(job.node); err != nil {
			// Unsupported protocol / cannot build outbound: skip (dead).
			return Result{Alive: false, ProbeCount: w.eng.opts.Probes}, nil
		}
	}
	w.mu.Lock()
	addr := w.proxyAddr
	w.mu.Unlock()
	r, err := w.eng.probeThrough(addr, job.node, job.ctx)
	if err != nil {
		return Result{Alive: false, ProbeCount: w.eng.opts.Probes}, nil
	}
	return r, nil
}

// configureForNode (re)builds the worker's xray with the given node as its
// outbound and restarts the process. Probes are sequential per worker, so this
// is safe: the previous backend is killed and fully reaped before the new one
// is spawned. The fake/test path never calls this (realBackend == false), so the
// injected-Spawn integration test is untouched.
func (w *worker) configureForNode(n model.Node) error {
	out, err := nodeXrayOutbound(n)
	if err != nil {
		return err
	}
	w.kill()
	// Wait for the old backend to be fully reaped (w.cmd cleared) before
	// spawning the new one, so the reaping flag and cmd slot stay consistent
	// and there is no double Wait on a shared cmd.
	for {
		w.mu.Lock()
		done := w.cmd == nil
		w.mu.Unlock()
		if done {
			break
		}
		select {
		case <-w.eng.ctx.Done():
			return w.eng.ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return w.startBackend(func(ctx context.Context, port int) (*exec.Cmd, error) {
		return w.eng.spawnXrayForNode(ctx, port, out)
	})
}

// ensureProxy starts the placeholder backend if it is not already running. On
// the real xray path this is a freedom-outbound proxy that configureForNode
// later replaces with the per-node outbound; on the fake/test path it is the
// injected SOCKS5 spawn.
func (w *worker) ensureProxy() error {
	w.mu.Lock()
	if w.cmd != nil && w.cmd.Process != nil {
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()
	return w.startBackend(w.eng.spawn)
}

// startBackend spawns a backend using spawnFn, registers it on the worker, and
// waits for it to bind (real backends only). It is the single spawn+register+
// wait path shared by ensureProxy (placeholder) and configureForNode (per-node).
func (w *worker) startBackend(spawnFn func(context.Context, int) (*exec.Cmd, error)) error {
	cmd, err := spawnFn(w.eng.ctx, w.port)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	w.mu.Lock()
	w.cmd = cmd
	w.proxyAddr = fmt.Sprintf("127.0.0.1:%d", w.port)
	w.reaping = false
	w.killed = false
	w.mu.Unlock()
	go w.reap()

	// Wait for the real backend to actually bind its listening port before we
	// hand out probes. Without this the engine raced xray's startup: probes
	// fired the instant after cmd.Start() and failed fast against a
	// not-yet-listening socket, marking healthy nodes dead. Injected fakes
	// (tests) either already listen or don't need egress, so they skip the wait.
	if w.eng.realBackend {
		if err := w.waitForProxy(proxyReadyTimeout); err != nil {
			// Kill the (likely-not-listening) backend, then clear the slot so
			// the next ensureProxy respawns a fresh one.
			w.kill()
			w.mu.Lock()
			w.cmd = nil
			w.mu.Unlock()
			return err
		}
	}
	return nil
}

// reap waits on the child so the OS does not keep a zombie, then clears cmd so
// the next ensureProxy (or job) respawns a fresh backend. It is the single owner
// of the Wait for the current cmd; kill() owns the Kill. The two coordinate via
// w.reaping so the Kill+Wait+nil lifecycle runs exactly once.
func (w *worker) reap() {
	w.mu.Lock()
	if w.cmd == nil || w.reaping {
		w.mu.Unlock()
		return
	}
	w.reaping = true
	cmd := w.cmd
	w.mu.Unlock()

	// Wait for the child to exit — naturally, or because kill() signalled it.
	// We never Kill here: kill() is the only one that does, so there is at
	// most one Kill and at most one Wait on a given cmd.
	_ = cmd.Wait()
	atomic.AddInt32(&w.reapCount, 1)

	w.mu.Lock()
	w.reaping = false
	if w.cmd == cmd {
		w.cmd = nil
	}
	w.mu.Unlock()
}

// waitForProxy polls the worker's SOCKS5 port until the spawned backend is
// actually listening, or the timeout/context fires. A successful TCP connect is
// sufficient: it proves xray has bound the inbound and can serve SOCKS5.
func (w *worker) waitForProxy(timeout time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", w.port)
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("test: proxy on %s not listening after %s", addr, timeout)
		}
		select {
		case <-w.eng.ctx.Done():
			return w.eng.ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// kill terminates the backend process if running. It is safe to call multiple
// times and concurrently with reap(): the w.killed flag (under w.mu) ensures
// Process.Kill is issued at most once, and w.reaping decides who performs the
// Wait+nil so there is no double Wait and no nil deref on a cleared cmd.
func (w *worker) kill() {
	w.mu.Lock()
	if w.cmd == nil || w.killed {
		w.mu.Unlock()
		return
	}
	w.killed = true
	cmd := w.cmd
	reaping := w.reaping
	if !reaping {
		// reap is not yet waiting on this process; we own Wait+nil too.
		w.reaping = true
	}
	w.mu.Unlock()

	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	if !reaping {
		_ = cmd.Wait()
		w.mu.Lock()
		w.reaping = false
		if w.cmd == cmd {
			w.cmd = nil
		}
		w.mu.Unlock()
	}
}

// nodeHash mirrors state.nodeHash so we can resolve a node id after UpsertNode
// without modifying the (read-only) state package. Keep in sync with
// internal/state/state.go.
func nodeHash(n model.Node) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|%s|%s", n.Protocol, n.Host, n.Port, n.User, n.Security, n.Encryption)))
	return hex.EncodeToString(sum[:])
}
