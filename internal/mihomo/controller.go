package mihomo

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"vpn-sub-manager/internal/model"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"gopkg.in/yaml.v3"
)

func sha256Sum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomSecret() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Controller embeds mihomo in-process and exposes a ProbeEngine.
type Controller struct {
	mu       sync.RWMutex
	selMu    sync.Mutex // guards selector mutation during Speed
	inflight sync.WaitGroup
	closed   atomic.Bool

	opts Options

	started  bool
	mixedPort int
	ecPort    int
	secret    string

	nodes map[string]model.Node // hash -> node (authoritative set)
}

// Start boots the embedded mihomo hub with an empty proxy set.
func (c *Controller) Start() {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	c.started = true
	c.mixedPort = freePort()
	c.ecPort = freePort()
	c.secret = randomSecret()
	cfg := c.buildConfig(nil)
	c.mu.Unlock()

	if err := hub.Parse(cfg, hub.WithExternalController(fmt.Sprintf("127.0.0.1:%d", c.ecPort)), hub.WithSecret(c.secret)); err != nil {
		// hub.Parse also applies; a parse failure here is fatal for probing.
		panic(fmt.Sprintf("mihomo: start: %v", err))
	}
}

// buildConfig renders the full clash-meta config. Caller must hold c.mu
// (write or read) — it reads mixedPort/ecPort/secret directly.
func (c *Controller) buildConfig(nodes []model.Node) []byte {
	proxies := make([]map[string]any, 0, len(nodes))
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		p := buildProxyYAML(n)
		proxies = append(proxies, p)
		names = append(names, p["name"].(string))
	}
	cfg := map[string]any{
		"mixed-port":         c.mixedPort,
		"external-controller": fmt.Sprintf("127.0.0.1:%d", c.ecPort),
		"secret":             c.secret,
		"mode":               "global",
		"proxies":            proxies,
	}
	// mihomo rejects a selector group with an empty `proxies` list, so only
	// emit the OUT group once at least one proxy exists. Start() runs before
	// any node is synced; the first SyncNodes/EnsureNode rebuilds the config
	// with the group present.
	if len(names) > 0 {
		cfg["proxy-groups"] = []map[string]any{
			{
				"name":    "OUT",
				"type":    "select",
				"proxies": names,
			},
		}
	}
	b, _ := yaml.Marshal(cfg)
	return b
}

// SyncNodes replaces the authoritative set with nodes and reloads mihomo.
// Always called with the full union (common alive + subscription members) so
// subscription members are never wiped by a partial reload.
func (c *Controller) SyncNodes(nodes []model.Node) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return ErrClosed
	}
	set := make(map[string]model.Node, len(nodes))
	for i := range nodes {
		set[nodeHash(&nodes[i])] = nodes[i]
	}
	if err := c.apply(nodes); err != nil {
		return err
	}
	c.nodes = set
	return nil
}

// EnsureNode merges a single node into the set and reloads the FULL set
// (never a partial reload). No-op if the node is already present.
func (c *Controller) EnsureNode(n model.Node) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return ErrClosed
	}
	h := nodeHash(&n)
	if _, ok := c.nodes[h]; ok {
		return nil
	}
	all := make([]model.Node, 0, len(c.nodes)+1)
	for _, nn := range c.nodes {
		all = append(all, nn)
	}
	all = append(all, n)
	if err := c.apply(all); err != nil {
		return err
	}
	c.nodes[h] = n
	return nil
}

func (c *Controller) apply(nodes []model.Node) error {
	cfgBytes := c.buildConfig(nodes)
	parsed, err := config.Parse(cfgBytes)
	if err != nil {
		// Retry with per-node filtering to drop a node that fails to parse,
		// so one bad node never wedges the whole reload.
		valid := make([]model.Node, 0, len(nodes))
		for _, n := range nodes {
			if _, e := config.Parse(c.buildConfig([]model.Node{n})); e != nil {
				continue
			}
			valid = append(valid, n)
		}
		if len(valid) == len(nodes) {
			return fmt.Errorf("mihomo: parse config: %w", err)
		}
		cfgBytes = c.buildConfig(valid)
		parsed, err = config.Parse(cfgBytes)
		if err != nil {
			return fmt.Errorf("mihomo: parse config: %w", err)
		}
	}
	executor.ApplyConfig(parsed, true)
	return nil
}

// Latency returns the URLTest RTT (ms) for the proxy named hash.
func (c *Controller) Latency(ctx context.Context, hash string, url string, timeoutMs int64, expected utils.IntRanges[uint16]) (int, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed.Load() {
		return 0, ErrClosed
	}
	pr, ok := tunnel.Proxies()[hash]
	if !ok {
		return 0, fmt.Errorf("mihomo: proxy %s not found", hash)
	}
	if timeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
	}
	d, err := pr.URLTest(ctx, url, expected)
	if err != nil {
		return 0, err
	}
	return int(d), nil
}

// Speed selects the node on the OUT selector and downloads through mixed-port.
func (c *Controller) Speed(ctx context.Context, hash string, url string) (int64, error) {
	c.inflight.Add(1)
	defer c.inflight.Done()
	if c.closed.Load() {
		return 0, ErrClosed
	}
	c.selMu.Lock()
	defer c.selMu.Unlock()
	c.mu.RLock()
	p, ok := tunnel.Proxies()["OUT"]
	var sel *outboundgroup.Selector
	if ok {
		sel, ok = p.Adapter().(*outboundgroup.Selector)
	}
	if ok {
		_ = sel.Set(hash)
	}
	c.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("mihomo: OUT selector not found")
	}
	client := c.mixedPortClient()
	return httpSpeed(ctx, client, url, c.opts.SpeedTestTopN, c.opts.MinSpeedMbps), nil
}

// Probe ensures the node is loaded, measures latency, and (on WithSpeed) speed.
func (c *Controller) Probe(ctx context.Context, n model.Node) (Result, error) {
	c.inflight.Add(1)
	defer c.inflight.Done()
	if c.closed.Load() {
		return Result{}, ErrClosed
	}

	h := nodeHash(&n)
	// Hot path: SyncNodes already loaded the full union before a batch probe,
	// so the node is present. Do NOT take the exclusive write lock here — each
	// Latency() holds the read lock for the whole URLTest, and a write-lock
	// request would block until that read lock is released, serializing every
	// probe into a single stream. Only fall back to EnsureNode (which reloads
	// config under the write lock) when the node was not yet synced.
	c.mu.RLock()
	_, present := c.nodes[h]
	c.mu.RUnlock()
	if !present {
		if err := c.EnsureNode(n); err != nil {
			// node may be unsupported by mihomo; treat as dead, not fatal.
			return Result{ProbeCount: 1}, nil
		}
	}
	expected, err := utils.NewUnsignedRanges[uint16]("200-299")
	if err != nil {
		expected, _ = utils.NewUnsignedRanges[uint16]("200-299")
	}
	lat, err := c.Latency(ctx, h, c.opts.ProbeURL, 2000, expected)
	if err != nil {
		return Result{ProbeCount: 1}, nil
	}
	r := Result{Alive: true, LatencyMs: int64(lat), ProbeCount: 1}
	if speedWanted(ctx) {
		if sp, serr := c.Speed(ctx, h, c.opts.SpeedTestURL); serr == nil {
			r.SpeedKbps = sp
		}
	}
	return r, nil
}

// Close shuts down mihomo after in-flight probes finish.
func (c *Controller) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.inflight.Wait()
	c.mu.RLock()
	started := c.started
	c.mu.RUnlock()
	if started {
		executor.Shutdown()
	}
	return nil
}

// mixedPortClient returns an HTTP client routing through the mixed-port proxy.
func (c *Controller) mixedPortClient() *http.Client {
	c.mu.RLock()
	port := c.mixedPort
	c.mu.RUnlock()
	u := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
