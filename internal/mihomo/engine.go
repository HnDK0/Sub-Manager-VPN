package mihomo

import (
	"context"

	"vpn-sub-manager/internal/model"
)

// Result is the outcome of probing a single node.
type Result struct {
	Alive      bool
	LatencyMs  int64
	SpeedKbps  int64
	ProbeCount int
	// EgressIP is the actual IP we exit through the node (as seen by the target
	// server during the probe). Empty when the trace body could not be fetched;
	// geo then falls back to the node name. Not persisted.
	EgressIP string
}

// Options configures the embedded mihomo probe engine.
type Options struct {
	ProbeURL      string
	SpeedTestURL  string
	MinSpeedMbps  int
	SpeedTestTopN int
	// Workers is the bounded probe-concurrency semaphore — the real concurrency
	// knob. Clamped to [16, 512] in New(): 512 is the RAM/network-safe ceiling
	// for gentle probing (no unbounded fan-out). 0 defaults to 350.
	Workers int
	// ProbeTimeoutMs bounds each URLTest (ms). 0 defaults to 2000.
	ProbeTimeoutMs int
}

type speedCtxKey struct{}

// WithSpeed opts a probe context into also measuring throughput.
func WithSpeed(ctx context.Context) context.Context {
	return context.WithValue(ctx, speedCtxKey{}, true)
}

func speedWanted(ctx context.Context) bool {
	v, _ := ctx.Value(speedCtxKey{}).(bool)
	return v
}

// ProbeEngine is the contract the scheduler uses to measure nodes.
type ProbeEngine interface {
	Start()
	Probe(ctx context.Context, n model.Node) (Result, error)
	Close() error
}

// New builds an embedded mihomo controller.
func New(opts Options) *Controller {
	if opts.Workers <= 0 || opts.Workers < 16 {
		opts.Workers = 350
	}
	if opts.Workers > 512 {
		opts.Workers = 512
	}
	if opts.ProbeTimeoutMs <= 0 {
		opts.ProbeTimeoutMs = 2000
	}
	if opts.ProbeURL == "" {
		// Contentful target (not a bare 204) so a fake/MITM node that
		// synthesizes an empty 204 locally fails the probe. The /cdn-cgi/trace
		// body also carries the egress IP (line "ip=<addr>") captured during the
		// probe for geo-by-egress (see Controller.egressIP).
		opts.ProbeURL = "https://cp.cloudflare.com/cdn-cgi/trace"
	}
	if opts.SpeedTestURL == "" {
		opts.SpeedTestURL = "http://speedtest.selectel.ru/10MB"
	}
	if opts.SpeedTestTopN <= 0 {
		opts.SpeedTestTopN = 1
	}
	return &Controller{
		opts:  opts,
		nodes: make(map[string]model.Node),
	}
}


