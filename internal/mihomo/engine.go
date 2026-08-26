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
}

// Options configures the embedded mihomo probe engine.
type Options struct {
	ProbeURL      string
	SpeedTestURL  string
	MinSpeedMbps  int
	SpeedTestTopN int
	Workers       int // probe concurrency semaphore (default 32)
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
		opts.Workers = 32
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
	return &Controller{
		opts:  opts,
		nodes: make(map[string]model.Node),
	}
}


