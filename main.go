package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"vpn-sub-manager/internal/bans"
	"vpn-sub-manager/internal/config"
	"vpn-sub-manager/internal/scheduler"
	"vpn-sub-manager/internal/serve"
	"vpn-sub-manager/internal/settings"
	"vpn-sub-manager/internal/state"
	"vpn-sub-manager/internal/web"
)

// Config holds the runtime knobs parsed from CLI flags.
type Config struct {
	StatePath   string
	SourcesPath string // plain-text sources whitelist (separate from state DB)
	AssetsDir   string
	OutDir      string
	Interval    time.Duration
	TopN        int
	DegradeMs   int
	MinKeep     int
	SeedFile    string // optional: newline-separated source URLs to seed (replace list) then exit
	ServeAddr   string // subscription HTTP server listen addr (loopback); empty disables
	ServeToken  string // secret token for /s/<token>/ hidden path; empty = direct /<file>
	WebAddr     string // web management UI listen addr
	WebToken    string // required token for the web management UI
	WebSecret   string // secret path prefix (>=24 chars) hiding the admin UI

	ProbeURL            string   // HTTP GET target for real RTT (empty -> engine default)
	SpeedTestURL        string   // HTTP download target for throughput (empty disables)
	MinSpeedMbps        int      // throughput floor for the speed brake (0 disables)
	SpeedTestTopN       int      // MB cap for the speed sample download
	ExcludeCountries    []string // ISO codes excluded from subscriptions (e.g. ru,cn)
	ExcludeProtocols    []string // schemes excluded from probing/subscriptions (e.g. vmess,trojan)
	Workers             int      // probe worker-pool size (in-process mihomo concurrency); clamped [16,512], default 350
	ProbeTimeoutMs      int      // per-URLTest timeout (ms); 0 = engine default 2000
	MaxPingMs           int      // drop nodes slower than this (ms) from the served subscription; 0 disables
	SubValidityInterval time.Duration
	SubPingInterval     time.Duration
	SubTopN             int
}

// main parses flags, builds the Config, and delegates all wiring to run so it
// can be exercised by tests. It exits with a non-zero code on error.
func main() {
	cfg, configPath := parseFlags()

	// Web UI: if enabled (addr set), it must be both authenticated AND hidden
	// behind a long secret path. The secret is additive to the token.
	if cfg.WebAddr != "" {
		if cfg.WebToken == "" {
			log.Fatal("web: -web-token is required; the management UI must never run unauthenticated")
		}
		if cfg.WebSecret == "" {
			log.Fatal("web: -web-secret is required; the admin UI must be hidden behind a secret path")
		}
		if len(cfg.WebSecret) < 24 {
			log.Fatal("web: -web-secret must be at least 24 characters (12+12); the admin path secret must be long enough to stay hidden")
		}
	}

	// Persist the effective config so config.json stays in sync with the last
	// run (CLI flags override file values; this records the resolved result).
	eff := settings.Settings{
		StatePath:        cfg.StatePath,
		SourcesPath:      cfg.SourcesPath,
		AssetsDir:        cfg.AssetsDir,
		OutDir:           cfg.OutDir,
		Interval:         cfg.Interval.String(),
		TopN:             cfg.TopN,
		DegradeMs:        cfg.DegradeMs,
		MinKeep:          cfg.MinKeep,
		ServeAddr:        cfg.ServeAddr,
		ServeToken:       cfg.ServeToken,
		WebAddr:          cfg.WebAddr,
		WebToken:         cfg.WebToken,
		WebSecret:        cfg.WebSecret,
		ProbeURL:         cfg.ProbeURL,
		SpeedTestURL:     cfg.SpeedTestURL,
		MinSpeedMbps:     cfg.MinSpeedMbps,
		SpeedTestTopN:    cfg.SpeedTestTopN,
		ExcludeCountries: cfg.ExcludeCountries,
		ExcludeProtocols: cfg.ExcludeProtocols,
		Workers:          cfg.Workers,
		ProbeTimeoutMs:   cfg.ProbeTimeoutMs,
		MaxPingMs:        cfg.MaxPingMs,
	}
	if err := settings.Save(configPath, eff); err != nil {
		log.Printf("config: save %s: %v", configPath, err)
	}

	if err := run(context.Background(), cfg, nil, configPath); err != nil {
		if err == context.Canceled {
			// Graceful shutdown via SIGINT/SIGTERM: not an error.
			os.Exit(0)
		}
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

// parseFlags reads CLI flags with sane defaults rooted at the user config dir.
// Flag defaults are seeded from config.json (if present); explicit CLI flags
// still win because the file values are only the flag defaults.
func parseFlags() (Config, string) {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "." // ponytail: fall back to cwd if no config dir
	}
	appDir := filepath.Join(base, "vpn-sub-manager")

	// Resolve -config before defining the rest so file values can seed defaults.
	configPath := extractConfigPath(os.Args[1:], filepath.Join(appDir, "config.json"))
	loaded, existed, lerr := settings.Load(configPath)
	if lerr != nil {
		log.Printf("config: load %s: %v (using defaults)", configPath, lerr)
	}

	statePath := flag.String("state", firstNonEmpty(loaded.StatePath, filepath.Join(appDir, "state.db")), "state DB path")
	sourcesPath := flag.String("sources", firstNonEmpty(loaded.SourcesPath, filepath.Join(appDir, "sources.txt")), "sources whitelist file (plain text)")
	assetsDir := flag.String("assets", firstNonEmpty(loaded.AssetsDir, filepath.Join(appDir, "assets")), "assets dir (geo db, etc.)")
	outDir := flag.String("out", firstNonEmpty(loaded.OutDir, filepath.Join(appDir, "out")), "generated subscriptions dir")
	intervalDef := 2 * time.Hour
	if existed && loaded.Interval != "" {
		if d, perr := time.ParseDuration(loaded.Interval); perr == nil {
			intervalDef = d
		} else {
			log.Printf("config: bad interval %q: %v (using 2h)", loaded.Interval, perr)
		}
	}
	subValidityDef := 5 * time.Minute
	if existed && loaded.SubValidityInterval != "" {
		if d, perr := time.ParseDuration(loaded.SubValidityInterval); perr == nil {
			subValidityDef = d
		} else {
			log.Printf("config: bad sub_validity_interval %q: %v (using 5m)", loaded.SubValidityInterval, perr)
		}
	}
	subPingDef := 30 * time.Minute
	if existed && loaded.SubPingInterval != "" {
		if d, perr := time.ParseDuration(loaded.SubPingInterval); perr == nil {
			subPingDef = d
		} else {
			log.Printf("config: bad sub_ping_interval %q: %v (using 30m)", loaded.SubPingInterval, perr)
		}
	}
	interval := flag.Duration("interval", intervalDef, "refresh interval")
	subValidity := flag.Duration("sub-validity", subValidityDef, "subscription aliveness check interval")
	subPing := flag.Duration("sub-ping", subPingDef, "subscription latency refresh interval")
	subTopN := flag.Int("sub-topn", dfltInt(existed, loaded.SubTopN, 0), "subscription top-N per country (0 = use topn)")
	topn := flag.Int("topn", dfltInt(existed, loaded.TopN, 5), "top-N nodes per country (clamped 3..500)")
	degrade := flag.Int("degrade", dfltInt(existed, loaded.DegradeMs, 0), "degrade latency threshold (ms)")
	minkeep := flag.Int("minkeep", dfltInt(existed, loaded.MinKeep, 1), "minimum kept subscription versions")
	seed := flag.String("seed", "", "seed sources from a file (newline-separated https URLs); replaces list and exits")
	serveAddr := flag.String("serve-addr", dfltStr(existed, loaded.ServeAddr, "127.0.0.1:18080"), "subscription HTTP server listen addr (loopback); empty disables")
	serveToken := flag.String("serve-token", loaded.ServeToken, "secret token for /s/<token>/ hidden path; empty = direct /<file>")
	webAddr := flag.String("web-addr", dfltStr(existed, loaded.WebAddr, "127.0.0.1:8090"), "web management UI listen addr")
	webToken := flag.String("web-token", loaded.WebToken, "required token for the web management UI")
	webSecret := flag.String("web-secret", loaded.WebSecret, "secret path prefix (>=24 chars / 12+12) hiding the admin UI; all UI+API mounted under http://<addr>/<secret>/")

	probeURL := flag.String("probe-url", dfltStr(existed, loaded.ProbeURL, ""), "HTTP GET target for real RTT measurement (empty -> engine default)")
	speedTestURL := flag.String("speed-test-url", dfltStr(existed, loaded.SpeedTestURL, ""), "HTTP download target for throughput (empty disables speed measurement)")
	minSpeedMbps := flag.Int("min-speed-mbps", dfltInt(existed, loaded.MinSpeedMbps, 0), "throughput floor (Mbps) for the speed brake; 0 disables")
	speedTestTopN := flag.Int("speed-test-topn", dfltInt(existed, loaded.SpeedTestTopN, 5), "MB cap for the speed sample download")
	excludeCountries := flag.String("exclude-countries", strings.Join(loaded.ExcludeCountries, ","), "comma-separated ISO country codes to exclude from subscriptions (e.g. ru,cn)")
	excludeProtocols := flag.String("exclude-protocols", strings.Join(loaded.ExcludeProtocols, ","), "comma-separated schemes to exclude from probing/subscriptions (e.g. vmess,trojan)")
	workers := flag.Int("workers", dfltInt(existed, loaded.Workers, 350), "probe worker-pool size (in-process mihomo concurrency); clamped [16,512], default 350")
	probeTimeout := flag.Int("probe-timeout", dfltInt(existed, loaded.ProbeTimeoutMs, 2000), "probe timeout per URLTest in ms (default 2000)")
	maxPing := flag.Int("max-ping", dfltInt(existed, loaded.MaxPingMs, 0), "drop nodes slower than this (ms) from the served subscription; 0 disables")
	// Re-register -config on the main set so flag.Parse accepts it (value already resolved).
	flag.String("config", configPath, "persisted runtime config (config.json); CLI flags override file values")
	flag.Parse()

	var excl []string
	for _, p := range strings.Split(*excludeCountries, ",") {
		if p = strings.TrimSpace(strings.ToUpper(p)); p != "" {
			excl = append(excl, p)
		}
	}
	var exclP []string
	for _, p := range strings.Split(*excludeProtocols, ",") {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
			exclP = append(exclP, p)
		}
	}

	n := *topn
	if n < 3 {
		n = 3
	}
	if n > 5 {
		n = 5
	}

	return Config{
		StatePath:           *statePath,
		SourcesPath:         *sourcesPath,
		AssetsDir:           *assetsDir,
		OutDir:              *outDir,
		Interval:            *interval,
		TopN:                n,
		DegradeMs:           *degrade,
		MinKeep:             *minkeep,
		SeedFile:            *seed,
		ServeAddr:           *serveAddr,
		ServeToken:          *serveToken,
		WebAddr:             *webAddr,
		WebToken:            *webToken,
		WebSecret:           *webSecret,
		ProbeURL:            *probeURL,
		SpeedTestURL:        *speedTestURL,
		MinSpeedMbps:        *minSpeedMbps,
		SpeedTestTopN:       *speedTestTopN,
		ExcludeCountries:    excl,
		ExcludeProtocols:    exclP,
		Workers:             *workers,
		ProbeTimeoutMs:      *probeTimeout,
		MaxPingMs:           *maxPing,
		SubValidityInterval: *subValidity,
		SubPingInterval:     *subPing,
		SubTopN:             *subTopN,
	}, configPath
}

// extractConfigPath pulls -config/--config from args (order-independent) so the
// persisted config can seed flag defaults before the real flag parse.
func extractConfigPath(args []string, def string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-config" || a == "--config" {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
		if s, ok := strings.CutPrefix(a, "-config="); ok {
			return s
		}
		if s, ok := strings.CutPrefix(a, "--config="); ok {
			return s
		}
	}
	return def
}

// dfltStr returns the file value when the file existed, else the hardcoded default.
func dfltStr(existed bool, loaded, def string) string {
	if existed {
		return loaded
	}
	return def
}

// firstNonEmpty returns loaded when non-empty, otherwise def. Used for filesystem
// path flags so a partial config.json (field absent or "") falls back to the
// default user-config location instead of an empty string that breaks MkdirAll.
// Unlike dfltStr it does NOT preserve an empty value, because there is no
// "empty disables" semantics for paths — only serve_addr/web_addr need that.
func firstNonEmpty(loaded, def string) string {
	if loaded != "" {
		return loaded
	}
	return def
}

// dfltInt returns the file value when the file existed, else the hardcoded default.
func dfltInt(existed bool, loaded, def int) int {
	if existed {
		return loaded
	}
	return def
}

// run parses flags, builds the Config, and delegates all wiring to runInner so
// it can be exercised by tests. It exits with a non-zero code on error.
func run(ctx context.Context, cfg Config, sch *scheduler.Scheduler, configPath string) error {
	return runInner(ctx, cfg, sch, false, configPath)
}

// runInner is the testable core of run. skipUI bypasses the foreground web UI
// (used by the smoke test so it never blocks on a server); it goes straight to
// the scheduler-wait shutdown path.
func runInner(ctx context.Context, cfg Config, sch *scheduler.Scheduler, skipUI bool, configPath string) error {
	// 1. Ensure all required directories exist.
	for _, dir := range []string{cfg.AssetsDir, cfg.OutDir, filepath.Dir(cfg.StatePath)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// 2. Open state and registry (the web UI reads through these).
	st, err := state.Open(cfg.StatePath)
	if err != nil {
		return fmt.Errorf("open state: %w", err)
	}
	defer st.Close()

	reg, err := config.New(cfg.SourcesPath)
	if err != nil {
		return fmt.Errorf("config registry: %w", err)
	}

	// Optional one-shot seed: replace the entire source list with the URLs in
	// the seed file (https only), then exit. Lets the user bootstrap their
	// whitelist without the UI and keeps the list reproducible.
	if cfg.SeedFile != "" {
		data, err := os.ReadFile(cfg.SeedFile)
		if err != nil {
			return fmt.Errorf("read seed file: %w", err)
		}
		var urls []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			urls = append(urls, line)
		}
		added, skipped, err := reg.ReplaceAll(urls)
		if err != nil {
			return fmt.Errorf("seed sources: %w", err)
		}
		log.Printf("seeded %d sources (%d skipped) from %s", added, skipped, cfg.SeedFile)
		return nil
	}

	// 3. Build scheduler config and scheduler (if not injected).
	bansStore := bans.New(filepath.Join(filepath.Dir(configPath), "bans.json"))
	schedCfg := scheduler.Config{
		StatePath:           cfg.StatePath,
		SourcesPath:         cfg.SourcesPath,
		AssetsDir:           cfg.AssetsDir,
		OutDir:              cfg.OutDir,
		Interval:            cfg.Interval,
		TopN:                cfg.TopN,
		DegradeMs:           cfg.DegradeMs,
		MinKeep:             cfg.MinKeep,
		ProbeURL:            cfg.ProbeURL,
		SpeedTestURL:        cfg.SpeedTestURL,
		MinSpeedMbps:        cfg.MinSpeedMbps,
		SpeedTestTopN:       cfg.SpeedTestTopN,
		ExcludeCountries:    cfg.ExcludeCountries,
		ExcludeProtocols:    cfg.ExcludeProtocols,
		Workers:             cfg.Workers,
		ProbeTimeoutMs:      cfg.ProbeTimeoutMs,
		MaxPingMs:           cfg.MaxPingMs,
		SubValidityInterval: cfg.SubValidityInterval,
		SubPingInterval:     cfg.SubPingInterval,
		SubTopN:             cfg.SubTopN,
		IsBanned:            bansStore.Has,
	}
	if sch == nil {
		sch, err = scheduler.New(schedCfg)
		if err != nil {
			return fmt.Errorf("scheduler: %w", err)
		}
	}

	// 4. Graceful shutdown: cancel on SIGINT/SIGTERM.
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 4.5 Subscription HTTP server (loopback). Auto-starts if addr is set so
	//     the Publish screen can show a live URL immediately. The controller is
	//     always built (non-nil) so the web UI can query generated files/status.
	pub := serve.NewController(cfg.OutDir, cfg.ServeAddr, cfg.ServeToken)
	if cfg.ServeAddr != "" {
		if err := pub.Start(ctx); err != nil {
			return fmt.Errorf("serve: %w", err)
		}
	}

	// 5. Run scheduler in the background.
	done := make(chan error, 1)
	go func() { done <- sch.Run(ctx) }()

	// 6. Foreground web UI (skipped in tests). Blocks until a signal arrives,
	//    then gracefully shuts the web server down.
	if !skipUI {
		runCtx, runCancel := context.WithCancel(context.Background())
		defer runCancel()
		store, err := settings.NewStore(configPath)
		if err != nil {
			return fmt.Errorf("settings store: %w", err)
		}
		webSrv := web.New(reg, st, sch, pub, web.Config{Addr: cfg.WebAddr, Token: cfg.WebToken, Secret: cfg.WebSecret}, store, bansStore)
		log.Printf("web: management UI at http://%s/%s/", cfg.WebAddr, cfg.WebSecret)
		go func() {
			if err := webSrv.Start(runCtx); err != nil {
				log.Printf("web: %v", err)
			}
		}()

		// Block on OS signal; then graceful shutdown below.
		<-ctx.Done()
		runCancel()
		_ = webSrv.Stop()
	}

	// 7. Stop the publisher and scheduler so no embedded mihomo hub or HTTP
	//    server is left running. Cancelling ctx (signal) makes sch.Run return,
	//    which closes the mihomo engine / stops the embedded hub.
	if cfg.ServeAddr != "" {
		_ = pub.Stop()
	}
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("scheduler did not stop in time")
	}
}
