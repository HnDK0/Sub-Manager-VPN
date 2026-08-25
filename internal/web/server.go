// Package web implements the management web UI for vpn-sub-manager: a small
// net/http server on its own port, an embedded vanilla-JS frontend, a REST API,
// and an SSE hub that streams live scheduler/state/log events. It reuses the
// engine packages (config/state/scheduler/serve) and adds no new dependencies.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vpn-sub-manager/internal/bans"
	"vpn-sub-manager/internal/config"
	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/scheduler"
	"vpn-sub-manager/internal/serve"
	"vpn-sub-manager/internal/settings"
	"vpn-sub-manager/internal/state"
)

//go:embed static
var staticFS embed.FS

// Config configures the web server.
type Config struct {
	Addr   string // listen address, e.g. "127.0.0.1:8090"
	Token  string // required; server refuses to start without it
	Secret string // secret path prefix (>=24 chars) hiding the admin UI under /<secret>/
}

// Server is the management web server.
type Server struct {
	reg  *config.Registry
	st   *state.State
	sch  *scheduler.Scheduler
	pub  *serve.Controller
	cfg  Config
	hub  *Hub
	mux  *http.ServeMux
	http *http.Server

	failLim *tokenLimiter

	store *settings.Store

	bans *bans.Store

	ctx     context.Context
	logCap  *logCapture
	origLog io.Writer

	sseMu      sync.Mutex
	sseTickets map[string]time.Time
}

// New builds a Server. It does not start listening; call Start. store backs the
// read-write Settings handlers (persisted to config.json).
func New(reg *config.Registry, st *state.State, sch *scheduler.Scheduler, pub *serve.Controller, cfg Config, store *settings.Store, banStore *bans.Store) *Server {
	return &Server{
		reg: reg,
		st:  st,
		sch: sch,
		pub: pub,
		cfg: cfg,
		hub: NewHub(),

		store: store,
		bans:  banStore,

		failLim: &tokenLimiter{fails: map[string]int{}, block: map[string]time.Time{}},
	}
}

// Start wires the mux, installs the live-log capture, launches the poller
// goroutine, and begins listening. It returns an error immediately if no token
// was configured (the server must never run unauthenticated).
func (s *Server) Start(ctx context.Context) error {
	if s.cfg.Token == "" {
		return errors.New("web: token is required (refusing to start without -web-token)")
	}
	if s.cfg.Secret == "" {
		return errors.New("web: secret is required (refusing to start without -web-secret)")
	}
	s.ctx = ctx

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("web: embed static: %w", err)
	}

	// Everything is mounted under the secret prefix so the admin UI and API are
	// unreachable without knowing the hidden path.
	p := "/" + s.cfg.Secret

	s.mux = http.NewServeMux()
	s.mux.Handle(p+"/static/", http.StripPrefix(p+"/static/", http.FileServer(http.FS(staticSub))))
	s.mux.HandleFunc(p+"/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != p+"/" {
			http.NotFound(w, r)
			return
		}
		f, err := staticSub.Open("index.html")
		if err != nil {
			http.Error(w, "index.html missing", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.Copy(w, f)
	})

	// REST + SSE (token enforced by s.auth).
	s.mux.HandleFunc("GET "+p+"/api/status", s.auth(s.handleStatus))
	s.mux.HandleFunc("GET "+p+"/api/sources", s.auth(s.handleSources))
	s.mux.HandleFunc("POST "+p+"/api/sources", s.auth(s.handleAddSource))
	s.mux.HandleFunc("POST "+p+"/api/sources/{id}/toggle", s.auth(s.handleToggleSource))
	s.mux.HandleFunc("DELETE "+p+"/api/sources/{id}", s.auth(s.handleDeleteSource))
	s.mux.HandleFunc("PUT "+p+"/api/sources/{id}", s.auth(s.handlePutSource))
	s.mux.HandleFunc("GET "+p+"/api/nodes", s.auth(s.handleNodes))
	s.mux.HandleFunc("GET "+p+"/api/nodes/", s.auth(s.handleNodeConfig))
	s.mux.HandleFunc("GET "+p+"/api/countries", s.auth(s.handleCountries))
	s.mux.HandleFunc("POST "+p+"/api/cycle", s.auth(s.handleCycle))
	s.mux.HandleFunc("POST "+p+"/api/nodes/test", s.auth(s.handleTestNodes))
	s.mux.HandleFunc("GET "+p+"/api/nodes/banned", s.auth(s.handleBanned))
	s.mux.HandleFunc("POST "+p+"/api/nodes/ban", s.auth(s.handleBan))
	s.mux.HandleFunc("DELETE "+p+"/api/nodes/ban/{hash}", s.auth(s.handleUnban))
	s.mux.HandleFunc("POST "+p+"/api/admin/cleanup", s.auth(s.handleCleanup))
	s.mux.HandleFunc("GET "+p+"/api/pipeline", s.auth(s.handlePipeline))
	s.mux.HandleFunc("GET "+p+"/api/generate", s.auth(s.handleGenerate))
	s.mux.HandleFunc("GET "+p+"/api/subscription", s.auth(s.handleSubscription))
	s.mux.HandleFunc("GET "+p+"/api/publish", s.auth(s.handlePublish))
	s.mux.HandleFunc("GET "+p+"/api/settings", s.auth(s.handleGetSettings))
	s.mux.HandleFunc("PUT "+p+"/api/settings", s.auth(s.handlePutSettings))
	s.mux.HandleFunc("GET "+p+"/api/stream", s.auth(s.handleStream))
	s.mux.HandleFunc("POST "+p+"/api/sse-ticket", s.auth(s.handleSseTicket))

	// Live-log capture: mirror the global log into the hub ring buffer.
	s.logCap = newLogCapture(s.hub, 500)
	s.origLog = log.Writer()
	log.SetOutput(io.MultiWriter(s.origLog, s.logCap))

	// Poller: publish status/pipeline/nodes deltas every ~500ms.
	go s.poll(ctx)

	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		log.SetOutput(s.origLog)
		s.origLog = nil
		return fmt.Errorf("web: listen %s: %w", s.cfg.Addr, err)
	}
	s.http = &http.Server{Handler: s.mux}
	go func() {
		if err := s.http.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("web: server error: %v", err)
		}
	}()
	log.Printf("web: management UI listening on %s", s.cfg.Addr)
	return nil
}

// Stop restores the original log writer and gracefully shuts the HTTP server.
func (s *Server) Stop() error {
	if s.origLog != nil {
		log.SetOutput(s.origLog)
		s.origLog = nil
	}
	if s.http != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.http.Shutdown(ctx)
	}
	return nil
}

// poll publishes status/pipeline/nodes events when they change.
func (s *Server) poll(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var lastStatus string
	var lastNodes, lastAlive int
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			snap := s.sch.Status()
			key := fmt.Sprintf("%v|%d|%v|%d|%d|%d|%d|%d|%d|%d",
				snap.Phase, snap.Cycle, snap.Running, snap.SourceTotal, snap.SourceDone,
				snap.NodesFetched, snap.NodesAlive, snap.Kept, snap.ProbeTotal, snap.ProbeDone)
			if key != lastStatus {
				lastStatus = key
				s.hub.Publish(Event{Type: "status", Payload: s.buildStatus()})
				s.hub.Publish(Event{Type: "pipeline", Payload: snap})
			}
			views, err := s.nodeViews()
			if err == nil {
				alive := 0
				for _, v := range views {
					if v.Alive {
						alive++
					}
				}
				if len(views) != lastNodes || alive != lastAlive {
					lastNodes, lastAlive = len(views), alive
					s.hub.Publish(Event{Type: "nodes", Payload: views})
				}
			}
		}
	}
}

// auth enforces the token on a handler (Bearer header primary; ?token= only for
// the SSE stream). Repeated bad tokens from one remote IP are rate-limited.
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.validToken(r) {
			h(w, r)
			return
		}
		ip := r.RemoteAddr
		if h, _, err := net.SplitHostPort(ip); err == nil {
			ip = h
		}
		if !s.failLim.allow(ip) {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
	}
}

func (s *Server) validToken(r *http.Request) bool {
	if s.cfg.Token == "" {
		return false
	}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		got := strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) == 1 {
			return true
		}
	}
	// Query token accepted ONLY for the SSE stream path (under any secret prefix).
	if strings.HasSuffix(r.URL.Path, "/api/stream") {
		if q := r.URL.Query().Get("token"); q != "" {
			if subtle.ConstantTimeCompare([]byte(q), []byte(s.cfg.Token)) == 1 {
				return true
			}
		}
		// Single-use, short-lived ticket (preferred over ?token=): the permanent
		// admin secret never appears in a URL/referer/log.
		if tk := r.URL.Query().Get("ticket"); tk != "" {
			return s.consumeTicket(tk)
		}
	}
	return false
}

// newTicket issues a single-use SSE ticket valid for 30s, so the long-lived
// admin token is never placed in a URL. ponytail: in-memory map guarded by
// sseMu; tickets are short-lived and single-use, no persistence needed.
func (s *Server) newTicket() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand should never fail; fall back to a time-derived value.
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	t := hex.EncodeToString(buf)
	s.sseMu.Lock()
	if s.sseTickets == nil {
		s.sseTickets = make(map[string]time.Time)
	}
	now := time.Now()
	for k, e := range s.sseTickets { // ponytail: prune expired to bound memory
		if now.After(e) {
			delete(s.sseTickets, k)
		}
	}
	s.sseTickets[t] = now.Add(30 * time.Second)
	s.sseMu.Unlock()
	return t
}

// consumeTicket validates and consumes a single-use SSE ticket.
func (s *Server) consumeTicket(t string) bool {
	if t == "" {
		return false
	}
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	if s.sseTickets == nil {
		return false
	}
	exp, ok := s.sseTickets[t]
	if !ok {
		return false
	}
	delete(s.sseTickets, t)
	return time.Now().Before(exp)
}

// handleSseTicket issues a single-use, short-lived ticket for opening the SSE
// stream, so the permanent admin token is never placed in a URL.
func (s *Server) handleSseTicket(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"ticket": s.newTicket()})
}

// tokenLimiter blocks a remote IP after too many failed token attempts within
// a rolling window. ponytail: in-memory, per-process; good enough for a single
// management UI. Swap for a shared store if behind multiple instances.
type tokenLimiter struct {
	mu    sync.Mutex
	fails map[string]int
	block map[string]time.Time
}

func (t *tokenLimiter) allow(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if until, ok := t.block[ip]; ok {
		if time.Now().Before(until) {
			return false
		}
		delete(t.block, ip)
		delete(t.fails, ip)
	}
	t.fails[ip]++
	if t.fails[ip] > 20 {
		t.block[ip] = time.Now().Add(time.Minute)
		return false
	}
	return true
}

// hashNode replicates scheduler/state nodeHash (sha256 of
// protocol|host|port|user) so the web layer can key CachedNodes entries without
// touching unexported engine code.
func hashNode(n model.Node) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s", n.Protocol, n.Host, n.Port, n.User)))
	return hex.EncodeToString(sum[:])
}
