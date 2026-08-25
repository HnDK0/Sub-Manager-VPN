package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"vpn-sub-manager/internal/model"
	"vpn-sub-manager/internal/netutil"
	"vpn-sub-manager/internal/settings"
)

func (s *Server) handleTestNodes(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErrorLog(w, http.StatusBadRequest, "bad request", err)
		return
	}
	cached := s.sch.CachedNodes()
	if len(cached) == 0 {
		writeJSONError(w, http.StatusConflict, "run a cycle first")
		return
	}
	hashToNode := make(map[string]model.Node, len(cached))
	for _, n := range cached {
		hashToNode[hashNode(n)] = n
	}
	views, err := s.nodeViews()
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to list nodes", err)
		return
	}
	viewByHash := make(map[string]NodeView, len(views))
	for _, v := range views {
		viewByHash[v.Hash] = v
	}
	var selected []model.Node
	for _, id := range req.IDs {
		if n, ok := hashToNode[id]; ok {
			selected = append(selected, n)
		}
	}
	if len(selected) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no matching cached nodes for given ids")
		return
	}
	// Confused-deputy / DNS-rebinding guard: validate the host resolves to a
	// public IP, then PIN the node to that IP so the engine connects to the
	// validated address (no TOCTOU window where the name re-resolves internally).
	// The ORIGINAL node (with the hostname) is kept for hashing/recording so the
	// existing viewByHash/RecordResult logic is unchanged.
	var kept []model.Node
	origHash := make([]string, 0, len(selected)) // kept[i] -> original node hash
	skipped := 0
	for _, n := range selected {
		ip, ok, err := netutil.ResolveAndCheckPublic(n.Host)
		if err != nil || !ok {
			skipped++
			log.Printf("web: handleTestNodes skipping %q: public=%v err=%v", n.Host, ok, err)
			continue
		}
		probe := n
		probe.Host = ip.String()
		kept = append(kept, probe)
		origHash = append(origHash, hashNode(n))
	}
	if skipped > 0 {
		log.Printf("web: handleTestNodes skipped %d non-public-host node(s)", skipped)
	}
	if len(kept) == 0 {
		writeJSONError(w, http.StatusBadRequest, "all selected nodes have non-public hosts; probing internal addresses is not allowed")
		return
	}
	results, err := s.sch.ProbeNodes(s.sch.WithSpeed(r.Context()), kept)
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to probe nodes", err)
		return
	}
	// ProbeNodes keys results by the IP-pinned copy; map back to the original hash.
	probeToOrig := make(map[string]string, len(kept))
	for i, probe := range kept {
		probeToOrig[hashNode(probe)] = origHash[i]
	}
	cycle := s.sch.Status().Cycle
	out := make(map[string]any, len(results))
	for h, res := range results {
		oh := probeToOrig[h]
		if v, ok := viewByHash[oh]; ok {
			if err := s.st.RecordResult(v.ID, res.Alive, int(res.LatencyMs), int(res.SpeedKbps), cycle); err != nil {
				log.Printf("web: record result: %v", err)
			}
		}
		out[oh] = map[string]any{"alive": res.Alive, "latencyMs": res.LatencyMs, "speedKbps": res.SpeedKbps, "probes": res.ProbeCount}
	}
	if fresh, err := s.nodeViews(); err == nil {
		s.hub.Publish(Event{Type: "nodes", Payload: fresh})
	}
	writeJSON(w, map[string]any{"cycle": cycle, "results": out})
}

func (s *Server) handlePipeline(w http.ResponseWriter, r *http.Request) {
	snap := s.sch.Status()
	writeJSON(w, map[string]any{
		"snapshot": snap,
		"logs":     s.logCap.Recent(50),
	})
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	names := s.pub.ListFiles()
	files := make([]map[string]any, 0, len(names))
	for _, name := range names {
		data, err := s.pub.Read(name)
		if err != nil {
			log.Printf("web: read generated file %q: %v", name, err)
			files = append(files, map[string]any{"name": name, "preview": "", "error": "failed to read file"})
			continue
		}
		prev := string(data)
		if len(prev) > 4096 {
			prev = prev[:4096]
		}
		files = append(files, map[string]any{"name": name, "preview": prev})
	}
	writeJSON(w, map[string]any{"files": files})
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	st := s.pub.Status()
	names := s.pub.ListFiles()
	serveAddr := st.ListenAddr // e.g. 127.0.0.1:18080
	adminAddr := s.cfg.Addr    // e.g. 127.0.0.1:8090

	// Derive public subscription/admin URLs from the installed nginx config.
	publicByFile := make(map[string]string)
	var publicAdmin string
	for _, srv := range s.pub.ParseNginxServers() {
		var name string
		for _, nm := range srv.Names {
			if nm == "*" || nm == "_" {
				continue
			}
			name = nm
			break
		}
		if name == "" {
			continue
		}
		for locPath, target := range srv.LocProxy {
			if target == serveAddr {
				base := "https://" + name + ensureTrailingSlash(locPath)
				for _, fn := range names {
					if publicByFile[fn] == "" {
						publicByFile[fn] = base + fn
					}
				}
			} else if target == adminAddr {
				if publicAdmin == "" {
					publicAdmin = "https://" + name + ensureTrailingSlash(locPath)
				}
			}
		}
	}

	urls := make([]map[string]any, 0, len(names))
	for _, name := range names {
		entry := map[string]any{"name": name, "url": st.LocalURL + name}
		if pub, ok := publicByFile[name]; ok && pub != "" {
			entry["public"] = pub
		} else {
			entry["public"] = ""
		}
		urls = append(urls, entry)
	}
	subSnippet := s.pub.NginxSnippet(st.LocalURL, "/s/"+st.Token+"/")
	adminTarget := "http://" + s.cfg.Addr
	adminSnippet := s.pub.AdminNginxSnippet(adminTarget, "/"+s.cfg.Secret+"/")
	// Never leak the serve token: build the status map explicitly without Token.
	writeJSON(w, map[string]any{
		"status": map[string]any{
			"running":    st.Running,
			"listenAddr": st.ListenAddr,
			"localURL":   st.LocalURL,
			"externalIP": st.ExternalIP,
		},
		"files":             urls,
		"nginxSnippet":      subSnippet,
		"adminNginxSnippet": adminSnippet,
		"httpds":            s.pub.DetectHTTPD(),
		"publicAdmin":       publicAdmin,
	})
}

// ensureTrailingSlash guarantees a path ends with "/".
func ensureTrailingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasSuffix(p, "/") {
		return p + "/"
	}
	return p
}

// settingsRestartNote documents that most params apply only after a restart.
const settingsRestartNote = "scheduler/web params persist to config.json; restart the service for interval/topn/degrade/minkeep/corpse and web-addr/secret/token to take effect."

// handleGetSettings returns the current persisted settings (read-write now) plus
// a note that most params require a restart to take effect.
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"settings": s.store.Get(),
		"note":     settingsRestartNote,
	})
}

// handlePutSettings applies a settings patch from the client, validates, and
// persists it to config.json. On error it returns a generic 400 (detail logged).
func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var patch settings.Settings
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeJSONErrorLog(w, http.StatusBadRequest, "bad request", err)
		return
	}
	merged, err := s.store.Update(patch)
	if err != nil {
		writeJSONErrorLog(w, http.StatusBadRequest, "update rejected", err)
		return
	}
	writeJSON(w, map[string]any{
		"applied": merged,
		"note":    settingsRestartNote,
	})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ch, unsub := s.hub.Subscribe()
	defer unsub()

	// Initial snapshot so the UI populates immediately on connect.
	s.writeSSE(w, flusher, Event{Type: "status", Payload: s.buildStatus()})
	s.writeSSE(w, flusher, Event{Type: "pipeline", Payload: s.sch.Status()})
	if views, err := s.nodeViews(); err == nil {
		s.writeSSE(w, flusher, Event{Type: "nodes", Payload: views})
	}
	// Replay recent historical logs so the Logs panel isn't empty until live
	// logs arrive.
	for _, line := range s.logCap.Recent(100) {
		s.writeSSE(w, flusher, Event{Type: "log", Payload: line})
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			s.writeSSE(w, flusher, ev)
		}
	}
}

func (s *Server) writeSSE(w http.ResponseWriter, f http.Flusher, ev Event) {
	data, err := json.Marshal(ev.Payload)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
	f.Flush()
}
