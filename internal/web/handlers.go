package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"vpn-sub-manager/internal/config"
	"vpn-sub-manager/internal/select"
)

// NodeView is a display/testable node enriched with the hash and port that
// state.NodeRow does not expose. It is built from a direct DB join (st.DB()) so
// the web layer can key probe results and the test endpoint without touching
// unexported engine code.
type NodeView struct {
	ID        int64  `json:"id"`
	Hash      string `json:"hash"`
	Name      string `json:"name"`
	NormName  string `json:"normName"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Country   string `json:"country"`
	Protocol  string `json:"protocol"`
	Alive     bool   `json:"alive"`
	LatencyMs int    `json:"latencyMs"`
	SpeedKbps int    `json:"speedKbps"`
}

// subscriptionProfileTitle is the name Hiddify/Happ show after importing a
// subscription served via the web API (sent as the Profile-Title header).
const subscriptionProfileTitle = "Sub Manager VPN"

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("web: encode: %v", err)
	}
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

// writeJSONErrorLog returns a generic user-facing message and logs the real
// error server-side so operators can still diagnose without leaking internals
// (filesystem paths, hostnames, dependency details) to the browser.
func writeJSONErrorLog(w http.ResponseWriter, code int, msg string, err error) {
	if err != nil {
		log.Printf("web: %s: %v", msg, err)
	}
	writeJSONError(w, code, msg)
}

// buildStatus combines the scheduler snapshot with KPIs derived from node rows.
func (s *Server) buildStatus() map[string]any {
	snap := s.sch.Status()
	total, alive, working, countries := s.nodeKPIs()
	dead := total - alive
	sources, _ := s.reg.ListSources()
	return map[string]any{
		"running":        snap.Running,
		"cycle":          snap.Cycle,
		"phase":          snap.Phase.String(),
		"sourceTotal":    snap.SourceTotal,
		"sourceDone":     snap.SourceDone,
		"probeTotal":     snap.ProbeTotal,
		"probeDone":      snap.ProbeDone,
		"aliveCount":     snap.AliveCount,
		"deadCount":      snap.DeadCount,
		"nodesFetched":   snap.NodesFetched,
		"nodesGeoTotal":  snap.NodesGeoTotal,
		"nodesGeoDone":   snap.NodesGeoDone,
		"geoWorkers":     snap.GeoWorkers,
		"nodesAlive":     snap.NodesAlive,
		"lastCycleDurMs": snap.LastCycleDur.Milliseconds(),
		"lastError":      snap.LastError,
		"kpis": map[string]any{
			"total":     total,
			"alive":     alive,
			"working":   working,
			"dead":      dead,
				"countries": countries,
		},
		"sources":      len(sources),
		"subscription": s.sch.SubStatus(),
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.buildStatus())
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	list, err := s.reg.ListSources()
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to list sources", err)
		return
	}
	writeJSON(w, list)
}

func (s *Server) handleAddSource(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL  string `json:"url"`
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONErrorLog(w, http.StatusBadRequest, "bad request", err)
		return
	}
	added := false
	if strings.TrimSpace(body.Text) != "" {
		var errs []string
		for _, line := range strings.Split(body.Text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if _, err := s.reg.AddSource(line); err != nil {
				// Surface the rejection to the client instead of silently
				// succeeding: a dropped (non-https / non-public / duplicate)
				// line must not look like a saved source.
				errs = append(errs, fmt.Sprintf("%s: %v", line, err))
			}
		}
		if len(errs) > 0 {
			writeJSONError(w, http.StatusBadRequest, "failed to add some sources: "+strings.Join(errs, "; "))
			return
		}
		added = true
	} else if u := strings.TrimSpace(body.URL); u != "" {
		if _, err := s.reg.AddSource(u); err != nil {
			writeJSONErrorLog(w, http.StatusBadRequest, "failed to add source: "+err.Error(), err)
			return
		}
		added = true
	}
	list, err := s.reg.ListSources()
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to list sources", err)
		return
	}
	// FIX B: a newly added source must be probed promptly instead of waiting for
	// the next commonTimer tick (default ~2h). RequestCycle is non-blocking.
	if added {
		s.sch.RequestCycle()
	}
	writeJSON(w, list)
}

func (s *Server) handleToggleSource(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	list, err := s.reg.ListSources()
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to list sources", err)
		return
	}
	var cur *config.Source
	for i := range list {
		if list[i].ID == id {
			cur = &list[i]
			break
		}
	}
	if cur == nil {
		writeJSONError(w, http.StatusNotFound, "source not found")
		return
	}
	if err := s.reg.SetEnabled(id, !cur.Enabled); err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to toggle source", err)
		return
	}
	writeJSON(w, map[string]any{"id": id, "enabled": !cur.Enabled})
}

func (s *Server) handleDeleteSource(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if err := s.reg.RemoveSource(id); err != nil {
		writeJSONErrorLog(w, http.StatusNotFound, "failed to delete source", err)
		return
	}
	writeJSON(w, map[string]any{"deleted": id})
}

func (s *Server) handlePutSource(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.URL) == "" {
		writeJSONError(w, http.StatusBadRequest, "bad request: url required")
		return
	}
	newURL := strings.TrimSpace(body.URL)
	// Capture the current URL so a failed update can be rolled back atomically.
	oldURL := ""
	if list, err := s.reg.ListSources(); err == nil {
		for _, src := range list {
			if src.ID == id {
				oldURL = src.URL
				break
			}
		}
	}
	if err := s.reg.RemoveSource(id); err != nil {
		writeJSONErrorLog(w, http.StatusNotFound, "failed to update source", err)
		return
	}
	if _, err := s.reg.AddSource(newURL); err != nil {
		// Restore the original source so no source is lost on a bad URL.
		if oldURL != "" {
			if _, rerr := s.reg.AddSource(oldURL); rerr != nil {
				log.Printf("web: handlePutSource restore failed: %v", rerr)
			}
		}
		writeJSONErrorLog(w, http.StatusBadRequest, "failed to update source", err)
		return
	}
	writeJSON(w, map[string]any{"id": id, "url": newURL})
}

// nodeViewsByHashes returns NodeViews for the given node hashes only — used by
// endpoints that enrich a known subset (subscription members, a manual probe
// selection) so they never materialize the full node table.
func (s *Server) nodeViewsByHashes(hashes []string) (map[string]NodeView, error) {
	db := s.st.DB()
	out := make(map[string]NodeView, len(hashes))
	if len(hashes) == 0 {
		return out, nil
	}
	ph := make([]string, len(hashes))
	args := make([]any, len(hashes))
	for i, h := range hashes {
		ph[i] = "?"
		args[i] = h
	}
	q := `
		SELECT n.id, n.hash, n.name, n.norm_name, n.host, n.port, n.country, n.protocol,
		       COALESCE(r.alive,0), COALESCE(r.latency_ms,0), COALESCE(n.speed_kbps,0)
		FROM nodes n
		LEFT JOIN (
			SELECT node_id, alive, latency_ms,
			       ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY cycle_id DESC, checked_at DESC) AS rn
			FROM results
		) r ON r.node_id = n.id AND r.rn = 1
		WHERE n.hash IN (` + strings.Join(ph, ",") + `)`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("web: node views by hashes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id       int64
			hash     string
			name     string
			normName string
			host     string
			port     int
			country  string
			proto    string
			alive    int
			latency  int
			speed    int
		)
		if err := rows.Scan(&id, &hash, &name, &normName, &host, &port, &country, &proto, &alive, &latency, &speed); err != nil {
			return nil, fmt.Errorf("web: scan node: %w", err)
		}
		out[hash] = NodeView{
			ID: id, Hash: hash, Name: normName, NormName: normName, Host: host, Port: port,
			Country: country, Protocol: proto, Alive: alive != 0, LatencyMs: latency, SpeedKbps: speed,
		}
	}
	return out, rows.Err()
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	db := s.st.DB()

	const fromJoin = `
		FROM nodes n
		LEFT JOIN (
			SELECT node_id, alive, latency_ms,
			       ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY cycle_id DESC, checked_at DESC) AS rn
			FROM results
		) r ON r.node_id = n.id AND r.rn = 1`

	var where []string
	var args []any

	if strings.TrimSpace(q.Get("pool")) == "subscription" {
		where = append(where, "n.hash IN (SELECT node_id FROM subscription)")
	}
	if country := strings.TrimSpace(q.Get("country")); country != "" {
		if strings.EqualFold(country, "unknown") {
			where = append(where, "n.country = ''")
		} else {
			codes := strings.Split(country, ",")
			ph := make([]string, 0, len(codes))
			for _, c := range codes {
				c = strings.ToUpper(strings.TrimSpace(c))
				if c != "" {
					ph = append(ph, "?")
					args = append(args, c)
				}
			}
			if len(ph) > 0 {
				where = append(where, "UPPER(n.country) IN ("+strings.Join(ph, ",")+")")
			}
		}
	}
	if protocol := strings.TrimSpace(q.Get("protocol")); protocol != "" {
		where = append(where, "LOWER(n.protocol) = LOWER(?)")
		args = append(args, protocol)
	}
	if ml := parseIntQuery(r, "maxlatency"); ml > 0 {
		where = append(where, "COALESCE(r.latency_ms,0) > 0 AND COALESCE(r.latency_ms,0) <= ?")
		args = append(args, ml)
	}
	switch strings.TrimSpace(q.Get("status")) {
	case "alive":
		where = append(where, "COALESCE(r.alive,0) = 1")
	case "dead":
		where = append(where, "COALESCE(r.alive,0) = 0")
	}
	if alive := strings.TrimSpace(q.Get("alive")); alive == "true" {
		where = append(where, "COALESCE(r.alive,0) = 1")
	} else if alive == "false" {
		where = append(where, "COALESCE(r.alive,0) = 0")
	}
	if strings.TrimSpace(q.Get("working")) == "true" {
		where = append(where, "COALESCE(r.alive,0) = 1 AND COALESCE(r.latency_ms,0) > 0")
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := db.QueryRow("SELECT COUNT(*) "+fromJoin+whereSQL, args...).Scan(&total); err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "count nodes", err)
		return
	}
	aliveWhere := append([]string{"COALESCE(r.alive,0) = 1"}, where...)
	aliveSQL := " WHERE " + strings.Join(aliveWhere, " AND ")
	var aliveCount int
	if err := db.QueryRow("SELECT COUNT(*) "+fromJoin+aliveSQL, args...).Scan(&aliveCount); err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "count alive nodes", err)
		return
	}

	sortParam := strings.ToLower(strings.TrimSpace(q.Get("sort")))
	orderParam := strings.ToLower(strings.TrimSpace(q.Get("order")))
	desc := orderParam == "desc"
	var orderSQL string
	switch sortParam {
	case "latency":
		orderSQL = "ORDER BY (COALESCE(r.latency_ms,0)=0), COALESCE(r.latency_ms,0)"
	case "country":
		orderSQL = "ORDER BY CASE WHEN n.country = '' THEN 'zz' ELSE n.country END"
	case "protocol":
		orderSQL = "ORDER BY n.protocol"
	case "name":
		orderSQL = "ORDER BY n.norm_name"
	case "alive":
		orderSQL = "ORDER BY COALESCE(r.alive,0)"
	default:
		orderSQL = "ORDER BY n.id"
	}
	if desc {
		orderSQL += " DESC"
	} else {
		orderSQL += " ASC"
	}

	limit := 50
	if l := parseIntQuery(r, "limit"); l > 0 {
		limit = l
		if limit > 200 {
			limit = 200
		}
	}
	offset := 0
	if o := parseIntQuery(r, "offset"); o > 0 {
		offset = o
	}

	pageQ := "SELECT n.id, n.hash, n.name, n.norm_name, n.host, n.port, n.country, n.protocol, " +
		"COALESCE(r.alive,0), COALESCE(r.latency_ms,0), COALESCE(n.speed_kbps,0) " +
		fromJoin + whereSQL + " " + orderSQL + " LIMIT ? OFFSET ?"
	rows, err := db.Query(pageQ, append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "list nodes", err)
		return
	}
	defer rows.Close()
	var out []NodeView
	for rows.Next() {
		var (
			id       int64
			hash     string
			name     string
			normName string
			host     string
			port     int
			country  string
			proto    string
			alive    int
			latency  int
			speed    int
		)
		if err := rows.Scan(&id, &hash, &name, &normName, &host, &port, &country, &proto, &alive, &latency, &speed); err != nil {
			writeJSONErrorLog(w, http.StatusInternalServerError, "scan node", err)
			return
		}
		out = append(out, NodeView{
			ID: id, Hash: hash, Name: normName, NormName: normName, Host: host, Port: port,
			Country: country, Protocol: proto, Alive: alive != 0, LatencyMs: latency, SpeedKbps: speed,
		})
	}
	if err := rows.Err(); err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "node rows", err)
		return
	}

	writeJSON(w, map[string]any{
		"total":  total,
		"alive":  aliveCount,
		"limit":  limit,
		"offset": offset,
		"nodes":  out,
	})
}

// handleSubscription serves a generated subscription file (singbox/clash/v2rayn)
// as plain text. The format query param maps to the persisted output filename.
func (s *Server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	var name string
	switch format {
	case "singbox", "sing-box", "sfa":
		name = "singbox.json"
	case "clash", "meta":
		name = "clash.yaml"
	case "v2rayn", "v2ray", "xray":
		name = "v2rayn.txt"
	default:
		writeJSONError(w, http.StatusBadRequest, "unknown format (use singbox|clash|v2rayn)")
		return
	}
	data, err := s.pub.Read(name)
	if err != nil {
		writeJSONErrorLog(w, http.StatusNotFound, "subscription not found", err)
		return
	}
	ct := "text/plain; charset=utf-8"
	if strings.HasSuffix(name, ".json") {
		ct = "application/json"
	} else if strings.HasSuffix(name, ".yaml") {
		ct = "text/yaml"
	}
	// ponytail: name via header so Hiddify/Happ show a real profile title.
	w.Header().Set("Profile-Title", subscriptionProfileTitle)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// handleSubAdd adds a node (by hash) to the subscription pool and regenerates
// out/ immediately so the change is served without waiting for the next tick.
func (s *Server) handleSubAdd(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	if hash == "" {
		var body struct {
			Hash string `json:"hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			hash = strings.TrimSpace(body.Hash)
		}
	}
	if hash == "" {
		writeJSONError(w, http.StatusBadRequest, "hash required")
		return
	}
	if err := s.st.AddSubscription(hash); err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to add subscription", err)
		return
	}
	if err := s.sch.RegenerateSubs(); err != nil {
		log.Printf("web: regenerate after add: %v", err)
	}
	s.hub.Publish(Event{Type: "nodes", Payload: map[string]any{"ok": true}})
	writeJSON(w, map[string]any{"added": hash, "ok": true})
}

// handleSubRemove removes a node (by hash) from the subscription pool and
// regenerates out/ immediately.
func (s *Server) handleSubRemove(w http.ResponseWriter, r *http.Request) {
	hash, _ := url.PathUnescape(r.PathValue("hash"))
	if hash == "" {
		writeJSONError(w, http.StatusBadRequest, "hash required")
		return
	}
	if err := s.st.RemoveSubscription(hash); err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to remove subscription", err)
		return
	}
	if err := s.sch.RegenerateSubs(); err != nil {
		log.Printf("web: regenerate after remove: %v", err)
	}
	s.hub.Publish(Event{Type: "nodes", Payload: map[string]any{"ok": true}})
	writeJSON(w, map[string]any{"removed": hash, "ok": true})
}

// handleSubList returns the current subscription members with their display
// fields and per-member check timestamps.
func (s *Server) handleSubList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.ListSubscription()
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "list subscription", err)
		return
	}
	hashes := make([]string, 0, len(rows))
	for _, row := range rows {
		hashes = append(hashes, row.NodeID)
	}
	viewByHash, err := s.nodeViewsByHashes(hashes)
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "node views", err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		v := viewByHash[row.NodeID]
		out = append(out, map[string]any{
			"hash":           row.NodeID,
			"name":           v.Name,
			"country":        v.Country,
			"protocol":       v.Protocol,
			"alive":          v.Alive,
			"latencyMs":      v.LatencyMs,
			"speedKbps":      v.SpeedKbps,
			"validCheckedAt": row.ValidCheckedAt,
			"pingLatencyMs":  row.PingLatencyMs,
			"pingCheckedAt":  row.PingCheckedAt,
		})
	}
	writeJSON(w, map[string]any{"members": out, "total": len(out)})
}

// handleCountries returns a clean, deduplicated distinct-country list for the
// country filter. Empty and "XX" (geo fallback) codes are folded into a single
// unknown bucket so the UI never shows raw junk.
func (s *Server) handleCountries(w http.ResponseWriter, r *http.Request) {
	db := s.st.DB()
	pool := strings.TrimSpace(r.URL.Query().Get("pool"))
	var q string
	if pool == "subscription" {
		q = `
			SELECT n.country, COUNT(*) FROM nodes n
			JOIN subscription sub ON sub.node_id = n.hash
			GROUP BY n.country ORDER BY n.country`
	} else {
		q = `SELECT country, COUNT(*) FROM nodes GROUP BY country ORDER BY country`
	}
	rows, err := db.Query(q)
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "list countries", err)
		return
	}
	defer rows.Close()

	unknown := 0
	countries := make([]map[string]any, 0, 8)
	for rows.Next() {
		var code string
		var cnt int
		if err := rows.Scan(&code, &cnt); err != nil {
			writeJSONErrorLog(w, http.StatusInternalServerError, "scan country", err)
			return
		}
		if code == "" || strings.EqualFold(code, "XX") || !isValidCountry(code) {
			unknown += cnt
			continue
		}
		countries = append(countries, map[string]any{"code": code, "count": cnt})
	}
	writeJSON(w, map[string]any{"countries": countries, "unknown": unknown})
}

// isValidCountry reports whether code is a plausible ISO-3166 alpha-2 country
// code (exactly two A–Z letters). Anything else — node remarks, latency
// strings, or other garbage left in the country column by older binaries — is
// treated as unknown by the filter. ponytail: geo only ever stores valid ISO
// codes or ""; a strict 2-letter check is enough to drop the junk.
func isValidCountry(code string) bool {
	up := strings.ToUpper(code)
	if len(up) != 2 {
		return false
	}
	return up[0] >= 'A' && up[0] <= 'Z' && up[1] >= 'A' && up[1] <= 'Z'
}



// parseIntQuery parses a non-negative integer query param, returning 0 on
// missing/invalid input.
func parseIntQuery(r *http.Request, key string) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// countNodes returns the total number of rows in the nodes table.
func (s *Server) countNodes() (int, error) {
	var n int
	if err := s.st.DB().QueryRow(`SELECT COUNT(*) FROM nodes`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// handleCleanup wipes all node + measurement tables so the DB is rebuilt from
// sources on the next cycle. It is Bearer-protected.
func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request) {
	before, err := s.countNodes()
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "cleanup failed", err)
		return
	}
	// Full reset: selective retention keeps weeks of history and removes almost
	// nothing in daily use, which is not what "clear the DB" should mean. Wipe
	// children first (results/history/subscription) then nodes, in one tx.
	tables := []string{"results", "history", "subscription", "nodes"}
	tx, terr := s.st.DB().Begin()
	if terr != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "cleanup failed", terr)
		return
	}
	for _, t := range tables {
		if _, e := tx.Exec("DELETE FROM " + t); e != nil {
			_ = tx.Rollback()
			writeJSONErrorLog(w, http.StatusInternalServerError, "cleanup failed", e)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "cleanup failed", err)
		return
	}
	after, err := s.countNodes()
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "cleanup count failed", err)
		return
	}
	writeJSON(w, map[string]any{
		"nodesBefore": before,
		"nodesAfter":  after,
		"removed":     before - after,
		"orphans":     0,
	})
}

// handleBanned lists the currently banned node hashes.
func (s *Server) handleBanned(w http.ResponseWriter, r *http.Request) {
	if s.bans == nil {
		writeJSONError(w, http.StatusNotFound, "ban store unavailable")
		return
	}
	writeJSON(w, map[string]any{"banned": s.bans.List()})
}

// handleBan adds a hash to the persisted ban list.
func (s *Server) handleBan(w http.ResponseWriter, r *http.Request) {
	if s.bans == nil {
		writeJSONError(w, http.StatusNotFound, "ban store unavailable")
		return
	}
	var body struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Hash == "" {
		writeJSONError(w, http.StatusBadRequest, "hash required")
		return
	}
	if err := s.bans.Add(body.Hash); err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to ban", err)
		return
	}
	writeJSON(w, map[string]any{"banned": s.bans.List()})
}

// handleUnban removes a hash from the persisted ban list.
func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	if s.bans == nil {
		writeJSONError(w, http.StatusNotFound, "ban store unavailable")
		return
	}
	hash, _ := url.PathUnescape(r.PathValue("hash"))
	if err := s.bans.Remove(hash); err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to unban", err)
		return
	}
	writeJSON(w, map[string]any{"banned": s.bans.List()})
}

func (s *Server) handleCycle(w http.ResponseWriter, r *http.Request) {
	s.sch.RequestCycle()
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]any{"requested": true})
}

// handleStopCycle aborts the currently running cycle (if any) without shutting
// down the process or the ticker. The scheduler's cycleCtx is cancelled so the
// in-flight cycle returns early; the next ticker tick starts a fresh one.
func (s *Server) handleStopCycle(w http.ResponseWriter, r *http.Request) {
	s.sch.StopCycle()
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]any{"stopped": true})
}

// handleNodeConfig serves a single node's raw v2rayN URI so the user can copy
// it into an external client (e.g. Throne) to cross-check ping. It is mounted
// as a subtree under /api/nodes/ so it coexists with the exact /api/nodes and
// /api/nodes/test routes. Path form: /api/nodes/{hash}/config. The hash is the
// same sha256(protocol|host|port|user) the UI already carries (NodeView.Hash),
// computed here with s.hashNode so the existing UI hash resolves.
func (s *Server) handleNodeConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	prefix := "/" + s.cfg.Secret + "/api/nodes/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[1] != "config" || parts[0] == "" {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	hash := parts[0]
	n, err := s.st.NodeByHash(hash)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	uri, err := selector.NodeURI(n)
	if err != nil {
		writeJSONErrorLog(w, http.StatusInternalServerError, "failed to build node uri", err)
		return
	}
	writeJSON(w, map[string]any{
		"hash": hash,
		"name": selector.NormName(n),
		"uri":  uri,
	})
}
