// Package state implements the SQLite-backed persistence layer for
// vpn-sub-manager. It uses modernc.org/sqlite (pure-Go, no cgo).
package state

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"vpn-sub-manager/internal/model"
	selector "vpn-sub-manager/internal/select"

	_ "modernc.org/sqlite"
)

// State wraps the application database handle.
type State struct {
	db *sql.DB
}

// Source is a user-managed subscription source.
type Source struct {
	ID      int64
	URL     string
	Kind    string
	Enabled bool
	AddedAt int64
}

// NodeRow is a node joined with its most recent liveness result, for display
// consumers (e.g. the TUI) that only need strings and a latest status.
type NodeRow struct {
	ID            int64
	Hash          string
	Name          string
	NormName      string
	Host          string
	Port          int
	Country       string
	Protocol      string
	Alive         bool
	LatencyMs     int
	SpeedKbps     int
	LastSeenCycle int
}

// Retention controls how aggressively the database is pruned so it grows only
// boundedly under continuous 24/7 operation. A field set to 0 disables that
// particular pruning entirely.
type Retention struct {
	HistoryDays   int // drop results older than this many days (per node)
	HistoryCycles int // keep at most this many history samples per node
	NodeTTLCycles int // delete nodes unseen for this many cycles
	DeadCycles    int // prune nodes with no alive result within this many cycles (cycle-delta from last alive)
}

// DefaultRetention returns the project-default retention window.
func DefaultRetention() Retention {
	return Retention{
		HistoryDays:   30,
		HistoryCycles: 200,
		NodeTTLCycles: 30,
		// DeadCycles: 0 — keep corpses in the DB so re-parsing a source upserts
		// the same hash instead of re-adding it as a fresh node (operator request).
		DeadCycles: 0,
	}
}

// Validate enforces HistoryCycles >= DeadCycles when both are non-zero. If a
// user configures HistoryCycles < DeadCycles (and neither is 0) we clamp
// DeadCycles down to HistoryCycles rather than rejecting: the history window
// must never be smaller than the consecutive-dead threshold it backs, and
// clamping keeps the config loadable instead of hard-failing the whole app.
// A 0 value disables that pruning, so no truncation occurs.
func (r *Retention) Validate() error {
	if r.HistoryCycles != 0 && r.DeadCycles != 0 && r.HistoryCycles < r.DeadCycles {
		r.DeadCycles = r.HistoryCycles
	}
	return nil
}

// migrations are idempotent (CREATE TABLE IF NOT EXISTS).
var migrations = []string{
	`CREATE TABLE IF NOT EXISTS sources(
		id INTEGER PRIMARY KEY,
		url TEXT UNIQUE NOT NULL,
		kind TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		added_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS nodes(
		id INTEGER PRIMARY KEY,
		hash TEXT UNIQUE NOT NULL,
		protocol TEXT,
		host TEXT,
		port INTEGER,
		name TEXT,
		source TEXT,
		country TEXT,
		added_at INTEGER NOT NULL,
		last_seen_cycle INTEGER NOT NULL DEFAULT 0,
		speed_kbps INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS results(
		node_id INTEGER NOT NULL,
		alive INTEGER NOT NULL,
		latency_ms INTEGER,
		speed_kbps INTEGER NOT NULL DEFAULT 0,
		checked_at INTEGER NOT NULL,
		cycle_id INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS history(
		node_id INTEGER NOT NULL,
		latency_ms INTEGER,
		checked_at INTEGER NOT NULL,
		cycle_id INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS meta(
		key TEXT PRIMARY KEY,
		value TEXT
	)`,
	// source_meta caches the last fetch validation headers per source URL so the
	// scheduler can issue a conditional GET (If-None-Match / If-Modified-Since).
	// A 304 lets us reuse the previously parsed nodes instead of re-downloading
	// and re-parsing an unchanged source. body_sha covers servers that send no
	// validation headers at all: we still download but skip the parse on a match.
	`CREATE TABLE IF NOT EXISTS source_meta(
		url TEXT PRIMARY KEY,
		etag TEXT NOT NULL DEFAULT '',
		last_modified TEXT NOT NULL DEFAULT '',
		body_sha TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL
	)`,
	// subscription is the curated pool: a subset of common nodes (by node hash)
	// that is served to out/. It is independent of the common pool — the common
	// pool is internal-only and never written to out/ directly.
	`CREATE TABLE IF NOT EXISTS subscription(
		node_id TEXT PRIMARY KEY,
		added_at INTEGER NOT NULL,
		valid_checked_at INTEGER NOT NULL DEFAULT 0,
		ping_latency_ms INTEGER NOT NULL DEFAULT 0,
		ping_checked_at INTEGER NOT NULL DEFAULT 0
	)`,
	// LatestResult and deadNodeIDs (Prune) both probe results.node_id with
	// per-node queries across the whole candidate set every cycle. Without these
	// indexes Postgres-free SQLite does a full table scan of results (which grows
	// to HistoryCycles * node_count rows, millions) for every one of ~16k calls —
	// that is the multi-minute end-of-cycle hang. Add them once, idempotently.
	`CREATE INDEX IF NOT EXISTS idx_results_node ON results(node_id)`,
	`CREATE INDEX IF NOT EXISTS idx_history_node ON history(node_id)`,
}

// Open opens (creating if needed) the SQLite database at path and runs
// migrations.
func Open(path string) (*State, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// WAL lets a reader and the single writer proceed concurrently, so we can
	// raise MaxOpenConns above 1: the web layer (reads) and the scheduler
	// (writes) no longer serialize on one connection and stop hitting
	// "database is locked". busy_timeout still covers the brief write-writer
	// contention that remains.
	db.SetMaxOpenConns(4)
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("busy timeout: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("wal: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	s := &State{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *State) Close() error {
	return s.db.Close()
}

// DB returns the underlying *sql.DB handle so other packages (e.g. config)
// can run their own parameterized queries over the SAME connection. The state
// layer remains the single owner of the connection; callers must not Close it.
func (s *State) DB() *sql.DB {
	return s.db
}

func (s *State) migrate() error {
	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration: %w", err)
		}
	}
	// ALTER TABLE has no IF NOT EXISTS; add the display column idempotently.
	if err := s.addColumnIfNotExists("nodes", "norm_name", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migration norm_name: %w", err)
	}
	// ponytail: node_json stores the full canonical model.Node (credential +
	// transport) so subscription members and same-country replacements can be
	// reconstructed into working configs instead of the partial hash/name row
	// that previously lost the credential and produced broken subscriptions.
	if err := s.addColumnIfNotExists("nodes", "node_json", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migration nodes.node_json: %w", err)
	}
	// ponytail: speed_kbps added for throughput measurement (REWORK.md).
	if err := s.addColumnIfNotExists("nodes", "speed_kbps", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("migration nodes.speed_kbps: %w", err)
	}
	if err := s.addColumnIfNotExists("results", "speed_kbps", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("migration results.speed_kbps: %w", err)
	}
	// Clean legacy garbage in country column: old binaries stored remark text
	// (e.g. " By EbraSha ⌨️ | 124ms") instead of ISO codes.  Idempotent —
	// on a clean DB this touches zero rows; on legacy data it blanks everything
	// that isn't a strict 2-letter A-Z code.  The scheduler re-resolves real
	// codes on the next cycle.
	if _, err := s.db.Exec(`UPDATE nodes SET country = '' WHERE country != '' AND (
		length(country) != 2 OR country = 'XX' OR
		UPPER(SUBSTR(country, 1, 1)) NOT BETWEEN 'A' AND 'Z' OR
		UPPER(SUBSTR(country, 2, 1)) NOT BETWEEN 'A' AND 'Z'
	)`); err != nil {
		return fmt.Errorf("migration clean country: %w", err)
	}
	return nil
}

// addColumnIfNotExists adds col to table only if it is absent, so migrations
// stay repeatable across opens. table is a compile-time constant (no injection
// surface); col is matched by name.
func (s *State) addColumnIfNotExists(table, col, def string) error {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return fmt.Errorf("column check: %w", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("scan column: %w", err)
		}
		if name == col {
			found = true
			break
		}
	}
	if found {
		return nil
	}
	if _, err := s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, col, def)); err != nil {
		return fmt.Errorf("add column: %w", err)
	}
	return nil
}

// nodeHash computes a stable dedup key from protocol|host|port|user|security|encryption.
// Includes Security/Encryption so nodes that differ only in those fields (kept
// distinct by filter.Dedup) don't collide here or in scheduler/engine lookups.
func nodeHash(n *model.Node) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|%s|%s", n.Protocol, n.Host, n.Port, n.User, n.Security, n.Encryption)))
	return hex.EncodeToString(sum[:])
}

// AddSource inserts a new subscription source (enabled by default).
func (s *State) AddSource(url, kind string) error {
	_, err := s.db.Exec(
		`INSERT INTO sources(url, kind, enabled, added_at) VALUES(?, ?, 1, ?)`,
		url, kind, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("add source: %w", err)
	}
	return nil
}

// SourceMeta is the per-URL fetch cache: the last validation headers returned
// by the source so the next cycle can issue a conditional GET, plus a hash of
// the body to skip re-parsing on servers that send no validation headers.
type SourceMeta struct {
	ETag         string
	LastModified string
	BodySHA      string
}

// GetSourceMeta returns the cached validation headers for url. The bool is false
// when no row exists (fresh source) or on error.
func (s *State) GetSourceMeta(url string) (SourceMeta, bool) {
	var m SourceMeta
	err := s.db.QueryRow(
		`SELECT etag, last_modified, body_sha FROM source_meta WHERE url = ?`, url,
	).Scan(&m.ETag, &m.LastModified, &m.BodySHA)
	if err != nil {
		return SourceMeta{}, false
	}
	return m, true
}

// SetSourceMeta upserts the validation headers for url.
func (s *State) SetSourceMeta(url string, m SourceMeta) error {
	if _, err := s.db.Exec(
		`INSERT INTO source_meta(url, etag, last_modified, body_sha, updated_at)
		 VALUES(?, ?, ?, ?, ?)
		 ON CONFLICT(url) DO UPDATE SET
		   etag = excluded.etag,
		   last_modified = excluded.last_modified,
		   body_sha = excluded.body_sha,
		   updated_at = excluded.updated_at`,
		url, m.ETag, m.LastModified, m.BodySHA, time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("set source meta: %w", err)
	}
	return nil
}

// ListSources returns all known sources.
func (s *State) ListSources() ([]Source, error) {
	rows, err := s.db.Query(`SELECT id, url, kind, enabled, added_at FROM sources ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list sources: %w", err)
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var src Source
		var enabled int
		if err := rows.Scan(&src.ID, &src.URL, &src.Kind, &enabled, &src.AddedAt); err != nil {
			return nil, fmt.Errorf("scan source: %w", err)
		}
		src.Enabled = enabled != 0
		out = append(out, src)
	}
	return out, rows.Err()
}

// ListNodes returns every node joined with its latest results row (by max
// cycle_id). Nodes with no results yet report Alive=false, LatencyMs=0 and
// LastSeenCycle=0. Used by the TUI status screen.
func (s *State) ListNodes() ([]NodeRow, error) {
	const q = `
		SELECT n.id, n.hash, n.name, n.norm_name, n.host, n.port, n.country, n.protocol,
		       COALESCE(r.alive, 0), COALESCE(r.latency_ms, 0), COALESCE(r.speed_kbps, 0), COALESCE(r.cycle_id, 0)
		FROM nodes n
		LEFT JOIN (
			SELECT node_id, alive, latency_ms, speed_kbps, cycle_id,
			       ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY cycle_id DESC, checked_at DESC) AS rn
			FROM results
		) r ON r.node_id = n.id AND r.rn = 1
		ORDER BY n.id`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()
	var out []NodeRow
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
			cycle    int
		)
		if err := rows.Scan(&id, &hash, &name, &normName, &host, &port, &country, &proto, &alive, &latency, &speed, &cycle); err != nil {
			return nil, fmt.Errorf("scan node row: %w", err)
		}
		out = append(out, NodeRow{
			ID:            id,
			Hash:          hash,
			Name:          name,
			NormName:      normName,
			Host:          host,
			Port:          port,
			Country:       country,
			Protocol:      proto,
			Alive:         alive != 0,
			LatencyMs:     latency,
			SpeedKbps:     speed,
			LastSeenCycle: cycle,
		})
	}
	return out, rows.Err()
}

// UpsertNode inserts a node or, if its hash already exists, refreshes its
// last_seen_cycle (and mutable display fields) without changing added_at. The
// normalized display name is derived from the node and stored in norm_name; the
// raw Node.Name is preserved unchanged.
func (s *State) UpsertNode(n *model.Node, cycle int) error {
	norm := selector.NormName(*n)
	nb, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("upsert node: marshal: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO nodes(hash, protocol, host, port, name, source, country, norm_name, node_json, added_at, last_seen_cycle)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(hash) DO UPDATE SET
		   last_seen_cycle = excluded.last_seen_cycle,
		   protocol = excluded.protocol,
		   host = excluded.host,
		   port = excluded.port,
		   name = excluded.name,
		   source = excluded.source,
		   norm_name = excluded.norm_name,
		   node_json = excluded.node_json`,
		nodeHash(n), string(n.Protocol), n.Host, n.Port, n.Name, n.Source, "", norm, string(nb), time.Now().Unix(), cycle,
	)
	if err != nil {
		return fmt.Errorf("upsert node: %w", err)
	}
	return nil
}

// UpsertNodeWithCountry inserts a node or, on hash conflict, refreshes its
// mutable display fields — exactly like UpsertNode — but writes the resolved
// country in the SAME transaction, so a node is never persisted with an empty
// country. The write is wrapped in a single sql.Tx and is idempotent.
func (s *State) UpsertNodeWithCountry(node model.Node, country string) error {
	norm := selector.NormName(node)
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("upsert node+country: begin: %w", err)
	}
	defer tx.Rollback()
	// Keep last_seen_cycle accurate for TTL pruning without a cycle argument:
	// the scheduler increments meta.cycle at the start of every cycle.
	var cycle int
	if err := tx.QueryRow(`SELECT value FROM meta WHERE key = 'cycle'`).Scan(&cycle); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("upsert node+country: read cycle: %w", err)
	}
	nb, err := json.Marshal(&node)
	if err != nil {
		return fmt.Errorf("upsert node+country: marshal: %w", err)
	}
	_, err = tx.Exec(
		`INSERT INTO nodes(hash, protocol, host, port, name, source, country, norm_name, node_json, added_at, last_seen_cycle)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(hash) DO UPDATE SET
		   last_seen_cycle = excluded.last_seen_cycle,
		   protocol = excluded.protocol,
		   host = excluded.host,
		   port = excluded.port,
		   name = excluded.name,
		   source = excluded.source,
		   country = excluded.country,
		   norm_name = excluded.norm_name,
		   node_json = excluded.node_json`,
		nodeHash(&node), string(node.Protocol), node.Host, node.Port, node.Name, node.Source, country, norm, string(nb), time.Now().Unix(), cycle,
	)
	if err != nil {
		return fmt.Errorf("upsert node+country: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("upsert node+country: commit: %w", err)
	}
	return nil
}

// SetCountry persists the resolved ISO country code for the node with the
// given hash. It is used by the geo scheduler to record lookups; it does not
// touch any other column (UpsertNode remains the owner of node fields).
func (s *State) SetCountry(hash string, country string) error {
	res, err := s.db.Exec(`UPDATE nodes SET country = ? WHERE hash = ?`, country, hash)
	if err != nil {
		return fmt.Errorf("set country: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("set country: no node with hash %q", hash)
	}
	return nil
}

// NodeID returns the id of the node with the given hash, or an error if none.
func (s *State) NodeID(hash string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM nodes WHERE hash = ?`, hash).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("node id: %w", err)
	}
	return id, nil
}

// RecordResult stores a single liveness check for a node. speedKbps is the
// measured throughput (0 if not measured); it is also written onto the node
// row so the web layer can surface it without a join.
func (s *State) RecordResult(nodeID int64, alive bool, latencyMs int, speedKbps int, cycle int) error {
	if _, err := s.db.Exec(
		`INSERT INTO results(node_id, alive, latency_ms, speed_kbps, checked_at, cycle_id) VALUES(?, ?, ?, ?, ?, ?)`,
		nodeID, boolToInt(alive), latencyMs, speedKbps, time.Now().Unix(), cycle,
	); err != nil {
		return fmt.Errorf("record result: %w", err)
	}
	if _, err := s.db.Exec(
		`UPDATE nodes SET speed_kbps = ? WHERE id = ?`,
		speedKbps, nodeID,
	); err != nil {
		return fmt.Errorf("record result speed: %w", err)
	}
	return nil
}

// AddHistory appends a latency sample to the per-node history log.
func (s *State) AddHistory(nodeID int64, latencyMs int, cycle int) error {
	_, err := s.db.Exec(
		`INSERT INTO history(node_id, latency_ms, checked_at, cycle_id) VALUES(?, ?, ?, ?)`,
		nodeID, latencyMs, time.Now().Unix(), cycle,
	)
	if err != nil {
		return fmt.Errorf("add history: %w", err)
	}
	return nil
}

// BatchResult carries one probe outcome for batched persistence.
type BatchResult struct {
	Hash      string
	Alive     bool
	LatencyMs int
	SpeedKbps int
}

// RecordResultsBatch persists a full probe fan-out. To avoid holding the SQLite
// write lock for one giant transaction (which would starve SubValidity), rows are
// committed in chunks; each chunk is its own short transaction so other writers
// can interleave between them. The previous per-worker design serialized 492
// goroutines on the write lock, collapsing probe concurrency and causing
// SQLITE_BUSY.
func (s *State) RecordResultsBatch(rows []BatchResult, cycle int) error {
	const chunk = 2000
	for start := 0; start < len(rows); start += chunk {
		end := start + chunk
		if end > len(rows) {
			end = len(rows)
		}
		if err := s.recordChunk(rows[start:end], cycle); err != nil {
			return err
		}
	}
	return nil
}

func (s *State) recordChunk(rows []BatchResult, cycle int) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin batch: %w", err)
	}
	now := time.Now().Unix()
	for _, r := range rows {
		id, e := s.NodeID(r.Hash)
		if e != nil {
			continue
		}
		if _, e := tx.Exec(
			`INSERT INTO results(node_id, alive, latency_ms, speed_kbps, checked_at, cycle_id) VALUES(?, ?, ?, ?, ?, ?)`,
			id, boolToInt(r.Alive), r.LatencyMs, r.SpeedKbps, now, cycle,
		); e != nil {
			tx.Rollback()
			return fmt.Errorf("batch result: %w", e)
		}
		if _, e := tx.Exec(
			`UPDATE nodes SET speed_kbps = ? WHERE id = ?`,
			r.SpeedKbps, id,
		); e != nil {
			tx.Rollback()
			return fmt.Errorf("batch speed: %w", e)
		}
		if _, e := tx.Exec(
			`INSERT INTO history(node_id, latency_ms, checked_at, cycle_id) VALUES(?, ?, ?, ?)`,
			id, r.LatencyMs, now, cycle,
		); e != nil {
			tx.Rollback()
			return fmt.Errorf("batch history: %w", e)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

// IncrementCycle reads the monotonic cycle counter from meta, increments it,
// persists it, and returns the new value (starting at 1 on a fresh DB).
func (s *State) IncrementCycle() (int, error) {
	var cur int
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'cycle'`).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("read cycle: %w", err)
	}
	cur++
	if _, err := s.db.Exec(
		`INSERT INTO meta(key, value) VALUES('cycle', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		cur,
	); err != nil {
		return 0, fmt.Errorf("write cycle: %w", err)
	}
	return cur, nil
}

// LastSuccess returns the timestamp of the last successful cycle, if one has
// been recorded. The boolean is false when no successful cycle has run yet (or
// on a fresh DB). An error is returned only for storage failures.
func (s *State) LastSuccess() (time.Time, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'last_success'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("read last_success: %w", err)
	}
	ts, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parse last_success: %w", err)
	}
	return ts, true, nil
}

// SetLastSuccess records the timestamp of a successful cycle so the scheduler
// can skip a redundant immediate cycle on restart.
func (s *State) SetLastSuccess(t time.Time) error {
	if _, err := s.db.Exec(
		`INSERT INTO meta(key, value) VALUES('last_success', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		t.Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("write last_success: %w", err)
	}
	return nil
}

// Prune enforces the retention policy. It is safe to call with a zero-valued
// Retention (nothing is pruned). sources is never touched.
func (s *State) Prune(cfg Retention, currentCycle int) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	// 1. Drop results older than HistoryDays.
	if cfg.HistoryDays != 0 {
		cutoff := time.Now().Unix() - int64(cfg.HistoryDays)*86400
		if _, err := s.db.Exec(`DELETE FROM results WHERE checked_at < ?`, cutoff); err != nil {
			return fmt.Errorf("prune results by days: %w", err)
		}
	}

	// 2. Keep only the last HistoryCycles history rows per node.
	if cfg.HistoryCycles != 0 {
		if _, err := s.db.Exec(`
			DELETE FROM history WHERE rowid IN (
				SELECT rowid FROM (
					SELECT rowid,
					       row_number() OVER (PARTITION BY node_id ORDER BY cycle_id DESC, checked_at DESC) AS rn
					FROM history
				) WHERE rn > ?
			)`, cfg.HistoryCycles); err != nil {
			return fmt.Errorf("prune history by cycles: %w", err)
		}
	}

	// 3. Delete nodes past their TTL.
	if cfg.NodeTTLCycles != 0 {
		if _, err := s.db.Exec(
			`DELETE FROM nodes WHERE ? - last_seen_cycle > ?`, currentCycle, cfg.NodeTTLCycles,
		); err != nil {
			return fmt.Errorf("prune nodes by ttl: %w", err)
		}
	}

	// 4. Delete nodes with no alive result within DeadCycles cycles (cycle-delta).
	if cfg.DeadCycles != 0 {
		ids, err := s.deadNodeIDs(cfg.DeadCycles, currentCycle)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := s.db.Exec(`DELETE FROM nodes WHERE id = ?`, id); err != nil {
				return fmt.Errorf("prune dead node: %w", err)
			}
			// Tidy orphaned rows so the file stays bounded.
			s.db.Exec(`DELETE FROM results WHERE node_id = ?`, id)
			s.db.Exec(`DELETE FROM history WHERE node_id = ?`, id)
		}
	}

	// Drop subscription rows whose node no longer exists (e.g. pruned above),
	// so the curated pool stays consistent with the common pool.
	if _, err := s.PruneOrphanSubs(); err != nil {
		return fmt.Errorf("prune orphan subs: %w", err)
	}

	return nil
}

// DeleteOrphanNodes removes nodes that have no results row at all — typically
// stale test artifacts that were upserted but never successfully probed. It uses
// NOT EXISTS so it also deletes everything when the results table is empty (no
// NULL-in-subquery trap). It is safe to call repeatedly (idempotent) and returns
// the number of nodes removed.
func (s *State) DeleteOrphanNodes() (int, error) {
	res, err := s.db.Exec(`
		DELETE FROM nodes
		WHERE NOT EXISTS (SELECT 1 FROM results WHERE results.node_id = nodes.id)`)
	if err != nil {
		return 0, fmt.Errorf("delete orphans: %w", err)
	}
	// Tidy any dangling history (none should exist without a node, but be safe).
	s.db.Exec(`DELETE FROM history WHERE NOT EXISTS (SELECT 1 FROM nodes WHERE nodes.id = history.node_id)`)
	n, _ := res.RowsAffected()
	return int(n), nil
}

// AliveNodeHashes returns the hashes of nodes whose most-recent results row is
// alive=1. The scheduler uses this to partition the freshly-parsed node set so
// the cycle probes the previously-alive ("valid") pool first and cleans corpses
// out of it at the start of the probe phase.
func (s *State) AliveNodeHashes() ([]string, error) {
	const q = `
		SELECT n.hash
		FROM nodes n
		JOIN (
			SELECT node_id, alive,
			       ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY cycle_id DESC, checked_at DESC) AS rn
			FROM results
		) r ON r.node_id = n.id AND r.rn = 1
		WHERE r.alive = 1`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("alive node hashes: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scan alive hash: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// deadNodeIDs returns the ids of nodes that have not been seen alive within the
// last deadCycles cycles. A node is pruned when its most recent ALIVE result is
// older than deadCycles cycles (or it has never been alive). The window is a
// cycle-delta from the last alive result, so it maps to wall-clock weeks
// regardless of how often dead nodes are re-probed on the ReProbeCycles rotation.
// deadCycles <= 0 disables the prune.
func (s *State) deadNodeIDs(deadCycles, currentCycle int) ([]int64, error) {
	if deadCycles <= 0 {
		return nil, nil
	}
	const q = `
		WITH la(nid, last_alive) AS (
			SELECT n.id, COALESCE((SELECT MAX(r.cycle_id) FROM results r WHERE r.node_id = n.id AND r.alive = 1), -1)
			FROM nodes n
		)
		SELECT nid FROM la WHERE last_alive = -1 OR last_alive < ? - ?`
	rows, err := s.db.Query(q, currentCycle, deadCycles)
	if err != nil {
		return nil, fmt.Errorf("dead node ids: %w", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan dead id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// NodeByHash returns the model.Node for a node hash, or an error if none
// exists. Used by the subscription routines to resolve a member hash to a node
// for probing/replacement (the engine.Probe path needs a model.Node).
func (s *State) NodeByHash(hash string) (model.Node, error) {
	const q = `
		SELECT n.hash, n.name, n.host, n.port, n.country, n.protocol, n.source, n.node_json
		FROM nodes n
		WHERE n.hash = ?`
	var (
		h        string
		name     string
		host     string
		port     int
		country  string
		proto    string
		source   string
		nodeJSON string
	)
	if err := s.db.QueryRow(q, hash).Scan(&h, &name, &host, &port, &country, &proto, &source, &nodeJSON); err != nil {
		return model.Node{}, fmt.Errorf("node by hash: %w", err)
	}
	if nodeJSON != "" {
		var n model.Node
		if err := json.Unmarshal([]byte(nodeJSON), &n); err == nil {
			return n, nil
		}
		// fall through to legacy partial reconstruction on parse error
	}
	return model.Node{
		Protocol: model.Scheme(proto),
		Host:     host,
		Port:     port,
		Name:     name,
		Country:  country,
		Source:   source,
		User:     name,
	}, nil
}

// LatestResult returns the most recent results row for a node id, or an error
// if none exists. Used by the scheduler to seed latency labels for ordering.
func (s *State) LatestResult(nodeID int64) (ResultRow, error) {
	const q = `
		SELECT alive, latency_ms, speed_kbps, cycle_id
		FROM results WHERE node_id = ?
		ORDER BY cycle_id DESC, checked_at DESC LIMIT 1`
	var r ResultRow
	var alive int
	if err := s.db.QueryRow(q, nodeID).Scan(&alive, &r.LatencyMs, &r.SpeedKbps, &r.CycleID); err != nil {
		return ResultRow{}, fmt.Errorf("latest result: %w", err)
	}
	r.Alive = alive != 0
	return r, nil
}

// ResultRow is a single liveness result (used by LatestResult).
type ResultRow struct {
	Alive     bool
	LatencyMs int
	SpeedKbps int
	CycleID   int
}

// CommonAliveSameCountry returns alive common-pool nodes in the given country,
// excluding any country in excludeCountries and any protocol in excludeProtocols.
// Used by ReplaceRoutine to find a same-country replacement for a dead member.
func (s *State) CommonAliveSameCountry(country string, excludeCountries, excludeProtocols []string) ([]selector.Candidate, error) {
	const q = `
		SELECT n.hash, n.name, n.norm_name, n.host, n.port, n.country, n.protocol,
		       COALESCE(r.latency_ms, 0), n.node_json
		FROM nodes n
		LEFT JOIN (
			SELECT node_id, alive, latency_ms,
			       ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY cycle_id DESC, checked_at DESC) AS rn
			FROM results
		) r ON r.node_id = n.id AND r.rn = 1
		WHERE n.country = ? AND COALESCE(r.alive, 0) = 1`
	rows, err := s.db.Query(q, country)
	if err != nil {
		return nil, fmt.Errorf("common same-country: %w", err)
	}
	defer rows.Close()
	exC := make(map[string]bool)
	for _, c := range excludeCountries {
		exC[c] = true
	}
	exP := make(map[string]bool)
	for _, p := range excludeProtocols {
		exP[p] = true
	}
	var out []selector.Candidate
	for rows.Next() {
		var (
			hash     string
			name     string
			norm     string
			host     string
			port     int
			country  string
			proto    string
			latency  int
			nodeJSON string
		)
		if err := rows.Scan(&hash, &name, &norm, &host, &port, &country, &proto, &latency, &nodeJSON); err != nil {
			return nil, fmt.Errorf("scan common: %w", err)
		}
		if exC[country] || exP[proto] {
			continue
		}
		node := model.Node{
			Protocol: model.Scheme(proto),
			Host:     host,
			Port:     port,
			Name:     name,
			Country:  country,
			User:     name,
		}
		if nodeJSON != "" {
			var full model.Node
			if err := json.Unmarshal([]byte(nodeJSON), &full); err == nil {
				full.Country = country
				node = full
			}
		}
		out = append(out, selector.Candidate{
			Node:      node,
			LatencyMs: latency,
			Country:   country,
		})
	}
	return out, rows.Err()
}

// SubscriptionMemberNodes returns the full model.Node for every current
// subscription member (joined from nodes). Used by regenerateSubs to build the
// served output.
func (s *State) SubscriptionMemberNodes() ([]model.Node, error) {
	const q = `
		SELECT n.hash, n.name, n.norm_name, n.host, n.port, n.country, n.protocol, n.source, n.node_json
		FROM subscription sub
		JOIN nodes n ON n.hash = sub.node_id
		ORDER BY sub.added_at`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("subscription members: %w", err)
	}
	defer rows.Close()
	var out []model.Node
	for rows.Next() {
		var (
			hash     string
			name     string
			norm     string
			host     string
			port     int
			country  string
			proto    string
			source   string
			nodeJSON string
		)
		if err := rows.Scan(&hash, &name, &norm, &host, &port, &country, &proto, &source, &nodeJSON); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		node := model.Node{
			Protocol: model.Scheme(proto),
			Host:     host,
			Port:     port,
			Name:     name,
			Country:  country,
			Source:   source,
			User:     name,
		}
		if nodeJSON != "" {
			var full model.Node
			if err := json.Unmarshal([]byte(nodeJSON), &full); err == nil {
				full.Country = country
				full.Name = norm
				node = full
			}
		}
		out = append(out, node)
	}
	return out, rows.Err()
}

// SubscriptionRow is a subscription table row (for listing/status).
type SubscriptionRow struct {
	NodeID         string
	AddedAt        int64
	ValidCheckedAt int64
	PingLatencyMs  int
	PingCheckedAt  int64
}

// ListSubscription returns all subscription rows.
func (s *State) ListSubscription() ([]SubscriptionRow, error) {
	rows, err := s.db.Query(`SELECT node_id, added_at, valid_checked_at, ping_latency_ms, ping_checked_at FROM subscription ORDER BY added_at`)
	if err != nil {
		return nil, fmt.Errorf("list subscription: %w", err)
	}
	defer rows.Close()
	var out []SubscriptionRow
	for rows.Next() {
		var r SubscriptionRow
		if err := rows.Scan(&r.NodeID, &r.AddedAt, &r.ValidCheckedAt, &r.PingLatencyMs, &r.PingCheckedAt); err != nil {
			return nil, fmt.Errorf("scan subscription: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddSubscription adds a node hash to the subscription pool (idempotent).
func (s *State) AddSubscription(nodeHash string) error {
	if _, err := s.db.Exec(
		`INSERT INTO subscription(node_id, added_at) VALUES(?, ?)
		 ON CONFLICT(node_id) DO NOTHING`,
		nodeHash, time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("add subscription: %w", err)
	}
	return nil
}

// RemoveSubscription removes a node hash from the subscription pool (idempotent).
func (s *State) RemoveSubscription(nodeHash string) error {
	if _, err := s.db.Exec(`DELETE FROM subscription WHERE node_id = ?`, nodeHash); err != nil {
		return fmt.Errorf("remove subscription: %w", err)
	}
	return nil
}

// SubPingRow is one batched subscription-latency update.
type SubPingRow struct {
	NodeHash  string
	LatencyMs int
}

// SetSubValidCheckedBatch records the aliveness check time for many members in
// chunked transactions. This mirrors RecordResultsBatch: one short transaction
// per chunk instead of one transaction per node, so SubValidity/SubPing don't
// acquire the SQLite write lock N times and contend with CommonScan (SQLITE_BUSY).
func (s *State) SetSubValidCheckedBatch(hashes []string, ts int64) error {
	const chunk = 2000
	for start := 0; start < len(hashes); start += chunk {
		end := start + chunk
		if end > len(hashes) {
			end = len(hashes)
		}
		if err := s.setSubValidChunk(hashes[start:end], ts); err != nil {
			return err
		}
	}
	return nil
}

func (s *State) setSubValidChunk(hashes []string, ts int64) error {
	if len(hashes) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin subvalid batch: %w", err)
	}
	for _, h := range hashes {
		if _, err := tx.Exec(`UPDATE subscription SET valid_checked_at = ? WHERE node_id = ?`, ts, h); err != nil {
			tx.Rollback()
			return fmt.Errorf("set sub valid: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit subvalid batch: %w", err)
	}
	return nil
}

// SetSubPingBatch records latency samples for many members in chunked
// transactions (see SetSubValidCheckedBatch for the rationale).
func (s *State) SetSubPingBatch(rows []SubPingRow, ts int64) error {
	const chunk = 2000
	for start := 0; start < len(rows); start += chunk {
		end := start + chunk
		if end > len(rows) {
			end = len(rows)
		}
		if err := s.setSubPingChunk(rows[start:end], ts); err != nil {
			return err
		}
	}
	return nil
}

func (s *State) setSubPingChunk(rows []SubPingRow, ts int64) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin subping batch: %w", err)
	}
	for _, r := range rows {
		if _, err := tx.Exec(`UPDATE subscription SET ping_latency_ms = ?, ping_checked_at = ? WHERE node_id = ?`, r.LatencyMs, ts, r.NodeHash); err != nil {
			tx.Rollback()
			return fmt.Errorf("set sub ping: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit subping batch: %w", err)
	}
	return nil
}

// PruneOrphanSubs removes subscription rows whose node no longer exists (e.g.
// the node was pruned by retention). Keeps the subscription pool bounded and
// consistent with the common pool.
func (s *State) PruneOrphanSubs() (int, error) {
	res, err := s.db.Exec(`
		DELETE FROM subscription
		WHERE NOT EXISTS (SELECT 1 FROM nodes WHERE nodes.hash = subscription.node_id)`)
	if err != nil {
		return 0, fmt.Errorf("prune orphan subs: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
