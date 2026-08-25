// Package state implements the SQLite-backed persistence layer for
// vpn-sub-manager. It uses modernc.org/sqlite (pure-Go, no cgo).
package state

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
	Name          string
	NormName      string
	Host          string
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
	DeadCycles    int // delete nodes with this many consecutive dead results
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
		SELECT n.id, n.name, n.norm_name, n.host, n.country, n.protocol,
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
			name     string
			normName string
			host     string
			country  string
			proto    string
			alive    int
			latency  int
			speed    int
			cycle    int
		)
		if err := rows.Scan(&id, &name, &normName, &host, &country, &proto, &alive, &latency, &speed, &cycle); err != nil {
			return nil, fmt.Errorf("scan node row: %w", err)
		}
		out = append(out, NodeRow{
			ID:            id,
			Name:          name,
			NormName:      normName,
			Host:          host,
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
	_, err := s.db.Exec(
		`INSERT INTO nodes(hash, protocol, host, port, name, source, country, norm_name, added_at, last_seen_cycle)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(hash) DO UPDATE SET
		   last_seen_cycle = excluded.last_seen_cycle,
		   protocol = excluded.protocol,
		   host = excluded.host,
		   port = excluded.port,
		   name = excluded.name,
		   source = excluded.source,
		   norm_name = excluded.norm_name`,
		nodeHash(n), string(n.Protocol), n.Host, n.Port, n.Name, n.Source, "", norm, time.Now().Unix(), cycle,
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
	_, err = tx.Exec(
		`INSERT INTO nodes(hash, protocol, host, port, name, source, country, norm_name, added_at, last_seen_cycle)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(hash) DO UPDATE SET
		   last_seen_cycle = excluded.last_seen_cycle,
		   protocol = excluded.protocol,
		   host = excluded.host,
		   port = excluded.port,
		   name = excluded.name,
		   source = excluded.source,
		   country = excluded.country,
		   norm_name = excluded.norm_name`,
		nodeHash(&node), string(node.Protocol), node.Host, node.Port, node.Name, node.Source, country, norm, time.Now().Unix(), cycle,
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

	// 4. Delete nodes with DeadCycles consecutive dead results (most recent first).
	if cfg.DeadCycles != 0 {
		ids, err := s.deadNodeIDs(cfg.DeadCycles)
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

// ConsecutiveDead returns how many of a node's results, counting from the most
// recent backwards, were dead (not alive) before the first alive result. Nodes
// with no results yield 0. It backs the scheduler's corpse-skip and the
// DeadCycles retention prune.
func (s *State) ConsecutiveDead(nodeID int64) (int, error) {
	res, err := s.db.Query(`SELECT alive FROM results WHERE node_id = ? ORDER BY cycle_id DESC`, nodeID)
	if err != nil {
		return 0, fmt.Errorf("consecutive dead: %w", err)
	}
	defer res.Close()
	count := 0
	for res.Next() {
		var alive bool
		if err := res.Scan(&alive); err != nil {
			return 0, fmt.Errorf("scan result: %w", err)
		}
		if !alive {
			count++
		} else {
			break
		}
	}
	return count, res.Err()
}

// deadNodeIDs returns the ids of nodes whose consecutive-dead count reaches
// deadCycles (most recent results all dead).
func (s *State) deadNodeIDs(deadCycles int) ([]int64, error) {
	nodeRows, err := s.db.Query(`SELECT id FROM nodes`)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	var nodeIDs []int64
	for nodeRows.Next() {
		var id int64
		if err := nodeRows.Scan(&id); err != nil {
			nodeRows.Close()
			return nil, fmt.Errorf("scan node id: %w", err)
		}
		nodeIDs = append(nodeIDs, id)
	}
	nodeRows.Close()
	if err := nodeRows.Err(); err != nil {
		return nil, err
	}

	var dead []int64
	for _, nid := range nodeIDs {
		count, err := s.ConsecutiveDead(nid)
		if err != nil {
			return nil, err
		}
		if count >= deadCycles {
			dead = append(dead, nid)
		}
	}
	return dead, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
