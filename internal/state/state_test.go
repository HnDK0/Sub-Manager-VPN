package state

import (
	"path/filepath"
	"testing"
	"time"

	"vpn-sub-manager/internal/model"
)

func newTestState(t *testing.T) *State {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenAndMigrations(t *testing.T) {
	s := newTestState(t)
	// meta table must exist and be queryable after migrations.
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM meta`).Scan(&n); err != nil {
		t.Fatalf("meta table missing: %v", err)
	}
}

func TestAddListSource(t *testing.T) {
	s := newTestState(t)
	if err := s.AddSource("https://example.com/sub", "raw"); err != nil {
		t.Fatalf("AddSource: %v", err)
	}
	srcs, err := s.ListSources()
	if err != nil {
		t.Fatalf("ListSources: %v", err)
	}
	if len(srcs) != 1 {
		t.Fatalf("want 1 source, got %d", len(srcs))
	}
	if srcs[0].URL != "https://example.com/sub" || srcs[0].Kind != "raw" || !srcs[0].Enabled {
		t.Fatalf("unexpected source: %+v", srcs[0])
	}
}

func TestUpsertNodeAndResult(t *testing.T) {
	s := newTestState(t)
	n := &model.Node{Protocol: model.SchemeVMess, Host: "1.2.3.4", Port: 443, User: "uuid-1", Name: "n1", Source: "src"}
	if err := s.UpsertNode(n, 1); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	id, err := s.NodeID(nodeHash(n))
	if err != nil {
		t.Fatalf("NodeID: %v", err)
	}
	if err := s.RecordResult(id, true, 50, 0, 1); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}

	var alive, latency, cycle int
	if err := s.db.QueryRow(`SELECT alive, latency_ms, cycle_id FROM results WHERE node_id = ?`, id).Scan(&alive, &latency, &cycle); err != nil {
		t.Fatalf("read result: %v", err)
	}
	if alive != 1 || latency != 50 || cycle != 1 {
		t.Fatalf("unexpected result row: alive=%d latency=%d cycle=%d", alive, latency, cycle)
	}

	// Re-upserting the same node must not create a duplicate (hash is unique).
	if err := s.UpsertNode(n, 5); err != nil {
		t.Fatalf("UpsertNode again: %v", err)
	}
	srcs, _ := s.ListSources() // unrelated; just ensure no panic
	_ = srcs
	var cnt int
	s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE hash = ?`, nodeHash(n)).Scan(&cnt)
	if cnt != 1 {
		t.Fatalf("node duplicated, count=%d", cnt)
	}
	// last_seen_cycle should have advanced to 5.
	var lsc int
	s.db.QueryRow(`SELECT last_seen_cycle FROM nodes WHERE id = ?`, id).Scan(&lsc)
	if lsc != 5 {
		t.Fatalf("last_seen_cycle not updated, got %d", lsc)
	}
}

func TestUpsertNodeNormName(t *testing.T) {
	s := newTestState(t)
	n := &model.Node{Protocol: model.SchemeVMess, Host: "1.2.3.4", Port: 443, User: "uuid-1", Name: "raw-name", Source: "src"}
	if err := s.UpsertNode(n, 1); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	// Raw name must be preserved; norm_name is the derived display name.
	rows, err := s.ListNodes()
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 node, got %d", len(rows))
	}
	if rows[0].Name != "raw-name" {
		t.Fatalf("raw name overwritten: %q", rows[0].Name)
	}
	want := "\U0001F3F3 VMESS tcp 1.2.3.4:443 aes-128-gcm"
	if rows[0].NormName != want {
		t.Fatalf("norm_name = %q, want %q", rows[0].NormName, want)
	}

	// With a resolved country, the flag segment reflects it.
	n.Country = "JP"
	if err := s.UpsertNode(n, 2); err != nil {
		t.Fatalf("UpsertNode again: %v", err)
	}
	rows, _ = s.ListNodes()
	if rows[0].NormName != "\U0001F1EF\U0001F1F5 VMESS tcp 1.2.3.4:443 aes-128-gcm" {
		t.Fatalf("norm_name after country = %q", rows[0].NormName)
	}
}

func TestPruneHistoryDays(t *testing.T) {
	s := newTestState(t)
	n := &model.Node{Protocol: model.SchemeTrojan, Host: "9.9.9.9", Port: 443, User: "u", Source: "src"}
	s.UpsertNode(n, 1)
	id, _ := s.NodeID(nodeHash(n))

	// Recent (kept) and old (pruned) results.
	s.RecordResult(id, true, 10, 0, 1)
	old := time.Now().Unix() - int64(100)*86400
	s.db.Exec(`INSERT INTO results(node_id, alive, latency_ms, checked_at, cycle_id) VALUES(?, 0, 999, ?, 0)`, id, old)

	if err := s.Prune(Retention{HistoryDays: 30}, 1); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	var cnt int
	s.db.QueryRow(`SELECT COUNT(*) FROM results WHERE node_id = ?`, id).Scan(&cnt)
	if cnt != 1 {
		t.Fatalf("want 1 result after prune, got %d", cnt)
	}
}

func TestPruneHistoryCycles(t *testing.T) {
	s := newTestState(t)
	n := &model.Node{Protocol: model.SchemeSS, Host: "5.5.5.5", Port: 8388, User: "u", Source: "src"}
	s.UpsertNode(n, 1)
	id, _ := s.NodeID(nodeHash(n))

	for i := 1; i <= 250; i++ {
		s.db.Exec(`INSERT INTO history(node_id, latency_ms, checked_at, cycle_id) VALUES(?, ?, ?, ?)`, id, i, time.Now().Unix(), i)
	}
	if err := s.Prune(Retention{HistoryCycles: 200}, 1); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	var cnt int
	s.db.QueryRow(`SELECT COUNT(*) FROM history WHERE node_id = ?`, id).Scan(&cnt)
	if cnt != 200 {
		t.Fatalf("want 200 history rows, got %d", cnt)
	}
}

func TestPruneNodeTTL(t *testing.T) {
	s := newTestState(t)
	keep := &model.Node{Protocol: model.SchemeVLESS, Host: "1.1.1.1", Port: 443, User: "a", Source: "src"}
	drop := &model.Node{Protocol: model.SchemeVLESS, Host: "2.2.2.2", Port: 443, User: "b", Source: "src"}
	s.UpsertNode(keep, 95)
	s.UpsertNode(drop, 60) // last_seen_cycle far behind
	dropID, _ := s.NodeID(nodeHash(drop))

	if err := s.Prune(Retention{NodeTTLCycles: 30}, 100); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	var cnt int
	s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id = ?`, dropID).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("stale node not pruned, count=%d", cnt)
	}
	var keepCnt int
	s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE hash = ?`, nodeHash(keep)).Scan(&keepCnt)
	if keepCnt != 1 {
		t.Fatalf("fresh node wrongly pruned")
	}
}

func TestPruneDeadCycles(t *testing.T) {
	s := newTestState(t)
	n := &model.Node{Protocol: model.SchemeHysteria2, Host: "7.7.7.7", Port: 443, User: "u", Source: "src"}
	s.UpsertNode(n, 1)
	id, _ := s.NodeID(nodeHash(n))

	for i := 1; i <= 10; i++ {
		s.db.Exec(`INSERT INTO results(node_id, alive, latency_ms, checked_at, cycle_id) VALUES(?, 0, 0, ?, ?)`, id, time.Now().Unix(), i)
	}
	if err := s.Prune(Retention{DeadCycles: 10}, 1); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	var cnt int
	s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id = ?`, id).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("dead node not pruned, count=%d", cnt)
	}
}

func TestRetentionValidateClamp(t *testing.T) {
	r := Retention{HistoryCycles: 5, DeadCycles: 10}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if r.DeadCycles != 5 {
		t.Fatalf("expected DeadCycles clamped to 5, got %d", r.DeadCycles)
	}
	// Zero disables pruning and must not be clamped.
	r2 := Retention{HistoryCycles: 0, DeadCycles: 10}
	r2.Validate()
	if r2.DeadCycles != 10 {
		t.Fatalf("zero HistoryCycles should not clamp DeadCycles, got %d", r2.DeadCycles)
	}
}

func TestSetCountryRoundTrip(t *testing.T) {
	s := newTestState(t)
	n := &model.Node{Protocol: model.SchemeVMess, Host: "1.2.3.4", Port: 443, User: "uuid-1", Name: "n1", Source: "src"}
	if err := s.UpsertNode(n, 1); err != nil {
		t.Fatalf("UpsertNode: %v", err)
	}
	h := nodeHash(n)

	if err := s.SetCountry(h, "JP"); err != nil {
		t.Fatalf("SetCountry: %v", err)
	}
	var country string
	if err := s.db.QueryRow(`SELECT country FROM nodes WHERE hash = ?`, h).Scan(&country); err != nil {
		t.Fatalf("read country: %v", err)
	}
	if country != "JP" {
		t.Fatalf("want country JP, got %q", country)
	}

	// Unknown hash must error rather than silently no-op.
	if err := s.SetCountry("deadbeef", "US"); err == nil {
		t.Fatalf("SetCountry with unknown hash should error")
	}
}

func TestIncrementCycle(t *testing.T) {
	s := newTestState(t)
	c1, _ := s.IncrementCycle()
	c2, _ := s.IncrementCycle()
	if c1 != 1 || c2 != 2 {
		t.Fatalf("cycle counter wrong: %d -> %d", c1, c2)
	}
}
