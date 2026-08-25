package selector

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"vpn-sub-manager/internal/model"
)

const (
	singboxFile = "singbox.json"
	v2raynFile  = "v2rayn.txt"
	clashFile   = "clash.yaml"
	metaFile    = "meta.json"
)

// Persister writes the three generated subscription artifacts to a directory
// and records a generation timestamp. It refuses to overwrite good
// subscriptions with an empty/zero selection (keeping the previous files) and
// returns an error when the target directory is unwritable.
type Persister struct {
	Dir     string
	MinKeep int
	Log     func(string)
}

// NewPersister builds a Persister. minKeep <= 0 defaults to 1.
func NewPersister(dir string, minKeep int) *Persister {
	if minKeep <= 0 {
		minKeep = 1
	}
	return &Persister{Dir: dir, MinKeep: minKeep}
}

func (p *Persister) logf(format string, args ...interface{}) {
	if p.Log != nil {
		p.Log(fmt.Sprintf(format, args...))
		return
	}
	log.Printf(format, args...)
}

// Persist generates the artifacts for nodes and writes them. It is a no-op
// (keeping previous files) when the selection is smaller than MinKeep.
func (p *Persister) Persist(nodes []model.Node) error {
	minKeep := p.MinKeep
	if minKeep < 1 {
		minKeep = 1
	}
	if len(nodes) < minKeep {
		p.logf("select: skipping persist, only %d nodes selected (min %d), keeping previous files", len(nodes), minKeep)
		return nil
	}

	sb, err := SingBox(nodes)
	if err != nil {
		return fmt.Errorf("select: persist singbox: %w", err)
	}
	vn, err := V2RayN(nodes)
	if err != nil {
		return fmt.Errorf("select: persist v2rayn: %w", err)
	}
	cl, err := ClashMeta(nodes)
	if err != nil {
		return fmt.Errorf("select: persist clash: %w", err)
	}

	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		return fmt.Errorf("select: persist mkdir %s: %w", p.Dir, err)
	}

	if err := os.WriteFile(filepath.Join(p.Dir, singboxFile), sb, 0o644); err != nil {
		return fmt.Errorf("select: persist write singbox: %w", err)
	}
	if err := os.WriteFile(filepath.Join(p.Dir, v2raynFile), []byte(vn), 0o644); err != nil {
		return fmt.Errorf("select: persist write v2rayn: %w", err)
	}
	if err := os.WriteFile(filepath.Join(p.Dir, clashFile), cl, 0o644); err != nil {
		return fmt.Errorf("select: persist write clash: %w", err)
	}

	meta := fmt.Sprintf("generated_at: %s\nnodes: %d\n", time.Now().UTC().Format(time.RFC3339), len(nodes))
	if err := os.WriteFile(filepath.Join(p.Dir, metaFile), []byte(meta), 0o644); err != nil {
		return fmt.Errorf("select: persist write meta: %w", err)
	}
	return nil
}
