package scheduler

import (
	"sort"

	"vpn-sub-manager/internal/model"
	selector "vpn-sub-manager/internal/select"
)

// applyDegrade swaps out selected nodes that are clearly degraded for the
// next-best alive node of the same country.
//
// A selected node is degraded when its latency exceeds 2x the median latency of
// the selected set, OR (when degradeMs > 0) exceeds degradeMs. The replacement
// is the lowest-latency alive candidate of the same country that is not already
// selected. If no such candidate exists the original node is kept. Dead nodes
// are never swapped in (cands only contains alive nodes).
func applyDegrade(selected []model.Node, cands []selector.Candidate, degradeMs int) []model.Node {
	if len(selected) == 0 {
		return selected
	}

	byHash := make(map[string]selector.Candidate, len(cands))
	for _, c := range cands {
		byHash[nodeHash(&c.Node)] = c
	}

	lats := make([]int, 0, len(selected))
	for _, n := range selected {
		if c, ok := byHash[nodeHash(&n)]; ok {
			lats = append(lats, c.LatencyMs)
		} else {
			lats = append(lats, 0)
		}
	}
	median := medianInt(lats)

	taken := make(map[string]bool, len(selected))
	for _, n := range selected {
		taken[nodeHash(&n)] = true
	}

	out := make([]model.Node, len(selected))
	copy(out, selected)
	for i, n := range selected {
		c, ok := byHash[nodeHash(&n)]
		if !ok {
			continue
		}
		degraded := c.LatencyMs > 2*median
		if degradeMs > 0 && c.LatencyMs > degradeMs {
			degraded = true
		}
		if !degraded {
			continue
		}
		if best, found := bestUnselected(cands, c.Country, taken); found {
			out[i] = best.Node
			taken[nodeHash(&best.Node)] = true
		}
	}
	return out
}

// bestUnselected returns the lowest-latency candidate of the given country that
// is not in taken. Cands are alive-only, so the result is always alive.
func bestUnselected(cands []selector.Candidate, country string, taken map[string]bool) (selector.Candidate, bool) {
	var best selector.Candidate
	found := false
	for _, c := range cands {
		if c.Country != country {
			continue
		}
		if taken[nodeHash(&c.Node)] {
			continue
		}
		if !found || c.LatencyMs < best.LatencyMs {
			best = c
			found = true
		}
	}
	return best, found
}

// medianInt returns the median of xs (average of the two middle values when the
// count is even). It does not mutate the caller's slice.
func medianInt(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	s := make([]int, len(xs))
	copy(s, xs)
	sort.Ints(s)
	m := len(s) / 2
	if len(s)%2 == 0 {
		return (s[m-1] + s[m]) / 2
	}
	return s[m]
}
