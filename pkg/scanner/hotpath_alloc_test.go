//go:build !race

package scanner

import "testing"

// Zero-allocation contract for the O2/O3 hot-path functions on ASCII tokens.
// Excluded from -race runs: race instrumentation changes allocation behavior.
// redactWithHMAC is not covered: O4 was dropped, and its sync.Pool makes
// AllocsPerRun flaky under GC pressure. BenchmarkRedactWithHMAC reports its
// allocations but asserts nothing.
func TestHotPathZeroAllocsASCII(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())
	st := cfgState()

	if n := testing.AllocsPerRun(200, func() {
		_ = calculateShannon("AbC9xY2kQ8pLmN0r")
	}); n != 0 {
		t.Errorf("calculateShannon allocates %v per run on ASCII", n)
	}

	if n := testing.AllocsPerRun(200, func() {
		_ = st.calculateBigramAdjustment("MixedCaseToken123")
	}); n != 0 {
		t.Errorf("calculateBigramAdjustment allocates %v per run on ASCII", n)
	}
}
