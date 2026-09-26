package scanner

import (
	"math"
	"testing"
)

// TestBaselineThresholdIsMeanPlusTwoSigma checks readiness and the formula on
// a local baseline, so no global state is left behind. The samples alternate
// 3.0 and 4.0: mean 3.5, population stddev 0.5, threshold 4.5. The old test fed
// a constant, where stddev is 0 and any mean + k*stddev gives the same answer.
func TestBaselineThresholdIsMeanPlusTwoSigma(t *testing.T) {
	stats := newBaselineStats(100)
	for i := 0; i < 99; i++ {
		stats.Update(3.0 + float64(i%2))
	}
	if _, ready := stats.GetThreshold(); ready || stats.IsReady() {
		t.Fatal("baseline ready before maxSamples")
	}
	stats.Update(4.0)
	threshold, ready := stats.GetThreshold()
	if !ready || !stats.IsReady() {
		t.Fatal("baseline not ready at maxSamples")
	}
	if math.Abs(threshold-4.5) > 1e-9 {
		t.Errorf("threshold = %v, want mean + 2*stddev = 4.5", threshold)
	}
	// Samples past maxSamples are ignored: the baseline is frozen once ready.
	stats.Update(100)
	if again, _ := stats.GetThreshold(); again != threshold {
		t.Errorf("threshold moved after the baseline was full: %v -> %v", threshold, again)
	}
}

func TestBaselineStats_HardReset(t *testing.T) {
	// 1. Create a baseline and fill it completely
	stats := newBaselineStats(5) // Small size for quick testing
	for i := 0; i < 10; i++ {
		stats.Update(float64(i))
	}

	// 2. Perform the reset
	stats.Reset()

	// 3. Verify EVERYTHING is truly empty/reset
	if len(stats.samples) != 0 {
		t.Errorf("Expected samples to be 0, got %d", len(stats.samples))
	}
	if stats.ready != false {
		t.Error("Expected ready to be false after hard reset")
	}

	// 4. Verify it can start over perfectly
	stats.Update(1.0)
	if len(stats.samples) != 1 {
		t.Errorf("Expected 1 sample after starting over, got %d", len(stats.samples))
	}
}
