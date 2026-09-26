package scanner

import (
	"strings"
	"testing"
)

// Micro-benchmarks isolating the Phase 4 hot-path functions: calculateShannon
// (O2), calculateBigramAdjustment (O3) and redactWithHMAC (the O4 candidate,
// which was dropped; the benchmark stays as a baseline). They exist so
// benchstat can attribute a win to the specific function; end-to-end effects
// show up in BenchmarkScanAndRedact / BenchmarkThroughput.

var benchShannonTokens = []string{
	"AbC9xY2kQ8pLmN0r",
	"user_service_prod_1234567890abcdef",
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	strings.Repeat("x7Qp", 32),
}

func BenchmarkCalculateShannon(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = calculateShannon(benchShannonTokens[i%len(benchShannonTokens)])
	}
}

var benchBigramTokens = []string{
	"MixedCaseToken123",
	"authentication",
	"AbC9xY2kQ8pLmN0rQwErTy",
	"GET/api/v1/users",
}

func BenchmarkBigramAdjustment(b *testing.B) {
	st := cfgState()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = st.calculateBigramAdjustment(benchBigramTokens[i%len(benchBigramTokens)])
	}
}

func BenchmarkRedactWithHMAC(b *testing.B) {
	st := cfgState()
	var sb strings.Builder
	sb.Grow(64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		st.redactWithHMAC("hunter2", "", "entropy", &sb)
	}
}
