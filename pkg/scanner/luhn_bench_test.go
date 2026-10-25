package scanner

import "testing"

// BenchmarkFindLuhnSequences runs the card scan over access-log lines and two
// lines with long digit runs. Kept in its own file so scripts/bench-gate.sh
// can copy it into a base ref that predates it.
func BenchmarkFindLuhnSequences(b *testing.B) {
	lines := accessLogLines(256)
	lines = append(lines, "paid with 4111 1111 1111 1111 today", "order 1234567890123456789 at 2026-10-25T10:00:00")
	var sink int
	for i := 0; i < b.N; i++ {
		sink += len(FindLuhnSequences(lines[i%len(lines)]))
	}
	_ = sink
}
