package scanner

import (
	"testing"
)

// result is a package-level variable to clear compiler optimizations
var result string

// BenchmarkScanAndRedact measures the latency of processing a single typical log line.
func BenchmarkScanAndRedact(b *testing.B) {
	// A typical structured log line with mixed content
	line := `{"level":"info","ts":1698765432,"msg":"User login successful","user_id":12345,"email":"test@example.com","session_id":"a1b2c3d4e5f6","api_key":"sk_test_1234567890abcdef1234567890abcdef","context":{"ip":"192.168.1.1","user_agent":"Mozilla/5.0"}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Assign to global variable to prevent compiler optimization
		result = ScanAndRedact(line)
	}
}

// BenchmarkScanAndRedact_Parallel measures performance under high concurrency
// to detect contention on shared state (the config snapshot, the HMAC pool).
// Adaptive threshold mode is off by default, so its mutex is not exercised.
func BenchmarkScanAndRedact_Parallel(b *testing.B) {
	line := `{"level":"info","ts":1698765432,"msg":"API request processed","request_id":"req_12345abcde","auth_token":"bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret","trace_id":"0af7651916cd43dd8448eb211c80319c"}`

	// Ensure adaptive mode is enabled (or tested state) if that's the contention target
	// For now, we test the default path which might hit regex locks.

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = ScanAndRedact(line)
		}
	})
}

// BenchmarkThroughput measures the throughput in MB/s by processing a typical log line repeatedly.
func BenchmarkThroughput(b *testing.B) {
	// A typical log line (approx 90 bytes)
	line := `{"ts":1700000000,"msg":"processing data","key":"sk_test_123abc","data":"some sensitive info"}`
	lineLen := int64(len(line))

	b.ResetTimer()
	b.SetBytes(lineLen) // Tell testing framework how many bytes we process per op

	for i := 0; i < b.N; i++ {
		_ = ScanAndRedact(line)
	}
}

// BenchmarkAllocations focuses on memory usage.
// Run with: go test -bench=BenchmarkAllocations -benchmem
func BenchmarkAllocations(b *testing.B) {
	line := `user=alice password=supersecret key=123456`

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		result = ScanAndRedact(line)
	}
}
