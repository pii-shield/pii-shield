package main

import (
	"fmt"
	"io"
	"testing"
)

// BenchmarkLinePipeline measures the CLI's line path without the reader:
// workers=1 is processLine on the calling goroutine (what the CLI does
// without PII_WORKERS), the rest go through a parallelSanitizer. Run with
// -cpu equal to or above the largest worker count.
func BenchmarkLinePipeline(b *testing.B) {
	lines := mixedCorpus(8192)
	var size int64
	for _, l := range lines {
		size += int64(len(l)) + 1
	}

	for _, workers := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			var out io.Writer = io.Discard
			if workers > 1 {
				p := newParallelSanitizer(io.Discard, workers, false, "open")
				defer p.Close()
				out = p
			}
			b.SetBytes(size / int64(len(lines)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				processLine(lines[i%len(lines)], false, "open", out)
			}
			if f, ok := out.(flusher); ok {
				_ = f.Flush() // count the lines still with the workers
			}
		})
	}
}
