package main

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pii-shield/pii-shield/v3/pkg/scanner"
)

// countingWriter counts the writes that reach the destination.
type countingWriter struct {
	lockedBuffer
	writes atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.lockedBuffer.Write(p)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestOutputWriterFlushesOnTimer(t *testing.T) {
	dst := &countingWriter{}
	out := newOutputWriter(dst, 5*time.Millisecond)
	defer out.Close()

	fmt.Fprintln(out, "first")
	waitFor(t, "the timer flush", func() bool { return dst.String() == "first\n" })

	// A second line after the first flush goes out on the next tick too.
	fmt.Fprintln(out, "second")
	waitFor(t, "the second timer flush", func() bool { return dst.String() == "first\nsecond\n" })
}

func TestOutputWriterUnbufferedWritesThrough(t *testing.T) {
	dst := &countingWriter{}
	out := newOutputWriter(dst, 0)
	for i := 0; i < 3; i++ {
		fmt.Fprintln(out, "line", i)
	}
	if got := dst.writes.Load(); got != 3 {
		t.Errorf("unbuffered writer made %d writes, want 3", got)
	}
	if err := out.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestOutputWriterBuffersUntilFlush(t *testing.T) {
	dst := &countingWriter{}
	out := newOutputWriter(dst, time.Hour)
	defer out.Close()

	for i := 0; i < 100; i++ {
		fmt.Fprintln(out, "line", i)
	}
	if got := dst.writes.Load(); got != 0 {
		t.Fatalf("buffered writer made %d writes before Flush, want 0", got)
	}
	if err := out.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := dst.writes.Load(); got != 1 {
		t.Errorf("Flush made %d writes, want 1", got)
	}
	if n := strings.Count(dst.String(), "\n"); n != 100 {
		t.Errorf("destination has %d lines, want 100", n)
	}
}

func TestOutputWriterFullBufferWritesOut(t *testing.T) {
	dst := &countingWriter{}
	out := newOutputWriter(dst, time.Hour)
	defer out.Close()

	line := strings.Repeat("x", 1000) + "\n"
	for i := 0; i < 100; i++ {
		_, _ = out.Write([]byte(line))
	}
	// 100 KB through a 64 KiB buffer: at least one write happened without
	// a timer or an explicit Flush, and nothing was reordered or lost.
	if got := dst.writes.Load(); got == 0 {
		t.Fatal("no write reached the destination when the buffer filled")
	}
	_ = out.Flush()
	if got := dst.String(); got != strings.Repeat(line, 100) {
		t.Errorf("destination content differs from what was written (%d bytes vs %d)", len(got), 100*len(line))
	}
}

// After Close every write goes straight through: a line sanitized while the
// process drains (metrics shutdown grace) must not be stranded in the buffer.
func TestOutputWriterCloseThenWriteThrough(t *testing.T) {
	dst := &countingWriter{}
	out := newOutputWriter(dst, time.Hour)

	fmt.Fprintln(out, "before close")
	if err := out.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if dst.String() != "before close\n" {
		t.Fatalf("Close did not flush: %q", dst.String())
	}
	fmt.Fprintln(out, "after close")
	if dst.String() != "before close\nafter close\n" {
		t.Errorf("write after Close was buffered: %q", dst.String())
	}
	if err := out.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// A DROP marker is pushed out at once, ahead of the flush timer; an ordinary
// line is not.
func TestProcessLineMarkerFlushesAtOnce(t *testing.T) {
	dst := &countingWriter{}
	out := newOutputWriter(dst, time.Hour)
	defer out.Close()

	processLine("plain line with nothing in it", false, "closed", out)
	if dst.String() != "" {
		t.Fatalf("ordinary line was written before the timer: %q", dst.String())
	}

	old := scanner.RedactionCallback
	scanner.RedactionCallback = func(string) { panic("induced scanner panic") }
	t.Cleanup(func() { scanner.RedactionCallback = old })
	processLine("contact john.doe@example.com now", false, "closed", out)
	if got := dst.String(); got != "plain line with nothing in it\n[PII_SHIELD_DROP: FATAL_ERROR]\n" {
		t.Errorf("marker did not flush the stream in order: %q", got)
	}
}

func TestWriteMarkerPlainWriter(t *testing.T) {
	var b bytes.Buffer
	writeMarker(&b, "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]")
	if b.String() != "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]\n" {
		t.Errorf("got %q", b.String())
	}
}

func TestParseFlushInterval(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want time.Duration
		ok   bool
	}{
		{"", defaultFlushInterval, true},
		{"0", 0, true},
		{"20ms", 20 * time.Millisecond, true},
		{"1s", time.Second, true},
		{"abc", defaultFlushInterval, false},
		{"-5ms", defaultFlushInterval, false},
		{"5", defaultFlushInterval, false},
	} {
		got, ok := parseFlushInterval(tc.raw)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseFlushInterval(%q) = %v, %v; want %v, %v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}
