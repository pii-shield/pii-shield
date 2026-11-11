package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pii-shield/pii-shield/v3/pkg/scanner"
)

// mixedCorpus returns n log lines in the eight shapes of
// benchmark/run_benchmarks.sh: JSON and text, with secrets, cards, emails
// and values that must stay.
func mixedCorpus(n int) []string {
	lines := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		var l string
		switch i % 8 {
		case 0:
			l = fmt.Sprintf(`{"timestamp":"2026-05-22T08:%02d:%02dZ","level":"INFO","message":"User login attempt","user_id":"user-%d","token":"tok_live_%032x","ip":"192.168.%d.%d","credit_card":"4111111111111111"}`, i%60, i%60, i, i, i%255, (i*7)%255)
		case 1:
			l = fmt.Sprintf("time=2026-05-22T08:%02d:%02dZ level=warn service=api request_id=req-%08x password=SecretPass%d status=401 latency_ms=%d", i%60, i%60, i, i, i%300)
		case 2:
			l = fmt.Sprintf(`{"msg":"payment failed","card":"5555555555554444","email":"customer%d@example.com","trace_id":"%040x","commit_sha":"%040x"}`, i, i, i*17)
		case 3:
			l = fmt.Sprintf("nginx access remote_addr=10.%d.%d.%d method=POST path=/v1/session authorization=Bearer eyJhbGciOiJIUzI1NiJ9.%032x response=200", i%255, (i*3)%255, (i*5)%255, i)
		case 4:
			l = fmt.Sprintf(`{"nested":"{\"api_key\":\"sk_test_%032x\",\"safe_uuid\":\"550e8400-e29b-41d4-a716-446655440000\"}","ok":true}`, i)
		case 5:
			l = fmt.Sprintf("INFO health_check ok instance=worker-%d memory_dump=[0a 1b 3c 4d 5e 6f] public_key=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0gZ", i%32)
		case 6:
			l = fmt.Sprintf("Error: database login failed for user admin secret=%032x endpoint=db.internal.local retry=%d", i*97, i%5)
		default:
			l = fmt.Sprintf(`{"event":"profile_update","phone":"+1-202-555-%04d","ssn":"123-45-6789","note":"ordinary text with punctuation, quotes, and unicode-safe ascii"}`, i%10000)
		}
		lines = append(lines, l)
	}
	return lines
}

// sequentialOutput is the reference: every line through processLine on the
// calling goroutine.
func sequentialOutput(lines []string, failPolicy string) string {
	var out bytes.Buffer
	for _, l := range lines {
		processLine(l, false, failPolicy, &out)
	}
	return out.String()
}

func parallelOutput(lines []string, workers int, failPolicy string) string {
	var out lockedBuffer
	p := newParallelSanitizer(&out, workers, false, failPolicy)
	for _, l := range lines {
		processLine(l, false, failPolicy, p)
	}
	p.Close()
	return out.String()
}

// firstDifference names the first line where two outputs part, so a failure
// does not print megabytes.
func firstDifference(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := range min(len(w), len(g)) {
		if w[i] != g[i] {
			return fmt.Sprintf("line %d: want %q, got %q", i+1, w[i], g[i])
		}
	}
	return fmt.Sprintf("want %d lines, got %d", len(w), len(g))
}

// The point of the design: whatever the number of workers, the output is
// byte for byte what one line at a time produces.
func TestParallelMatchesSequential(t *testing.T) {
	lines := mixedCorpus(6000)
	// A line longer than a whole batch, and empty lines, which the scanner
	// returns early on.
	lines = append(lines, strings.Repeat("padding ", maxBatchBytes/4)+"password=SecretPass1", "", "", "last line")
	want := sequentialOutput(lines, "open")
	if !strings.Contains(want, "[HIDDEN:") {
		t.Fatal("the corpus was not redacted at all; the comparison would prove nothing")
	}

	for _, workers := range []int{2, 3, 8} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			if got := parallelOutput(lines, workers, "open"); got != want {
				t.Errorf("output differs from one line at a time: %s", firstDifference(want, got))
			}
		})
	}
}

// Audit mode writes the input back unchanged; with workers that still means
// in order.
func TestParallelAuditModeKeepsStream(t *testing.T) {
	auditMode = true
	t.Cleanup(func() { auditMode = false })

	lines := mixedCorpus(2000)
	want := strings.Join(lines, "\n") + "\n"
	if got := parallelOutput(lines, 4, "closed"); got != want {
		t.Errorf("audit mode changed the stream: %s", firstDifference(want, got))
	}
}

// A line that panics the scanner becomes a DROP marker (fail-closed) or goes
// out as it came (fail-open), in its own place in the stream.
func TestParallelPanicRecoveryKeepsOrder(t *testing.T) {
	old := scanner.RedactionCallback
	scanner.RedactionCallback = func(string) { panic("induced scanner panic") }
	t.Cleanup(func() { scanner.RedactionCallback = old })

	lines := mixedCorpus(400)
	for i := range lines {
		if i%3 == 0 {
			lines[i] = fmt.Sprintf("plain line %d with nothing in it", i)
		}
	}
	for _, failPolicy := range []string{"open", "closed"} {
		t.Run(failPolicy, func(t *testing.T) {
			want := sequentialOutput(lines, failPolicy)
			if failPolicy == "closed" && !strings.Contains(want, "[PII_SHIELD_DROP: FATAL_ERROR]") {
				t.Fatal("no line panicked; the comparison would prove nothing")
			}
			if got := parallelOutput(lines, 4, failPolicy); got != want {
				t.Errorf("output differs from one line at a time: %s", firstDifference(want, got))
			}
		})
	}
}

// A DROP marker made by a worker is pushed out at once, with the lines
// before it, as it is with one line at a time.
func TestParallelMarkerFlushesAtOnce(t *testing.T) {
	dst := &countingWriter{}
	out := newOutputWriter(dst, time.Hour)
	defer out.Close()
	p := newParallelSanitizer(out, 2, false, "closed")
	defer p.Close()

	old := scanner.RedactionCallback
	scanner.RedactionCallback = func(string) { panic("induced scanner panic") }
	t.Cleanup(func() { scanner.RedactionCallback = old })

	processLine("plain line with nothing in it", false, "closed", p)
	processLine("contact john.doe@example.com now", false, "closed", p)

	const want = "plain line with nothing in it\n[PII_SHIELD_DROP: FATAL_ERROR]\n"
	waitFor(t, "the marker to reach the destination", func() bool { return dst.String() == want })
}

// A marker the reader writes itself (a line too long for the buffer) waits
// for the lines read before it.
func TestParallelWriteMarkerAfterPendingLines(t *testing.T) {
	lines := mixedCorpus(1000)
	dst := &countingWriter{}
	out := newOutputWriter(dst, time.Hour)
	defer out.Close()
	p := newParallelSanitizer(out, 4, false, "open")
	defer p.Close()

	for _, l := range lines {
		processLine(l, false, "open", p)
	}
	writeMarker(p, overflowMarker("open"))

	// writeMarker returns only when the marker is written and flushed.
	want := sequentialOutput(lines, "open") + overflowMarker("open") + "\n"
	if got := dst.String(); got != want {
		t.Errorf("marker out of place: %s", firstDifference(want, got))
	}
}

// While every worker is busy a line waits for its batch to fill. If the
// input then pauses, the timer sends the batch; nothing else would.
func TestParallelLingerSendsPartialBatch(t *testing.T) {
	release := make(chan struct{})
	old := scanner.RedactionCallback
	scanner.RedactionCallback = func(string) { <-release }
	t.Cleanup(func() { scanner.RedactionCallback = old })

	var out lockedBuffer
	p := newParallelSanitizer(&out, 1, false, "open")
	defer p.Close()

	// The first line goes to the only worker, which blocks in the callback.
	p.submit("contact john.doe@example.com now")
	// The second line finds the worker busy and stays in the batch.
	p.submit("plain line with nothing in it")
	waitFor(t, "the timer to send the waiting batch", func() bool { return p.inFlight.Load() == 2 })

	close(release)
	waitFor(t, "both lines to be written", func() bool {
		return strings.HasSuffix(out.String(), "now\nplain line with nothing in it\n")
	})
}

// gatedWriter blocks every write until the gate is opened.
type gatedWriter struct {
	lockedBuffer
	gate chan struct{}
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	<-g.gate
	return g.lockedBuffer.Write(p)
}

// A destination that does not take the output must stop the reader, not
// fill memory: the lines held are bounded by the two queues.
func TestParallelBackPressureBoundsQueuedLines(t *testing.T) {
	const workers = 2
	lines := mixedCorpus(20000)
	want := sequentialOutput(lines, "open")

	dst := &gatedWriter{gate: make(chan struct{})}
	p := newParallelSanitizer(dst, workers, false, "open")

	var submitted atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, l := range lines {
			p.submit(l)
			submitted.Add(1)
		}
	}()

	// Wait until the reader has stopped making progress.
	last := int64(-1)
	waitFor(t, "the reader to block", func() bool {
		time.Sleep(50 * time.Millisecond)
		now := submitted.Load()
		stalled := now == last
		last = now
		return stalled
	})
	// One batch with the writer, the ordered queue, one batch being sent.
	bound := int64((workers*queuedBatchesPerWorker + 2) * maxBatchLines)
	if got := submitted.Load(); got >= int64(len(lines)) || got > bound {
		t.Errorf("reader took %d lines with the destination blocked, want at most %d", got, bound)
	}

	close(dst.gate)
	<-done
	p.Close()
	if got := dst.String(); got != want {
		t.Errorf("output differs after back-pressure: %s", firstDifference(want, got))
	}
}

// Close writes out what is queued; a line that arrives later (the reader
// racing a SIGTERM) is still sanitized and written after it.
func TestParallelCloseDrainsThenPassesThrough(t *testing.T) {
	lines := mixedCorpus(500)
	late := "late line password=SecretPass1"
	want := sequentialOutput(append(lines[:len(lines):len(lines)], late), "open")

	var out lockedBuffer
	p := newParallelSanitizer(&out, 4, false, "open")
	for _, l := range lines {
		p.submit(l)
	}
	p.Close()
	p.Close() // a second Close is a no-op
	p.submit(late)
	writeMarker(p, "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]")

	want += "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]\n"
	if got := out.String(); got != want {
		t.Errorf("output differs around Close: %s", firstDifference(want, got))
	}
	if strings.Contains(out.String(), "SecretPass1") {
		t.Error("a line submitted after Close was written unsanitized")
	}
}

func TestParseWorkers(t *testing.T) {
	cases := []struct {
		raw  string
		want int
		ok   bool
	}{
		{"", 1, true},
		{"1", 1, true},
		{" 4 ", 4, true},
		{"auto", runtime.GOMAXPROCS(0), true},
		{"AUTO", runtime.GOMAXPROCS(0), true},
		{"100000", maxWorkers, true},
		{"0", 1, false},
		{"-2", 1, false},
		{"many", 1, false},
		{"1.5", 1, false},
	}
	for _, tc := range cases {
		got, ok := parseWorkers(tc.raw)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseWorkers(%q) = %d, %v; want %d, %v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

// runMainOnStdin runs main over input with the given environment and returns
// what it wrote to stdout.
func runMainOnStdin(t *testing.T, input string, env map[string]string) string {
	t.Helper()
	for _, k := range []string{"PII_METRICS_ENABLED", "PII_METRICS_PORT", "PII_STATS_LOG_INTERVAL", "PII_FAIL_POLICY", "PII_MODE", "PII_WORKERS", "PII_ADAPTIVE_THRESHOLD"} {
		t.Setenv(k, env[k])
	}
	oldCallback := scanner.RedactionCallback
	t.Cleanup(func() { scanner.RedactionCallback = oldCallback })

	oldStdin, oldStdout := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = oldStdin, oldStdout }()
	rStdin, wStdin, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rStdout, wStdout, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin, os.Stdout = rStdin, wStdout

	go func() {
		_, _ = io.WriteString(wStdin, input)
		_ = wStdin.Close()
	}()
	go func() {
		main()
		_ = wStdout.Close()
	}()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, rStdout); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The whole CLI on stdin: PII_WORKERS changes nothing in what comes out.
func TestMainWorkersMatchSequential(t *testing.T) {
	lines := mixedCorpus(3000)
	input := strings.Join(lines, "\n") + "\n"
	want := sequentialOutput(lines, "open")

	for _, workers := range []string{"", "4", "auto"} {
		t.Run("PII_WORKERS="+workers, func(t *testing.T) {
			got := runMainOnStdin(t, input, map[string]string{"PII_WORKERS": workers})
			if got != want {
				t.Errorf("output differs from one line at a time: %s", firstDifference(want, got))
			}
		})
	}
}
