package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/pii-shield/pii-shield/v3/pkg/metrics"
	"github.com/pii-shield/pii-shield/v3/pkg/scanner"
)

func TestParseMode(t *testing.T) {
	cases := []struct {
		raw  string
		mode string
		ok   bool
	}{
		{"", modeRedact, true},
		{"redact", modeRedact, true},
		{" Audit ", modeAudit, true},
		{"AUDIT", modeAudit, true},
		{"dry-run", modeRedact, false},
		{"true", modeRedact, false},
	}
	for _, tc := range cases {
		mode, ok := parseMode(tc.raw)
		if mode != tc.mode || ok != tc.ok {
			t.Errorf("parseMode(%q) = %q, %v; want %q, %v", tc.raw, mode, ok, tc.mode, tc.ok)
		}
	}
}

// setAudit turns audit mode on for one test and installs the callback main
// installs, so findings reach the audit counters the way they do in the
// binary.
func setAudit(t *testing.T) {
	t.Helper()
	auditMode = true
	old := scanner.RedactionCallback
	scanner.RedactionCallback = func(strategy string) { metrics.IncrementAuditFinding(strategy) }
	t.Cleanup(func() {
		auditMode = false
		scanner.RedactionCallback = old
	})
	metrics.AuditLinesTotal.Reset()
	metrics.AuditFindingsTotal.Reset()
	metrics.RedactionEventsTotal.Reset()
}

// Audit mode writes every line as it came, secrets included, and counts the
// lines that would have changed and the findings in them; the redaction
// counter does not move, because nothing was redacted.
func TestProcessLineAuditPassesLinesThroughAndCounts(t *testing.T) {
	setAudit(t)
	lines := []string{
		`{"ts": 1700000000, "msg": "hello", "password": "hunter2hunter2"}`,
		"Log line with key=AKIAIOSFODNN7EXAMPLE and token=abcDEF123456",
		"GET /healthz 200 in 1ms",
		"User session active: jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
	}
	var out bytes.Buffer
	for _, l := range lines {
		processLine(l, true, "closed", &out)
	}
	if got, want := out.String(), strings.Join(lines, "\n")+"\n"; got != want {
		t.Errorf("audit output differs from the input:\n got: %q\nwant: %q", got, want)
	}
	if n := testutil.ToFloat64(metrics.AuditLinesTotal.WithLabelValues("would_redact")); n != 3 {
		t.Errorf("would_redact lines = %v, want 3", n)
	}
	if n := testutil.ToFloat64(metrics.AuditLinesTotal.WithLabelValues("clean")); n != 1 {
		t.Errorf("clean lines = %v, want 1", n)
	}
	findings := 0.0
	for _, typ := range []string{"entropy", "regex", "luhn", "signature", "key", "unknown"} {
		findings += testutil.ToFloat64(metrics.AuditFindingsTotal.WithLabelValues(typ))
	}
	if findings < 3 {
		t.Errorf("audit findings = %v, want at least one per changed line", findings)
	}
	if n := testutil.ToFloat64(metrics.AuditFindingsTotal.WithLabelValues("signature")); n < 1 {
		t.Errorf("the AWS key must be a signature finding, got %v", n)
	}
	if n := testutil.ToFloat64(metrics.AuditFindingsTotal.WithLabelValues("key")); n < 1 {
		t.Errorf("the password must be a key finding, got %v", n)
	}
	for _, typ := range []string{"entropy", "regex", "luhn", "signature", "key", "unknown"} {
		if n := testutil.ToFloat64(metrics.RedactionEventsTotal.WithLabelValues(typ)); n != 0 {
			t.Errorf("redaction_events_total{type=%q} = %v in audit mode, want 0", typ, n)
		}
	}
}

// The same lines in redact mode do change, so the test above is not passing
// because the scanner missed everything.
func TestProcessLineRedactModeChangesTheSameLines(t *testing.T) {
	var out bytes.Buffer
	processLine("Log line with key=AKIAIOSFODNN7EXAMPLE and token=abcDEF123456", false, "open", &out)
	if !strings.Contains(out.String(), "[HIDDEN:") || strings.Contains(out.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("redact mode must hide the key: %q", out.String())
	}
}

// A scanner panic under a closed fail policy drops the line in redact mode;
// audit mode passes it through, because its promise is an unchanged stream.
func TestProcessLineAuditNeverDrops(t *testing.T) {
	setAudit(t)
	scanner.RedactionCallback = func(string) { panic("induced scanner panic") }
	const input = "contact john.doe@example.com now"
	var out bytes.Buffer
	processLine(input, true, "closed", &out)
	if got := strings.TrimSpace(out.String()); got != input {
		t.Errorf("audit with a closed fail policy: got %q, want the original line", got)
	}
}

func TestOverflowMarker(t *testing.T) {
	if got := overflowMarker("closed"); !strings.Contains(got, "DROP") {
		t.Errorf("closed in redact mode: %q", got)
	}
	if got := overflowMarker("open"); !strings.Contains(got, "WARN") {
		t.Errorf("open in redact mode: %q", got)
	}
	auditMode = true
	t.Cleanup(func() { auditMode = false })
	if got := overflowMarker("closed"); !strings.Contains(got, "WARN") {
		t.Errorf("closed in audit mode must warn, not drop: %q", got)
	}
}

func TestStatsSummaryInAuditMode(t *testing.T) {
	auditMode = true
	t.Cleanup(func() { auditMode = false })
	s := newStatsCollector()
	for i := 0; i < 1000; i++ {
		s.recordLine(100)
	}
	for i := 0; i < 25; i++ {
		s.recordAuditLine(true)
		s.recordRedaction("entropy")
		s.recordRedaction("signature")
	}
	s.recordAuditLine(false)
	got := s.summary()
	for _, want := range []string{
		"PII-Shield audit:",
		"50 would-be redactions",
		"25 high-entropy secrets",
		"25 signatures",
		"in 25 of 1,000 lines (2.5%)",
		"nothing was changed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("audit summary missing %q\n got: %s", want, got)
		}
	}
	if strings.Contains(got, "PII-Shield stats:") {
		t.Errorf("audit summary must not read as the redact summary: %s", got)
	}
}

// runMainInProcess feeds input to main() through stdin and returns what it
// wrote to stdout and to the log. The caller sets the PII_* environment.
func runMainInProcess(t *testing.T, input string) (stdout, logs string) {
	t.Helper()
	oldCallback := scanner.RedactionCallback
	oldStats := stats
	t.Cleanup(func() {
		scanner.RedactionCallback = oldCallback
		stats = oldStats
		auditMode = false
	})

	oldStdin, oldStdout, oldStderr := os.Stdin, os.Stdout, os.Stderr
	defer func() { os.Stdin, os.Stdout, os.Stderr = oldStdin, oldStdout, oldStderr }()
	rStdin, wStdin, _ := os.Pipe()
	rStdout, wStdout, _ := os.Pipe()
	rStderr, wStderr, _ := os.Pipe()
	os.Stdin, os.Stdout, os.Stderr = rStdin, wStdout, wStderr
	// The log package keeps the stderr it saw at init; point it at the pipe.
	log.SetOutput(wStderr)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	go func() {
		_, _ = wStdin.Write([]byte(input))
		_ = wStdin.Close()
	}()
	done := make(chan struct{})
	go func() {
		main()
		_ = wStdout.Close()
		_ = wStderr.Close()
		close(done)
	}()
	<-done

	var outBuf, errBuf bytes.Buffer
	_, _ = io.Copy(&outBuf, rStdout)
	_, _ = io.Copy(&errBuf, rStderr)
	return outBuf.String(), errBuf.String()
}

// The whole binary in audit mode: stdin in, the same bytes out, and the
// final stats summary names the lines that would have changed.
func TestMainAuditPassesStdinThrough(t *testing.T) {
	for _, k := range []string{"PII_METRICS_ENABLED", "PII_METRICS_PORT", "PII_FAIL_POLICY"} {
		t.Setenv(k, "")
	}
	t.Setenv("PII_MODE", "audit")
	t.Setenv("PII_STATS_LOG_INTERVAL", "1h")

	input := "hello test@example.com world\nline 2\npassword=Sup3rS3cretValue!\n"
	out, logs := runMainInProcess(t, input)
	if out != input {
		t.Errorf("audit mode changed the stream:\n got: %q\nwant: %q", out, input)
	}
	if !strings.Contains(logs, "PII_MODE=audit") || !strings.Contains(logs, "PII-Shield audit:") || !strings.Contains(logs, "in 2 of 3 lines") {
		t.Errorf("expected the audit notice and summary in the log, got:\n%s", logs)
	}
}

// With metrics on, audit mode exports piishield_audit_mode and counts what
// the scanner finds as audit findings, never as redactions. A bad metrics
// port keeps the metrics on but the server off, so no port is needed.
func TestMainAuditWithMetricsCountsFindings(t *testing.T) {
	t.Setenv("PII_METRICS_ENABLED", "true")
	t.Setenv("PII_METRICS_PORT", "none")
	t.Setenv("PII_FAIL_POLICY", "")
	t.Setenv("PII_STATS_LOG_INTERVAL", "")
	t.Setenv("PII_MODE", "audit")
	t.Cleanup(func() { metrics.AuditMode.Set(0) })

	countAll := func(v *prometheus.CounterVec) float64 {
		var n float64
		for _, typ := range []string{"entropy", "regex", "luhn", "signature", "key", "unknown"} {
			n += testutil.ToFloat64(v.WithLabelValues(typ))
		}
		return n
	}
	findingsBefore := countAll(metrics.AuditFindingsTotal)
	redactionsBefore := countAll(metrics.RedactionEventsTotal)

	input := "password=Sup3rS3cretValue!\n"
	out, _ := runMainInProcess(t, input)
	if out != input {
		t.Errorf("audit mode changed the stream:\n got: %q\nwant: %q", out, input)
	}
	if testutil.ToFloat64(metrics.AuditMode) != 1 {
		t.Error("piishield_audit_mode must be 1 in audit mode")
	}
	if n := countAll(metrics.AuditFindingsTotal) - findingsBefore; n < 1 {
		t.Errorf("expected at least one audit finding, got %v", n)
	}
	if n := countAll(metrics.RedactionEventsTotal) - redactionsBefore; n != 0 {
		t.Errorf("audit mode must count no redactions, got %v", n)
	}
}

// An unknown PII_MODE is logged and the sidecar redacts, the safe default.
func TestMainInvalidModeRedacts(t *testing.T) {
	for _, k := range []string{"PII_METRICS_ENABLED", "PII_METRICS_PORT", "PII_FAIL_POLICY", "PII_STATS_LOG_INTERVAL"} {
		t.Setenv(k, "")
	}
	t.Setenv("PII_MODE", "dry-run")

	out, logs := runMainInProcess(t, "password=Sup3rS3cretValue!\n")
	if strings.Contains(out, "Sup3rS3cretValue") || !strings.Contains(out, "[HIDDEN") {
		t.Errorf("an unknown mode must redact, got: %q", out)
	}
	if !strings.Contains(logs, `Invalid PII_MODE "dry-run"`) {
		t.Errorf("expected the invalid mode in the log, got:\n%s", logs)
	}
}

// A line longer than the buffer breaks the stream in every mode; audit mode
// warns about it instead of writing the DROP marker a closed fail policy
// would, because audit never drops. Runs the binary in a subprocess, like
// the other overflow tests, since main exits.
func TestMainAuditBufferOverflowWarnsInsteadOfDropping(t *testing.T) {
	t.Setenv("PII_MODE", "audit")
	stdout, stderr, exitCode := runMainWithLongLine(t, "closed")
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for a broken stream, got %d", exitCode)
	}
	if !strings.Contains(stdout, "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]") || strings.Contains(stdout, "DROP") {
		t.Errorf("audit mode must warn, not drop, got stdout: %.200s", stdout)
	}
	if !strings.Contains(stderr, "PII_MODE=audit") {
		t.Errorf("expected the audit notice in stderr, got: %.300s", stderr)
	}
}
