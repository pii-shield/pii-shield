package scanner

import (
	"strings"
	"testing"
)

// Regression tests for #192: a diff marker glued to the first token of a line
// was scored as part of that token, so the marker's character class pushed
// ordinary words and file names over the entropy threshold.

func newMarkerScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Salt = []byte("diff-marker-test-salt-1234567890")
	return NewScanner(cfg)
}

func TestGluedDiffMarkerDoesNotRedactOrdinaryTokens(t *testing.T) {
	s := newMarkerScanner(t)
	for _, line := range []string{
		"+report.csv", "+config.yaml", "+src/main.go", "+Traceback",
		"-report.csv", "-config.yaml", "-src/main.go", "-Traceback",
		"++report.csv", "--report.csv", "+see report.csv for totals",
		"+import lib/foo/bar.py", "+total,4532015112.830366", "+2,bob,20.25",
	} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}

func TestGluedDiffMarkerKeepsSecretsRedacted(t *testing.T) {
	s := newMarkerScanner(t)
	for _, tc := range []struct{ line, secret string }{
		{"+password=SuperSecretValue123", "SuperSecretValue123"},
		{"-password=SuperSecretValue123", "SuperSecretValue123"},
		{"+AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
		{"+Zq8vN3pL7xR2wT9yB4mK6", "Zq8vN3pL7xR2wT9yB4mK6"},
		{"+4532015112830366", "4532015112830366"},
		{"+alice@example.com", "alice@example.com"},
		{"--flag=SuperSecretValue123", "SuperSecretValue123"},
	} {
		got := s.ScanAndRedact(tc.line)
		if strings.Contains(got, tc.secret) {
			t.Errorf("ScanAndRedact(%q) = %q, secret %q survived", tc.line, got, tc.secret)
		}
	}
}

// The marker itself must reach the output untouched, or a sanitized diff stops
// being a valid patch.
func TestGluedDiffMarkerIsPreservedInOutput(t *testing.T) {
	s := newMarkerScanner(t)
	for _, tc := range []struct{ line, prefix string }{
		{"+password=SuperSecretValue123", "+"},
		{"-password=SuperSecretValue123", "-"},
		{"+Zq8vN3pL7xR2wT9yB4mK6", "+"},
		{"++Zq8vN3pL7xR2wT9yB4mK6", "++"},
	} {
		if got := s.ScanAndRedact(tc.line); !strings.HasPrefix(got, tc.prefix) {
			t.Errorf("ScanAndRedact(%q) = %q, want prefix %q", tc.line, got, tc.prefix)
		}
	}
	for _, line := range []string{"+", "-", "++", "--", "---"} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}

// Deliberate behaviour change recorded in #192: a bare signed integer was
// redacted only because of the sign; the unsigned form never was. Pinned here
// so the change is explicit rather than incidental.
func TestSignedBareIntegersAreNotRedacted(t *testing.T) {
	s := newMarkerScanner(t)
	for _, in := range []string{"-123456789", "-123456789012", "+123456789012", "123456789", "123456789012"} {
		if got := s.ScanAndRedact(in); got != in {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestGitDiffHeadersStillPassThrough(t *testing.T) {
	s := newMarkerScanner(t)
	for _, line := range []string{
		"--- a/report.csv", "+++ b/report.csv", "--- /dev/null",
		"diff --git a/report.csv b/report.csv", "index 3b18e51..a1c9f02 100644",
	} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}
