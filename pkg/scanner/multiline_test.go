package scanner

import (
	"strings"
	"testing"
)

// Regression tests for #184: the WASM SDKs pass whole documents to the
// engine, and ScanAndRedact treats '\n' as an ordinary byte, so a value at
// the end of a line was scored together with its newline and redacted as
// entropy, with the newline swallowed by the marker. ScanAndRedactText scans
// per line and preserves line endings.

func newMultilineScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Salt = []byte("multiline-test-salt-1234567890")
	return NewScanner(cfg)
}

func TestScanAndRedactText_DecimalAtLineEndIsNotRedacted(t *testing.T) {
	s := newMultilineScanner(t)
	for _, in := range []string{
		"4532015112.830366\n",
		"+total,4532015112.830366\n",
		"+total,4532015112.830366\r\n",
		"+2,bob,20.25\n+total,4532015112.830366\n",
		"a\n4532015112.830366",
	} {
		if got := s.ScanAndRedactText(in); got != in {
			t.Errorf("ScanAndRedactText(%q) = %q, want input unchanged", in, got)
		}
	}
}

func TestScanAndRedactText_SingleLineMatchesScanAndRedact(t *testing.T) {
	s := newMultilineScanner(t)
	for _, in := range []string{
		"",
		"plain text",
		"password=SuperSecretValue123",
		"token=Zq8vN3pL7xR2wT9yB4mK6 and 4532015112.830366",
	} {
		if got, want := s.ScanAndRedactText(in), s.ScanAndRedact(in); got != want {
			t.Errorf("ScanAndRedactText(%q) = %q, ScanAndRedact = %q", in, got, want)
		}
	}
}

func TestScanAndRedactText_EachLineIsScanned(t *testing.T) {
	s := newMultilineScanner(t)
	in := "line one\npassword=SuperSecretValue123\r\ntoken=Zq8vN3pL7xR2wT9yB4mK6\n\nlast"
	got := s.ScanAndRedactText(in)
	want := "line one\n" + s.ScanAndRedact("password=SuperSecretValue123") + "\r\n" +
		s.ScanAndRedact("token=Zq8vN3pL7xR2wT9yB4mK6") + "\n\nlast"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if !strings.Contains(got, "[HIDDEN:") {
		t.Fatalf("expected secrets on inner lines to be redacted, got %q", got)
	}
}

func TestScanAndRedactText_PreservesLineCount(t *testing.T) {
	s := newMultilineScanner(t)
	diff := "diff --git a/report.csv b/report.csv\n" +
		"index 3b18e51..a1c9f02 100644\n" +
		"--- a/report.csv\n" +
		"+++ b/report.csv\n" +
		"@@ -1,3 +1,4 @@\n" +
		" id,name,total\n" +
		" 1,alice,10.5\n" +
		"-2,bob,20.25\n" +
		"+2,bob,20.25\n" +
		"+total,4532015112.830366\n"
	got := s.ScanAndRedactText(diff)
	if strings.Count(got, "\n") != strings.Count(diff, "\n") {
		t.Fatalf("line count changed: %d -> %d\n%s", strings.Count(diff, "\n"), strings.Count(got, "\n"), got)
	}
	if !strings.HasSuffix(got, "+total,4532015112.830366\n") {
		t.Fatalf("decimal at end of last line was altered:\n%s", got)
	}
	if !strings.HasSuffix(got, "\n") || strings.HasSuffix(got, "\n\n") {
		t.Fatalf("trailing newline not preserved exactly: %q", got[len(got)-4:])
	}
}

func TestScanAndRedactText_PackageLevelUsesGlobalConfig(t *testing.T) {
	in := "x\n4532015112.830366\n"
	if got := ScanAndRedactText(in); got != in {
		t.Fatalf("ScanAndRedactText(%q) = %q, want unchanged", in, got)
	}
	if got := ScanAndRedactText("password=SuperSecretValue123\n"); got == "password=SuperSecretValue123\n" || !strings.HasSuffix(got, "\n") {
		t.Fatalf("expected redaction with trailing newline kept, got %q", got)
	}
}
