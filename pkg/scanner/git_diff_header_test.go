package scanner

import (
	"strings"
	"testing"
)

// Regression tests for #186: git diff header lines (a/ b/ relative paths,
// abbreviated hash ranges) were redacted as entropy.

func newDiffHeaderScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Salt = []byte("diff-header-test-salt-1234567890")
	return NewScanner(cfg)
}

func TestGitDiffHeaderLinesPassThrough(t *testing.T) {
	s := newDiffHeaderScanner(t)
	for _, line := range []string{
		"diff --git a/report.csv b/report.csv",
		"diff --git a/src/pkg/scanner/scanner_test.go b/src/pkg/scanner/scanner_test.go",
		"diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml",
		"diff --cc pkg/scanner/scanner.go",
		"index 3b18e51..a1c9f02 100644",
		"index 3b18e51f2c9d0a7..a1c9f02b4e8d1c3 100644",
		"index 3b18e51f2c9d0a7b4e8d1c3f6a9b2c5d8e1f4a7b..a1c9f02b4e8d1c3f6a9b2c5d8e1f4a7b3b18e51f 100644",
		"--- a/report.csv",
		"+++ b/report.csv",
		"--- a/b/Dockerfile",
		"+++ b/lib/foo/bar.py",
		"--- /dev/null",
		"+++ /dev/null",
		"rename from old/name.txt",
		"rename to new/name.txt",
		"copy from a/README.md",
		"copy to b/README.md",
		"Binary files a/logo.png and b/logo.png differ",
	} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}

func TestGitDiffBodyLinesAreStillScanned(t *testing.T) {
	s := newDiffHeaderScanner(t)
	for _, line := range []string{
		"+password=SuperSecretValue123",
		"-password=SuperSecretValue123",
		" token=Zq8vN3pL7xR2wT9yB4mK6",
		"--- password=SuperSecretValue123",         // not a header: no a/ prefix
		"+++ password=SuperSecretValue123",         // not a header: no b/ prefix
		"diff password=SuperSecretValue123",        // not a header
		"rename password=SuperSecretValue123",      // not a header
		"\"--- a/x\" password=SuperSecretValue123", // header text quoted inside a value line
	} {
		got := s.ScanAndRedact(line)
		if !strings.Contains(got, "[HIDDEN:") || strings.Contains(got, "SuperSecretValue123") || strings.Contains(got, "Zq8vN3pL7xR2wT9yB4mK6") {
			t.Errorf("ScanAndRedact(%q) = %q, want the secret redacted", line, got)
		}
	}
}

func TestIsGitHashRange(t *testing.T) {
	yes := []string{"3b18e51..a1c9f02", "3b18e51...a1c9f02", "3b18e51f2c9d0a7..a1c9f02b4e8d1c3",
		strings.Repeat("a", 40) + ".." + strings.Repeat("b", 40)}
	no := []string{"abc..def", "3b18e51..notahex", "3b18e51.a1c9f02", "3b18e51..", "..a1c9f02",
		strings.Repeat("a", 41) + ".." + strings.Repeat("b", 40), "3b18e51..a1c9f02..deadbee", "Zq8vN3pL7xR2wT9yB4mK6"}
	for _, tok := range yes {
		if !isGitHashRange(tok) {
			t.Errorf("isGitHashRange(%q) = false, want true", tok)
		}
	}
	for _, tok := range no {
		if isGitHashRange(tok) {
			t.Errorf("isGitHashRange(%q) = true, want false", tok)
		}
	}
}

func TestGitDiffLineByLineKeepsHeadersRedactsBody(t *testing.T) {
	s := newDiffHeaderScanner(t)
	diff := "diff --git a/config.env b/config.env\n" +
		"index 3b18e51..a1c9f02 100644\n" +
		"--- a/config.env\n" +
		"+++ b/config.env\n" +
		"@@ -1,2 +1,2 @@\n" +
		" APP_NAME=demo\n" +
		"-password=OldSecretValue123\n" +
		"+password=SuperSecretValue123\n"
	// Line by line, as the CLI reads stdin (multi-line WASM input is #184).
	var out strings.Builder
	for _, line := range strings.SplitAfter(diff, "\n") {
		out.WriteString(s.ScanAndRedact(strings.TrimSuffix(line, "\n")))
		if strings.HasSuffix(line, "\n") {
			out.WriteString("\n")
		}
	}
	got := out.String()
	if strings.Count(got, "\n") != strings.Count(diff, "\n") {
		t.Fatalf("line count changed:\n%s", got)
	}
	for _, header := range []string{"diff --git a/config.env b/config.env\n", "index 3b18e51..a1c9f02 100644\n", "--- a/config.env\n", "+++ b/config.env\n", "@@ -1,2 +1,2 @@\n", " APP_NAME=demo\n"} {
		if !strings.Contains(got, header) {
			t.Errorf("header/context line %q altered:\n%s", header, got)
		}
	}
	if strings.Contains(got, "OldSecretValue123") || strings.Contains(got, "SuperSecretValue123") {
		t.Fatalf("body secrets leaked:\n%s", got)
	}
}
