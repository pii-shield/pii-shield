package scanner

import (
	"strings"
	"testing"
)

// Regression tests for #189: file names and relative paths with an extension
// were redacted as entropy.

func newFileNameScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Salt = []byte("filename-test-salt-1234567890")
	return NewScanner(cfg)
}

func TestIsFileName(t *testing.T) {
	yes := []string{
		"report.csv", "config.yaml", "README.md", "src/main.go", "lib/foo/bar.py",
		"app/models/user.py", "package-lock.json", "invoice_2024.xlsx", "scanner_test.go",
		"data.jsonl", "photo.JPG", "archive.tar.gz", "a.b", "x/y/z.c", "v2.2.1.md",
	}
	no := []string{
		"Dockerfile", "Makefile", ".gitignore", "src/", "/etc/passwd", "./run.sh", "a//b.txt",
		"1.2.3.4", "10.0.0.1", "v2.2.1", "3.14", "alice@example.com", "https://x.io/a.txt",
		"key=value.txt", "a:b.txt", "file..txt", "report.sqlite", "report.",
		"Zq8vN3pL7xR2wT9yB4mK6",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"KEY.ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr",
		strings.Repeat("a", 260) + ".txt",
	}
	for _, tok := range yes {
		if !isFileName(tok) {
			t.Errorf("isFileName(%q) = false, want true", tok)
		}
	}
	for _, tok := range no {
		if isFileName(tok) {
			t.Errorf("isFileName(%q) = true, want false", tok)
		}
	}
}

func TestFileNamesAreNotRedacted(t *testing.T) {
	s := newFileNameScanner(t)
	for _, line := range []string{
		"report.csv",
		"src/main.go",
		"invoice_2024.xlsx",
		"package-lock.json",
		`Traceback: File "app/services/billing.py", line 42, in charge`,
		"ERROR main.go:42 failed to open report.csv",
		"uploaded invoice_2024.xlsx to bucket",
		"modified: src/pkg/scanner/scanner_test.go",
		"+++ b/config.yaml",
		"-import lib/foo/bar.py",
	} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}

func TestFileNameRuleDoesNotHideSecrets(t *testing.T) {
	s := newFileNameScanner(t)
	for _, tc := range []struct{ line, secret string }{
		{"password=secret.txt", "secret.txt"}, // sensitive key forces redaction before isSafe
		{"api_key=Zq8vN3pL7xR2wT9yB4mK6.key", "Zq8vN3pL7xR2wT9yB4mK6.key"},
		{"token: Zq8vN3pL7xR2wT9yB4mK6", "Zq8vN3pL7xR2wT9yB4mK6"},
		{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
		{"apikey KEY.ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr", "TwL2iGABf9DHoTf"},
		{"contact alice@example.com now", "alice@example.com"},
		{"card 4532015112830366", "4532015112830366"},
	} {
		got := s.ScanAndRedact(tc.line)
		if strings.Contains(got, tc.secret) {
			t.Errorf("ScanAndRedact(%q) = %q, secret %q survived", tc.line, got, tc.secret)
		}
	}
}
