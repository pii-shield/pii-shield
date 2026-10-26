package scanner

import (
	"strings"
	"testing"
)

// A secret that is the last path segment of a quoted URL with no query was
// written as it is: the closing quote stuck to the segment and failed the
// character test of isSecretPathSegment. The same URL unquoted, or with a
// query, hid it (AG-2026-10-25-03).
func TestURLPathTokenBeforeClosingQuote(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Salt = []byte("url-path-closing-quote-test-salt-1234567890")
	s := NewScanner(cfg)
	const tok = "q7Rm2vLp9Xk4Tz8Wn3Yb6Hc1Jd5Fg0S"
	hidden := []string{
		`{"ChallengeURL": "https://files.example.com/auth/reset-password/` + tok + `", "To": "x"}`,
		`{"a": 1, "ChallengeURL": "https://files.example.com/auth/reset-password/` + tok + `"}`,
		`{"url":"https://hooks.example.com/hooks/` + tok + `"}`,
		`url='https://files.example.com/auth/reset-password/` + tok + `'`,
		`reset https://files.example.com/auth/reset-password/` + tok + ` sent`,
		`{"u": "https://files.example.com/auth/reset-password/` + tok + `?lang=en"}`,
		`{"u": "https://files.example.com/r/` + tok + `/"}`,
	}
	for _, line := range hidden {
		got := s.ScanAndRedact(line)
		if strings.Contains(got, tok) {
			t.Errorf("token in the URL path survived: %q -> %q", line, got)
		}
		if after := line[strings.Index(line, tok)+len(tok):]; !strings.HasSuffix(got, after) {
			t.Errorf("framing after the URL changed: %q -> %q", line, got)
		}
	}
	// Quoted URLs whose last segment is a name or a public id stay as they are.
	kept := []string{
		`{"u": "https://files.example.com/auth/reset-password/"}`,
		`{"u": "https://files.example.com/docs/getting-started.html"}`,
		`{"u": "https://files.example.com/c/123e4567-e89b-12d3-a456-426614174000"}`,
		`{"u": "https://files.example.com/blobs/sha256/` + strings.Repeat("ab", 32) + `"}`,
		`"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"`,
	}
	for _, line := range kept {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}
