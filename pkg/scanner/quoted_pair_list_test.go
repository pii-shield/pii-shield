package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// A quoted value that holds a pair followed by another pair passed its
// secret: "session=<v>; theme=dark" was split on its own '=' and "<v>; theme"
// became a key half that read as a field name. The same list unquoted, or
// with the secret last, hid it (AG-2026-10-25-02).
func TestQuotedValuePairBeforeAnotherPair(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Salt = []byte("quoted-pair-list-test-salt-1234567890")
	s := NewScanner(cfg)
	const v = "q7Rm2vLp9Xk4Tz8Wn3Yb6Hc1Jd5Fg0Sa"
	hidden := []string{
		`{"request": {"headers": {"Cookie": ["session=` + v + `; theme=dark"]}}}`,
		`{"request": {"headers": {"Cookie": "session=` + v + `; theme=dark"}}}`,
		`{"request": {"headers": {"Cookie": ["_ga=GA1.2.1234567.7654321; session=` + v + `; theme=dark"]}}}`,
		`{"request": {"headers": {"Cookie": ["theme=dark; session=` + v + `"]}}}`,
		`Cookie: session=` + v + `; theme=dark`,
		`{"m": "session=` + v + `, theme=dark"}`,
		`msg="user=bob session=` + v + ` theme=dark"`,
	}
	for _, line := range hidden {
		got := s.ScanAndRedact(line)
		if strings.Contains(got, v) {
			t.Errorf("secret survived: %q -> %q", line, got)
		}
		if !strings.Contains(got, "theme=dark") {
			t.Errorf("the pair after the secret changed: %q -> %q", line, got)
		}
		if strings.HasPrefix(line, "{") && !json.Valid([]byte(got)) {
			t.Errorf("output is not valid JSON: %q", got)
		}
	}
	// Values with a pair followed by plain words keep their words.
	for _, line := range []string{
		`{"m": "mode=fast and verbose=true"}`,
		`{"m": "retries=3 then stop"}`,
		`cmd="ls -la"`,
	} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}
