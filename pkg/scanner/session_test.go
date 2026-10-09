package scanner

import (
	"strings"
	"testing"
)

// A long digit session id under a cookie or session key is hidden; digits
// under other keys and short numbers under these keys stay (see session.go).
func TestSessionIDUnderKeyHidden(t *testing.T) {
	s := newFileNameScanner(t)
	const id = "8092026976377529079"
	for _, line := range []string{
		"DEBUG: Cookie: " + id,
		"Cookie: " + id,
		"cookie=" + id,
		`{"sessionId":"` + id + `"}`,
		"session_id=" + id + " ok",
		"JSESSIONID=" + id,
		"GET /a?JSESSIONID=" + id + "&x=1",
		"sid=1234567890 ok",
	} {
		got := s.ScanAndRedact(line)
		if strings.Contains(got, id) || strings.Contains(got, "1234567890") || !strings.Contains(got, "[HIDDEN") {
			t.Errorf("ScanAndRedact(%q) = %q, want the session id hidden", line, got)
		}
	}
	for _, line := range []string{
		"session: 3",
		"session_count: 123456789012",
		"cookie_consent: 1700000000000",
		"user_id: " + id,
		"order_id=" + id,
		"sid=123456789 ok",
		"Cookie: 8092 cookies",
	} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}

func TestIsSessionKey(t *testing.T) {
	for _, k := range []string{"cookie", "Cookie", "Set-Cookie", "session", "session_id", "sessionId", "JSESSIONID", "PHPSESSID", "sid", "auth.sid"} {
		if !isSessionKey(k) {
			t.Errorf("isSessionKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"cookie_consent", "session_count", "sessions", "user_id", "id", "consider"} {
		if isSessionKey(k) {
			t.Errorf("isSessionKey(%q) = true, want false", k)
		}
	}
}
