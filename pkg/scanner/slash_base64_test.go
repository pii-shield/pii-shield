package scanner

import (
	"strings"
	"testing"
)

// A token that starts with '/' and has no other '/' is a path only when the
// rest reads as a name; a base64 value starting with '/' is scored.
func TestSlashBase64NotAPath(t *testing.T) {
	s := newFileNameScanner(t)
	const v = "/BQtKx2y0rdboVsnQNX4ZiK57ib0R61CKvIiqP7oXs9TkaS8"
	for _, line := range []string{"sgcookie: " + v, v, `{"sgcookie": "` + v + `"}`} {
		if got := s.ScanAndRedact(line); strings.Contains(got, "BQtKx2y0rd") {
			t.Errorf("ScanAndRedact(%q) = %q, want hidden", line, got)
		}
	}
	for _, p := range []string{"/", "/tmp", "/python3", "/app.log", "/data-dir", "/wp-login.php", "/usr/local/bin/python3"} {
		if !isPath(p) {
			t.Errorf("isPath(%q) = false, want true", p)
		}
	}
	// /16kb starts with a digit, so it is not a path by this rule; it is
	// scored and kept, like any short low-entropy token.
	for _, p := range []string{"/", "/tmp", "/python3", "/app.log", "/data-dir", "/wp-login.php", "/usr/local/bin/python3", "/16kb"} {
		if got := s.ScanAndRedact("open " + p); got != "open "+p {
			t.Errorf("ScanAndRedact(open %s) = %q, want unchanged", p, got)
		}
	}
	if isPath(v) {
		t.Errorf("isPath(base64) = true, want false")
	}
}
