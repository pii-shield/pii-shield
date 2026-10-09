package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// A hidden bare number after an unquoted key keeps the line's shape: no
// quotes are added around the marker. After a quoted JSON key the marker is
// quoted, so the JSON stays valid.
func TestBareKeyNumericMarkerNotQuoted(t *testing.T) {
	s := newFileNameScanner(t)
	for _, line := range []string{
		"token: 8092026976377529079",
		"secret: 12345678",
		"INFO:root:password: 12345678",
		"password: true",
	} {
		got := s.ScanAndRedact(line)
		if strings.Contains(got, `"`) {
			t.Errorf("ScanAndRedact(%q) = %q, quotes added", line, got)
		}
		if line != "password: true" && !strings.Contains(got, "[HIDDEN") {
			t.Errorf("ScanAndRedact(%q) = %q, want hidden", line, got)
		}
	}
	for _, line := range []string{
		`{"token": 8092026976377529079}`,
		`{"token":8092026976377529079}`,
		`{"secret": 12345678, "x": 1}`,
	} {
		got := s.ScanAndRedact(line)
		if !json.Valid([]byte(got)) || !strings.Contains(got, `"[HIDDEN`) {
			t.Errorf("ScanAndRedact(%q) = %q, want valid JSON with a quoted marker", line, got)
		}
	}
}
