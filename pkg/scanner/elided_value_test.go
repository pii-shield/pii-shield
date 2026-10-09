package scanner

import (
	"strings"
	"testing"
)

// A padded base64 value shortened with three dots in the middle
// (value[:30] + "..." + value[-20:]) is hidden whole: split on its padding,
// the head and tail went out as an unscored dotted key.
func TestElidedBase64ValueHidden(t *testing.T) {
	s := newFileNameScanner(t)
	const v = "E100B3V0nvPqK0PYNyX1vZGAacLJJQ...dLGyGWH3aqQD/akk47=="
	for _, line := range []string{
		"sgcookie: " + v,
		`{"sgcookie": "` + v + `"}`,
		`{"sgcookie":"` + v + `"}`,
		"sgcookie=" + v,
		"  1. cookie2: " + v,
	} {
		if got := s.ScanAndRedact(line); strings.Contains(got, "E100B3V0nvPqK0PYNyX1vZGAacLJJQ") || strings.Contains(got, "dLGyGWH3aqQD") {
			t.Errorf("ScanAndRedact(%q) = %q, want the value hidden", line, got)
		}
	}
	for _, line := range []string{"loading...done=", "waiting.....=", "x=abc...def="} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}

func TestIsElidedBase64(t *testing.T) {
	for _, tok := range []string{"E100B3V0nvPqK0PY...dLGyGWH3aqQD/akk47==", "abcdefgh...ijklmnop="} {
		if !isElidedBase64(tok) {
			t.Errorf("isElidedBase64(%q) = false, want true", tok)
		}
	}
	for _, tok := range []string{"abcdefgh...ijklmnop", "abc...ijklmnop=", "abcdefgh...ijk=", "abcdefgh...ijklmnop===", "abcd efgh...ijklmnop=", "loading...done="} {
		if isElidedBase64(tok) {
			t.Errorf("isElidedBase64(%q) = true, want false", tok)
		}
	}
}
