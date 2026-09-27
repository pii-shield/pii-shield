package scanner

import (
	"regexp"
	"testing"
)

var markerRe = regexp.MustCompile(`\[HIDDEN:[^\]]*\]`)

// withoutMarkers drops every [HIDDEN:…] marker, so a check that a short secret
// is gone cannot be fooled, or tripped, by the hex digits of a marker's hash.
func withoutMarkers(s string) string {
	return markerRe.ReplaceAllString(s, "")
}

// useDefaultConfig puts the package-level scanner on the shipped defaults with
// a fixed salt for the rest of the test, and restores the previous config when
// the test ends. pkg/scanner tests share one published config snapshot, so a
// test that changes it and does not restore it changes every test after it
// in the run, and one that silently relies on it passes or fails depending on
// what ran before.
func useDefaultConfig(t testing.TB) {
	t.Helper()
	old := activeCfg()
	t.Cleanup(func() { UpdateConfig(old) })
	UpdateConfig(campaignConfig())
}
