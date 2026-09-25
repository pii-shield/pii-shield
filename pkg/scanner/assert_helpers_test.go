package scanner

import "regexp"

var markerRe = regexp.MustCompile(`\[HIDDEN:[^\]]*\]`)

// withoutMarkers drops every [HIDDEN:…] marker, so a check that a short secret
// is gone cannot be fooled, or tripped, by the hex digits of a marker's hash.
func withoutMarkers(s string) string {
	return markerRe.ReplaceAllString(s, "")
}
