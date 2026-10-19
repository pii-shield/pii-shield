package scanner

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzScanner(f *testing.F) {
	// Seed corpus with some interesting values
	f.Add("normal log line")
	f.Add("key=value")
	f.Add("password=secret")
	f.Add("https://example.com?token=123")
	f.Add("{\"user\": \"admin\", \"pass\": \"12345\"}")
	f.Add("Fehler beim Verbinden mit Datenbank") // German
	f.Add("Ошибка доступа")                      // Russian
	f.Add("::1")                                 // IPv6
	f.Add(string([]byte{0xff, 0xfe, 0xfd}))      // Invalid UTF-8
	f.Add(`{"nested": {"deep": {"secret": "123"}}}`)
	f.Add("key\u00A0value")                                   // Non-breaking space
	f.Add("key\tvalue")                                       // Tab
	f.Add(strings.Repeat("a=", 10_000) + "b")                 // Deep '=' chain (recursion depth bound, SCN-S 2d)
	f.Add("\u043A\u0430\u0440\u0442\u04304539148803436467 x") // Multibyte neighbor at Luhn boundary (SCN-S 2c)
	f.Add(`pAss":"h`)                                         // Unterminated quoted value after a sensitive key
	f.Add(`0=" ?X02aA`)                                       // Marker after an unterminated quote

	f.Fuzz(func(t *testing.T, input string) {
		// 1. Crash Check: Should not panic
		output := ScanAndRedact(input)

		// 2. Property Check: Output should be valid UTF-8
		if !utf8.ValidString(output) {
			t.Errorf("Scanner produced invalid UTF-8 for input %q", input)
		}

		// 3. Length Check: Check for output explosion
		if len(output) > len(input)*3+100 {
			t.Errorf("Output size exploded. Input: %d, Output: %d", len(input), len(output))
		}

		// 4. Rescan keeps markers: every marker of the first pass survives a
		// second pass whole and in order, and none is nested. Strict
		// Scan(Scan(x)) == Scan(x) does not hold on arbitrary bytes: hiding a
		// token that held a quote changes the quoting of the rest of the line,
		// and an invalid byte comes back as U+FFFD, so the second pass reads
		// different text. FuzzLogShapes checks the strict form on log-shaped
		// lines.
		if twice := ScanAndRedact(output); !keepsMarkers(output, twice) {
			t.Errorf("Rescan broke a marker\nInput: %q\nOnce:  %q\nTwice: %q", input, output, twice)
		}
	})
}
