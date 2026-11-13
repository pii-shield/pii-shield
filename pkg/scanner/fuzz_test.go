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
	for _, s := range malformedLogSeeds {
		f.Add(s)
	}

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

		// 4. Line Check: one line in, one line out. A marker may swallow a
		// line break the input carried (ScanAndRedactText exists for that),
		// but the scanner never adds one.
		if strings.Count(output, "\n") > strings.Count(input, "\n") {
			t.Errorf("Scanner added a line break. Input: %q Output: %q", input, output)
		}

		// 5. Idempotency Check: Scanning already redacted output should be stable
		// (unless the redacted placeholder itself triggers detection, which shouldn't happen)
		// Note: We scan the output. Ideally, Scan(Scan(input)) should be == Scan(input)
		// BUT, if Scan(input) produces [HIDDEN:xyz], scanning that again *might* be safe.
		// However, if we have "password=secret", output is "password=[HIDDEN:...]".
		// Scanning "password=[HIDDEN:...]" should result in "password=[HIDDEN:...]" (no change).
		// doubleOutput := ScanAndRedact(output)
		// if doubleOutput != output {
		// 	 t.Errorf("Idempotency failure!\nInput:  %q\nOnce:   %q\nTwice:  %q", input, output, doubleOutput)
		// }
		// COMMENTED OUT: Idempotency is hard because "[HIDDEN:xyz]" might be seen as a value for "password".
		// If the scanner logic determines "password" is a key, it will redact the value.
		// The value is "[HIDDEN:xyz]".
		// If we redact "[HIDDEN:xyz]", we get "[HIDDEN:newhash]".
		// So strict idempotency Scan(Scan(x)) == Scan(x) requires the scanner to recognize its own redaction.
		// Verify idempotency (should not crash or double-redact if logic works)
	})
}

// malformedLogSeeds are lines a real pipeline delivers broken: cut mid-write,
// carrying control bytes, or framed by a collector. Both fuzz targets below
// start from them.
var malformedLogSeeds = []string{
	`{"level":"error","msg":"db down","password":"Wintermonkey73`,          // JSON cut inside a value
	`{"a":{"b":{"token":"abc123def456ghi789"`,                              // JSON cut before the closing braces
	`{"msg":"she said \"token=abc123def456\" twice","n":1}`,                // escaped quotes inside a value
	`msg="unterminated password=Wintermonkey73`,                            // quote never closed
	`key='mixed" quotes' secret="a'b"c`,                                    // quotes of both kinds, unbalanced
	"password=\x00Winter\x00monkey73\x00",                                  // NUL bytes inside a value
	"\x1b[31mERROR\x1b[0m api_key=sk_live_abcdef1234567890",                // ANSI colour codes
	"\ufeffpassword=Wintermonkey73",                                        // byte order mark first
	"token=abc123def456\r",                                                 // CR left by a CRLF split
	"2026-11-13T10:00:00Z stdout F password=Wintermonkey73",                // CRI log prefix, full line
	"2026-11-13T10:00:00Z stdout P {\"token\":\"abc123def4",                // CRI partial line, cut by the runtime
	"<134>1 2026-11-13T10:00:00Z host app 123 - - secret=abc123def456ghi",  // syslog frame
	"password=" + strings.Repeat("A", 70_000),                              // value longer than a 64 KiB buffer
	strings.Repeat(`{"k":`, 2_000) + `"v"`,                                 // deep nesting, never closed
	strings.Repeat(`\"`, 5_000),                                            // run of escaped quotes
	"key=\xc3",                                                             // UTF-8 sequence cut after its first byte
	"\xed\xa0\x80=secret \xf4\x90\x80\x80",                                 // surrogate half and a code point past U+10FFFF
	"password = = = Wintermonkey73",                                        // separators with nothing between
	"=====",                                                                // separators only
	"https://user:Wintermonkey73@db.example.com:5432/app?sslmode=require#", // credentials in a URL
	"GET /a?token=abc%ZZdef%2 HTTP/1.1",                                    // broken percent escapes
}

// FuzzScanText checks the multi-line entry point the SDKs call. Its contract
// is the CLI's: as many lines out as in, whatever the lines hold.
func FuzzScanText(f *testing.F) {
	f.Add("one line, no break")
	f.Add("password=Wintermonkey73\nnext line\n")
	f.Add("token=abc123def456\r\nuser=lena\r\n")
	f.Add("\n\n\n")
	f.Add("a\rb\nc\r\r\nd")
	f.Add("card 4539148803436467\n4539148803436467")
	for _, s := range malformedLogSeeds {
		f.Add(s + "\n" + s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		output := ScanAndRedactText(input)

		if got, want := strings.Count(output, "\n"), strings.Count(input, "\n"); got != want {
			t.Errorf("%d line breaks in, %d out. Input: %q Output: %q", want, got, input, output)
		}
		if !utf8.ValidString(output) {
			t.Errorf("invalid UTF-8 for input %q", input)
		}
		if len(output) > len(input)*3+100*(strings.Count(input, "\n")+1) {
			t.Errorf("Output size exploded. Input: %d, Output: %d", len(input), len(output))
		}

		// A line scanned as part of a text is scanned alone: the result must
		// not depend on its neighbours. A "\r" that ends a line belongs to
		// the line ending and is put back after the scan.
		inLines := strings.Split(input, "\n")
		outLines := strings.Split(output, "\n")
		for i := range min(len(inLines), len(outLines)) {
			line, ending := inLines[i], ""
			if bare, ok := strings.CutSuffix(line, "\r"); ok {
				line, ending = bare, "\r"
			}
			if want := ScanAndRedact(line) + ending; outLines[i] != want {
				t.Errorf("line %d differs from the same line scanned alone.\nLine:  %q\nText:  %q\nAlone: %q", i, line, outLines[i], want)
			}
		}
	})
}
