package scanner

import (
	"strings"
	"testing"
)

// rescanLines are ordinary log shapes whose first pass leaves a marker next to
// a key, a context word or inside a URL or a quoted value — the places where a
// second pass used to find something new to hide.
var rescanLines = []string{
	"password=hunter2xyz",
	"token=abc123def456 user=bob",
	"password: hunter2xyz next",
	`{"password":"hunter2xyz","user":"bob"}`,
	`{"key": "password", "value": "x=hunter2"}`,
	`{"key":"password","value":"x=hunter2"}`,
	`{"msg": "login token=abc123def456, ok"}`,
	`{"pl": "binary_data=aSJDR1jaJlTrANqyWZvI"}`,
	"https://h/p?token=abc123def456&x=1",
	"GET /a?password=hunter2xyz&b=2 HTTP/1.1",
	"Error: 192.168.1.5 aSJDR1jaJlTrANqyWZvI connection failed",
	"Error 00A0a1 00112A",
	"Authorization: Bearer abcdefghijklmnop1234",
	"card 4539148803436467 end",
	`{"data": "{\"password\": \"hunter2xyz\", \"user\": \"bob\"}"}`,
	`{"msg": "login failed for \"bob\" token=abc123def456"}`,
	`{"name": "password", "value": "x=hunter2"}`,
	`name=password value=hunter`,
	"https://h/p?token=abc123def456&aB3dE9",
	"?keY=0&a010A",
}

// TestRescanIsStable pins invariant I3: scanning already-redacted output
// changes nothing. It failed on key=value under a sensitive key (password= was
// seen with an empty value and a new marker added on every pass), on URL
// parameters, on a marker inside a quoted value, after a context word, and
// with entity labels, where [HIDDEN:key:abc123] was parsed as key:value and
// nested.
func TestRescanIsStable(t *testing.T) {
	for _, labels := range []bool{false, true} {
		oldCfg := activeCfg()
		cfg := campaignConfig()
		cfg.EntityTypeLabels = labels
		UpdateConfig(cfg)
		for _, in := range rescanLines {
			once := ScanAndRedact(in)
			if once == in && !strings.Contains(in, "Bearer") {
				// Every line carries something to hide; an unchanged first pass
				// would make the rescan check vacuous.
				t.Errorf("labels=%v: first pass changed nothing: %q", labels, in)
			}
			for pass := 2; pass <= 3; pass++ {
				again := ScanAndRedact(once)
				if again != once {
					t.Errorf("labels=%v: pass %d changed the output:\n in:    %q\n once:  %q\n again: %q", labels, pass, in, once, again)
					break
				}
			}
		}
		UpdateConfig(oldCfg)
	}
}

// TestEmptyValueKeptAsIs: an empty value under a sensitive key holds nothing to
// hide. It used to become the marker of the empty string, which added text to
// the line and was the root of the password=[HIDDEN:x] rescan bug.
func TestEmptyValueKeptAsIs(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"password= user=bob",
		"password=",
		`{"password":""}`,
		`password=""`,
		"https://h/p?token=&x=1",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("empty value changed: in=%q out=%q", in, out)
		}
	}
}

// TestMarkerEdgeShapes covers the less common ways a marker reaches the
// scanner: glued to more text inside a quoted pair (sent back through the
// tokenizer), after a token with an invalid UTF-8 byte, unterminated, and
// inside a quoted phrase. Each must come back unchanged, and valid UTF-8.
func TestMarkerEdgeShapes(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, want string }{
		{`data="k=[HIDDEN:abc123](note)"`, `data="k=[HIDDEN:abc123](note)"`},
		{"x [HIDDEN:abc unterminated", "x [HIDDEN:abc unterminated"},
		{`{"msg": "[HIDDEN:abc123] tail"}`, `{"msg": "[HIDDEN:abc123] tail"}`},
		{"k\xff=[HIDDEN:abc123] x", "k�=[HIDDEN:abc123] x"},
	} {
		if out := ScanAndRedact(tc.in); out != tc.want {
			t.Errorf("in=%q\n got  %q\n want %q", tc.in, out, tc.want)
		}
	}
}

// TestMarkerGluedQueryTail pins the scope of the query-tail rule: a
// parameter without '=' glued to a marker is kept, as maskURLParameters kept
// it on the first pass; one with '=' is still scored; and a token separated
// from the marker by a space is not a query tail at all.
func TestMarkerGluedQueryTail(t *testing.T) {
	useDefaultConfig(t)

	if in := "https://h/p?token=[HIDDEN:78de3d]&aB3dE9"; ScanAndRedact(in) != in {
		t.Errorf("glued query flag redacted: %q", ScanAndRedact(in))
	}
	if out := ScanAndRedact("https://h/p?token=[HIDDEN:78de3d]&sig=Zq8vN3pL7xR2wT9yB4mK6"); strings.Contains(out, "Zq8vN3pL7xR2wT9yB4mK6") {
		t.Errorf("a glued parameter with a value skipped scoring: %q", out)
	}
	if out := ScanAndRedact("x [HIDDEN:abc123] &aB3dE9Kx9 y"); strings.Contains(out, "aB3dE9Kx9") {
		t.Errorf("a token after a marker and a space was kept as a query flag: %q", out)
	}
}
