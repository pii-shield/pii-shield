package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTailAfterCarvedNumberUnderSensitiveKey pins a value under a sensitive
// key that starts with a phone or a card: the number is carved out before
// tokenizing, and the rest of the value then arrived as a token of its own
// with the key's force already spent, so token=+4917412345678.Ab12 came back
// as token=[HIDDEN:x].Ab12 while the quoted form hid the tail. Found by
// FuzzLogShapes (INFO:app.worker:0 token=+00000000.A).
func TestTailAfterCarvedNumberUnderSensitiveKey(t *testing.T) {
	useDefaultConfig(t)

	markerCount := func(s string) int { return strings.Count(s, "[HIDDEN:") }
	for _, tc := range []struct {
		in      string
		markers int
		keep    string // text that must survive
		drop    string // text that must not
	}{
		{"token=+4917412345678.Ab12", 2, "token=", ".Ab12"},
		{"INFO:app.worker:0 token=+00000000.A", 2, "INFO:app.worker:0 token=", ".A"},
		{"2026-10-17 10:00:00,123 INFO x token: +00000000.A", 2, " token: ", ".A"},
		{`level=warn msg="x token=+00000000.A" retry=1`, 2, `" retry=1`, ".A"},
		{"password=4111111111111111+447911123456xyz", 2, "password=", "xyz"},
		// A number in the middle of the value: the head spends the key's
		// force as a pair, the tail is still the same value.
		{`level=info msg="0" api_key=~+00000000~ user=bob`, 3, "] user=bob", "~"},
		{"api_key=ab+4917412345678cd", 1, "api_key=[", "cd"},
		{"2026-10-17 10:00:00,123 INFO 0 api_key: ~+00000000~", 3, " api_key: [", "~"},
		// Two numbers in one value, quoted: [HIDDEN:x]~[HIDDEN:y] used to
		// pass isRedacted as one marker and was written as it was.
		{`client_secret="+00000000~+00000000"`, 3, `client_secret="[`, "~"},
		{`{"data": "{\"client_secret\": \"+00000000~+00000000\", \"user\": \"bob\"}"}`, 3, `\"user\": \"bob\"`, "~"},
		// A lone punctuation mark after the number ends the sentence, not
		// the value, and stays outside the marker as on a whole value.
		{"token=+4917412345678.", 1, "].", ""},
		{"token=+4917412345678,", 1, "],", ""},
		// Under an ordinary key the tail is scored on its own, as before.
		{"user=+4917412345678.Ab12", 1, "].Ab12", ""},
		{`msg="call +4917412345678.Ab12 done"`, 1, "].Ab12 done", ""},
	} {
		out := ScanAndRedact(tc.in)
		if markerCount(out) != tc.markers || !strings.Contains(out, tc.keep) || (tc.drop != "" && strings.Contains(out, tc.drop)) {
			t.Errorf("%q -> %q, want %d markers, %q kept, %q hidden", tc.in, out, tc.markers, tc.keep, tc.drop)
		}
		if twice := ScanAndRedact(out); twice != out {
			t.Errorf("second pass changed %q -> %q", out, twice)
		}
	}

	in := `{"level":"info","token":"+00000000.A","user":"bob"}`
	out := ScanAndRedact(in)
	if !json.Valid([]byte(out)) || markerCount(out) != 2 || strings.Contains(out, ".A") {
		t.Errorf("%q -> %q, want valid JSON with two markers and no tail", in, out)
	}
}
