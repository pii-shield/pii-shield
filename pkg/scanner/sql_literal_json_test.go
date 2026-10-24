package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// sqlRow is the dump line of leak-radar complaints 2026-09-30 (elan-registry
// /registry#2256): a JSON document in a single-quoted SQL literal whose error
// string quotes the address again, with the inner quotes escaped the way
// mysqldump writes them (esc) or bare, the way the issue quoted them.
func sqlRow(addr string, esc bool) string {
	q := "'"
	if esc {
		q = `\'`
	}
	return "INSERT INTO `us_rate_limits` VALUES (1,'register','10.0.0.7','2026-09-30 01:02:03'," +
		`'{"username_attempted": "li439", "email_attempted": "` + addr + `", "error": "SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry ` +
		q + addr + q + ` for key ` + q + `users.email` + q + `"}');`
}

// TestJSONInsideSQLLiteral: both copies of the address are hidden, the table
// name in backticks is kept, and the JSON inside the literal stays valid.
// On main the second address passed (0 of 20), the table name was hidden
// whole, and the tail 'users.email'"}'); became '[HIDDEN:...]'); with the
// closing "} swallowed.
func TestJSONInsideSQLLiteral(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	const addr = "lena.meyer42@example.com"
	for _, esc := range []bool{true, false} {
		in := sqlRow(addr, esc)
		out := ScanAndRedact(in)
		if strings.Contains(out, addr) {
			t.Errorf("address passed (escaped=%v):\n in: %s\nout: %s", esc, in, out)
		}
		if !strings.HasPrefix(out, "INSERT INTO `us_rate_limits` VALUES (1,'register',") {
			t.Errorf("table name or leading values changed: %s", out)
		}
		if !strings.HasSuffix(out, `"}');`) {
			t.Errorf("closing of the JSON and the literal lost: %s", out)
		}
		for _, ch := range []string{`"`, `'`, "`", `\`} {
			if strings.Count(out, ch) != strings.Count(in, ch) {
				t.Errorf("%s count changed (escaped=%v): %s", ch, esc, out)
			}
		}
		if esc {
			start := strings.Index(out, `'{`) + 1
			end := strings.LastIndex(out, `}'`) + 1
			doc := strings.ReplaceAll(out[start:end], `\'`, `'`)
			if !json.Valid([]byte(doc)) {
				t.Errorf("JSON inside the literal is not valid: %s", doc)
			}
		}
	}
}

// TestEscapedQuoteAndBacktickWrappers: a value between \' \' or backticks is
// judged without its framing, and the framing is written back as it was.
func TestEscapedQuoteAndBacktickWrappers(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, gone, keep string }{
		{`'Duplicate entry \'lena@example.com\' for key'`, "lena@example.com", `entry \'[HIDDEN:`},
		{`msg="login \"lena@example.com\" failed"`, "lena@example.com", `login \"[HIDDEN:`},
		{"x `aB3dE9xYqZ7wL0pK` y", "aB3dE9xYqZ7wL0pK", "x `[HIDDEN:"},
		{`password \'hunter2x\'`, "hunter2x", `password \'[HIDDEN:`},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.gone) || !strings.Contains(out, tc.keep) {
			t.Errorf("wrapped value not handled:\n in: %s\nout: %s", tc.in, out)
		}
	}
	for _, in := range []string{
		"SELECT * FROM `us_rate_limits` WHERE id=1",
		"INSERT INTO `users` (`id`,`created_at`) VALUES (1,'x');",
		"ALTER TABLE `order_items` ADD INDEX `idx_order_id` (`order_id`);",
		`'{"a": "x"}'`,
		`VALUES (1,'{"status": "ok", "items": [1, 2]}');`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", in, out)
		}
	}
	for _, tc := range []struct {
		in       string
		pre, end int
		ok       bool
	}{
		{`\'x\'`, 2, 2, true}, {`\"abc\"`, 2, 2, true}, {"`t`", 1, 1, true},
		{`\'x`, 0, 0, false}, {`\'a\'b\'`, 0, 0, false}, {"`a`b`", 0, 0, false}, {"``", 0, 0, false}, {`\'\'`, 0, 0, false},
	} {
		pre, post, ok := escapedOrBacktickWrap(tc.in)
		if ok != tc.ok || pre != tc.pre || post != tc.end {
			t.Errorf("escapedOrBacktickWrap(%q) = %d, %d, %v; want %d, %d, %v", tc.in, pre, post, ok, tc.pre, tc.end, tc.ok)
		}
	}
	for _, tc := range []struct {
		s    string
		i, e int
	}{
		{`{"a": "}"}`, 0, 10}, {`x{"a": [1, {"b": 2}]}'`, 1, 21}, {`["a\"]", 1]`, 0, 11}, {`{"a": 1`, 0, -1},
	} {
		if got := jsonDocumentEnd(tc.s, tc.i); got != tc.e {
			t.Errorf("jsonDocumentEnd(%q, %d) = %d, want %d", tc.s, tc.i, got, tc.e)
		}
	}
}
