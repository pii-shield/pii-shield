package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestNestedJSONString covers JSON that carries more JSON (or quoted text) in
// a string value, the "matryoshka" of the smoke test. The pair splitters did
// not honour backslash escapes, so {"data": "{\"nested_key\": \"s\"}"} was cut
// at the first \" and came back as {"data": "{\"nested_key\":[HIDDEN:x]} —
// closing quote and brace gone, invalid JSON — while with more than one inner
// field the secret passed through untouched.
func TestNestedJSONString(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	deep := enc(map[string]string{"data": enc(map[string]string{"inner": enc(map[string]string{"password": "hunter2xyz", "user": "bob"})})})

	for _, tc := range []struct {
		in     string
		secret string
		keep   []string
	}{
		{`{"data": "{\"nested_key\": \"nested_secret\"}"}`, "nested_secret", []string{`nested_key`}},
		{`{"data":"{\"password\":\"hunter2xyz\"}"}`, "hunter2xyz", []string{`\"password\":`}},
		{`{"data": "{\"password\": \"hunter2xyz\", \"user\": \"bob\"}"}`, "hunter2xyz", []string{`\"user\": \"bob\"`}},
		{`{"msg": "login failed for \"bob\" token=abc123def456"}`, "abc123def456", []string{`\"bob\"`}},
		{`{"secret": "{\"a\": \"b\"}"}`, `\"a\"`, nil},
		{deep, "hunter2xyz", []string{`bob`}},
	} {
		out := ScanAndRedact(tc.in)
		if !json.Valid([]byte(out)) {
			t.Errorf("output is not valid JSON:\n in:  %s\n out: %s", tc.in, out)
		}
		if strings.Contains(out, tc.secret) {
			t.Errorf("secret %q survived:\n in:  %s\n out: %s", tc.secret, tc.in, out)
		}
		if !strings.Contains(out, "[HIDDEN:") {
			t.Errorf("no marker:\n in:  %s\n out: %s", tc.in, out)
		}
		for _, k := range tc.keep {
			if !strings.Contains(out, k) {
				t.Errorf("%q lost:\n in:  %s\n out: %s", k, tc.in, out)
			}
		}
	}

	// Nothing to hide: the token is written byte for byte, escapes included,
	// rather than decoded and re-encoded.
	for _, in := range []string{
		`{"data": "{\"user\": \"bob\"}"}`,
		`{"msg": "said \"hello\" ok"}`,
		`{"t": "café \"x\" \/path"}`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("unchanged line was rewritten:\n in:  %s\n out: %s", in, out)
		}
	}
}
