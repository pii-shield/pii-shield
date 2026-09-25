package scanner

import (
	"strings"
	"testing"
)

// TestGenericKeyPair covers a key/value pair whose name and value sit in two
// fields: {"name": "DB_PASSWORD", "value": "…"} (Kubernetes env),
// {"key": "password", "value": "…"}, {"setting": "token", "data": "…"}. Only
// "key" worked, and only because "key" is a sensitive word itself: "name" and
// "setting" never armed the check, and logfmt (name=password value=…) carries
// the first pair in one token, which nothing looked at. The values here are
// low-entropy so entropy alone would not hide them.
func TestGenericKeyPair(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, secret, keep string }{
		{`{"name": "password", "value": "x=hunter2"}`, "hunter2", `"name": "password"`},
		{`{"name": "password", "value": "hunter"}`, "hunter", `"name": "password"`},
		{`{"setting": "token", "data": "a=hunter2"}`, "hunter2", `"setting": "token"`},
		{`{"name":"password","value":"hunter"}`, "hunter", `"name":"password"`},
		{`{"key": "password", "value": "hunter"}`, "hunter", `"value": "[HIDDEN:`},
		{`name=password value=hunter`, "hunter", `name=password`},
		{`setting=token value=hunter`, "hunter", `setting=token`},
		{`key=password value="x=hunter2"`, "hunter2", `value="[HIDDEN:`},
		{`{"name": "DB_PASSWORD", "value": "hunter"}`, "hunter", `DB_PASSWORD`},
		// A key in between does not break the pairing.
		{`{"name": "password", "type": "string", "value": "hunter"}`, "hunter", `"type": "string"`},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) {
			t.Errorf("value of a generic pair leaked:\n in:  %s\n out: %s", tc.in, out)
		}
		if !strings.Contains(out, tc.keep) {
			t.Errorf("%q lost:\n in:  %s\n out: %s", tc.keep, tc.in, out)
		}
	}

	// The mirror: only the value of the pair is hidden. A non-secret name,
	// another key, a later pair and prose after "name: password" stay as they
	// are.
	for _, in := range []string{
		`{"name": "alice", "value": "hello"}`,
		`name=alice value=hello`,
		`{"name": "password", "type": "string"}`,
		`my name: password is required, user bob`,
		`[{"name": "DB_HOST", "value": "db.local"}]`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("line changed:\n in:  %s\n out: %s", in, out)
		}
	}
	for _, tc := range []struct{ in, keep string }{
		{`{"name": "password", "value": "hunter", "other": {"value": "keep"}}`, `{"value": "keep"}`},
		// Compact: the complete "value":"hunter" pair is not reported as a
		// key, so only spending the flag on use keeps "keep".
		{`{"name":"password","value":"hunter","other":{"value":"keep"}}`, `{"value":"keep"}`},
		{`[{"name": "DB_PASSWORD", "value": "hunter"}, {"name": "DB_HOST", "value": "db.local"}]`, `"value": "db.local"`},
	} {
		if out := ScanAndRedact(tc.in); !strings.Contains(out, tc.keep) || strings.Contains(out, "hunter") {
			t.Errorf("only the paired value should be hidden:\n in:  %s\n out: %s", tc.in, out)
		}
	}
}
