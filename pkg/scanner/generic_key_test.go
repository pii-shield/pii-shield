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

// TestGenericValueKeyBySuffix: the value of a generic pair can sit under a
// name that ends in the word value. An OCPP 2.0.1 SetVariables frame names the
// variable in one object and carries its value as attributeValue, so a
// word-like charger password passed (seen in shiv3/ocpp-cp-simulator#400).
func TestGenericValueKeyBySuffix(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		`Received: [2,"19","SetVariables",{"setVariableData":[{"component":{"name":"SecurityCtrlr"},"variable":{"name":"BasicAuthPassword"},"attributeValue":"Winter7413#"}]}]`,
		`{"variable": {"name": "BasicAuthPassword"}, "attributeValue": "Winter7413#"}`,
		`{"name":"password","attribute_value":"Winter7413#"}`,
		`{"name":"password","newValue":"Winter7413#"}`,
		`name=password newValue=Winter7413#`,
	} {
		out := ScanAndRedact(in)
		if strings.Contains(out, "Winter7413#") {
			t.Errorf("value leaked:\n in:  %s\n out: %s", in, out)
		}
		if strings.Contains(in, "SecurityCtrlr") && !strings.Contains(out, `"name":"SecurityCtrlr"`) {
			t.Errorf("component name lost: %s", out)
		}
	}

	// A name that only ends in the letters "value", and a value key with no
	// secret name in front, change nothing.
	for _, in := range []string{
		`{"name":"password","devalue":"Winter7413"}`,
		`{"name":"OfflineThreshold","attributeValue":"Winter7413"}`,
		`{"variable":{"name":"HeartbeatInterval"},"attributeValue":"300"}`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("line changed:\n in:  %s\n out: %s", in, out)
		}
	}

	for k, want := range map[string]bool{
		"value": true, "data": true, "attributeValue": true, "attribute_value": true,
		"new-value": true, "old.value": true, "Value": true,
		"devalue": false, "evaluevalue": false, "values2": false, "valued": false,
	} {
		if got := isGenericValueKey(k); got != want {
			t.Errorf("isGenericValueKey(%q) = %v, want %v", k, got, want)
		}
	}
}
