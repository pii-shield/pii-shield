package scanner

import (
	"strings"
	"testing"
)

// TestShortValueUnderPatternKeyHidden: a key made sensitive by the user's
// PII_SENSITIVE_KEY_PATTERNS, or by a pw/pwd component, names a secret
// outright, so a quoted value of 2 to 5 letters after it is hidden the way it
// is after "password". Before, {"first_name": "Lena"} under the pattern
// (^|_)name$ and {"db_pwd": "Lena"} came back unchanged while
// {"first_name":"Lena"} and first_name=Lena were hidden (tracker 2026-10-23,
// found while checking the person-name workaround of AG-2026-10-23-03).
func TestShortValueUnderPatternKeyHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	if err := cfg.ApplySensitiveKeyPatterns([]string{"(^|_)name$"}); err != nil {
		t.Fatal(err)
	}
	UpdateConfig(cfg)

	for _, tc := range []struct{ in, value string }{
		{`{"first_name": "Lena"}`, "Lena"},
		{`{"first_name": "Al"}`, "Al"},
		{`{"first_name": "Priya", "role": "ta"}`, "Priya"},
		{`{"last_name": "Li"}`, "Li"},
		{`{"name": "Lena"}`, "Lena"},
		{`{"first_name": "Lena Meyer"}`, "Lena Meyer"},
		{`{"first_name":"Lena"}`, "Lena"},
		{`first_name=Lena`, "Lena"},
		{`{"db_pwd": "Lena"}`, "Lena"},
		{`{"smtpPw": "ab"}`, "ab"},
		{`{"password": "Lena"}`, "Lena"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.value) || !strings.Contains(out, "[HIDDEN") {
			t.Errorf("value passed through: %q -> %q", tc.in, out)
		}
		if strings.Count(out, `"`) != strings.Count(tc.in, `"`) {
			t.Errorf("quotes changed: %q -> %q", tc.in, out)
		}
	}

	// What stays: a literal under the key, an unquoted "key: word" (a type
	// annotation or a docstring line far more often than data, as for the
	// built-in keys), a bare pwd (the shell's working directory), and keys the
	// pattern does not match.
	for _, in := range []string{
		`{"first_name": "true"}`,
		`{"first_name": null}`,
		`first_name: Lena`,
		`{"pwd": "Lena"}`,
		`PWD=/home/lena`,
		`{"lastName": "Li"}`,
		`{"author": "Lena"}`,
		`{"username": "lena"}`,
		`{"nickname_count": 3}`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", in, out)
		}
	}

	st := cfgState()
	for k, want := range map[string]bool{
		"first_name": true, "name": true, "user_name": true, "db_pwd": true, "smtpPw": true, "DB_PW": true,
		"lastName": false, "pwd": false, "author": false, "username": false, "key": false,
	} {
		if got := st.keyNamesSecret(k); got != want {
			t.Errorf("keyNamesSecret(%q) = %v, want %v", k, got, want)
		}
	}
}

// TestShortValueWithoutPatternUnchanged pins that the pattern is what makes
// the difference: with no pattern configured, first_name is not a sensitive
// key and the short value stays, while db_pwd still names a secret.
func TestShortValueWithoutPatternUnchanged(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	if out := ScanAndRedact(`{"first_name": "Lena"}`); out != `{"first_name": "Lena"}` {
		t.Errorf("first_name is not sensitive without a pattern: %q", out)
	}
	if out := ScanAndRedact(`{"db_pwd": "Lena"}`); strings.Contains(out, "Lena") {
		t.Errorf("db_pwd value passed through: %q", out)
	}
}
