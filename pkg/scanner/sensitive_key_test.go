package scanner

import (
	"strings"
	"testing"
)

// TestLongSecretFieldNames covers keys the entropy guard in isSensitiveKey
// wrongly rejected: longer than 15 characters, and the separators push them
// over the threshold. aws_access_key_id is in the default list itself, but the
// loop returned on the first partial match ("key") before reaching it, so a
// low-entropy value after it came back in the clear. Values here are
// low-entropy so that only key sensitivity can hide them.
func TestLongSecretFieldNames(t *testing.T) {
	useDefaultConfig(t)
	applyCfg(func(c *Config) { c.EntityTypeLabels = true })

	for _, in := range []string{
		"aws_access_key_id=some_value",
		"AWS_ACCESS_KEY_ID=some_value",
		"aws_secret_access_key=some_value",
		"aws_session_token=some_value",
		"github_access_token=hunter",
	} {
		out := ScanAndRedact(in)
		if strings.Contains(out, "some_value") || strings.Contains(out, "hunter") || !strings.Contains(out, "[HIDDEN:key:") {
			t.Errorf("value under a long secret field name not hidden as key: in=%q out=%q", in, out)
		}
	}

	// The guard still does its other job: long names where a weak word sits
	// inside an ordinary word, and dotted attribute paths, do not force their
	// values.
	for _, in := range []string{
		`"closed_lock_with_key": "x"`,
		`"hear-no-evil_monkey": "x"`,
		`"keycap_digit_one": "1"`,
		`Keyword.Namespace: "#875f5f",`,
		`token.ADD_ASSIGN: token.ADD,`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ordinary long name forced its value: in=%q out=%q", in, out)
		}
	}

	st := cfgState()
	for k, want := range map[string]bool{
		"aws_access_key_id":     true, // exact list entry
		"aws_session_token":     true, // strong word as a segment
		"db-password-hash":      true,
		"closed_lock_with_key":  false, // weak word only
		"heavy_minus_sign":      false,
		"token.name.builtin":    false, // dotted path
		"zq8vn3plsecret7xr2wt9": false, // random, has digits
		"zq8vn3_secret_7xr2":    false, // random with separators and a strong segment
	} {
		if got := st.isWordsSecretName(k); got != want {
			t.Errorf("isWordsSecretName(%q) = %v, want %v", k, got, want)
		}
	}
}
