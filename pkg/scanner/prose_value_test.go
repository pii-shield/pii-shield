package scanner

import (
	"strings"
	"testing"
)

// TestShortHashUnderHashKey covers the golden-file line labelled "Safe data
// check" that hid git_sha=a1b2c3d4e5f6: isGitHash knew only the full 40
// characters, and a 12-character hash scores above the threshold. Under a
// commit/sha key the hash is kept; bare, or under a sensitive or unrelated
// key, it is still scored.
func TestShortHashUnderHashKey(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"git_sha=a1b2c3d4e5f6",
		`{"commit": "a1b2c3d4e5f6", "user": "bob"}`,
		`{"commit":"a1b2c3d4e5f6"}`,
		"commit_id=4f2a9c1e7b3d rev=deadbeefcafe12",
		"commit: a1b2c3d4e5f6",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("hash under a hash key redacted: in=%q out=%q", in, out)
		}
	}
	for _, in := range []string{
		"password_hash=a1b2c3d4e5f6",
		"token_sha=a1b2c3d4e5f6",
		"data=a1b2c3d4e5f6",
		"commit a1b2c3d4e5f6",
		"git_sha=aSJDR1jaJlTr",
		"commit: a1b2c3d4e5f6 token: a1b2c3d4e5f6",
	} {
		out := ScanAndRedact(in)
		if !strings.Contains(out, "[HIDDEN:") {
			t.Errorf("expected a marker: in=%q out=%q", in, out)
		}
	}
}

// TestSensitiveWordThenCopula covers the golden-file prompt "my pass is
// 123456", which passed in the clear: the sensitive word forces only its next
// token, "is", which is freed as a short word (B12). The force now carries
// past is/was/are/were onto a word shaped like a secret, and never onto an
// ordinary word.
func TestSensitiveWordThenCopula(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, secret string }{
		{"my pass is 123456", "123456"},
		{"password is hunter2", "hunter2"},
		{"the token was abc123def456, then", "abc123def456"},
		{"password is p@ss!word", "p@ss!word"},
		{`{"prompt": "User said \"my pass is 123456\""}`, "123456"},
	} {
		out := ScanAndRedact(tc.in)
		if !strings.Contains(out, "[HIDDEN:") || strings.Contains(out, tc.secret) {
			t.Errorf("value after a copula not hidden: in=%q out=%q", tc.in, out)
		}
	}
	for _, in := range []string{
		"the pass is valid for 3 days",
		"the pass is valid.",
		"password is incorrect",
		"token is auto-generated",
		"password is too-short",
		"the password is 12345",
		"password was changed on 2026-09-25",
		"key is 2048 bits",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ordinary word after a copula redacted: in=%q out=%q", in, out)
		}
	}
}

// TestHiddenNumberQuotedOnlyAsValue: a hidden bare number is wrapped in quotes
// so a JSON value stays valid, but in prose the quotes were text that was
// never there ("password 123456" became password "[HIDDEN:x]").
func TestHiddenNumberQuotedOnlyAsValue(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	if out := ScanAndRedact("password 123456"); strings.Contains(out, `"`) || !strings.Contains(out, "[HIDDEN:") {
		t.Errorf("prose number: %q", out)
	}
	if out := ScanAndRedact(`{"password": 123456}`); !strings.Contains(out, `"password": "[HIDDEN:`) {
		t.Errorf("JSON number value lost its quotes: %q", out)
	}
}
