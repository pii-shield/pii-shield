package scanner

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

const b7Blob = "QUJDRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5PQ=="

// TestQuotedSensitiveValueWithEquals covers B7: a quoted value under a
// sensitive key leaked whenever the value itself contained '='.
// processEqualPair re-parsed the value as its own key=value pair and never
// consulted the caller's forcedSensitive flag, so base64 padding was enough to
// turn the secret into a "key" that was written out verbatim.
func TestQuotedSensitiveValueWithEquals(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	in := `{"secret": "` + b7Blob + `"}`
	out := ScanAndRedact(in)
	if strings.Contains(out, b7Blob) {
		t.Errorf("secret leaked: %q", out)
	}
	if !strings.Contains(out, "[HIDDEN") {
		t.Errorf("expected redaction: %q", out)
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("output is no longer valid JSON: %q", out)
	}

	// The logfmt shape of the same thing.
	if out := ScanAndRedact(`secret="AbC9xY2kQ8pLmN0rZq7=="`); strings.Contains(out, "AbC9xY2kQ8pLmN0rZq7") {
		t.Errorf("secret leaked: %q", out)
	}

	// A sensitive key means the whole value is secret, including any part that
	// would score as safe on its own: one marker, no user= or pass= left.
	if out := ScanAndRedact(`{"secret": "user=admin pass=hunter2"}`); !regexp.MustCompile(`^\{"secret": "\[HIDDEN:[0-9a-f]{6}\]"\}$`).MatchString(out) {
		t.Errorf("forced value not hidden as one blob: %q", out)
	}

	// A {"key": "password", "value": …} pair marks the value sensitive. Spaced,
	// "value": is its own token, so the value arrives forced and is hidden as
	// one blob. Compact, "value":"x=hunter2" is one token that reaches the
	// quoted key=value branch with overrideSensitivity set, and that branch
	// used to ignore the flag, so the tail was scored on its own.
	for _, in := range []string{
		`{"key": "password", "value": "x=hunter2"}`,
		`{"key":"password","value":"x=hunter2"}`,
		`{"key":"password","value":"hunter2"}`,
	} {
		out := ScanAndRedact(in)
		if strings.Contains(out, "hunter2") {
			t.Errorf("value under a password-typed pair leaked: in=%q out=%q", in, out)
		}
		if !json.Valid([]byte(out)) {
			t.Errorf("output is no longer valid JSON: in=%q out=%q", in, out)
		}
		if !strings.Contains(out, `"value":`) {
			t.Errorf("the value's own key was hidden: in=%q out=%q", in, out)
		}
	}

	// Regression (B3): an inner key under a NON-sensitive outer key stays
	// readable and only its value is hidden, quotes intact.
	if out := ScanAndRedact(`data="password=hunter2"`); out != `data="password=[HIDDEN:3920d5]"` {
		t.Errorf("B3 regression: %q", out)
	}
}

// TestQuotedBase64BlobNotReparsed covers the half of the same defect that needs
// no sensitive key: a quoted base64 payload was re-parsed on its own padding,
// so the body became a "key" and was written out in the clear. F3 already
// guarded the raw token; this is the same guard one level in, on the quoted
// content.
func TestQuotedBase64BlobNotReparsed(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// The blob must come back as one marker. Checking only that the blob is
	// gone is not enough: its body has digits in it, so B19 hides it as a key
	// half even when the guard is removed, and the output then keeps a stray
	// "==" after the marker.
	in := `{"payload": "` + b7Blob + `"}`
	out := ScanAndRedact(in)
	if !regexp.MustCompile(`^\{"payload": "\[HIDDEN:[0-9a-f]{6}\]"\}$`).MatchString(out) {
		t.Errorf("payload not hidden as one blob: %q", out)
	}
}

// TestKeyNamesAreNeverScored pins why B19 scores a key half only when it does
// not look like a field name. Scoring every key is not viable: ordinary
// snake_case log keys sit right on the entropy threshold (context_id,
// request_id and commit_sha all score 3.622 against a 3.600 default), and
// scoring them produced 255 false positives on the 1000-line smoke corpus
// (measured 2026-09-18). A length-dependent threshold does not fix it either
// (F6, retired 2026-09-25). Field-name-shaped keys must come back untouched.
func TestKeyNamesAreNeverScored(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"context_id=12345",
		"request_id=EB1FEED2-4EA4-4513-B1EA-9CEC65169D7E",
		"commit_sha=abc123 status=200",
		"user=admin role=viewer",
		"rows=10&page=1",
		"requestId=5",
		"payment.declined=1",
		"HTTP=1",
		"sha256=abc",
		"Аутентификация=да",
		"host:port=1",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("key name redacted: in=%q out=%q", in, out)
		}
	}
}

// TestSecretAsKeyIsScored covers B19: the key half of key=value used to be
// written out unscored, so appending "=x" to a secret defeated the scanner,
// even the signature detectors. A key that does not look like a field name
// now goes through the same single-token path as a value.
func TestSecretAsKeyIsScored(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, secret := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"AbC9xY2kQ8pLmN0rZq7",
		"hqw55CTBeUqNyfgG89hHmA",
	} {
		for _, in := range []string{secret + "=x", "msg " + secret + "=1 done", `"` + secret + `=x"`} {
			out := ScanAndRedact(in)
			if strings.Contains(out, secret) {
				t.Errorf("secret used as a key leaked: in=%q out=%q", in, out)
			}
			if !strings.Contains(out, "[HIDDEN") {
				t.Errorf("expected a marker: in=%q out=%q", in, out)
			}
		}
	}

	// The signature detector keeps its label on a key half too. The prefixed
	// tokens with '_' or '-' look like field names, so only the signature check
	// in writeKeyHalf stops them from being written out as is.
	applyCfg(func(c *Config) { c.EntityTypeLabels = true })
	for _, tc := range []struct{ secret, label string }{
		{"AKIAIOSFODNN7EXAMPLE", "aws-key"},
		{stripeLowEntropy, "stripe-key"},
		{githubLowEntropy, "github-token"},
		{slackLowEntropy, "slack-token"},
	} {
		out := ScanAndRedact(tc.secret + "=x")
		if !strings.HasPrefix(out, "[HIDDEN:"+tc.label+":") || !strings.HasSuffix(out, "=x") {
			t.Errorf("signature label lost on a key half: in=%q out=%q", tc.secret+"=x", out)
		}
	}
}

// TestSeparatedSecretAsKeyKnownLimit pins a documented gap (KNOWN_LIMITATIONS):
// a random secret with '-' or '_' in it has a field-name shape, so as the key
// half of key=value it is written out unscored. A fix has to change this test
// on purpose.
func TestSeparatedSecretAsKeyKnownLimit(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"Zq8vN3pL-7xR2wT9yB4mK6=x",
		"hqw55CTBeUqNyfgG89hH_mA=1",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("known limit changed, update KNOWN_LIMITATIONS.md and this test: in=%q out=%q", in, out)
		}
	}
}
