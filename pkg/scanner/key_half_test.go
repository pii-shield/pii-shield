package scanner

import (
	"encoding/json"
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
	// would score as safe on its own.
	if out := ScanAndRedact(`{"secret": "user=admin pass=hunter2"}`); strings.Contains(out, "admin") {
		t.Errorf("part of a forced value survived: %q", out)
	}

	// The same defect through the other sensitivity flag: a {"key": "password",
	// "value": …} pair marks the value sensitive via overrideSensitivity, and
	// the quoted branch used to ignore that flag too, so a value containing
	// '=' was re-parsed and its tail scored on its own.
	out4 := ScanAndRedact(`{"key": "password", "value": "x=hunter2"}`)
	if strings.Contains(out4, "hunter2") {
		t.Errorf("value under a password-typed pair leaked: %q", out4)
	}
	if !json.Valid([]byte(out4)) {
		t.Errorf("output is no longer valid JSON: %q", out4)
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

	in := `{"payload": "` + b7Blob + `"}`
	out := ScanAndRedact(in)
	if strings.Contains(out, b7Blob) {
		t.Errorf("payload leaked under a non-sensitive key: %q", out)
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("output is no longer valid JSON: %q", out)
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

	// The signature detector keeps its label on a key half too.
	applyCfg(func(c *Config) { c.EntityTypeLabels = true })
	if out := ScanAndRedact("AKIAIOSFODNN7EXAMPLE=x"); !strings.HasPrefix(out, "[HIDDEN:aws-key:") || !strings.HasSuffix(out, "=x") {
		t.Errorf("signature label lost on a key half: %q", out)
	}
}
