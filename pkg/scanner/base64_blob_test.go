package scanner

import (
	"strings"
	"testing"
)

// A 76-character base64 payload with '==' padding. Short enough to read, long
// enough to clear the >64 gate.
const longBase64Blob = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsuIE1hbnkgaGFuZHMgbWFrZSBsaWdodCB3b3JrLg=="

// TestLongBase64Redacted covers F3: a long, clean, padded base64 blob is a
// payload far more often than it is something safe to keep, so at the default
// confidence it is now redacted instead of skipped.
//
// Two mechanisms had to change, and the second is why editing the skip alone
// did nothing: processEqualPair used to split such a token on its own '='
// padding, emit the whole body as a "key" verbatim, and never score it. That is
// also why the same blob with the padding stripped was already redacted.
func TestLongBase64Redacted(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		longBase64Blob,
		"Payload: " + longBase64Blob,
		"body=" + longBase64Blob + " status=200",
	} {
		out := ScanAndRedact(in)
		if strings.Contains(out, longBase64Blob) {
			t.Errorf("base64 payload passed through: in=%q out=%q", in, out)
		}
		if !strings.Contains(out, "[HIDDEN") {
			t.Errorf("expected redaction: in=%q out=%q", in, out)
		}
	}

	// Framing around the blob survives: only the payload is replaced.
	out := ScanAndRedact("src=data:image/png;base64," + longBase64Blob)
	if !strings.HasPrefix(out, "src=data:image/png;base64,") {
		t.Errorf("data-URI framing lost: %q", out)
	}

	// An SSH public key body stays whitelisted (F2 interlock) — it is public by
	// design, and the whitelist is what decides, not the base64 rule.
	sshKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLd4bJ5gWlLmT8pVcQnR3xY7fKzN2mHpJwErTyUiOaSdFgHjKlZxCvBnMqAwEsRdTfYgUhIjOkPlQmWnEbRcVtXyZa user@host"
	if out := ScanAndRedact(sshKey); out != sshKey {
		t.Errorf("ssh public key should stay whitelisted: %q", out)
	}

	// Short base64-ish tokens are untouched.
	for _, in := range []string{"ok=", "dGVzdA==", "count=42"} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("short token redacted: in=%q out=%q", in, out)
		}
	}
}

// TestLongBase64SkippedAtHighConfidence pins the other half of the F3 decision:
// raising ConfidenceThreshold above 1.2 is a request for fewer redactions, and
// there the old pass-through is kept. This is the same boundary the Luhn
// card-context gate uses, and it is what keeps TestFalsePositives (which runs
// at 1.5) honest rather than merely green.
func TestLongBase64SkippedAtHighConfidence(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)

	cfg := campaignConfig()
	cfg.ConfidenceThreshold = 1.5
	UpdateConfig(cfg)

	if out := ScanAndRedact(longBase64Blob); out != longBase64Blob {
		t.Errorf("expected pass-through at ConfidenceThreshold 1.5: %q", out)
	}

	// A sensitive key still wins over the relaxed setting.
	out := ScanAndRedact("api_key=" + longBase64Blob)
	if strings.Contains(out, longBase64Blob) {
		t.Errorf("sensitive key must still force redaction at 1.5: %q", out)
	}
}
