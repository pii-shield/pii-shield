package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// TestMaskURLNonSensitiveEntropyParam exercises the B2 URL-parameter branches
// that the acceptance test does not reach: a non-sensitive key whose value is
// high-entropy (redacted via entropy) and a bare flag parameter without '='
// (passed through unchanged).
func TestMaskURLNonSensitiveEntropyParam(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	out := ScanAndRedact("http://x.com/a?data=AbC9xY2kQ8pLmN0rZ1&low=hi")
	if strings.Contains(out, "AbC9xY2kQ8pLmN0rZ1") || !strings.Contains(out, "data=[HIDDEN") {
		t.Errorf("high-entropy URL param not redacted: %q", out)
	}
	if !strings.Contains(out, "low=hi") {
		t.Errorf("low-entropy URL param altered: %q", out)
	}

	out2 := ScanAndRedact("http://x.com/a?flagonly&foo=1")
	if !strings.Contains(out2, "flagonly") || !strings.Contains(out2, "foo=1") {
		t.Errorf("bare/low URL params altered: %q", out2)
	}
}

// TestGenericKeyPropagatesSensitivity covers the processAndAppend branch where a
// generic key ("key"/"name"/"setting") whose value is itself a sensitive keyword
// (password) marks the following pair's value as sensitive. "plaintext" is
// low-entropy and does not redact on its own, so redaction here proves the
// propagation path fired.
func TestGenericKeyPropagatesSensitivity(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	out := ScanAndRedact(`{"key": "password", "value": "plaintext"}`)
	if strings.Contains(out, "plaintext") {
		t.Errorf("generic-key sensitivity not propagated to next value: %q", out)
	}
}

// TestCustomRegexFallbackPath covers the non-combined custom-regex loop in
// processSingleToken, reached when CustomRegexes is set but CombinedCustomRegex
// is nil (the CLI normally compiles the combined mega-regex; the fallback runs
// each rule individually).
func TestCustomRegexFallbackPath(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	applyCfg(func(c *Config) {
		c.CustomRegexes = []CustomRegexRule{{Regexp: regexp.MustCompile(`^ACCT-\d{6}$`), Name: "acct"}}
		c.CombinedCustomRegex = nil
	})

	out := ScanAndRedact("id ACCT-123456 end")
	if strings.Contains(out, "ACCT-123456") || !strings.Contains(out, "[HIDDEN:acct:") {
		t.Errorf("custom-regex fallback did not redact: %q", out)
	}
}

// TestAdaptiveThresholdPath covers the AdaptiveThreshold branches in
// processSingleToken: the baseline Update on scored tokens and, once the
// baseline is ready, the GetThreshold read that replaces the static threshold.
// It used to train on "the quick brown fox…", whose words are all shorter than
// MinSecretLength and never reach the scorer, so the baseline never became
// ready and the test asserted nothing (audit 2026-09-25). zebra42 scores 3.31:
// under the static 3.6 threshold, above the ~2.8 baseline learned here.
func TestAdaptiveThresholdPath(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	globalBaseline.Reset()
	defer globalBaseline.Reset()

	cfg := campaignConfig()
	UpdateConfig(cfg)
	if out := ScanAndRedact("value zebra42 end"); out != "value zebra42 end" {
		t.Fatalf("static threshold already hides the probe token: %q", out)
	}

	cfg.AdaptiveThreshold = true
	UpdateConfig(cfg)
	for i := 0; i < 30; i++ {
		ScanAndRedact("ordinary operational message received successfully")
	}
	threshold, ready := globalBaseline.GetThreshold()
	if !ready || threshold >= cfg.EntropyThreshold {
		t.Fatalf("baseline not learned: threshold=%v ready=%v", threshold, ready)
	}
	if out := ScanAndRedact("value zebra42 end"); strings.Contains(out, "zebra42") {
		t.Errorf("adaptive threshold %.2f did not apply: %q", threshold, out)
	}
}
