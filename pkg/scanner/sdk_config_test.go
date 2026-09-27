package scanner

import (
	"strings"
	"testing"
)

// TestConfigFromSDKJSON pins the SDK config mapping the WASM kernel uses:
// defaults plus a random salt, only the fields present applied, and no error
// path that can take down the host process.
func TestConfigFromSDKJSON(t *testing.T) {
	def := ConfigFromSDKJSON([]byte(`{}`))
	if len(def.Salt) != 32 || def.EntropyThreshold != DefaultEntropyThreshold || len(def.SensitiveKeys) == 0 {
		t.Fatalf("empty payload should give the defaults with a 32-byte random salt: %+v", def)
	}
	if bad := ConfigFromSDKJSON([]byte(`{not json`)); len(bad.Salt) != 32 || bad.EntropyThreshold != DefaultEntropyThreshold {
		t.Errorf("invalid JSON should fall back to the defaults: %+v", bad)
	}

	cfg := ConfigFromSDKJSON([]byte(`{
		"entropy_threshold": 4.2, "salt": "s-1234567890abcdef", "confidence_score": 1.5,
		"min_secret_length": 9, "sensitive_keys": [" PIN ", "Otp"],
		"disable_bigram_check": true, "adaptive_threshold": true, "entity_type_labels": true,
		"custom_regexes": [{"pattern": "^ACCT-\\d+$", "name": "acct"}, {"pattern": "(", "name": "broken"}],
		"safe_regexes": [{"pattern": "^ok$", "name": "ok"}]
	}`))
	if cfg.EntropyThreshold != 4.2 || string(cfg.Salt) != "s-1234567890abcdef" || cfg.ConfidenceThreshold != 1.5 || cfg.MinSecretLength != 9 {
		t.Errorf("scalar fields not applied: %+v", cfg)
	}
	if len(cfg.SensitiveKeys) != 2 || cfg.SensitiveKeys[0] != "pin" || cfg.SensitiveKeys[1] != "otp" {
		t.Errorf("sensitive keys not normalized: %q", cfg.SensitiveKeys)
	}
	if !cfg.DisableBigramCheck || !cfg.AdaptiveThreshold || !cfg.EntityTypeLabels {
		t.Errorf("bool fields not applied: %+v", cfg)
	}
	if len(cfg.CustomRegexes) != 1 || cfg.CustomRegexNames[0] != "acct" || len(cfg.SafeRegexes) != 1 {
		t.Errorf("an invalid custom rule must be skipped and the rest kept: custom=%d names=%q safe=%d", len(cfg.CustomRegexes), cfg.CustomRegexNames, len(cfg.SafeRegexes))
	}

	// A bad sensitive-key pattern list is dropped whole instead of failing.
	if p := ConfigFromSDKJSON([]byte(`{"sensitive_key_patterns": ["("]}`)); p.SensitiveKeyPatterns != nil {
		t.Errorf("invalid sensitive_key_patterns should be dropped, got %q", p.SensitiveKeyPatterns)
	}
	if p := ConfigFromSDKJSON([]byte(`{"sensitive_key_patterns": ["^x-.*$"]}`)); len(p.SensitiveKeyPatterns) != 1 {
		t.Errorf("valid sensitive_key_patterns not applied: %q", p.SensitiveKeyPatterns)
	}
}

// TestSDKConfigWithoutSaltIsRandom pins that an SDK caller who gives no salt
// gets a fresh secret one: two instances tag the same value differently, and
// neither uses the fixed salt the kernel shipped before, whose tags anyone
// could compute for a guessed value.
func TestSDKConfigWithoutSaltIsRandom(t *testing.T) {
	a := ConfigFromSDKJSON([]byte(`{}`))
	b := ConfigFromSDKJSON([]byte(`{"entropy_threshold": 3.8}`))
	if string(a.Salt) == string(b.Salt) {
		t.Fatal("two salt-less SDK configs got the same salt")
	}
	const oldFixedSalt = "pii-shield-default-salt-12345678"
	for _, c := range []Config{a, b, ConfigFromSDKJSON([]byte(`{not json`))} {
		if string(c.Salt) == oldFixedSalt {
			t.Fatal("salt-less SDK config fell back to the old fixed salt")
		}
	}

	old := activeCfg()
	t.Cleanup(func() { UpdateConfig(old) })
	UpdateConfig(a)
	tagA := ScanAndRedactText("password=SuperSecretValue123")
	UpdateConfig(b)
	tagB := ScanAndRedactText("password=SuperSecretValue123")
	if tagA == tagB || !strings.HasPrefix(tagA, "password=[HIDDEN:") {
		t.Errorf("expected two different redaction tags, got %q and %q", tagA, tagB)
	}
	// [HIDDEN:8836e2] is this value's tag under the old fixed salt.
	if tagA == "password=[HIDDEN:8836e2]" || tagB == "password=[HIDDEN:8836e2]" {
		t.Error("tag matches the one computed with the old fixed salt")
	}
}
