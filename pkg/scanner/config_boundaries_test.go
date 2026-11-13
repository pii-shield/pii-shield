package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests in this file pin the edges of the settings that decide how much
// the scanner protects: how short a salt may be, how long a secret must be,
// how large a policy file may be, and which spellings switch a check off.
// Each edge was found by flipping one operator in the config code and seeing
// every existing test still pass.

// A salt of 16 bytes is the shortest one that counts as strong; 15 is weak.
// With PII_REQUIRE_STRONG_SALT a weak salt stops the process, without it the
// salt is used and a warning is printed.
func TestSaltLengthBoundary(t *testing.T) {
	const strong, weak = "0123456789abcdef", "0123456789abcde"

	t.Setenv("PII_REQUIRE_STRONG_SALT", "true")
	t.Setenv("PII_SALT", strong)
	if cfg := ApplyEnvOverrides(DefaultConfig()); string(cfg.Salt) != strong {
		t.Errorf("a 16-byte salt must be accepted as strong, got %q", cfg.Salt)
	}

	t.Setenv("PII_SALT", weak)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("a 15-byte salt must stop the process when PII_REQUIRE_STRONG_SALT is on")
			}
		}()
		ApplyEnvOverrides(DefaultConfig())
	}()

	t.Setenv("PII_REQUIRE_STRONG_SALT", "")
	if cfg := ApplyEnvOverrides(DefaultConfig()); string(cfg.Salt) != weak {
		t.Errorf("without the strict flag a short salt is still the salt, got %q", cfg.Salt)
	}
}

// No PII_SALT: an empty salt becomes a random one, never an empty or fixed
// one, and a salt already in the config (a reload) is kept.
func TestSaltWithoutEnv(t *testing.T) {
	t.Setenv("PII_SALT", "")
	a := ApplyEnvOverrides(DefaultConfig())
	b := ApplyEnvOverrides(DefaultConfig())
	if len(a.Salt) != 32 || len(b.Salt) != 32 || string(a.Salt) == string(b.Salt) {
		t.Errorf("want two different 32-byte random salts, got %d and %d bytes, equal=%v", len(a.Salt), len(b.Salt), string(a.Salt) == string(b.Salt))
	}
	kept := DefaultConfig()
	kept.Salt = []byte("salt-of-the-running-process-0123")
	if cfg := ApplyEnvOverrides(kept); string(cfg.Salt) != string(kept.Salt) {
		t.Errorf("a reload replaced the running salt with %q", cfg.Salt)
	}
}

func TestEnvMinSecretLengthBounds(t *testing.T) {
	def := DefaultConfig().MinSecretLength
	for raw, want := range map[string]int{
		"1":    1,
		"1024": MaxMinSecretLength,
		"1025": def,
		"0":    def,
		"-4":   def,
		"8x":   def,
	} {
		t.Setenv("PII_MIN_SECRET_LENGTH", raw)
		if got := ApplyEnvOverrides(DefaultConfig()).MinSecretLength; got != want {
			t.Errorf("PII_MIN_SECRET_LENGTH=%s gave %d, want %d", raw, got, want)
		}
	}
}

// Switching the bigram check off or the adaptive threshold on widens or
// narrows what is hidden, so only the documented spellings may do it.
func TestEnvSwitchSpellings(t *testing.T) {
	for raw, want := range map[string]bool{"true": true, "1": true, "": false, "yes": false, "TRUE": false, "0": false, "false": false} {
		t.Setenv("PII_DISABLE_BIGRAM_CHECK", raw)
		t.Setenv("PII_ADAPTIVE_THRESHOLD", raw)
		cfg := ApplyEnvOverrides(DefaultConfig())
		if cfg.DisableBigramCheck != want {
			t.Errorf("PII_DISABLE_BIGRAM_CHECK=%q gave %v, want %v", raw, cfg.DisableBigramCheck, want)
		}
		if cfg.AdaptiveThreshold != want {
			t.Errorf("PII_ADAPTIVE_THRESHOLD=%q gave %v, want %v", raw, cfg.AdaptiveThreshold, want)
		}
	}
}

func TestEnvAdaptiveSamplesBounds(t *testing.T) {
	def := DefaultConfig().AdaptiveBaselineSamples
	t.Setenv("PII_ADAPTIVE_THRESHOLD", "true")
	for raw, want := range map[string]int{"1": 1, "250": 250, "0": def, "-1": def, "many": def, "": def} {
		t.Setenv("PII_ADAPTIVE_SAMPLES", raw)
		if got := ApplyEnvOverrides(DefaultConfig()).AdaptiveBaselineSamples; got != want {
			t.Errorf("PII_ADAPTIVE_SAMPLES=%q gave %d, want %d", raw, got, want)
		}
	}
}

func TestEnvSensitiveKeyPatternsApplied(t *testing.T) {
	t.Setenv("PII_SENSITIVE_KEY_PATTERNS", "^x-.*-token$")
	cfg := ApplyEnvOverrides(DefaultConfig())
	cfg.Salt = []byte("key-pattern-test-salt-0123456789")
	if len(cfg.SensitiveKeyPatterns) != 1 {
		t.Fatalf("patterns = %v", cfg.SensitiveKeyPatterns)
	}
	out := NewScanner(cfg).ScanAndRedact("x-upstream-token=plainwordvalue")
	if strings.Contains(out, "plainwordvalue") {
		t.Errorf("the value under a key the pattern names was not hidden: %q", out)
	}
}

// A policy file may carry the smallest values that still mean something: a
// threshold between 0 and 1, a minimum length of 1, the maximum length.
func TestParsePolicyJSON_SmallestAndLargestValues(t *testing.T) {
	cfg, _, err := ParsePolicyJSON([]byte(`{"entropy_threshold": 0.5, "confidence_score": 0.25, "min_secret_length": 1}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EntropyThreshold != 0.5 || cfg.ConfidenceThreshold != 0.25 || cfg.MinSecretLength != 1 {
		t.Errorf("got %v, %v, %d; want 0.5, 0.25, 1", cfg.EntropyThreshold, cfg.ConfidenceThreshold, cfg.MinSecretLength)
	}
	cfg, _, err = ParsePolicyJSON([]byte(`{"min_secret_length": 1024}`))
	if err != nil || cfg.MinSecretLength != MaxMinSecretLength {
		t.Errorf("min_secret_length 1024 must be accepted: %d, %v", cfg.MinSecretLength, err)
	}
	if _, _, err := ParsePolicyJSON([]byte(`{"min_secret_length": 1025}`)); err == nil {
		t.Error("min_secret_length 1025 must be rejected")
	}
}

// The size limit is the last accepted size: a file of exactly
// MaxPolicyFileBytes loads, one byte more is rejected.
func TestLoadPolicyFile_SizeLimitIsInclusive(t *testing.T) {
	body := `{"min_secret_length": 9}`
	dir := t.TempDir()

	exact := filepath.Join(dir, "exact.json")
	if err := os.WriteFile(exact, []byte(body+strings.Repeat(" ", MaxPolicyFileBytes-len(body))), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := LoadPolicyFile(exact)
	if err != nil || cfg.MinSecretLength != 9 {
		t.Errorf("a file of exactly the limit must load: %d, %v", cfg.MinSecretLength, err)
	}

	over := filepath.Join(dir, "over.json")
	if err := os.WriteFile(over, []byte(body+strings.Repeat(" ", MaxPolicyFileBytes-len(body)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPolicyFile(over); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a file one byte over the limit must be rejected, got %v", err)
	}
}

// The SDK config applies the same smallest values, and a list of one entry
// is a list.
func TestConfigFromSDKJSON_SmallestValuesAndSingleEntries(t *testing.T) {
	cfg := ConfigFromSDKJSON([]byte(`{
		"entropy_threshold": 0.5, "confidence_score": 0.25, "min_secret_length": 1,
		"sensitive_keys": [" Session "],
		"custom_regexes": [{"name": "tx", "pattern": "^TX-\\d+$"}],
		"safe_regexes": [{"pattern": "^build-\\d+$"}]}`))
	if cfg.EntropyThreshold != 0.5 || cfg.ConfidenceThreshold != 0.25 || cfg.MinSecretLength != 1 {
		t.Errorf("got %v, %v, %d; want 0.5, 0.25, 1", cfg.EntropyThreshold, cfg.ConfidenceThreshold, cfg.MinSecretLength)
	}
	if len(cfg.SensitiveKeys) != 1 || cfg.SensitiveKeys[0] != "session" {
		t.Errorf("one sensitive key must replace the defaults, normalized: %v", cfg.SensitiveKeys)
	}
	if len(cfg.CustomRegexes) != 1 || len(cfg.SafeRegexes) != 1 {
		t.Errorf("one custom and one safe rule must apply: %d, %d", len(cfg.CustomRegexes), len(cfg.SafeRegexes))
	}
}

// An SDK config that sets one field leaves every other one at its default.
// A zero in the JSON is "not set": it must never switch a threshold or the
// minimum length to zero, which would hide almost everything.
func TestConfigFromSDKJSON_PartialConfigKeepsDefaults(t *testing.T) {
	def := DefaultConfig()
	for _, in := range []string{
		`{"salt": "partial-config-salt-0123456789ab"}`,
		`{"entropy_threshold": 0, "confidence_score": 0, "min_secret_length": 0}`,
		`{"sensitive_keys": [], "custom_regexes": [], "safe_regexes": [], "sensitive_key_patterns": []}`,
	} {
		cfg := ConfigFromSDKJSON([]byte(in))
		if cfg.EntropyThreshold != def.EntropyThreshold || cfg.ConfidenceThreshold != def.ConfidenceThreshold || cfg.MinSecretLength != def.MinSecretLength {
			t.Errorf("%s: thresholds %v, %v, length %d; want the defaults %v, %v, %d", in,
				cfg.EntropyThreshold, cfg.ConfidenceThreshold, cfg.MinSecretLength,
				def.EntropyThreshold, def.ConfidenceThreshold, def.MinSecretLength)
		}
		if len(cfg.SensitiveKeys) != len(def.SensitiveKeys) {
			t.Errorf("%s: %d sensitive keys, want the %d defaults", in, len(cfg.SensitiveKeys), len(def.SensitiveKeys))
		}
	}
}
