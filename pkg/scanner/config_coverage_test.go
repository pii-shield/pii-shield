package scanner

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseHelpers(t *testing.T) {
	valF, errF := parseFloat("12.34")
	if errF != nil || valF != 12.34 {
		t.Errorf("parseFloat failed: %v", errF)
	}

	valI, errI := parseInt("1234")
	if errI != nil || valI != 1234 {
		t.Errorf("parseInt failed: %v", errI)
	}
}

func TestLoadConfigEdgeCases(t *testing.T) {
	// Save environment to restore later
	oldConfig := activeCfg()
	defer UpdateConfig(oldConfig)

	// t.Setenv restores each variable, including unsetting one that was not
	// set before; the old manual restore wrote "" back instead.
	t.Setenv("PII_SALT", "short123") // Less than 16 bytes
	t.Setenv("PII_ENTROPY_THRESHOLD", "invalid_float")
	t.Setenv("PII_ADAPTIVE_THRESHOLD", "true")
	t.Setenv("PII_ADAPTIVE_SAMPLES", "50")
	t.Setenv("PII_SENSITIVE_KEYS", "custom1,custom2 ")

	cfg := loadConfig()

	if string(cfg.Salt) != "short123" {
		t.Errorf("expected salt 'short123', got %s", cfg.Salt)
	}
	if cfg.EntropyThreshold != DefaultEntropyThreshold {
		t.Errorf("invalid PII_ENTROPY_THRESHOLD: expected the default %v, got %v", DefaultEntropyThreshold, cfg.EntropyThreshold)
	}
	if !cfg.AdaptiveThreshold {
		t.Errorf("PII_ADAPTIVE_THRESHOLD=true was not applied")
	}
	if cfg.AdaptiveBaselineSamples != 50 {
		t.Errorf("expected 50 adaptive samples, got %d", cfg.AdaptiveBaselineSamples)
	}
	expectedKeys := []string{"custom1", "custom2"}
	if !reflect.DeepEqual(cfg.SensitiveKeys, expectedKeys) {
		t.Errorf("expected sensitive keys %v, got: %v", expectedKeys, cfg.SensitiveKeys)
	}

	// Ensure UpdateConfig functions well
	UpdateConfig(cfg)
}

func TestLoadConfigMinSecretLength(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("PII_SALT", "test_salt_123456")
		t.Setenv("PII_MIN_SECRET_LENGTH", "")

		cfg := loadConfig()

		if cfg.MinSecretLength != DefaultMinSecretLength {
			t.Errorf("expected default min secret length %d, got %d", DefaultMinSecretLength, cfg.MinSecretLength)
		}
	})

	t.Run("valid override", func(t *testing.T) {
		t.Setenv("PII_SALT", "test_salt_123456")
		t.Setenv("PII_MIN_SECRET_LENGTH", "12")

		cfg := loadConfig()

		if cfg.MinSecretLength != 12 {
			t.Errorf("expected min secret length 12, got %d", cfg.MinSecretLength)
		}
	})

	tests := []struct {
		name  string
		value string
	}{
		{name: "non integer", value: "abc"},
		{name: "partial integer", value: "12abc"},
		{name: "zero", value: "0"},
		{name: "negative", value: "-1"},
		{name: "above maximum", value: fmt.Sprintf("%d", MaxMinSecretLength+1)},
	}

	for _, tt := range tests {
		t.Run("invalid override "+tt.name, func(t *testing.T) {
			t.Setenv("PII_SALT", "test_salt_123456")
			t.Setenv("PII_MIN_SECRET_LENGTH", tt.value)

			cfg := loadConfig()

			if cfg.MinSecretLength != DefaultMinSecretLength {
				t.Errorf("expected invalid min secret length %q to keep default %d, got %d", tt.value, DefaultMinSecretLength, cfg.MinSecretLength)
			}
		})
	}
}

func TestLoadConfigRequireStrongSalt(t *testing.T) {
	t.Run("allows weak salt by default for backward compatibility", func(t *testing.T) {
		t.Setenv("PII_SALT", "short123")
		t.Setenv("PII_REQUIRE_STRONG_SALT", "")

		cfg := loadConfig()

		if string(cfg.Salt) != "short123" {
			t.Errorf("expected weak salt to be accepted by default, got %q", string(cfg.Salt))
		}
	})

	t.Run("rejects weak salt when required", func(t *testing.T) {
		t.Setenv("PII_SALT", "short123")
		t.Setenv("PII_REQUIRE_STRONG_SALT", "true")

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected weak salt to panic when PII_REQUIRE_STRONG_SALT is enabled")
			}
		}()

		_ = loadConfig()
	})

	t.Run("accepts strong salt when required", func(t *testing.T) {
		t.Setenv("PII_SALT", "strong_salt_123456789")
		t.Setenv("PII_REQUIRE_STRONG_SALT", "true")

		cfg := loadConfig()

		if string(cfg.Salt) != "strong_salt_123456789" {
			t.Errorf("expected strong salt to be accepted, got %q", string(cfg.Salt))
		}
	})
}
