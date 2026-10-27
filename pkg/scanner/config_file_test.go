package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePolicyJSON_AppliesFieldsOverDefaults(t *testing.T) {
	cfg, rev, err := ParsePolicyJSON([]byte(`{
		"revision": "r42",
		"entropy_threshold": 4.1,
		"confidence_score": 1.1,
		"min_secret_length": 8,
		"sensitive_keys": [" Geheim ", "clave"],
		"disable_bigram_check": true,
		"entity_type_labels": true,
		"sensitive_key_patterns": ["^x_"],
		"custom_regexes": [{"pattern": "^TX-\\d{5}$", "name": "tx"}],
		"safe_regexes": [{"pattern": "^[a-f0-9]{7}$", "name": "sha"}]
	}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rev != "r42" {
		t.Errorf("revision = %q, want r42", rev)
	}
	if cfg.EntropyThreshold != 4.1 || cfg.ConfidenceThreshold != 1.1 || cfg.MinSecretLength != 8 {
		t.Errorf("thresholds not applied: %+v", cfg)
	}
	if got := strings.Join(cfg.SensitiveKeys, ","); got != "geheim,clave" {
		t.Errorf("sensitive keys = %q, want normalized geheim,clave", got)
	}
	if !cfg.DisableBigramCheck || !cfg.EntityTypeLabels {
		t.Errorf("bool fields not applied: %+v", cfg)
	}
	if len(cfg.SensitiveKeyPatterns) != 1 || len(cfg.CustomRegexes) != 1 || len(cfg.SafeRegexes) != 1 {
		t.Errorf("pattern lists not applied: %+v", cfg)
	}
	if cfg.Salt != nil {
		t.Errorf("a parsed policy must carry no salt, got %q", cfg.Salt)
	}
}

func TestParsePolicyJSON_PartialKeepsDefaults(t *testing.T) {
	cfg, rev, err := ParsePolicyJSON([]byte(`{"entropy_threshold": 4.0}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	def := DefaultConfig()
	if rev != "" || cfg.MinSecretLength != def.MinSecretLength || len(cfg.SensitiveKeys) != len(def.SensitiveKeys) {
		t.Errorf("partial file must keep defaults: %+v", cfg)
	}
}

func TestParsePolicyJSON_SaltAndFailPolicyIgnored(t *testing.T) {
	cfg, _, err := ParsePolicyJSON([]byte(`{"salt": "0123456789abcdef0123456789abcdef", "fail_policy": "closed"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Salt != nil {
		t.Errorf("salt from the file must be ignored, got %q", cfg.Salt)
	}
}

func TestParsePolicyJSON_RejectsWhole(t *testing.T) {
	cases := map[string]string{
		"invalid json":            `{"entropy_threshold": `,
		"bad key pattern":         `{"sensitive_key_patterns": ["("]}`,
		"bad custom regex":        `{"custom_regexes": [{"pattern": "ok"}, {"pattern": "["}]}`,
		"empty custom pattern":    `{"custom_regexes": [{"regex": "^TX$", "name": "typo"}]}`,
		"bad safe regex":          `{"safe_regexes": [{"pattern": "(?P<"}]}`,
		"negative entropy":        `{"entropy_threshold": -1}`,
		"min length out of range": `{"min_secret_length": 100000}`,
		"empty sensitive key":     `{"sensitive_keys": ["a", " "]}`,
	}
	for name, in := range cases {
		if _, _, err := ParsePolicyJSON([]byte(in)); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
}

func TestLoadPolicyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"revision": "1", "sensitive_keys": ["zzz"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, rev, err := LoadPolicyFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rev != "1" || len(cfg.SensitiveKeys) != 1 || cfg.SensitiveKeys[0] != "zzz" {
		t.Errorf("file not applied: rev=%q cfg=%+v", rev, cfg)
	}

	if _, _, err := LoadPolicyFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file: expected an error")
	}

	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat(" ", MaxPolicyFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPolicyFile(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: expected a size error, got %v", err)
	}
}

func TestApplyEnvOverrides_EnvWinsOverBase(t *testing.T) {
	base, _, err := ParsePolicyJSON([]byte(`{"entropy_threshold": 4.4, "min_secret_length": 9, "sensitive_keys": ["fromfile"]}`))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PII_SALT", "0123456789abcdef0123456789abcdef")
	t.Setenv("PII_ENTROPY_THRESHOLD", "3.9")
	t.Setenv("PII_MIN_SECRET_LENGTH", "")
	t.Setenv("PII_SENSITIVE_KEYS", "fromenv")
	cfg := ApplyEnvOverrides(base)
	if cfg.EntropyThreshold != 3.9 {
		t.Errorf("env must win: entropy = %v, want 3.9", cfg.EntropyThreshold)
	}
	if cfg.MinSecretLength != 9 {
		t.Errorf("unset env must leave the file value: min length = %d, want 9", cfg.MinSecretLength)
	}
	if strings.Join(cfg.SensitiveKeys, ",") != "fromenv" {
		t.Errorf("env must replace the file list: %v", cfg.SensitiveKeys)
	}
	if string(cfg.Salt) != "0123456789abcdef0123456789abcdef" {
		t.Errorf("salt must come from PII_SALT, got %q", cfg.Salt)
	}
}

func TestApplyEnvOverrides_KeepsBaseSaltWithoutEnv(t *testing.T) {
	t.Setenv("PII_SALT", "")
	base := DefaultConfig()
	base.Salt = []byte("salt-from-the-running-process-xx")
	cfg := ApplyEnvOverrides(base)
	if string(cfg.Salt) != string(base.Salt) {
		t.Errorf("a salt already in the base must be kept across a reload, got %q", cfg.Salt)
	}

	empty := ApplyEnvOverrides(DefaultConfig())
	if len(empty.Salt) != 32 {
		t.Errorf("an empty base salt must become a random one, got %d bytes", len(empty.Salt))
	}
}
