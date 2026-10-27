package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// MaxPolicyFileBytes bounds a policy file: anything larger is rejected
// unread, so a wrong path (a log file, say) cannot be parsed as a policy.
const MaxPolicyFileBytes = 4 << 20

// policyFile is the on-disk policy: the same JSON the SDKs pass to
// init_config (SDKConfig), plus an informational revision. The sidecar
// reads it from PII_CONFIG_FILE and reloads it when the file changes, so
// the operator can deliver rules through a ConfigMap and a rule server
// without restarting pods.
type policyFile struct {
	SDKConfig
	// Revision names the version of the rule set (a counter, a hash, a
	// date); it is logged and exported on reload and never changes detection.
	Revision string `json:"revision"`
}

// ParsePolicyJSON builds a Config from a policy file. Unlike the env path
// and ConfigFromSDKJSON, which warn and skip a bad entry, a file is
// all-or-nothing: the first invalid JSON, pattern or value is an error and
// nothing is applied, so a sidecar keeps its previous rules instead of
// running a half-read set. The returned Config has no salt: a salt in the
// file is ignored with a warning, as is fail_policy, because both are
// runtime settings of the process, not rules, and stay with the pod spec.
func ParsePolicyJSON(b []byte) (Config, string, error) {
	cfg := DefaultConfig()

	var pf policyFile
	if err := json.Unmarshal(b, &pf); err != nil {
		return Config{}, "", fmt.Errorf("invalid json: %w", err)
	}
	if pf.Salt != "" {
		fmt.Fprintf(os.Stderr, "WARNING: policy file: salt ignored, the salt comes from PII_SALT only\n")
	}
	if pf.FailPolicy != "" {
		fmt.Fprintf(os.Stderr, "WARNING: policy file: fail_policy ignored, it comes from PII_FAIL_POLICY only\n")
	}

	if pf.EntropyThreshold < 0 {
		return Config{}, "", errors.New("entropy_threshold must not be negative")
	}
	if pf.EntropyThreshold > 0 {
		cfg.EntropyThreshold = pf.EntropyThreshold
	}
	if pf.ConfidenceThreshold < 0 {
		return Config{}, "", errors.New("confidence_score must not be negative")
	}
	if pf.ConfidenceThreshold > 0 {
		cfg.ConfidenceThreshold = pf.ConfidenceThreshold
	}
	if pf.MinSecretLength < 0 || pf.MinSecretLength > MaxMinSecretLength {
		return Config{}, "", fmt.Errorf("min_secret_length must be between 1 and %d", MaxMinSecretLength)
	}
	if pf.MinSecretLength > 0 {
		cfg.MinSecretLength = pf.MinSecretLength
	}
	if len(pf.SensitiveKeys) > 0 {
		keys := make([]string, 0, len(pf.SensitiveKeys))
		for _, k := range pf.SensitiveKeys {
			k = strings.ToLower(strings.TrimSpace(k))
			if k == "" {
				return Config{}, "", errors.New("sensitive_keys holds an empty entry")
			}
			keys = append(keys, k)
		}
		cfg.SensitiveKeys = keys
	}
	if pf.DisableBigramCheck != nil {
		cfg.DisableBigramCheck = *pf.DisableBigramCheck
	}
	if pf.AdaptiveThreshold != nil {
		cfg.AdaptiveThreshold = *pf.AdaptiveThreshold
	}
	if pf.EntityTypeLabels != nil {
		cfg.EntityTypeLabels = *pf.EntityTypeLabels
	}
	if len(pf.SensitiveKeyPatterns) > 0 {
		for _, p := range pf.SensitiveKeyPatterns {
			if _, err := regexp.Compile(p); err != nil {
				return Config{}, "", fmt.Errorf("sensitive_key_patterns: invalid regex %q: %w", p, err)
			}
		}
		if err := cfg.ApplySensitiveKeyPatterns(pf.SensitiveKeyPatterns); err != nil {
			return Config{}, "", fmt.Errorf("sensitive_key_patterns: %w", err)
		}
	}
	if err := checkRegexRules("custom_regexes", pf.CustomRegexes); err != nil {
		return Config{}, "", err
	}
	if len(pf.CustomRegexes) > 0 {
		if err := cfg.ApplyCustomRegexes(pf.CustomRegexes); err != nil {
			return Config{}, "", fmt.Errorf("custom_regexes: %w", err)
		}
	}
	if err := checkRegexRules("safe_regexes", pf.SafeRegexes); err != nil {
		return Config{}, "", err
	}
	if len(pf.SafeRegexes) > 0 {
		if err := cfg.ApplySafeRegexes(pf.SafeRegexes); err != nil {
			return Config{}, "", fmt.Errorf("safe_regexes: %w", err)
		}
	}
	return cfg, pf.Revision, nil
}

// checkRegexRules rejects a rule with an empty or invalid pattern. An empty
// pattern matches every token, so a misspelled key ("regex" for "pattern")
// must not slip through as a rule that hides the whole line.
func checkRegexRules(field string, rules []CustomRegexConfig) error {
	for i, r := range rules {
		if r.Pattern == "" {
			return fmt.Errorf("%s[%d]: empty pattern", field, i)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("%s[%d]: invalid regex %q: %w", field, i, r.Pattern, err)
		}
	}
	return nil
}

// LoadPolicyFile reads and parses the policy at path (see ParsePolicyJSON).
// The caller lays the environment over the result with ApplyEnvOverrides and
// supplies the salt.
func LoadPolicyFile(path string) (Config, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxPolicyFileBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Config{}, "", err
	}
	if len(b) > MaxPolicyFileBytes {
		return Config{}, "", fmt.Errorf("policy file larger than %d bytes", MaxPolicyFileBytes)
	}
	return ParsePolicyJSON(b)
}
