package scanner

import (
	"encoding/json"
	"strings"
)

// SDKDefaultSalt is the salt the WASM kernel seeds when an SDK caller gives
// none, so redaction is deterministic across SDK processes by default.
const SDKDefaultSalt = "pii-shield-default-salt-12345678"

// SDKConfig is the JSON config the Node and Python SDKs pass to the WASM
// kernel's init_config. Every field the scanner supports at scan time is
// accepted; fail_policy is handled in the SDK wrappers and ignored here.
type SDKConfig struct {
	EntropyThreshold     float64             `json:"entropy_threshold"`
	Salt                 string              `json:"salt"`
	ConfidenceThreshold  float64             `json:"confidence_score"`
	FailPolicy           string              `json:"fail_policy"`
	MinSecretLength      int                 `json:"min_secret_length"`
	SensitiveKeys        []string            `json:"sensitive_keys"`
	DisableBigramCheck   *bool               `json:"disable_bigram_check"`
	AdaptiveThreshold    *bool               `json:"adaptive_threshold"`
	EntityTypeLabels     *bool               `json:"entity_type_labels"`
	SensitiveKeyPatterns []string            `json:"sensitive_key_patterns"`
	CustomRegexes        []CustomRegexConfig `json:"custom_regexes"`
	SafeRegexes          []CustomRegexConfig `json:"safe_regexes"`
}

// ConfigFromSDKJSON builds the Config the WASM kernel applies for an SDK
// payload. It starts from DefaultConfig with SDKDefaultSalt, so a partial
// override (just a salt, say) keeps the default sensitive keys and threshold,
// and applies only the fields present. Invalid JSON yields that default.
//
// Errors never abort: unlike the CLI, an SDK caller's bad pattern must not
// terminate the host Node/Python process. An invalid sensitive-key pattern
// list is dropped whole; an invalid custom or safe rule is skipped (and
// reported on stderr by the scanner, B14) while the valid ones apply.
//
// The WASM kernel and the parity test (sdks/parity) both call this, so the
// Go-side golden check cannot drift from what the SDKs actually run.
func ConfigFromSDKJSON(b []byte) Config {
	cfg := DefaultConfig()
	cfg.Salt = []byte(SDKDefaultSalt)

	var sdk SDKConfig
	if err := json.Unmarshal(b, &sdk); err != nil {
		return cfg
	}
	if sdk.EntropyThreshold > 0 {
		cfg.EntropyThreshold = sdk.EntropyThreshold
	}
	if sdk.Salt != "" {
		cfg.Salt = []byte(sdk.Salt)
	}
	if sdk.ConfidenceThreshold > 0 {
		cfg.ConfidenceThreshold = sdk.ConfidenceThreshold
	}
	if sdk.MinSecretLength > 0 {
		cfg.MinSecretLength = sdk.MinSecretLength
	}
	if len(sdk.SensitiveKeys) > 0 {
		// Normalized the same way loadConfig does for PII_SENSITIVE_KEYS, so
		// SDK-provided keys match the CLI's case-insensitive matching.
		keys := make([]string, len(sdk.SensitiveKeys))
		for i, k := range sdk.SensitiveKeys {
			keys[i] = strings.ToLower(strings.TrimSpace(k))
		}
		cfg.SensitiveKeys = keys
	}
	if sdk.DisableBigramCheck != nil {
		cfg.DisableBigramCheck = *sdk.DisableBigramCheck
	}
	if sdk.AdaptiveThreshold != nil {
		cfg.AdaptiveThreshold = *sdk.AdaptiveThreshold
	}
	if sdk.EntityTypeLabels != nil {
		cfg.EntityTypeLabels = *sdk.EntityTypeLabels
	}
	if len(sdk.SensitiveKeyPatterns) > 0 {
		if err := cfg.ApplySensitiveKeyPatterns(sdk.SensitiveKeyPatterns); err != nil {
			cfg.SensitiveKeyPatterns = nil
		}
	}
	if len(sdk.CustomRegexes) > 0 {
		_ = cfg.ApplyCustomRegexes(sdk.CustomRegexes)
	}
	if len(sdk.SafeRegexes) > 0 {
		_ = cfg.ApplySafeRegexes(sdk.SafeRegexes)
	}
	return cfg
}
