// Package parity holds the cross-entrypoint redaction parity golden
// (cases.json) and the Go/CLI-side assertion. The Node and Python SDK tests
// load the SAME cases.json and assert byte-identical output, so every
// entrypoint (Go API, CLI, Node, Python) is proven to redact identically for a
// given input and config. See sdks/*/test.* and issue #48.
package parity

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pii-shield/pii-shield/pkg/scanner"
)

type parityCase struct {
	Name     string                 `json:"name"`
	Config   map[string]interface{} `json:"config"`
	Input    string                 `json:"input"`
	Expected string                 `json:"expected"`
}

// sdkConfig mirrors ConfigFromSDK in cmd/wasm-ffi/main.go.
type sdkConfig struct {
	EntropyThreshold     float64                     `json:"entropy_threshold"`
	Salt                 string                      `json:"salt"`
	ConfidenceThreshold  float64                     `json:"confidence_score"`
	MinSecretLength      int                         `json:"min_secret_length"`
	SensitiveKeys        []string                    `json:"sensitive_keys"`
	DisableBigramCheck   *bool                       `json:"disable_bigram_check"`
	AdaptiveThreshold    *bool                       `json:"adaptive_threshold"`
	SensitiveKeyPatterns []string                    `json:"sensitive_key_patterns"`
	CustomRegexes        []scanner.CustomRegexConfig `json:"custom_regexes"`
	SafeRegexes          []scanner.CustomRegexConfig `json:"safe_regexes"`
}

// applyConfig mirrors the config mapping in cmd/wasm-ffi/main.go init_config,
// including the fixed default salt the WASM kernel seeds. Keep the two in sync;
// any drift makes the Node/Python SDK tests fail against this golden.
func applyConfig(t *testing.T, c map[string]interface{}) scanner.Config {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal case config: %v", err)
	}
	var sdk sdkConfig
	if err := json.Unmarshal(raw, &sdk); err != nil {
		t.Fatalf("unmarshal case config: %v", err)
	}

	cfg := scanner.DefaultConfig()
	cfg.Salt = []byte("pii-shield-default-salt-12345678")
	if sdk.Salt != "" {
		cfg.Salt = []byte(sdk.Salt)
	}
	if sdk.EntropyThreshold > 0 {
		cfg.EntropyThreshold = sdk.EntropyThreshold
	}
	if sdk.ConfidenceThreshold > 0 {
		cfg.ConfidenceThreshold = sdk.ConfidenceThreshold
	}
	if sdk.MinSecretLength > 0 {
		cfg.MinSecretLength = sdk.MinSecretLength
	}
	if len(sdk.SensitiveKeys) > 0 {
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
	if len(sdk.SensitiveKeyPatterns) > 0 {
		if err := cfg.ApplySensitiveKeyPatterns(sdk.SensitiveKeyPatterns); err != nil {
			t.Fatalf("apply sensitive key patterns: %v", err)
		}
	}
	if len(sdk.CustomRegexes) > 0 {
		if err := cfg.ApplyCustomRegexes(sdk.CustomRegexes); err != nil {
			t.Fatalf("apply custom regexes: %v", err)
		}
	}
	if len(sdk.SafeRegexes) > 0 {
		if err := cfg.ApplySafeRegexes(sdk.SafeRegexes); err != nil {
			t.Fatalf("apply safe regexes: %v", err)
		}
	}
	return cfg
}

func loadCases(t *testing.T) []parityCase {
	t.Helper()
	raw, err := os.ReadFile("cases.json")
	if err != nil {
		t.Fatalf("read cases.json: %v", err)
	}
	var cases []parityCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases.json: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("cases.json is empty")
	}
	return cases
}

// TestGoParity asserts the Go API (scanner.ScanAndRedactText, the entry point
// the WASM kernel calls) reproduces the golden for every case. The Node and
// Python SDKs assert the same golden via WASM.
func TestGoParity(t *testing.T) {
	for _, tc := range loadCases(t) {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			scanner.UpdateConfig(applyConfig(t, tc.Config))
			got := scanner.ScanAndRedactText(tc.Input)
			if got != tc.Expected {
				t.Fatalf("parity mismatch\n input:    %q\n config:   %v\n expected: %q\n got:      %q",
					tc.Input, tc.Config, tc.Expected, got)
			}
		})
	}
}
