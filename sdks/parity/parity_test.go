// Package parity holds the cross-entrypoint redaction parity golden
// (cases.json) and the Go-side assertion. The Node and Python SDK tests load
// the SAME cases.json and assert byte-identical output against the freshly
// built WASM kernel, so the Go API, Node and Python are proven to redact
// identically for a given input and config. The CLI is not run here: it is
// configured from environment variables, not this JSON. See sdks/*/test.*
// and issue #48.
package parity

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pii-shield/pii-shield/pkg/scanner"
)

type parityCase struct {
	Name     string                 `json:"name"`
	Config   map[string]interface{} `json:"config"`
	Input    string                 `json:"input"`
	Expected string                 `json:"expected"`
}

// applyConfig builds the config exactly as the WASM kernel's init_config does:
// both call scanner.ConfigFromSDKJSON, so this side cannot drift from what the
// Node and Python SDKs run. It used to be a hand-kept copy of that mapping,
// which had already lost entity_type_labels and turned a bad
// sensitive_key_patterns list into a test failure where the kernel drops it.
func applyConfig(t *testing.T, c map[string]interface{}) scanner.Config {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal case config: %v", err)
	}
	return scanner.ConfigFromSDKJSON(raw)
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
