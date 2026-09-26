package scanner

import (
	"os"
	"regexp"
	"testing"
)

func TestScanner_CustomRegexRedaction(t *testing.T) {
	// Save original config to restore later
	originalConfig := activeCfg()
	defer UpdateConfig(originalConfig)

	tests := []struct {
		name           string
		regexConfig    string // JSON for PII_CUSTOM_REGEX_LIST
		input          string
		expectedOutput string
	}{
		{
			name:        "Account Redaction (Named)",
			regexConfig: `[{"pattern": "^ACCT-[0-9]{10}$", "name": "Account"}]`,
			input:       "User ID: ACCT-1234567890",
			// Expect: [HIDDEN:Account:HexHash]
			expectedOutput: `User ID: \[HIDDEN:Account:[a-f0-9]{6}\]`,
		},
		{
			name:           "Documentation Example (TX License)",
			regexConfig:    `[{"pattern": "^TX-[0-9]{5}$", "name": "TX"}]`,
			input:          "License: TX-12345",
			expectedOutput: `License: \[HIDDEN:TX:[a-f0-9]{6}\]`,
		},
		{
			name:        "Account Redaction (Unnamed)",
			regexConfig: `[{"pattern": "^ACCT-[0-9]{10}$", "name": ""}]`,
			input:       "Transaction: ACCT-1234567890",
			// Expect: [HIDDEN:HexHash] (Wait, redactWithHMAC adds extra colon if name empty? Let's check logic)
			// Logic: if name != "" { append :name }; append :hash
			// So if name is empty: [HIDDEN:hash]
			expectedOutput: `Transaction: \[HIDDEN:[a-f0-9]{6}\]`,
		},
		{
			name:           "Case Insensitivity (Implicit in Pattern)",
			regexConfig:    `[{"pattern": "(?i)^acct-[0-9]{10}$", "name": "Account"}]`,
			input:          "ID: ACCT-1234567890",
			expectedOutput: `ID: \[HIDDEN:Account:[a-f0-9]{6}\]`,
		},
		{
			// A short rule fires on a short token: there is no length gate
			// in front of custom rules since B5 (the old "< 5 characters is
			// skipped" case asserted a gate that no longer exists).
			name:        "Short rule fires on a short token",
			regexConfig: `[{"pattern": "^[0-9]{4}$", "name": "PIN"}]`,
			input:       "Code: 1234",
			// After "Code:" the number is in value position, so it is quoted
			// the way a hidden JSON number is.
			expectedOutput: `^Code: "\[HIDDEN:PIN:[a-f0-9]{6}\]"$`,
		},
		{
			name:           "Short rule leaves a token it does not match",
			regexConfig:    `[{"pattern": "^[0-9]{4}$", "name": "PIN"}]`,
			input:          "Code: 123",
			expectedOutput: "^Code: 123$",
		},
		{
			name:           "Multiple Regexes",
			regexConfig:    `[{"pattern": "^ACCT-[0-9]{10}$", "name": "Account"}, {"pattern": "^TX-[0-9]{5}$", "name": "TX"}]`,
			input:          "ID: ACCT-1234567890 Ref: TX-12345",
			expectedOutput: `ID: \[HIDDEN:Account:[a-f0-9]{6}\] Ref: \[HIDDEN:TX:[a-f0-9]{6}\]`,
		},
		{
			name:           "No Config",
			regexConfig:    "",
			input:          "Value: ACCT-1234567890",
			expectedOutput: "Value: ACCT-1234567890", // Not hidden without config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tConfig := originalConfig                   // Copy defaults
			tConfig.CustomRegexes = []CustomRegexRule{} // Reset

			if tt.regexConfig != "" {
				// Simulate loading from env
				os.Setenv("PII_CUSTOM_REGEX_LIST", tt.regexConfig)
				// Re-load config to parse regexes.
				// Note: In real app, init() runs once. Here we simulate it.
				tConfig = loadConfig()
				os.Unsetenv("PII_CUSTOM_REGEX_LIST")
			}

			// Swap global config. Reset entropy threshold to a very high value
			// (100.0) for ALL tests. This proves that redaction is happening
			// purely due to Regex, not entropy.
			tConfig.EntropyThreshold = 100.0
			UpdateConfig(tConfig)

			got := ScanAndRedact(tt.input)

			// CHANGED: Use Regex to verify output because Hash is dynamic/random if salt is random
			// We expect [HIDDEN:Name:Hash] or [HIDDEN:Hash]
			// The original expectedOutput in struct is just the prefix part for simplicity, OR we update the struct to be a regex.
			// Let's treat tt.expectedOutput as a REGEX pattern now.

			matched, err := regexp.MatchString(tt.expectedOutput, got)
			if err != nil {
				t.Fatalf("Invalid regex in test case: %v", err)
			}
			if !matched {
				t.Errorf("ScanAndRedact() = %v, want match %v", got, tt.expectedOutput)
			}
		})
	}
}

func TestScanner_SafeRegexWhitelist(t *testing.T) {
	originalConfig := activeCfg()
	defer UpdateConfig(originalConfig)

	tests := []struct {
		name           string
		safeConfig     string // JSON for PII_SAFE_REGEX_LIST
		customConfig   string // JSON for PII_CUSTOM_REGEX_LIST
		input          string
		expectedOutput string
	}{
		{
			name:           "Whitelist Custom ID",
			safeConfig:     `[{"pattern": "^ALLOWED-[0-9]+$", "name": "Allowed"}]`,
			customConfig:   "",
			input:          "Safe ID: ALLOWED-12345",
			expectedOutput: "Safe ID: ALLOWED-12345",
		},
		{
			name:           "Conflict: Whitelist Wins over Custom Redaction",
			safeConfig:     `[{"pattern": "^SAFE-[0-9]{4}$", "name": "Safe"}]`,
			customConfig:   `[{"pattern": "^SAFE-[0-9]{4}$", "name": "Block"}]`,
			input:          "Value: SAFE-1234",
			expectedOutput: "Value: SAFE-1234", // Should NOT be redacted
		},
		{
			name:           "Conflict: Whitelist Wins over High Entropy",
			safeConfig:     `[{"pattern": "^[a-zA-Z0-9]{20,}$", "name": "LongToken"}]`,
			customConfig:   "",
			input:          "Token: abcdefghijklmnopqrstuvwxyz123456", // High entropy/length
			expectedOutput: "Token: abcdefghijklmnopqrstuvwxyz123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tConfig := originalConfig
			tConfig.CustomRegexes = []CustomRegexRule{}
			tConfig.SafeRegexes = []CustomRegexRule{}

			if tt.safeConfig != "" {
				os.Setenv("PII_SAFE_REGEX_LIST", tt.safeConfig)
			}
			if tt.customConfig != "" {
				os.Setenv("PII_CUSTOM_REGEX_LIST", tt.customConfig)
			}

			// Reload config
			if tt.safeConfig != "" || tt.customConfig != "" {
				tConfig = loadConfig()
				os.Unsetenv("PII_SAFE_REGEX_LIST")
				os.Unsetenv("PII_CUSTOM_REGEX_LIST")
			}
			// Ensure entropy is sensitive enough to catch the "High Entropy" case if whitelist fails
			if tt.name == "Conflict: Whitelist Wins over High Entropy" {
				tConfig.EntropyThreshold = 2.0 // Very sensitive
			}
			UpdateConfig(tConfig)

			got := ScanAndRedact(tt.input)
			if got != tt.expectedOutput {
				t.Errorf("ScanAndRedact() = %v, want %v", got, tt.expectedOutput)
			}
		})
	}
}
