package scanner

import (
	"strings"
	"testing"
)

// A lone "=" or ":" after a sensitive key carries the key's force onto the
// value, when the value looks like a secret; code and prose keep their words.
func TestSensitiveKeyForceAcrossSpacedSeparator(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ line, secret string }{
		{"api_key = lenapass2024", "lenapass2024"},
		{"client_secret = lenapass2024", "lenapass2024"},
		{"key = bGVuYTpoNllvNGdmcQ==", "bGVuYTpoNllvNGdmcQ"},
		{"Header: api_key = lenapass2024", "lenapass2024"},
		{"api_key : lenapass2024", "lenapass2024"},
		{"key = 12345678", "12345678"},
	} {
		if got := ScanAndRedact(tc.line); strings.Contains(got, tc.secret) {
			t.Errorf("ScanAndRedact(%q) = %q, secret survived", tc.line, got)
		}
	}
	for _, line := range []string{
		"api_key = api_key if api_key is not None",
		"the key = value",
		"key = value",
		"the key = 3",
		"auth = basic support",
		"authorization = failed for user bob",
		"secret = None",
		"password = password",
		"token = token_value",
	} {
		if got := ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}
