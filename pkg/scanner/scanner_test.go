package scanner

import (
	"strings"
	"testing"
)

func TestScanner_Multilingual(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedSafe   []string
		expectedHidden []string
	}{
		{
			name:           "Spanish Log",
			input:          "El usuario inició sesión con éxito. ID de sesión: 12345",
			expectedSafe:   []string{"El", "usuario", "inició", "sesión", "con", "éxito.", "ID", "de", "12345"},
			expectedHidden: []string{},
		},
		{
			name:           "German Log",
			input:          "Fehler beim Verbinden mit Datenbank Benutzername: admin",
			expectedSafe:   []string{"Fehler", "beim", "Verbinden", "mit", "Datenbank", "Benutzername:", "admin"},
			expectedHidden: []string{},
		},
		{
			name:           "Russian Log (Cyrillic)",
			input:          "Ошибка доступа для пользователя Ivan",
			expectedSafe:   []string{"Ошибка", "доступа", "для", "пользователя", "Ivan"},
			expectedHidden: []string{},
		},
	}

	// At the default config (bigrams on): since F5 bigrams are scored only on
	// ASCII pairs, so non-English text needs no special setup. The line must
	// come back byte for byte; the per-word checks below only name what broke.
	savedCfg := activeCfg()
	UpdateConfig(campaignConfig())
	defer UpdateConfig(savedCfg)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanAndRedact(tt.input)
			if got != tt.input {
				t.Errorf("line changed: %q -> %q", tt.input, got)
			}
			for _, safe := range tt.expectedSafe {
				if !strings.Contains(got, safe) {
					t.Errorf("Expected safe word %q to be present, but it was redacted or modified. Got: %s", safe, got)
				}
			}
			for _, hidden := range tt.expectedHidden {
				if strings.Contains(got, hidden) {
					t.Errorf("Expected sensitive word %q to be hidden, but it was present. Got: %s", hidden, got)
				}
			}
		})
	}
}

func TestScanner_TechnicalJargon(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"UUID", "Request ID: 550e8400-e29b-41d4-a716-446655440000"},
		{"Git SHA", "Commit: 7b3f1c2"},
		{"IPv6", "Address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"Path", "Path: /var/log/nginx/access.log"},
		{"URL", "URL: https://example.com/api/v1/users"},
		{"Date", "Date: 2023-10-27T10:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanAndRedact(tt.input)
			if got != tt.input {
				t.Errorf("Technical jargon should be safe. Input: %q, Got: %q", tt.input, got)
			}
		})
	}
}

// TestScanner_NegativeCases checks that each secret is gone from the output,
// not only that a marker appeared somewhere: the "Stress Test Leak" line also
// carries an IP, which is redacted on its own, so with entropy redaction
// disabled the old marker-anywhere check stayed green while
// ccGazanojgGcOSa came back in the clear (audit 2026-09-25).
func TestScanner_NegativeCases(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		shouldRedact bool
		secret       string // must not survive outside a marker
	}{
		{"Weak Password", "password=123", true, "123"},                                                                   // Should be redacted because key 'password' is sensitive
		{"Common Word", "key=value", true, "value"},                                                                      // Should be redacted because key 'key' is sensitive
		{"High Entropy Secret", "api_key=sk_live_51Nc7qE...", true, "sk_live_51Nc7qE"},                                   // Should be redacted
		{"Random Noise", "data=8f7d9a2b3c4e5f6", true, "8f7d9a2b3c4e5f6"},                                                // High entropy hex
		{"Valid Visa (Luhn)", "cc=4556737586899855", true, "4556737586899855"},                                           // Valid Luhn with enough distinct digits (7 >= 2)
		{"Stress Test Leak (ccGazanojgGcOSa)", "Error: 192.168.1.5 ccGazanojgGcOSa connection", true, "ccGazanojgGcOSa"}, // Regression test for Threshold 3.6
		{"Stripe/Visa Test Card (low digit diversity)", "card=4111111111111111", true, "4111111111111111"},               // Regression: only 2 distinct digits (4,1), was wrongly filtered by countDistinctDigits<4
		{"Mastercard Test Card (low digit diversity)", "card=5555555555554444", true, "5555555555554444"},                // Regression: only 2 distinct digits (5,4)
	}

	// Ensure default config for this test
	// SAFE CONFIG MODIFICATION
	savedCfg := activeCfg()
	applyCfg(func(c *Config) {
		c.EntropyThreshold = DefaultEntropyThreshold
		c.MinSecretLength = 6
	})
	defer UpdateConfig(savedCfg)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanAndRedact(tt.input)
			isRedacted := strings.Contains(got, "[HIDDEN:")
			if isRedacted != tt.shouldRedact {
				t.Errorf("Expected redaction: %v, Got redaction: %v. Input: %q, Output: %q", tt.shouldRedact, isRedacted, tt.input, got)
			}
			if tt.secret != "" && strings.Contains(withoutMarkers(got), tt.secret) {
				t.Errorf("secret %q survived. Input: %q, Output: %q", tt.secret, tt.input, got)
			}
		})
	}
}

// TestFindLuhnSequences_LowDigitDiversityCards is a regression test for a bug
// where FindLuhnSequences silently missed valid card numbers that use few
// distinct digits (e.g. Stripe/Visa's standard test card 4111111111111111,
// which is made up of only '4' and '1'). The connectivity/boundary/Luhn
// checks all passed for this input, but a countDistinctDigits < 4 filter
// (intended to reject degenerate padding like "0000000000000000") rejected
// it anyway, so ScanAndRedact left the card number in plaintext.
func TestFindLuhnSequences_LowDigitDiversityCards(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantMatched string // substring expected to be found within a returned range
	}{
		{
			"Visa test card in key=value log line",
			"2026-07-24T10:22:45Z INFO stripe_webhook card=4111111111111111 status=success",
			"4111111111111111",
		},
		{
			"Mastercard test card",
			"card=5555555555554444",
			"5555555555554444",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges := FindLuhnSequences(tt.line)
			if len(ranges) == 0 {
				t.Fatalf("FindLuhnSequences returned no ranges for %q", tt.line)
			}
			found := false
			for _, r := range ranges {
				if tt.line[r.Start:r.End] == tt.wantMatched {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected a range matching %q, got ranges %+v for line %q", tt.wantMatched, ranges, tt.line)
			}

			redacted := ScanAndRedact(tt.line)
			if strings.Contains(redacted, tt.wantMatched) {
				t.Errorf("ScanAndRedact left card number in plaintext: %q", redacted)
			}
		})
	}
}

// TestFindLuhnSequences_AllSameDigitStillSuppressed makes sure the fix for
// the low-digit-diversity bug above didn't remove the guard against
// degenerate single-digit padding (e.g. all zeros), which is Luhn-valid by
// construction but never a real card number.
func TestFindLuhnSequences_AllSameDigitStillSuppressed(t *testing.T) {
	line := "id=0000000000000000"
	ranges := FindLuhnSequences(line)
	if len(ranges) != 0 {
		t.Errorf("expected all-same-digit sequence to be suppressed, got ranges %+v", ranges)
	}
}
