package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// Benchmarks for the whitelist, blacklist and custom-regex steps in isolation.
// There is no Test function here: the file was performance_test.go, a name
// that promised timing assertions it never had. Each benchmark checks only
// that the step still gives the right answer inside its loop.

// resetConfig puts the benchmark on the shipped defaults (campaignConfig =
// DefaultConfig plus a fixed salt) and restores the previous config when the
// benchmark ends. The old hand-copied Config left out ConfidenceThreshold (0
// instead of 1.0) and was never restored, so benchmarks that ran after it in
// file order, BenchmarkScanAndRedact and BenchmarkThroughput among them,
// measured that config plus whatever custom rules the last one added.
func resetConfig(b *testing.B) {
	b.Helper()
	old := activeCfg()
	b.Cleanup(func() { UpdateConfig(old) })
	UpdateConfig(campaignConfig())
}

// -----------------------------------------------------------------------------
// Whitelist Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkWhitelist_Static(b *testing.B) {
	resetConfig(b)
	// Test standard static whitelist check
	token := "2001:db8:85a3::8a2e:370:7334" // Valid IPv6

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// We use isSafe directly to isolate whitelist logic
		if !isSafe(token) {
			b.Fatal("Expected token to be safe")
		}
	}
}

func BenchmarkWhitelist_Regex(b *testing.B) {
	resetConfig(b)
	// Configure a Safe Regex
	safePattern := `^SAFE-ID-\d+$`
	re := regexp.MustCompile(safePattern)
	applyCfg(func(c *Config) {
		c.SafeRegexes = []CustomRegexRule{{Regexp: re, Name: "SafeID"}}
	})

	token := "SAFE-ID-987654321"

	var sb strings.Builder
	sb.Grow(64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		cfgState().processSingleToken(token, token, false, false, false, &sb)
		res := sb.String()
		if res != token {
			b.Fatalf("Expected token to be preserved, got %s", res)
		}
	}
}

// -----------------------------------------------------------------------------
// Blacklist Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkBlacklist_Static(b *testing.B) {
	resetConfig(b)
	// "password" is in default SensitiveKeys
	key := "password"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !cfgState().isSensitiveKey(key) {
			b.Fatal("Expected key to be sensitive")
		}
	}
}

func BenchmarkBlacklist_Regex(b *testing.B) {
	resetConfig(b)
	// Configure Sensitive Key Patterns
	// We simulate what loadConfig does: combine into one regex
	// Drive the sensitive-key regex through the real config path so it is
	// published atomically like production (UpdateConfig compiles the patterns
	// into the combined case-insensitive sensitiveRegex).
	applyCfg(func(c *Config) {
		c.SensitiveKeyPatterns = []string{"custom_secret", "super_confidential"}
	})

	// A key NOT in static list, but matches regex
	key := "custom_secret"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !cfgState().isSensitiveKey(key) {
			b.Fatalf("Expected key '%s' to be sensitive via regex", key)
		}
	}
}

// -----------------------------------------------------------------------------
// Regex Redaction Benchmarks (Custom Regex List)
// -----------------------------------------------------------------------------

func BenchmarkCustomRegex(b *testing.B) {
	resetConfig(b)
	// Configure Custom Regex for redaction (e.g. finding SSNs in values)
	pattern := `\b\d{3}-\d{2}-\d{4}\b` // SSN-like
	re := regexp.MustCompile(pattern)
	applyCfg(func(c *Config) {
		c.CustomRegexes = []CustomRegexRule{{Regexp: re, Name: "SSN"}}
	})

	token := "123-45-6789"
	var sb strings.Builder
	sb.Grow(64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		cfgState().processSingleToken(token, token, false, false, false, &sb)
		res := sb.String()
		if res == token {
			b.Fatalf("Expected redaction for token %s", token)
		}
	}
}

func BenchmarkCustomRegex_5Rules(b *testing.B) {
	resetConfig(b)
	// Five rules through ApplyCustomRegexes, the path the config loader
	// uses, so the benchmark measures the real combined regex rather than a
	// hand-built copy of it.
	cfg := activeCfg()
	if err := cfg.ApplyCustomRegexes([]CustomRegexConfig{
		{Pattern: `\buser-\d+\b`, Name: "UserId"},
		{Pattern: `\bemail-[a-z]+\b`, Name: "EmailId"},
		{Pattern: `\bkb-\d{5}\b`, Name: "KB"},
		{Pattern: `\bticket-[a-z0-9]+\b`, Name: "Ticket"},
		{Pattern: `\b\d{3}-\d{2}-\d{4}\b`, Name: "SSN"}, // the one that matches
	}); err != nil {
		b.Fatal(err)
	}
	UpdateConfig(cfg)

	token := "123-45-6789"
	var sb strings.Builder
	sb.Grow(64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Reset()
		cfgState().processSingleToken(token, token, false, false, false, &sb)
		res := sb.String()
		if res == token {
			b.Fatalf("Expected redaction for token %s", token)
		}
	}
}
