package scanner

import (
	"errors"
	"strings"
	"testing"
)

// These tests cover the shared config-compile helpers introduced so the SDK/WASM
// entrypoint derives the same matching state as the CLI (issue #48). The error
// branches matter most: an invalid pattern from an SDK caller must return an
// error rather than panic or terminate the host.

func TestCompileSensitiveKeyPatterns(t *testing.T) {
	// Empty / whitespace-only input compiles to no regex, no error.
	re, err := compileSensitiveKeyPatterns([]string{"", "   "})
	if err != nil {
		t.Fatalf("unexpected error for empty patterns: %v", err)
	}
	if re != nil {
		t.Fatalf("expected nil regex for empty patterns, got %v", re)
	}

	// Valid patterns compile, case-insensitively.
	re, err = compileSensitiveKeyPatterns([]string{"^x-secret-"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if re == nil || !re.MatchString("X-Secret-Token") {
		t.Fatalf("expected case-insensitive match for compiled pattern")
	}

	// Invalid regex returns an error instead of panicking.
	if _, err := compileSensitiveKeyPatterns([]string{"["}); err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestApplySensitiveKeyPatterns(t *testing.T) {
	originalConfig := activeCfg()
	defer UpdateConfig(originalConfig)

	// Valid: patterns stored, and UpdateConfig derives the live sensitiveRegex.
	cfg := DefaultConfig()
	cfg.Salt = []byte("test-salt-000000000000000")
	if err := cfg.ApplySensitiveKeyPatterns([]string{" ^x-custom- ", ""}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.SensitiveKeyPatterns) != 1 || cfg.SensitiveKeyPatterns[0] != "^x-custom-" {
		t.Fatalf("expected trimmed single pattern, got %#v", cfg.SensitiveKeyPatterns)
	}
	UpdateConfig(cfg)
	if !cfgState().isSensitiveKey("X-Custom-Header") {
		t.Fatal("expected key matching the pattern to be sensitive after UpdateConfig")
	}

	// Invalid regex returns an error.
	if err := cfg.ApplySensitiveKeyPatterns([]string{"("}); err == nil {
		t.Fatal("expected error for invalid pattern, got nil")
	}
}

func TestApplyCustomRegexes(t *testing.T) {
	cfg := DefaultConfig()

	// Valid rules populate the combined regex and names.
	err := cfg.ApplyCustomRegexes([]CustomRegexConfig{
		{Pattern: `TX-\d{5}`, Name: "TX"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CombinedCustomRegex == nil || !cfg.CombinedCustomRegex.MatchString("TX-12345") {
		t.Fatal("expected combined custom regex to match")
	}
	if len(cfg.CustomRegexNames) != 1 || cfg.CustomRegexNames[0] != "TX" {
		t.Fatalf("expected custom regex name 'TX', got %#v", cfg.CustomRegexNames)
	}
	if len(cfg.CustomRegexes) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(cfg.CustomRegexes))
	}

	// Empty input clears the derived state.
	if err := cfg.ApplyCustomRegexes(nil); err != nil {
		t.Fatalf("unexpected error clearing: %v", err)
	}
	if cfg.CombinedCustomRegex != nil || cfg.CustomRegexNames != nil {
		t.Fatal("expected combined regex and names cleared on empty input")
	}

	// Invalid pattern returns an error.
	if err := cfg.ApplyCustomRegexes([]CustomRegexConfig{{Pattern: "(", Name: "bad"}}); err == nil {
		t.Fatal("expected error for invalid custom regex, got nil")
	}
}

func TestUpdateConfigInvalidPatternWarnsNotPanics(t *testing.T) {
	originalConfig := activeCfg()
	defer UpdateConfig(originalConfig)

	// A caller can set SensitiveKeyPatterns directly (bypassing Apply*), so
	// UpdateConfig must tolerate an invalid pattern: warn, leave sensitiveRegex
	// nil, and never panic.
	cfg := DefaultConfig()
	cfg.Salt = []byte("test-salt-000000000000000")
	cfg.SensitiveKeyPatterns = []string{"("}
	UpdateConfig(cfg)
	if cfgState().sensitiveRegex != nil {
		t.Fatal("expected sensitiveRegex to be nil after an invalid pattern")
	}
}

func TestApplySafeRegexes(t *testing.T) {
	cfg := DefaultConfig()

	if err := cfg.ApplySafeRegexes([]CustomRegexConfig{{Pattern: `^A1b2.*`, Name: "safe"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.SafeRegexes) != 1 || !cfg.SafeRegexes[0].Regexp.MatchString("A1b2xyz") {
		t.Fatal("expected safe regex to be compiled and match")
	}

	if err := cfg.ApplySafeRegexes([]CustomRegexConfig{{Pattern: "(", Name: "bad"}}); err == nil {
		t.Fatal("expected error for invalid safe regex, got nil")
	}
}

// TestApplyRegexesSkipsInvalidRuleKeepsRest covers B14: one rule that does not
// compile must not take the whole list with it. Before this, the first bad
// pattern made ApplyCustomRegexes/ApplySafeRegexes return early with nothing
// applied, and init_config (WASM/SDK path) discards that error — so one stray
// bracket in a client's rules file silently switched off every client rule.
func TestApplyRegexesSkipsInvalidRuleKeepsRest(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)

	cfg := campaignConfig()
	err := cfg.ApplyCustomRegexes([]CustomRegexConfig{
		{Pattern: `^[0-9]{4,5}/[0-9]{2}$`, Name: "case-no"},
		{Pattern: `^\(?(?(`, Name: "broken"},
	})
	var skipped *SkippedRegexRulesError
	if !errors.As(err, &skipped) {
		t.Fatalf("expected *SkippedRegexRulesError, got %v", err)
	}
	if len(skipped.Skipped) != 1 || skipped.Skipped[0].Name != "broken" || skipped.List != "custom regex list" {
		t.Errorf("wrong skipped report: %+v", skipped)
	}
	// The error text is what an SDK user sees in a log: it must name the list,
	// the count and the offending pattern.
	if msg := err.Error(); !strings.Contains(msg, "custom regex list") || !strings.Contains(msg, "1 invalid rule") ||
		!strings.Contains(msg, `^\(?(?(`) {
		t.Errorf("unhelpful error text: %q", msg)
	}
	if len(cfg.CustomRegexes) != 1 || cfg.CombinedCustomRegex == nil || len(cfg.CustomRegexNames) != 1 {
		t.Fatalf("valid rule not applied alongside the skipped one: rules=%d combined=%v names=%v",
			len(cfg.CustomRegexes), cfg.CombinedCustomRegex != nil, cfg.CustomRegexNames)
	}
	UpdateConfig(cfg)
	if out := ScanAndRedact("ref 12345/06 filed"); strings.Contains(out, "12345/06") {
		t.Errorf("valid custom rule stopped working next to an invalid one: %q", out)
	}

	cfg = campaignConfig()
	err = cfg.ApplySafeRegexes([]CustomRegexConfig{
		{Pattern: `^[0-9]{1,3}-year-old$`, Name: "age"},
		{Pattern: `^\(?(?(`, Name: "broken"},
	})
	if !errors.As(err, &skipped) || skipped.List != "safe regex list" {
		t.Fatalf("expected safe-list skip report, got %v", err)
	}
	if len(cfg.SafeRegexes) != 1 {
		t.Fatalf("valid safe rule not applied: %d", len(cfg.SafeRegexes))
	}
	UpdateConfig(cfg)
	if out := ScanAndRedact("a 55-year-old man"); !strings.Contains(out, "55-year-old") {
		t.Errorf("valid safe rule stopped working next to an invalid one: %q", out)
	}

	// A fully valid list still reports no error at all.
	cfg = campaignConfig()
	if err := cfg.ApplyCustomRegexes([]CustomRegexConfig{{Pattern: `^[0-9]{4,5}/[0-9]{2}$`, Name: "case-no"}}); err != nil {
		t.Errorf("valid list reported an error: %v", err)
	}
}
