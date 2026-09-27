package scanner

// Phase 2 of the scanner quality campaign (SCN-S): acceptance tests for four
// small bugs — strict parseFloat (2a), ASCII-only Luhn digit collection (2b),
// UTF-8-aware boundary checks (2c), and the recursion depth bound (2d).

import (
	"strings"
	"testing"
	"time"
)

// TestParseFloatStrict (2a): fmt.Sscanf silently stopped at trailing junk, so
// PII_ENTROPY_THRESHOLD=9.9junk was applied as 9.9 instead of falling back to
// the default.
func TestParseFloatStrict(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want float64
	}{
		{"3.6", true, 3.6},
		{" 3.6 ", true, 3.6},
		{"3.6junk", false, 0},
		{"", false, 0},
		{"abc", false, 0},
	}
	for _, c := range cases {
		got, err := parseFloat(c.in)
		if (err == nil) != c.ok || (c.ok && got != c.want) {
			t.Errorf("parseFloat(%q) = %v, %v; want ok=%v val=%v", c.in, got, err, c.ok, c.want)
		}
	}
}

// Env-level companion for 2a: a junk-suffixed threshold keeps the default.
func TestEntropyThresholdJunkSuffixKeepsDefault(t *testing.T) {
	t.Setenv("PII_SALT", "test_salt_123456")

	t.Setenv("PII_ENTROPY_THRESHOLD", "9.9junk")
	if cfg := loadConfig(); cfg.EntropyThreshold != DefaultEntropyThreshold {
		t.Errorf("junk-suffixed threshold applied: got %v, want default %v", cfg.EntropyThreshold, DefaultEntropyThreshold)
	}

	t.Setenv("PII_ENTROPY_THRESHOLD", "4.2")
	if cfg := loadConfig(); cfg.EntropyThreshold != 4.2 {
		t.Errorf("valid threshold not applied: got %v", cfg.EntropyThreshold)
	}
}

// TestLuhnASCIIDigitsOnly (2b): index collection used unicode.IsDigit while
// validation does ASCII byte math (line[idx]-'0'), so non-ASCII digits fed
// multibyte rune offsets into garbage arithmetic (latent, not exploding).
func TestLuhnASCIIDigitsOnly(t *testing.T) {
	// Mixed-script digits: must not panic, must not match (only 12 ASCII
	// digits remain, below the 13-digit minimum).
	if r := FindLuhnSequences("id ٤١١١111111111111 x"); len(r) != 0 {
		t.Errorf("false Luhn match on mixed-script digits: %v", r)
	}
	// Pure Arabic-Indic digits: no ASCII digits at all, no match, no panic.
	if r := FindLuhnSequences("id ٤٥٣٩١٤٨٨٠٣٤٣٦٤٦٧ x"); len(r) != 0 {
		t.Errorf("false Luhn match on Arabic-Indic digits: %v", r)
	}
	// ASCII controls must still match.
	if r := FindLuhnSequences("card 4539 1488 0343 6467 end"); len(r) == 0 {
		t.Errorf("ASCII card no longer matched")
	}
	// Canonical Visa passes the distinct-digit>=2 gate on current main and
	// must stay matched.
	if r := FindLuhnSequences("card 4111 1111 1111 1111 end"); len(r) == 0 {
		t.Errorf("canonical Visa no longer matched")
	}
}

// TestBoundaryUTF8 (2c): isValidBoundary read one byte as a rune, so the
// continuation byte of a Cyrillic letter (0xB0 of 'а' → '°', not a letter)
// wrongly passed the letter-adjacency check.
func TestBoundaryUTF8(t *testing.T) {
	// Pre-fix observed: [{10 26}] — Cyrillic-letter-adjacent card accepted.
	if r := FindLuhnSequences("карта4539148803436467 x"); len(r) != 0 {
		t.Errorf("letter-adjacent (Cyrillic) card matched: %v", r)
	}
	// Latin control (already correct pre-fix): stays rejected.
	if r := FindLuhnSequences("karta4539148803436467 x"); len(r) != 0 {
		t.Errorf("letter-adjacent (Latin) card matched: %v", r)
	}
	// Trailing Cyrillic letter: rejected for the right reason now.
	if r := FindLuhnSequences("x 4539148803436467конец"); len(r) != 0 {
		t.Errorf("letter-adjacent (trailing Cyrillic) card matched: %v", r)
	}
	// Separated card next to Cyrillic words: must stay matched.
	if r := FindLuhnSequences("карта: 4539148803436467 конец"); len(r) != 1 {
		t.Errorf("separated card lost: %v", r)
	}
}

// TestDeepEqualsChainBounded (2d): a 2MB "a=a=a=...b" line recursed once per
// '=' (measured pre-fix: 53.5s wall, 779MB peak RSS). The depth bound must
// keep it fast while preserving the line byte-for-byte (nothing redacts).
func TestDeepEqualsChainBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("2MB input")
	}
	useDefaultConfig(t)
	in := strings.Repeat("a=", 1_000_000) + "b"
	done := make(chan string, 1)
	go func() { done <- ScanAndRedact(in) }()
	select {
	case out := <-done:
		if out != in {
			t.Errorf("deep chain altered: len(in)=%d len(out)=%d", len(in), len(out))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("recursion-depth DoS: >10s for one 2MB line")
	}
}

// Deep quote nesting goes through the same recursion cycle via the
// quoted-token unwrap path (processTokenLogic → scanSegment); it must be
// bounded by the same depth limit.
func TestDeepQuoteNestingBounded(t *testing.T) {
	useDefaultConfig(t)
	in := strings.Repeat(`"`, 100_000)
	done := make(chan string, 1)
	go func() { done <- ScanAndRedact(in) }()
	select {
	case out := <-done:
		if len(out) == 0 {
			t.Error("output vanished")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("quote-nesting DoS: >10s for a 100KB line")
	}
}
