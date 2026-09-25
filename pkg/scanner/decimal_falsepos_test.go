package scanner

import (
	"math"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// TestPlainDecimalNotRedacted pins the SCN-B11 fix: plain decimal numbers
// must pass through unredacted. Before the isPlainDecimal safe rule,
// 6742381.25 scored 3.62 (entropy 3.12 + 0.5 class bonus for the dot)
// against the 3.6 default threshold and was redacted.
func TestPlainDecimalNotRedacted(t *testing.T) {
	inputs := []string{
		"6742381.25",
		"value 6742381.25 end",
		"total=6742381.25",
		"amount: 12345.6789",
		"delta -6742381.25 applied",
		"avg 6.394267984578837e-05 end",
		"error: 6742381.25",
		// Luhn-valid 16-digit fractional part must not be carved as a card:
		// digits on both sides of the dot mean it is part of one number.
		"value 0.6378436834372556 end",
		"total 6378436834372556.25 charged",
	}
	for _, in := range inputs {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("plain decimal was modified:\n in:  %q\n out: %q", in, out)
		}
	}
}

// TestPlainDecimalHelper covers the isPlainDecimal grammar directly.
func TestPlainDecimalHelper(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{"6742381.25", true},
		{"-0.5", true},
		{"+123.456", true},
		{"1.5e-7", true},
		{"1.2E+10", true},
		{"6.394267984578837e-05", true},
		{"6742381", false},
		{"1.2.3", false},
		{"192.168.1.100", false},
		{"1e10", false},
		{".25", false},
		{"25.", false},
		{"-.5", false},
		{"1.5e", false},
		{"1.5e+", false},
		{"1.25abc", false},
		{"abc1.25", false},
		{"", false},
		{"-", false},
	}
	for _, c := range cases {
		if got := isPlainDecimal(c.token); got != c.want {
			t.Errorf("isPlainDecimal(%q) = %v, want %v", c.token, got, c.want)
		}
	}
}

// TestPlainDecimalRegressions proves the safe rule does not open recall
// holes: forced-sensitive values and Luhn card numbers still redact.
func TestPlainDecimalRegressions(t *testing.T) {
	// Sensitive key forces the value regardless of isSafe.
	out := ScanAndRedact("password=6742381.25")
	if !strings.Contains(out, "[HIDDEN") || strings.Contains(out, "6742381.25") {
		t.Errorf("sensitive-key decimal value leaked: %q", out)
	}

	// Luhn carve-out runs before tokenization and must be unaffected for
	// bare, dashed, and trailing-dot card forms.
	// Every digit group of the card must be gone: the old check looked for
	// "4539", which the dashed card does not contain, so a partial leak such
	// as 4556-7375-[HIDDEN] would have passed.
	for _, tc := range []struct {
		in     string
		groups []string
	}{
		{"card 4539148803436467 end", []string{"4539148803436467"}},
		{"card 4556-7375-8689-9855 end", []string{"4556", "7375", "8689", "9855"}},
		{"card 4539148803436467. next", []string{"4539148803436467"}},
	} {
		out = ScanAndRedact(tc.in)
		rest := withoutMarkers(out)
		for _, g := range tc.groups {
			if strings.Contains(rest, g) {
				t.Errorf("card digits %q leaked: %q -> %q", g, tc.in, out)
			}
		}
		if !strings.Contains(out, "[HIDDEN") {
			t.Errorf("no marker: %q -> %q", tc.in, out)
		}
	}

	// Version-like tokens stay untouched either way.
	in := "ver 1.2.3 ok"
	if out := ScanAndRedact(in); out != in {
		t.Errorf("version string was modified: %q", out)
	}
}

// TestFullPrecisionFloatCorpus reproduces the corpus measurement from the
// SCN-B11 report (29-35% of full-precision floats redacted before the fix):
// 1000 seeded floats in both fixed and shortest-repr formats, zero
// redactions expected.
func TestFullPrecisionFloatCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	redacted := 0
	for i := 0; i < 1000; i++ {
		v := rng.Float64() * math.Pow10(rng.Intn(8))
		format := byte('f')
		if i%2 == 1 {
			format = 'g'
		}
		in := "value " + strconv.FormatFloat(v, format, -1, 64) + " end"
		if out := ScanAndRedact(in); out != in {
			redacted++
			if redacted <= 3 {
				t.Logf("redacted: %q -> %q", in, out)
			}
		}
	}
	if redacted != 0 {
		t.Errorf("%d of 1000 float lines were modified, want 0", redacted)
	}
}
