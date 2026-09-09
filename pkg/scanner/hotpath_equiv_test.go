package scanner

import (
	"math"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

// Equivalence oracles for the Phase 4 hot-path optimizations: each reference
// function below is a verbatim copy of the pre-optimization implementation,
// so the tests prove old == new on a corpus rather than eyeballing output.

// referenceShannon is calculateShannon as it was before O2 (direct math.Log2
// calls instead of logTable lookups).
func referenceShannon(token string) float64 {
	if len(token) == 0 {
		return 0
	}

	var counts [256]int
	isASCII := true
	totalChars := 0

	for i := 0; i < len(token); i++ {
		b := token[i]
		if b >= 0x80 {
			isASCII = false
			break
		}
		counts[b]++
		totalChars++
	}

	if isASCII {
		entropy := 0.0
		logLen := math.Log2(float64(totalChars))
		for _, count := range counts {
			if count == 0 {
				continue
			}
			p := float64(count) / float64(totalChars)
			entropy -= p * (math.Log2(float64(count)) - logLen)
		}
		return entropy
	}

	freq := make(map[rune]int)
	totalChars = 0
	for _, r := range token {
		freq[r]++
		totalChars++
	}

	entropy := 0.0
	logLen := math.Log2(float64(totalChars))

	for _, count := range freq {
		p := float64(count) / float64(totalChars)
		entropy -= p * (math.Log2(float64(count)) - logLen)
	}
	return entropy
}

// TestShannonLogTableEquivalence covers O2: table-driven Log2 must match the
// direct computation within 1e-9 on random ASCII strings of every length the
// table covers (1..255), on longer tokens that exercise the >=256 fallback,
// and on the unicode path (untouched by O2).
func TestShannonLogTableEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for l := 1; l <= 255; l++ {
		b := make([]byte, l)
		for i := range b {
			b[i] = byte(32 + rng.Intn(95)) // printable ASCII
		}
		s := string(b)
		got, want := calculateShannon(s), referenceShannon(s)
		if math.Abs(got-want) > 1e-9 {
			t.Fatalf("len %d: calculateShannon=%v reference=%v (token %q)", l, got, want, s)
		}
	}
	// Low-diversity strings (high per-char counts) across the same lengths.
	for l := 1; l <= 255; l += 7 {
		s := strings.Repeat("ab", l/2+1)[:l]
		got, want := calculateShannon(s), referenceShannon(s)
		if math.Abs(got-want) > 1e-9 {
			t.Fatalf("repeat len %d: got %v want %v", l, got, want)
		}
	}
	// Fallback and edge cases: counts and lengths beyond the table, unicode.
	cases := []string{
		"",
		"a",
		strings.Repeat("a", 300) + strings.Repeat("b", 100), // counts > 255
		strings.Repeat("xyz", 200),                          // len > 255, counts < 256
		"пароль",
		"Аутентификация",
		"mixedПароль123",
	}
	for _, s := range cases {
		got, want := calculateShannon(s), referenceShannon(s)
		if math.Abs(got-want) > 1e-9 {
			t.Fatalf("case %q: got %v want %v", s, got, want)
		}
	}
}

// referenceBigramAdjustment is calculateBigramAdjustment as it was before O3
// (strings.ToLower per token, string-sliced bigrams for every input).
func referenceBigramAdjustment(st *configState, token string) float64 {
	if st.config.DisableBigramCheck || len(token) <= 3 {
		return 0.0
	}

	sumProb := 0.0
	count := 0
	sLower := strings.ToLower(token)
	for i := 0; i < len(sLower)-1; i++ {
		bg := sLower[i : i+2]
		sumProb += st.bigramProb(bg)
		count++
	}

	if count > 0 {
		avgProb := sumProb / float64(count)
		if avgProb > -5.8 {
			return -1.5
		} else if avgProb < -7.0 {
			return 0.5
		}
	}
	return 0.0
}

var bigramEquivCorpus = []string{
	"",
	"ok",
	"abc", // <= 3: early return
	"abcd",
	"authentication",
	"MixedCaseToken123",
	"UPPERCASEONLY",
	"AbC9xY2kQ8pLmN0r",
	"1234567890",
	"user_id=42;q",
	"key:value/path",
	// Non-ASCII tokens used to live here too. F5 deliberately changed what the
	// scanner does with them — byte-sliced bigrams cut multibyte runes in half —
	// so the pre-O3 ToLower implementation is no longer the oracle for them.
	// Their behavior is pinned in TestBigramNonASCII instead.
	"ends-with-upperZ",
	"Z@#$%^&*()aa",
}

// TestBigramInlineLowerEquivalence covers O3: the inline ASCII lowercase path
// must return exactly what the ToLower-based implementation returns, at the
// default config and at a custom BigramDefaultScore that activates the +0.5
// branch. Pure-ASCII tokens only: see the note on bigramEquivCorpus.
func TestBigramInlineLowerEquivalence(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)

	for _, defaultScore := range []float64{-7.0, -9.0} {
		cfg := campaignConfig()
		cfg.BigramDefaultScore = defaultScore
		UpdateConfig(cfg)
		st := cfgState()
		for _, tok := range bigramEquivCorpus {
			got := st.calculateBigramAdjustment(tok)
			want := referenceBigramAdjustment(st, tok)
			if got != want {
				t.Errorf("default %v, token %q: got %v want %v", defaultScore, tok, got, want)
			}
		}
	}
}

// TestRedactWithHMACFormatUnchanged pins the redaction marker format and the
// deterministic hash prefix (hunter2 under the campaign salt is always
// 3920d5). Written for O4, which measured no win and was dropped; the
// contract it guards is worth keeping for any future attempt at that hunk.
func TestRedactWithHMACFormatUnchanged(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())
	st := cfgState()

	var sb strings.Builder
	st.redactWithHMAC("hunter2", "", "entropy", &sb)
	if sb.String() != "[HIDDEN:3920d5]" {
		t.Errorf("unnamed marker changed: %q", sb.String())
	}

	sb.Reset()
	st.redactWithHMAC("hunter2", "code", "regex", &sb)
	if sb.String() != "[HIDDEN:code:3920d5]" {
		t.Errorf("named marker changed: %q", sb.String())
	}
}

// TestIsSepRuneEquivalence covers O5: the separator table must agree with
// strings.ContainsRune over every byte value, negative runes, and a unicode
// sample.
func TestIsSepRuneEquivalence(t *testing.T) {
	const seps = " \t,;[]{}()<>"
	for r := rune(-2); r < 256; r++ {
		if got, want := isSepRune(r), strings.ContainsRune(seps, r); got != want {
			t.Errorf("rune %U: got %v want %v", r, got, want)
		}
	}
	for _, r := range []rune{'ф', '—', '　', 0x2028, utf8.MaxRune} {
		if got, want := isSepRune(r), strings.ContainsRune(seps, r); got != want {
			t.Errorf("rune %U: got %v want %v", r, got, want)
		}
	}
}
