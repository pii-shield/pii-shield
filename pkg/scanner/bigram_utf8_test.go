package scanner

import (
	"strings"
	"testing"
)

// TestBigramNonASCII covers F5: the bigram table is English and byte-indexed,
// so the pre-fix implementation sliced multibyte runes in half and scored every
// non-Latin token as "all bigrams unknown" — i.e. as BigramDefaultScore. At the
// default score (-7.0) that lands in the neutral band and hides the bug; at any
// stricter custom score every Cyrillic word picked up the +0.5 "looks random"
// boost and ordinary Russian text started to redact.
//
// After the fix only pairs of adjacent ASCII characters are scored, so a token
// with no such pair gets no adjustment, and a Latin word carrying an accent
// keeps the English-likeness bonus its ASCII run earns.
//
// Not fixed here (belongs to F6, the length-dependent threshold): Аутентификация
// (3.825) and Днепропетровск (3.736) still exceed the 3.6 default threshold on
// entropy plus class bonus alone, with no bigram contribution involved.
func TestBigramNonASCII(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)

	// 1. No adjustment for tokens that contain no adjacent ASCII pair, at the
	//    default score and at a stricter custom one.
	for _, defaultScore := range []float64{-7.0, -9.0} {
		cfg := campaignConfig()
		cfg.BigramDefaultScore = defaultScore
		UpdateConfig(cfg)
		st := cfgState()
		for _, tok := range []string{
			"конфигурация", "маршрутизация", "пользователь", "Аутентификация",
			"соединение", "пароль", "テスト環境",
		} {
			if got := st.calculateBigramAdjustment(tok); got != 0.0 {
				t.Errorf("default %v, token %q: adjustment %v, want 0", defaultScore, tok, got)
			}
		}
	}

	// 1b. Mixed ASCII + multibyte tokens are scored on their ASCII runs, with
	//     the pair that straddles a multibyte rune skipped. These cases used to
	//     live in bigramEquivCorpus (hotpath_equiv_test.go), whose oracle is the
	//     pre-F5 byte-slicing implementation; pinned here with explicit values
	//     instead, since that oracle is what this change replaces.
	for _, tc := range []struct {
		token        string
		defaultScore float64
		want         float64
	}{
		{"mixedПароль123", -7.0, 0.0}, // "mi ix xe ed" + "12 23": neutral band
		{"mixedПароль123", -9.0, 0.5}, // the digit pairs are unknown: random-looking
		{"emoji🙂token", -7.0, 0.0},
		{"emoji🙂token", -9.0, 0.0},
	} {
		cfg := campaignConfig()
		cfg.BigramDefaultScore = tc.defaultScore
		UpdateConfig(cfg)
		if got := cfgState().calculateBigramAdjustment(tc.token); got != tc.want {
			t.Errorf("default %v, token %q: adjustment %v, want %v",
				tc.defaultScore, tc.token, got, tc.want)
		}
	}

	// 2. End-to-end: at a stricter default score ordinary Russian text passes
	//    through untouched. Verified pre-fix at -9.0: конфигурация scored 3.918
	//    and маршрутизация 3.739, both over the 3.6 threshold.
	cfg := campaignConfig()
	cfg.BigramDefaultScore = -9.0
	UpdateConfig(cfg)
	for _, in := range []string{
		"конфигурация",
		"маршрутизация",
		"пользователь авторизован успешно",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("Cyrillic false positive at BigramDefaultScore=-9.0: %q -> %q", in, out)
		}
	}

	// 3. Accented Latin keeps the bonus its ASCII run earns, so a stricter
	//    default score does not push German or French words over the threshold
	//    either. (A plain "bail out on the first non-ASCII byte" fix would drop
	//    these to 0 and raise every such word's score by 1.5.)
	for _, tok := range []string{"Änderung", "übertragen", "réservation"} {
		st := cfgState()
		if got := st.calculateBigramAdjustment(tok); got != -1.5 {
			t.Errorf("token %q: adjustment %v, want -1.5 (English-like ASCII run)", tok, got)
		}
		if out := ScanAndRedact(tok); out != tok {
			t.Errorf("accented Latin false positive at BigramDefaultScore=-9.0: %q -> %q", tok, out)
		}
	}

	// 4. Detection of a real secret next to non-ASCII text is unaffected.
	UpdateConfig(campaignConfig())
	out := ScanAndRedact("пароль AbC9xY2kQ8pLmN0r конец")
	if strings.Contains(out, "AbC9xY2kQ8pLmN0r") || !strings.Contains(out, "[HIDDEN:") {
		t.Errorf("secret next to Cyrillic text not redacted: %q", out)
	}
}
