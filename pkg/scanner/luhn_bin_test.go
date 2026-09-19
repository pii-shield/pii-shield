package scanner

import (
	"strings"
	"testing"
)

// luhnValid reports whether a pure digit string passes the package's own Luhn
// check. Used so every negative below is proven to fail on the issuer prefix or
// length, never on the checksum.
func luhnValid(digits string) bool {
	idx := make([]int, len(digits))
	for i := range digits {
		idx[i] = i
	}
	return validLuhnFromIndices(digits, idx)
}

// TestLuhnBINValidation covers F7: a Luhn-valid digit run counts as a card only
// when it starts with a real issuer prefix and has a length that issuer uses.
// A checksum alone accepts one random digit string in ten.
func TestLuhnBINValidation(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	positives := []struct{ name, number string }{
		{"Visa 16", "4539148803436467"},
		{"Visa 16 low diversity", "4111111111111111"},
		{"Visa 13", "4222222222222"},
		{"Visa 19", "4539148803436467008"},
		{"Mastercard 51–55", "5500005555555559"},
		{"Mastercard 2221–2720", "2223000048400011"},
		{"Amex 37", "378282246310005"},
		{"Amex 34", "341111111111111"},
		{"Discover 6011", "6011111111111117"},
		{"Discover 65", "6511111111111112"},
		{"Discover 644", "6440000000000005"},
		{"JCB 3530", "3530111333300000"},
		{"JCB 3589", "3589000000000003"},
		{"Diners 36", "36259600000004"},
		{"UnionPay 62", "6200000000000005"},
	}
	for _, p := range positives {
		if !luhnValid(p.number) {
			t.Fatalf("test data error: %s %s is not Luhn-valid", p.name, p.number)
		}
		line := "charge " + p.number + " ok"
		if r := FindLuhnSequences(line); len(r) == 0 {
			t.Errorf("%s: %s not matched", p.name, p.number)
		}
		if out := ScanAndRedact(line); strings.Contains(out, p.number) {
			t.Errorf("%s: card left in plaintext: %q", p.name, out)
		}
	}

	// Every negative passes Luhn; only the issuer prefix or the length is
	// wrong. Before F7 each of these was redacted and labelled a card.
	negatives := []struct{ name, number string }{
		{"prefix 1", "1023456789012346"},
		{"prefix 9", "9023456789012349"},
		{"13-digit ms timestamp", "1548138160707"},
		{"Visa prefix, 15 digits", "453914880343649"},
		{"Amex prefix, 16 digits", "3782822463100052"},
		{"Mastercard prefix, 15 digits", "510000000000003"},
		{"prefix 63, no issuer", "6378436834372556"},
	}
	for _, n := range negatives {
		if !luhnValid(n.number) {
			t.Fatalf("test data error: %s %s must be Luhn-valid so the BIN gate is what rejects it", n.name, n.number)
		}
		line := "id " + n.number + " x"
		if r := FindLuhnSequences(line); len(r) != 0 {
			t.Errorf("%s: %s matched as a card: %+v", n.name, n.number, r)
		}
	}

	// Grouped digits still match when the issuer does.
	if r := FindLuhnSequences("card 4539 1488 0343 6467 end"); len(r) != 1 {
		t.Errorf("spaced Visa not matched: %+v", r)
	}
}

// TestLuhnBINLabelDoesNotLie covers B16: the entity-type label must not call
// something a card that no issuer would have issued. A court case number that
// happens to pass Luhn used to come out as [HIDDEN:card:…]; the report that
// answers "what protected this data" is part of what the pilot sells, so the
// label has to be right even when the redaction was.
func TestLuhnBINLabelDoesNotLie(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	if !luhnValid("1747919220567223") {
		t.Fatal("test data error: case number must be Luhn-valid")
	}
	out := ScanAndRedact("case no 1747-9192-2056-7223 filed")
	if strings.Contains(out, "[HIDDEN:card:") {
		t.Errorf("case number labelled as a card: %q", out)
	}

	out2 := ScanAndRedact("card 4539148803436467 end")
	if !strings.Contains(out2, "[HIDDEN:card:") {
		t.Errorf("real card lost its label: %q", out2)
	}
}
