package scanner

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// referenceFindLuhnSequences is FindLuhnSequences as it was before O9: the
// connectivity of every window re-checked from its first digit for every
// length, with continue (not break) on a disconnect. The oracle for the
// equivalence test below.
func referenceFindLuhnSequences(line string) []Range {
	if !strings.ContainsAny(line, "0123456789") {
		return nil
	}
	var ranges []Range
	if len(line) < 13 {
		return ranges
	}
	var digitIndices []int
	for i := 0; i < len(line); i++ {
		if line[i] >= '0' && line[i] <= '9' {
			digitIndices = append(digitIndices, i)
		}
	}
	numDigits := len(digitIndices)
	if numDigits < 13 {
		return ranges
	}
	for i := 0; i <= numDigits-13; i++ {
		maxLen := 19
		if i+maxLen > numDigits {
			maxLen = numDigits - i
		}
		for L := 13; L <= maxLen; L++ {
			startIdx := digitIndices[i]
			endIdx := digitIndices[i+L-1] + 1
			if !areDigitsConnected(line, digitIndices[i:i+L]) {
				continue
			}
			if !isValidBoundary(line, startIdx, endIdx) {
				continue
			}
			if countDistinctDigits(line, digitIndices[i:i+L]) < 2 {
				continue
			}
			if !matchesCardBIN(line, digitIndices[i:i+L]) {
				continue
			}
			if validLuhnFromIndices(line, digitIndices[i:i+L]) {
				ranges = append(ranges, Range{Start: startIdx, End: endIdx})
			}
		}
	}
	return mergeRanges(ranges)
}

// luhnCorpus is cards of every length and issuer shape, spaced and dashed,
// two cards in one line, near-cards, long ids, access-log lines and random
// digit strings with separators, all from a fixed seed.
func luhnCorpus() []string {
	rng := rand.New(rand.NewSource(20261025))
	lines := []string{
		"", "4111111111111111", "card 4111 1111 1111 1111 ok", "card 4111-1111-1111-1111 ok",
		"4111 1111-1111 1111", "4111  1111 1111 1111", "x4111111111111111", "4111111111111111x",
		"5500000000000004 and 378282246310005", "6011111111111117,3530111333300000",
		"order 4111111111111112", "id 1234567890123456789 ts 1698765432", "0000000000000000",
		"4111111111111111 4111111111111111", "a-4111111111111111", "4111111111111111-b",
		"uuid 123e4567-e89b-12d3-a456-426614174000", "2026-10-25T10:00:00.000Z 4111111111111111",
		"3782 822463 10005", "3782-822463-10005", "378282246310005", "4111111111111",
		"card=4111111111111111;cvv=123", "{\"card\":\"4111 1111 1111 1111\"}",
	}
	lines = append(lines, accessLogLines(256)...)
	digits := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte('0' + rng.Intn(10))
		}
		return string(b)
	}
	seps := []string{"", " ", "-", "  ", "x", ".", "/"}
	for i := 0; i < 3000; i++ {
		var sb strings.Builder
		parts := 1 + rng.Intn(5)
		for p := 0; p < parts; p++ {
			if p > 0 {
				sb.WriteString(seps[rng.Intn(len(seps))])
			}
			sb.WriteString(digits(1 + rng.Intn(20)))
		}
		if rng.Intn(3) == 0 {
			sb.WriteString(" " + digits(13+rng.Intn(7)))
		}
		lines = append(lines, sb.String())
	}
	// Luhn-valid numbers with an issuer prefix and length the BIN check
	// accepts (Visa 13/16, Mastercard 16, Amex 15, Discover 16, JCB 16),
	// with and without separators.
	issuers := []struct {
		prefix string
		n      int
	}{{"4", 16}, {"4", 13}, {"51", 16}, {"55", 16}, {"34", 15}, {"37", 15}, {"6011", 16}, {"3530", 16}}
	for i := 0; i < 500; i++ {
		is := issuers[rng.Intn(len(issuers))]
		n := is.n
		b := []byte(is.prefix + digits(n-1-len(is.prefix)))
		// Append the check digit that makes the number Luhn-valid.
		sum := 0
		alt := true
		for k := len(b) - 1; k >= 0; k-- {
			d := int(b[k] - '0')
			if alt {
				d *= 2
				if d > 9 {
					d -= 9
				}
			}
			sum += d
			alt = !alt
		}
		b = append(b, byte('0'+(10-sum%10)%10))
		s := string(b)
		switch rng.Intn(4) {
		case 1:
			s = s[:4] + " " + s[4:8] + " " + s[8:12] + " " + s[12:]
		case 2:
			s = s[:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:]
		case 3:
			s = s[:6] + " " + s[6:]
		}
		lines = append(lines, "paid with "+s+" today", s+" "+s, "ref"+s)
	}
	return lines
}

// TestFindLuhnSequencesMatchesReference proves the incremental window gives
// the same ranges as the per-length rescan on the corpus.
func TestFindLuhnSequencesMatchesReference(t *testing.T) {
	lines := luhnCorpus()
	mismatches, hits := 0, 0
	for _, l := range lines {
		got, want := FindLuhnSequences(l), referenceFindLuhnSequences(l)
		if len(want) > 0 {
			hits++
		}
		if !reflect.DeepEqual(got, want) {
			mismatches++
			if mismatches <= 10 {
				t.Errorf("FindLuhnSequences(%q) = %v, reference %v", l, got, want)
			}
		}
	}
	if mismatches > 10 {
		t.Errorf("%d mismatches in %d lines", mismatches, len(lines))
	}
	if hits < 400 {
		t.Errorf("corpus has only %d lines with a card; the test needs hits to mean anything", hits)
	}
}

func TestDigitsConnected(t *testing.T) {
	for _, tc := range []struct {
		line string
		p, c int
		want bool
	}{
		{"12", 0, 1, true}, {"1 2", 0, 2, true}, {"1-2", 0, 2, true},
		{"1.2", 0, 2, false}, {"1x2", 0, 2, false}, {"1  2", 0, 3, false}, {"1 - 2", 0, 4, false},
	} {
		if got := digitsConnected(tc.line, tc.p, tc.c); got != tc.want {
			t.Errorf("digitsConnected(%q, %d, %d) = %v, want %v", tc.line, tc.p, tc.c, got, tc.want)
		}
	}
}
