package scanner

import (
	"strings"
	"testing"
)

// TestUnterminatedQuotedValue pins the first pass for a value that opens a
// quote and never closes it, as in a truncated line. The marker used to be
// wrapped in a pair of quotes, so a closing quote that was never in the input
// appeared, the opening quote went into the hash, and a second pass read the
// added quote as a new empty value and hid it again.
func TestUnterminatedQuotedValue(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	bare := ScanAndRedact("password=hunter2xyz")
	marker := bare[len("password="):]
	if !isRedacted(marker) {
		t.Fatalf("bare value not hidden: %q", bare)
	}
	for _, tc := range []struct{ in, want string }{
		{`password="hunter2xyz`, `password="` + marker},
		{`password='hunter2xyz`, `password='` + marker},
		{`{"password":"hunter2xyz`, `{"password":"` + marker},
		// An opening quote with nothing after it holds no value.
		{`{"password":"`, `{"password":"`},
		{`password="`, `password="`},
	} {
		if got := ScanAndRedact(tc.in); got != tc.want {
			t.Errorf("ScanAndRedact(%q)\n got:  %q\n want: %q", tc.in, got, tc.want)
		}
	}

	// A balanced quoted value keeps both quotes.
	if got := ScanAndRedact(`password="hunter2xyz"`); got != `password="`+marker+`"` {
		t.Errorf("balanced quotes: got %q", got)
	}
}

// keepsMarkers reports whether every marker of once appears, whole and in
// order, in twice.
func keepsMarkers(once, twice string) bool {
	want := markerRe.FindAllString(once, -1)
	j := 0
	for _, m := range markerRe.FindAllString(twice, -1) {
		if j < len(want) && m == want[j] {
			j++
		}
	}
	return j == len(want) && !strings.Contains(twice, "[HIDDEN:[HIDDEN")
}

// TestRescanKeepsMarkersNextToQuotes pins inputs found by fuzzing where a
// second pass cut a marker that sat next to a quote at its colon and nested
// it, [HIDDEN:[HIDDEN:x]: the tokenizer read the marker as part of a quoted
// span, and the pair splitter took HIDDEN as a key.
func TestRescanKeepsMarkersNextToQuotes(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	for _, labels := range []bool{false, true} {
		cfg := campaignConfig()
		cfg.EntityTypeLabels = labels
		UpdateConfig(cfg)
		for _, in := range []string{
			`0=" ?X02aA`,
			`"0"1Wa0(`,
			`pAss":"h`,
			`'"!1A04a`,
			`key='0`,
			`error: "Zx9aQ2Lm8Pq4Rs7Tv1Kq`,
			`seCret":"0`,
			`"" {\"password\": \"hunter2xyz9"}"}`,
		} {
			once := ScanAndRedact(in)
			if !strings.Contains(once, "[HIDDEN") {
				t.Errorf("labels=%v: first pass hid nothing: %q", labels, in)
				continue
			}
			twice := ScanAndRedact(once)
			if !keepsMarkers(once, twice) || twice != once {
				t.Errorf("labels=%v: second pass changed the line\n in:    %q\n once:  %q\n twice: %q", labels, in, once, twice)
			}
		}
	}
}
