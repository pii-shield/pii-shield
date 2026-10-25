package scanner

import "testing"

// referenceBigramProbBytes is bigramProbBytes as it was before the table: a
// map lookup of the two-byte string, the default score when absent.
func (st *configState) referenceBigramProbBytes(b0, b1 byte) float64 {
	bg := [2]byte{b0, b1}
	if v, ok := EnglishBigramFreqs[string(bg[:])]; ok {
		return v
	}
	return st.config.BigramDefaultScore
}

// TestBigramTableMatchesMap proves the table gives the map's answer for every
// pair of bytes, ASCII and not, under two default scores.
func TestBigramTableMatchesMap(t *testing.T) {
	for _, def := range []float64{-7.0, -8.5} {
		cfg := DefaultConfig()
		cfg.BigramDefaultScore = def
		st := buildConfigState(cfg)
		mismatches := 0
		for i := 0; i < 256; i++ {
			for j := 0; j < 256; j++ {
				b0, b1 := byte(i), byte(j)
				if got, want := st.bigramProbBytes(b0, b1), st.referenceBigramProbBytes(b0, b1); got != want {
					mismatches++
					if mismatches <= 5 {
						t.Errorf("default %v: bigramProbBytes(%q, %q) = %v, want %v", def, b0, b1, got, want)
					}
				}
			}
		}
		if mismatches > 5 {
			t.Errorf("default %v: %d mismatches of 65536 pairs", def, mismatches)
		}
	}
}

// Every entry of the map is two ASCII bytes; a table of ASCII pairs would
// silently drop an entry that is not, so the shape is pinned here.
func TestBigramMapEntriesAreASCIIPairs(t *testing.T) {
	for bg := range EnglishBigramFreqs {
		if len(bg) != 2 || bg[0] >= 0x80 || bg[1] >= 0x80 {
			t.Errorf("EnglishBigramFreqs has a key that is not two ASCII bytes: %q", bg)
		}
	}
}

func BenchmarkBigramProbBytes(b *testing.B) {
	st := buildConfigState(DefaultConfig())
	token := "authorization_header_value_7f3a"
	var sink float64
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 1; j < len(token); j++ {
			sink += st.bigramProbBytes(token[j-1], token[j])
		}
	}
	_ = sink
}
