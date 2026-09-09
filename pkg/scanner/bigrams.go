package scanner

// EnglishBigramFreqs contains log-probabilities of bigrams in English text.
// Derived from standard corpus statistics.
//
// LANGUAGE LIMITATION: This map is optimized for English text. Using this scanner
// on non-English logs (German, Spanish, Chinese, etc.) or technical content (base64,
// hex dumps) will result in higher false positive rates. Scoring covers pairs of
// adjacent ASCII characters only: a word in a non-Latin script has no such pair and
// therefore receives no adjustment in either direction, and an accented Latin word is
// judged on the ASCII runs it does contain. The remaining false positives on such
// text come from the entropy side, not from this table.
//
// CUSTOMIZATION: To support other languages, you have two options:
// 1. Disable bigram checking entirely: Set PII_DISABLE_BIGRAM_CHECK=true
// 2. Adjust the default score: Set PII_BIGRAM_DEFAULT_SCORE (e.g., -8.0 for stricter)
//
// Future versions may support custom bigram frequency maps for other languages.
//
// DISABLE: Set environment variable PII_DISABLE_BIGRAM_CHECK=true to disable
// bigram analysis entirely. This will increase sensitivity but may also increase
// false positives for common words.
var EnglishBigramFreqs = map[string]float64{
	"th": -3.5, "he": -3.8, "in": -3.9, "er": -4.0, "an": -4.1, "re": -4.1,
	"nd": -4.3, "at": -4.4, "on": -4.4, "nt": -4.5, "ha": -4.5, "es": -4.6,
	"st": -4.6, "en": -4.7, "ed": -4.7, "to": -4.7, "it": -4.7, "ou": -4.8,
	"ea": -4.8, "hi": -4.8, "is": -4.9, "or": -4.9, "ti": -4.9, "as": -4.9,
	"te": -5.0, "et": -5.0, "ng": -5.0, "of": -5.0, "al": -5.0, "de": -5.1,
	"se": -5.1, "le": -5.1, "sa": -5.1, "si": -5.2, "ar": -5.2, "ve": -5.2,
	"ra": -5.2, "ld": -5.3, "ur": -5.3, "ac": -5.3, "ne": -5.3, "no": -5.3,
	"fo": -5.3, "co": -5.3, "me": -5.4, "ec": -5.4, "ot": -5.4, "ri": -5.4,
	"ro": -5.4, "io": -5.4, "ic": -5.4, "ma": -5.4, "ta": -5.4, "el": -5.4,
	"li": -5.4, "om": -5.4, "us": -5.4, "ce": -5.5, "ca": -5.5, "il": -5.5,
	"na": -5.5, "la": -5.5, "ge": -5.5, "un": -5.5, "ch": -5.5, "wi": -5.5,
	"di": -5.5, "pe": -5.5, "be": -5.5, "so": -5.5, "rt": -5.5, "wa": -5.5,
	"nc": -5.6, "wh": -5.6, "tr": -5.6, "pr": -5.6, "ul": -5.6, "ni": -5.6,
	"ns": -5.6, "ts": -5.6, "ow": -5.6, "em": -5.6, "ie": -5.6, "ll": -5.6,
	"ut": -5.6, "po": -5.6, "lo": -5.6, "ss": -5.6, "ad": -5.6, "ho": -5.6,
	"rs": -5.6, "mo": -5.7, "we": -5.7, "pa": -5.7, "im": -5.7,
	"tt": -5.7, "mi": -5.7, "ai": -5.7, "su": -5.7, "qu": -5.7, "pp": -5.7,
	"pl": -5.7, "da": -5.7, "os": -5.7, "bl": -5.7, "ty": -5.7, "nf": -5.8,
	"bu": -5.7, "rn": -5.7, "fe": -5.8, "gh": -5.8, "ds": -5.8, "ke": -5.8,
	"ct": -5.8, "op": -5.8, "sc": -5.8, "rr": -5.8, "sp": -5.8, "vo": -5.8,
	"mp": -5.8, "am": -5.8, "iv": -5.8, "id": -5.8, "ef": -5.8, "ev": -5.8,
	"au": -5.8, "ck": -5.8, "ir": -5.8, "ep": -5.8, "tu": -5.8, "bo": -5.8,
	"ci": -5.8, "ab": -5.8, "eg": -5.8, "ye": -5.8, "wn": -5.8, "dr": -5.8,
	"gr": -5.8, "od": -5.8, "ph": -5.8, "av": -5.8, "ew": -5.8, "do": -5.8,
	"ag": -5.8, "ex": -5.9, "ly": -5.9, "mu": -5.9, "fr": -5.9, "ms": -6.0,
	"sg": -6.0, "ja": -6.0, "ju": -6.0, "jy": -6.0, "jo": -6.0, "aj": -6.5,
	"ay": -5.5, "ga": -5.5, "ym": -6.0, "nu": -5.8, "um": -5.5,
	"mm": -6.0, "t_": -9.0,
	"pi": -5.5, "eb": -5.5, "ug": -5.5, "yl": -5.8, "oa": -5.3,
	// Technical Keys / Rare
	"cv": -8.0, "vv": -9.0, // CVV
	"pw": -8.0, "wd": -7.5, // PWD
	"tk": -8.5, // Token
	"nm": -7.5, // num
	"ky": -7.5, // key
	"ey": -5.5,
}

// GetBigramProb returns the log-probability for a given bigram.
// If the bigram is not found in the English frequency map, returns the
// configured default score (BigramDefaultScore, default -7.0).
// Lower (more negative) values indicate rarer bigrams, which may suggest
// non-English text or random/encoded data.
func GetBigramProb(b string) float64 {
	return cfgState().bigramProb(b)
}

// bigramProb is GetBigramProb's config-aware implementation, used internally
// so a Scanner instance's own BigramDefaultScore is honored instead of
// silently falling back to the package-level default.
func (st *configState) bigramProb(b string) float64 {
	if v, ok := EnglishBigramFreqs[b]; ok {
		return v
	}
	// Return configured default score instead of hardcoded -7.0
	// This allows tuning for different language environments
	return st.config.BigramDefaultScore
}

// bigramProbBytes is bigramProb for a two-byte bigram without building an
// intermediate string: the string(bg[:]) conversion sits directly in the map
// index expression, which the compiler compiles to an allocation-free lookup.
func (st *configState) bigramProbBytes(b0, b1 byte) float64 {
	bg := [2]byte{b0, b1}
	if v, ok := EnglishBigramFreqs[string(bg[:])]; ok {
		return v
	}
	return st.config.BigramDefaultScore
}
