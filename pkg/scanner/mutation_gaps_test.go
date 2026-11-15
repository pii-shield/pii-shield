package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// The cases in this file come from mutation testing: each one is a line whose
// output changed when a single operator in the scanner was flipped (a "<"
// into "<=", an "&&" into "||", a "+ 1" into "- 1") while every existing test
// still passed. A flipped operator is the smallest slip a refactoring can
// make, so each line below guards a boundary that nothing else was guarding.
// They are grouped by what goes wrong when the boundary moves: a safe line
// gets hidden (false positive), a secret gets through (false negative), or
// the marker changes although the value did not.

// markerHash matches the hash part of a marker, so expected outputs can name
// the detector ([HIDDEN:card]) without depending on the salt.
var markerHash = regexp.MustCompile(`\[HIDDEN:([a-z0-9-]+):[0-9a-f]{6}\]`)

func gapScanner() *Scanner {
	cfg := DefaultConfig()
	cfg.Salt = []byte("mutation-gaps-salt-0123456789abc")
	cfg.EntityTypeLabels = true
	return NewScanner(cfg)
}

func TestMutationGaps_SafeLinesStayUnchanged(t *testing.T) {
	sc := gapScanner()
	for _, tc := range []struct{ why, line string }{
		// Keys that name personal data, values that are not that data.
		{"a word under a date-of-birth key is not a date", `GET /api/patient?dob=pending&ward=4`},
		{"one digit under a phone key is a flag, not a phone", `GET /basket/add/101?mobile=1&addedValues= HTTP/1.1`},
		{"a date key right at the end of the line", `patient dob=12`},
		{"a date cut after its first separator", `patient dob=1/2`},

		// The status code and size after a quoted request line are not the
		// value of the last query parameter.
		{"request line whose path holds '&' and '='", `"GET /filter/a,b&page=1 HTTP/1.1" 200 512`},

		// Identifiers made of words.
		{"a name that starts with a digit", `2fa_code`},
		{"a dotted property with a hyphenated last part", `spring.datasource.hikari.maximum-pool-size`},
		{"two words joined by an ellipsis", `abcdefgh...ijklmnop`},
		{"a command-line flag with a short alphanumeric part", `re-pin with -update-f6-expected and commit`},
		{"a possessive", `John's`},
		{"a package with a version", `pkg@v1`},
		{"a word in a non-Latin script", `конфигурация`},
		{"a boolean setting", `DEBUG=false`},
		{"a non-Latin phrase that starts with the word for password", `密码错误 请重试`},
		{"an ordinary image file name in a query", `GET /image/1?name=report.jpg&wh=max`},

		// A card number is a whole token: sixteen digits glued to a letter or
		// joined to one by a hyphen are part of an identifier.
		{"digits glued to a leading letter", `x4111111111111111`},
		{"digits after a letter and a hyphen", `a-4111111111111111`},
		{"digits before a hyphen and a letter", `4111111111111111-b`},

		{"an IPv6 address whose last groups look like key and value", `2001:db8:85a3::8a2e:370:7334`},

		// User-agent parts.
		{"an Android build id", `"Dalvik/1.6.0 (Linux; U; Android 4.1.2; Build/JZO54K)"`},
		{"a product token with a dotted version and letters", `"Mozilla/5.0 (Linux; Android 9; MI 8 MIUI/V10.1.1.0.NCFMIFI)"`},

		// Fragments with a quote that never closes. A boundary slip here does
		// not just hide text, it writes the same character over and over.
		{"a Python bytes prefix and an open quote", `recv b'`},
		{"an apostrophe that ends a word", ` now' end`},
		{"escaped single quotes", `\'a\'b\'`},
		{"an open quote before a URL", `" http://example.org/`},
		{"an open quote, a word and a URL", `"see https://api.example.com/ `},
		{"the tail of a JSON object after a closing quote", `", "To": "x"}`},
		{"a JSON tail that opens a nested object", `": {"role": "admin"}}`},
		{"the same tail, compact", `":{"role":"admin"}}`},
	} {
		if got := sc.ScanAndRedact(tc.line); got != tc.line {
			t.Errorf("%s:\n in:  %q\n out: %q", tc.why, tc.line, got)
		}
	}
}

func TestMutationGaps_SecretsAreHidden(t *testing.T) {
	sc := gapScanner()
	for _, tc := range []struct{ why, line, want string }{
		// Card boundaries: a full stop after the number ends a sentence, it
		// does not make the number part of a longer token.
		{"a card number that ends a sentence", `card 4539148803436467. next`, `card [HIDDEN:card]. next`},

		// Four groups of four digits are not a timestamp.
		{"digit groups joined by hyphens", `case no 1747-9192-2056-7223 filed`, `case no [HIDDEN:entropy] filed`},

		// A value after "key = " is hidden as it stands: no quotes are added.
		{"a spaced assignment keeps its shape", `key = 12345678`, `key = [HIDDEN:key]`},

		// Brackets around a value are not a marker, and neither is a marker
		// cut short: only a complete [HIDDEN:…] is left alone.
		{"double brackets under a session key", `{"sid": "[[abc123]]"}`, `{"sid": "[HIDDEN:key]"}`},
		{"double brackets under an auth header", `{"Authorization": "[[Bearer abc123]]"}`, `{"Authorization": "[HIDDEN:key]"}`},
		{"a marker cut after its colon", `"token=[HIDDEN:`, `"token=[HIDDEN:key]`},
		{"a marker cut before its colon", `"password=[HIDDEN`, `"password=[HIDDEN:key]`},

		// An address and a password joined by a colon are two values, each
		// hidden once.
		{"address:password", `lena@example.com:hunter2`, `[HIDDEN:email]:[HIDDEN:key]`},
		{"address:password inside a sentence", `login lena@example.com:hunter2 failed`, `login [HIDDEN:email]:[HIDDEN:key] failed`},

		// A word part followed by a long digit run is an account or record
		// number, not a word compound.
		{"prefix-prefix-digits", `SAFE-ID-987654321`, `[HIDDEN:entropy]`},
		{"prefix-digits after a label", `ID: ACCT-1234567890`, `ID: [HIDDEN:entropy]`},
		{"word_digits", `user_12345678901234`, `[HIDDEN:entropy]`},

		// Random groups joined by hyphens are not a word compound either.
		{"random groups", `xK9-fQ2mZ7pL`, `[HIDDEN:entropy]`},
		{"random groups of four", `Zx81-Qm47-Lp93`, `[HIDDEN:entropy]`},
		{"random groups in a sentence", `ref Qm47Zx81-Lp93Vt26 ok`, `ref [HIDDEN:entropy] ok`},

		// A file name that is a random string keeps being hidden in a query.
		{"a random file name", `GET /image/1?name=cm6hlrso.jpg&wh=max`, `GET /image/1?name=[HIDDEN:url]&wh=max`},
		{"a random file name with a digit inside", `GET /image/1?name=note9mmm.jpg&wh=max`, `GET /image/1?name=[HIDDEN:url]&wh=max`},

		// An empty value under a key that is checked by shape (a one-time
		// code, an identity number, a phone) must not stop the scan of the
		// rest of the line.
		{"empty one-time code, then a token", `GET /verify?otp=&token=abc123def456ghi789 HTTP/1.1`, `GET /verify?otp=&token=[HIDDEN:key] HTTP/1.1`},
		{"empty identity number, then a token", `GET /check?ssn=&token=abc123def456ghi789 HTTP/1.1`, `GET /check?ssn=&token=[HIDDEN:key] HTTP/1.1`},
		{"empty phone, then a token", `GET /call?mobile=&token=abc123def456ghi789 HTTP/1.1`, `GET /call?mobile=&token=[HIDDEN:key] HTTP/1.1`},
		// The same for a value that starts with a sign: "-1" is not a code
		// or an identity number, and the token after it is still hidden.
		{"a negative number, then a token", `GET /i?ref=-1&token=abc123def456ghi789`, `GET /i?ref=-1&token=[HIDDEN:key]`},
		{"a signed number under an identity key", `GET /i?ssn=-123456789&x=1`, `GET /i?ssn=[HIDDEN:url]&x=1`},

		// A two-letter prefix and a number is a record id, not a word
		// compound.
		{"prefix-digits in a sentence", `order TX-12345 shipped`, `order [HIDDEN:entropy] shipped`},

		// The word after a bare "password" is hidden because of the key, and
		// the marker says so.
		{"a word after a bare sensitive word", `password swordfish`, `password [HIDDEN:key]`},
	} {
		got := markerHash.ReplaceAllString(sc.ScanAndRedact(tc.line), "[HIDDEN:$1]")
		if got != tc.want {
			t.Errorf("%s:\n in:   %q\n out:  %q\n want: %q", tc.why, tc.line, got, tc.want)
		}
	}
}

// The tag is a hash of the value alone, so the same value must get the same
// tag whatever stands around it. A slip in where the value starts or ends
// still hides it, but under a different tag, and tags stop matching across
// lines.
func TestMutationGaps_SameValueSameTag(t *testing.T) {
	sc := gapScanner()
	tag := func(line string) string {
		out := sc.ScanAndRedact(line)
		m := regexp.MustCompile(`\[HIDDEN:[a-z0-9-]+:[0-9a-f]{6}\]`).FindAllString(out, -1)
		if len(m) != 1 {
			t.Fatalf("want exactly one marker for %q, got %q", line, out)
		}
		return m[0]
	}
	for _, tc := range []struct{ why, a, b string }{
		{"an address before a full stop", `sent to marcosantos@corp.example.`, `sent to marcosantos@corp.example`},
		{"a value with a colon, quoted or bare", `password="abc:def"`, `password=abc:def`},
		{"a value with a colon, in JSON or bare", `{"password": "abc:def"}`, `password=abc:def`},
	} {
		if ta, tb := tag(tc.a), tag(tc.b); ta != tb {
			t.Errorf("%s: %q gives %s, %q gives %s", tc.why, tc.a, ta, tc.b, tb)
		}
	}
	if out := sc.ScanAndRedact(`sent to marcosantos@corp.example.`); !strings.HasSuffix(out, "].") {
		t.Errorf("the full stop after the address must stay outside the marker: %q", out)
	}
}

// PII_CONFIDENCE_THRESHOLD and PII_BIGRAM_DEFAULT_SCORE are read only when
// set. With the test for "set" inverted, a configured value was ignored
// without a word and the default stayed in force.
func TestMutationGaps_NumericEnvOverridesApply(t *testing.T) {
	t.Setenv("PII_CONFIDENCE_THRESHOLD", "2.5")
	t.Setenv("PII_BIGRAM_DEFAULT_SCORE", "-3.25")
	cfg := ApplyEnvOverrides(DefaultConfig())
	if cfg.ConfidenceThreshold != 2.5 {
		t.Errorf("PII_CONFIDENCE_THRESHOLD=2.5 gave %v", cfg.ConfidenceThreshold)
	}
	if cfg.BigramDefaultScore != -3.25 {
		t.Errorf("PII_BIGRAM_DEFAULT_SCORE=-3.25 gave %v", cfg.BigramDefaultScore)
	}

	t.Setenv("PII_CONFIDENCE_THRESHOLD", "")
	t.Setenv("PII_BIGRAM_DEFAULT_SCORE", "")
	t.Setenv("PII_ADAPTIVE_THRESHOLD", "")
	def := DefaultConfig()
	cfg = ApplyEnvOverrides(DefaultConfig())
	if cfg.ConfidenceThreshold != def.ConfidenceThreshold || cfg.BigramDefaultScore != def.BigramDefaultScore || cfg.AdaptiveThreshold {
		t.Errorf("unset variables changed the defaults: %v, %v, adaptive %v", cfg.ConfidenceThreshold, cfg.BigramDefaultScore, cfg.AdaptiveThreshold)
	}
}
