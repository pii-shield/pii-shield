package scanner

import (
	"regexp"
	"strings"
	"sync"
	"testing"
)

// campaignConfig returns a deterministic config (fixed salt) so redaction
// hashes are stable across runs. hunter2 under this salt is always
// [HIDDEN:3920d5].
func campaignConfig() Config {
	cfg := DefaultConfig()
	cfg.Salt = []byte("0123456789abcdef0123456789abcdef")
	return cfg
}

// TestNoCascadeAfterBareSensitiveWord covers B1: a bare sensitive keyword in
// prose must not force-redact the whole rest of the segment.
//
// Policy: the FIRST token after a bare sensitive key stays redacted (this is
// the "password hunter2" recall behavior, the single most important detection
// case). Only the tokens AFTER that first value are freed. So the cases below
// check that the cascade is broken — later tokens survive — without asserting
// anything about the single token immediately following the key.
func TestNoCascadeAfterBareSensitiveWord(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// 1. Bare sensitive word in prose: the tail past the first value survives.
	//    ("was" — the first token after "password" — may still be hidden.)
	out := ScanAndRedact("password was rejected for user bob")
	for _, w := range []string{"rejected", "for", "user", "bob"} {
		if !strings.Contains(out, w) {
			t.Errorf("cascade over-redaction: %q missing from %q", w, out)
		}
	}

	// 2. Regression: the value immediately after the key is still hidden.
	out2 := ScanAndRedact("password hunter2")
	if strings.Contains(out2, "hunter2") || !strings.Contains(out2, "[HIDDEN") {
		t.Errorf("key-value detection lost: %q", out2)
	}

	// 3. Second prose case. "provided" is the first token after the "token"
	//    key and may be hidden like "was" above; the cascade fix is proven by
	//    "by" and "client" surviving.
	out3 := ScanAndRedact("invalid token provided by client")
	for _, w := range []string{"by", "client"} {
		if !strings.Contains(out3, w) {
			t.Errorf("cascade over-redaction: %q missing from %q", w, out3)
		}
	}
}

// TestMaskURLPreservesAllContent covers B2: maskURLParameters must not silently
// drop bytes after a second '?', and a secret in a later section must be
// redacted in place rather than dropped.
func TestMaskURLPreservesAllContent(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// 1. Nothing lost across multiple '?'.
	in := "GET http://x.com/a?foo=1?bar=2 done"
	out := ScanAndRedact(in)
	if strings.Count(out, "?") != strings.Count(in, "?") {
		t.Errorf("'?' count changed: in=%q out=%q", in, out)
	}
	if !strings.Contains(out, "bar") || !strings.Contains(out, " done") {
		t.Errorf("URL tail dropped: %q", out)
	}

	// 2. Secret after the second '?' is redacted, not dropped.
	in2 := "http://x.com/cb?state=ok?token=AbC123XyZ987qwerty"
	out2 := ScanAndRedact(in2)
	if strings.Contains(out2, "AbC123XyZ987qwerty") {
		t.Errorf("secret leaked: %q", out2)
	}
	if !strings.Contains(out2, "token=[HIDDEN") {
		t.Errorf("secret dropped instead of redacted: %q", out2)
	}
}

// TestUnbalancedQuoteNotMangled covers B3: the scanner must never invent quote
// characters that were not in the input.
func TestUnbalancedQuoteNotMangled(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	cases := []string{`data="key=value`, `data='key=value`, `x="a=b`, `"k=v`}
	for _, in := range cases {
		out := ScanAndRedact(in)
		if strings.Count(out, `"`) != strings.Count(in, `"`) ||
			strings.Count(out, `'`) != strings.Count(in, `'`) {
			t.Errorf("quotes invented: in=%q out=%q", in, out)
		}
	}

	// Regression: balanced case keeps redaction AND both quotes.
	out := ScanAndRedact(`data="password=hunter2"`)
	if strings.Contains(out, "hunter2") || strings.Count(out, `"`) != 2 {
		t.Errorf("balanced quoted case broken: %q", out)
	}
}

// TestSingleQuoteRewritePreservesQuoteChar covers B8: a single-quoted value
// that gets redacted must keep its original quote character. processSingleToken
// used to always emit `"` regardless of the original quote, so
// token='abc123def456gh' came back as token="[HIDDEN:...]" — changing the
// quote count. This is distinct from B3 (invented/dropped quotes).
func TestSingleQuoteRewritePreservesQuoteChar(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// Entropy/forced-sensitive path (processSingleToken's main redaction branch).
	in := `msg='hello world' token='abc123def456gh'`
	out := ScanAndRedact(in)
	if strings.Contains(out, "abc123def456gh") {
		t.Fatalf("secret leaked: %q", out)
	}
	if strings.Count(out, `'`) != strings.Count(in, `'`) {
		t.Errorf("quote character changed: in=%q out=%q", in, out)
	}
	if strings.Contains(out, `"`) {
		t.Errorf("single quote rewritten to double quote: %q", out)
	}

	// Regression: a double-quoted value still gets double quotes.
	in2 := `token="abc123def456gh"`
	out2 := ScanAndRedact(in2)
	if strings.Count(out2, `"`) != 2 {
		t.Errorf("double-quoted case broken: %q", out2)
	}

	// Custom-regex path (processSingleToken's CombinedCustomRegex branch).
	cfg := campaignConfig()
	if err := cfg.ApplyCustomRegexes([]CustomRegexConfig{{Pattern: `CUST-\d{4}`, Name: "custom-id"}}); err != nil {
		t.Fatalf("ApplyCustomRegexes: %v", err)
	}
	UpdateConfig(cfg)
	in3 := `ref='CUST-1234'`
	out3 := ScanAndRedact(in3)
	if strings.Contains(out3, "CUST-1234") {
		t.Fatalf("secret leaked: %q", out3)
	}
	if strings.Count(out3, `'`) != 2 || strings.Contains(out3, `"`) {
		t.Errorf("custom-regex path rewrote quote character: %q", out3)
	}
}

// TestQuoteCharRemainingBranches closes the coverage gaps left by the B8 fix
// in all three processSingleToken redaction paths (CombinedCustomRegex, the
// CustomRegexes fallback loop, and the entropy/forced path): the
// double-quote-original branch and the autoQuote (digit/bool/null, no
// original quote) branch, each only exercised for one quote character by
// TestSingleQuoteRewritePreservesQuoteChar and TestCustomRegexFallbackPath.
func TestQuoteCharRemainingBranches(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)

	digitRule := CustomRegexRule{Regexp: regexp.MustCompile(`^\d{6,}$`), Name: "digits"}
	var sb strings.Builder

	// CombinedCustomRegex path (block 1): double-quote original, and autoQuote
	// on a bare digit token with no original quote.
	applyCfg(func(c *Config) {
		c.CustomRegexes = []CustomRegexRule{digitRule}
		c.CombinedCustomRegex = regexp.MustCompile(`(\d{6,})`)
		c.CustomRegexNames = []string{"digits"}
	})
	sb.Reset()
	cfgState().processSingleToken("123456", `"123456"`, false, false, false, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("CombinedCustomRegex: double-quote not preserved: %q", got)
	}
	sb.Reset()
	cfgState().processSingleToken("123456", "123456", false, false, true, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("CombinedCustomRegex: autoQuote digit not quoted: %q", got)
	}

	// Fallback CustomRegexes path (block 2): force CombinedCustomRegex nil.
	applyCfg(func(c *Config) {
		c.CustomRegexes = []CustomRegexRule{digitRule}
		c.CombinedCustomRegex = nil
	})
	sb.Reset()
	cfgState().processSingleToken("123456", `"123456"`, false, false, false, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("fallback: double-quote not preserved: %q", got)
	}
	sb.Reset()
	cfgState().processSingleToken("123456", `'123456'`, false, false, false, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `'[HIDDEN`) || !strings.HasSuffix(got, `]'`) {
		t.Errorf("fallback: single-quote not preserved: %q", got)
	}
	sb.Reset()
	cfgState().processSingleToken("123456", "123456", false, false, true, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("fallback: autoQuote digit not quoted: %q", got)
	}

	// Entropy/forced path (block 3): no custom regexes configured.
	UpdateConfig(campaignConfig())
	sb.Reset()
	cfgState().processSingleToken("999999", "999999", true, false, true, &sb)
	if got := sb.String(); !strings.HasPrefix(got, `"[HIDDEN`) || !strings.HasSuffix(got, `]"`) {
		t.Errorf("entropy: autoQuote digit not quoted: %q", got)
	}
}

// TestUpdateConfigConcurrent covers B4: UpdateConfig must be safe to call while
// other goroutines are scanning. It is meaningful under -race, which the CI and
// the campaign [T] gate always enable; before the atomic.Pointer snapshot the
// race detector reported writes in UpdateConfig racing reads in scanLine /
// isSensitiveKey.
func TestUpdateConfigConcurrent(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ScanAndRedact("password=hunter2 and value AbC9xY2kQ8pLmN0r")
			}
		}()
	}
	for i := 0; i < 50; i++ {
		UpdateConfig(campaignConfig())
	}
	wg.Wait()
}

// TestQuotedMultiWordValueRedacted covers B9: a quoted multi-word value must
// be re-tokenized (so an embedded email/secret is scored on its own) whether
// or not whitespace follows the ':' that introduces it. Compact JSON
// (no space after the key's colon) used to leak the whole value verbatim,
// because processColonPair fed it straight to processSingleToken instead of
// through processTokenLogic's isValuePos re-tokenize branch. Reported
// externally by David Youssef (GuardSpine/CodeGuard), 2026-08-06.
func TestQuotedMultiWordValueRedacted(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// Previously leaking: compact JSON / bare quoted phrase, no space after ':'.
	leaky := []string{
		`"contact alice@example.com"`,
		`{"m":"contact alice@example.com"}`,
	}
	for _, in := range leaky {
		out := ScanAndRedact(in)
		if strings.Contains(out, "alice@example.com") {
			t.Errorf("PII leaked: in=%q out=%q", in, out)
		}
		if !strings.Contains(out, "[HIDDEN") {
			t.Errorf("expected redaction: in=%q out=%q", in, out)
		}
	}

	// Regression: shapes that already redacted correctly must keep working.
	working := []string{
		`contact alice@example.com`,
		`{"m":"alice@example.com"}`,
		`{"m": "contact alice@example.com"}`,
	}
	for _, in := range working {
		out := ScanAndRedact(in)
		if strings.Contains(out, "alice@example.com") {
			t.Errorf("regression: PII leaked: in=%q out=%q", in, out)
		}
	}

	// Ordinary multi-word text with no PII must not start getting redacted.
	if out := ScanAndRedact(`{"m": "ok fine"}`); out != `{"m": "ok fine"}` {
		t.Errorf("over-redaction on benign compact JSON: %q", out)
	}
}

// TestSafeRegexWhitelistAppliesToLuhnAndURL covers B10: cfg.SafeRegexes
// (PII_SAFE_REGEX_LIST) is a no-op for the Luhn credit-card path and the URL
// query-parameter path. Both call redactWithHMAC directly in scanLine /
// maskURLParameters without ever consulting the whitelist that
// processSingleToken checks, so a wildcard safe-regex rule that exempts every
// other token still leaves these two paths byte-identical to running with no
// whitelist at all. Reported externally (GuardSpine/CodeGuard integrator,
// 2026-08).
func TestSafeRegexWhitelistAppliesToLuhnAndURL(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)

	wildcard := campaignConfig()
	if err := wildcard.ApplySafeRegexes([]CustomRegexConfig{{Pattern: ".*", Name: "all"}}); err != nil {
		t.Fatalf("ApplySafeRegexes: %v", err)
	}

	// Sanity check: without the whitelist, both paths redact (so a passing
	// test below is proof the whitelist worked, not that nothing matched).
	UpdateConfig(campaignConfig())
	cardBaseline := ScanAndRedact("charge card 4539148803436467 end")
	if !strings.Contains(cardBaseline, "[HIDDEN") {
		t.Fatalf("test setup broken: card not redacted without whitelist: %q", cardBaseline)
	}
	urlBaseline := ScanAndRedact("GET http://x.com/cb?token=AbC123XyZ987qwerty")
	if !strings.Contains(urlBaseline, "[HIDDEN") {
		t.Fatalf("test setup broken: URL param not redacted without whitelist: %q", urlBaseline)
	}

	// 1. Luhn-valid card number must be exempted by a wildcard whitelist rule.
	UpdateConfig(wildcard)
	cardOut := ScanAndRedact("charge card 4539148803436467 end")
	if strings.Contains(cardOut, "[HIDDEN") {
		t.Errorf("SafeRegexes did not exempt Luhn match: %q", cardOut)
	}

	// 2. URL query-parameter secret must be exempted by a wildcard whitelist rule.
	urlOut := ScanAndRedact("GET http://x.com/cb?token=AbC123XyZ987qwerty")
	if strings.Contains(urlOut, "[HIDDEN") {
		t.Errorf("SafeRegexes did not exempt URL param: %q", urlOut)
	}
}

// TestPossessiveApostropheDoesNotOpenQuote covers B13: a lone apostrophe in
// prose ("John's", "patient's", "O'Brien's") used to be read as an opening
// quote, so everything after it to the end of the line became one unscanned
// "value" and a secret or identifier there passed through. Real quoted values
// (token='...') and quoted phrases with inner apostrophes ('don't ...') must
// keep today's behaviour.
func TestPossessiveApostropheDoesNotOpenQuote(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	const secret = "AbC9xY2kQ8pLmN0rZq7"
	const secret2 = "Zq7AbC9xY2kQ8pLmN0r"

	mustHide := []string{
		"John's token " + secret + " leaked",
		"the patient's key " + secret + " and the doctor's key " + secret2,
		"O'Brien's key " + secret + " ok",
		"[HIDDEN:person:d56c6f]'s report lists " + secret,
	}
	for _, in := range mustHide {
		out := ScanAndRedact(in)
		if strings.Contains(out, secret) || strings.Contains(out, secret2) {
			t.Errorf("secret survived after an apostrophe: in=%q out=%q", in, out)
		}
		// The possessive itself must survive as text (the token "John's" is a
		// plain word). "O'Brien's" is a high-entropy token and was already
		// redacted before this fix, so it is not checked here.
		if strings.HasPrefix(in, "John") && !strings.Contains(out, "John's") {
			t.Errorf("possessive word damaged: in=%q out=%q", in, out)
		}
	}

	// A genuine single-quoted value still redacts and keeps both quotes (B8).
	out := ScanAndRedact("token='abc123def456gh' and 'def'")
	if strings.Contains(out, "abc123def456gh") || strings.Count(out, "'") != 4 {
		t.Errorf("quoted value handling regressed: %q", out)
	}
	// A quoted phrase with an inner apostrophe: the inner one is not a closer,
	// the phrase is still scanned token by token and both quotes survive.
	out = ScanAndRedact("he said 'don't leak " + secret + " now' end")
	if strings.Contains(out, secret) || strings.Count(out, "'") != 3 {
		t.Errorf("inner apostrophe handling regressed: %q", out)
	}
	// Closing quote followed by punctuation rather than a space.
	out = ScanAndRedact("he said 'leak " + secret + " now', then left")
	if strings.Contains(out, secret) || strings.Count(out, "'") != 2 {
		t.Errorf("closer before punctuation regressed: %q", out)
	}
	// The look-ahead skips an escaped quote inside a quoted value and still
	// finds the real closer; a trailing backslash at the very end is harmless.
	for _, in := range []string{
		"he said 'it\\'s " + secret + " now' end",
		"note='" + secret + "\\",
		"John's " + secret + " \\",
	} {
		out = ScanAndRedact(in)
		if strings.Contains(out, secret) {
			t.Errorf("secret survived with escapes: in=%q out=%q", in, out)
		}
	}
}

// TestBareKeyKeepsMinLength covers B12: the token after a bare sensitive word
// is forced, and the forced path used to skip MinSecretLength, so "pass an
// extraordinary resolution" hid "an" and "token to the" hid "to". A short
// all-letter word cannot be a secret and must keep its text; anything long
// enough or carrying a digit stays forced, and key=value pairs are untouched.
func TestBareKeyKeepsMinLength(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	keep := map[string]string{
		"password an extraordinary resolution was required": "an",
		"token to the holder":                               "to",
		"the secret of the trade":                           "of",
	}
	for in, word := range keep {
		out := ScanAndRedact(in)
		if !strings.Contains(out, " "+word+" ") {
			t.Errorf("short word after a bare key was redacted: in=%q out=%q", in, out)
		}
	}

	hide := map[string]string{
		"password hunter2 was used": "hunter2",
		"password: 12345 was used":  "12345",
		"password=an":               "=an",
		"token: ab1 given":          "ab1",
	}
	for in, secret := range hide {
		out := ScanAndRedact(in)
		if strings.Contains(out, secret) {
			t.Errorf("secret after a key survived: in=%q out=%q", in, out)
		}
	}
}
