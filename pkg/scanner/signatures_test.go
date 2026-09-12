package scanner

import (
	"strings"
	"testing"
)

// The test tokens below are assembled at runtime instead of being written out
// as literals: they are fake, but they match the issuer formats exactly, and
// GitHub push protection rejects a commit that contains a complete Slack or
// Stripe key in a file. Concatenation keeps the value the scanner sees
// identical while leaving no matchable literal in the source.
var (
	aRun24 = strings.Repeat("a", 24)
	aRun36 = strings.Repeat("a", 36)

	awsLowEntropy    = "AK" + "IA" + strings.Repeat("A", 16)
	asiaLowEntropy   = "AS" + "IA" + strings.Repeat("A", 16)
	gcpLowEntropy    = "AI" + "za" + strings.Repeat("A", 35)
	githubLowEntropy = "gh" + "p_" + aRun36
	slackLowEntropy  = "xo" + "xb-1111111111-" + aRun24
	stripeLowEntropy = "sk" + "_live_" + aRun24
	stripeRestricted = "rk" + "_test_" + aRun24
	jwtLowEntropy    = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
)

// lowEntropySecrets are valid-format tokens whose bodies are deliberately
// repetitive, so entropy scoring alone lets every one of them through. Verified
// on main before this change: all of them pass unredacted at the default
// threshold. They are the reason signature detectors exist.
var lowEntropySecrets = []struct {
	name  string
	token string
	label string
}{
	{"aws access key id", awsLowEntropy, "aws-key"},
	{"aws session key id", asiaLowEntropy, "aws-key"},
	{"gcp api key", gcpLowEntropy, "gcp-key"},
	{"github token", githubLowEntropy, "github-token"},
	{"slack bot token", slackLowEntropy, "slack-token"},
	{"stripe secret key", stripeLowEntropy, "stripe-key"},
	{"stripe restricted key", stripeRestricted, "stripe-key"},
	{"jwt", jwtLowEntropy, "jwt"},
}

// TestStructuralDetectors covers F1: a token whose issuer prefix identifies it
// as a secret is redacted regardless of its entropy, and the marker names the
// issuer when entity labels are on.
func TestStructuralDetectors(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range lowEntropySecrets {
		t.Run(tc.name, func(t *testing.T) {
			out := ScanAndRedact("value " + tc.token + " end")
			if strings.Contains(out, tc.token) {
				t.Errorf("%s passed through: %q", tc.name, out)
			}
			if !strings.Contains(out, "[HIDDEN:") {
				t.Errorf("%s produced no marker: %q", tc.name, out)
			}
			if !strings.HasSuffix(strings.TrimSpace(out), "end") {
				t.Errorf("%s ate the rest of the line: %q", tc.name, out)
			}
		})
	}

	// High-entropy instances of the same formats keep working; they were
	// already redacted by entropy before this change.
	for _, tok := range []string{
		"AK" + "IAIOSFODNN7EXAMPLE",
		"gh" + "p_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx",
		"sk" + "_live_4eC39HqLyjWDarjtT1zdp7dcAAAA",
	} {
		if out := ScanAndRedact("value " + tok); strings.Contains(out, tok) {
			t.Errorf("high-entropy %q passed through: %q", tok, out)
		}
	}

	// Entity labels name the issuer, not just "entropy".
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)
	for _, tc := range lowEntropySecrets {
		want := "[HIDDEN:" + tc.label + ":"
		if out := ScanAndRedact(tc.token); !strings.Contains(out, want) {
			t.Errorf("%s: got %q, want a %s marker", tc.name, out, want)
		}
	}
}

// TestStructuralDetectorsAntiCorpus pins the things that must NOT start
// redacting because of a signature rule.
func TestStructuralDetectorsAntiCorpus(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, line := range []string{
		"version 1.2.3 released",
		"build date 2026-07-08 ok",
		"AKIA is the prefix",                  // prefix alone, too short
		"ghp_short token",                     // right prefix, wrong length
		"pk_live_aaaaaaaaaaaaaaaaaaaaaaaa",    // publishable Stripe key: public by design
		"xoxo hugs and kisses",                // xox prefix, not a Slack token
		"the bearer of this note gets coffee", // auth scheme word in prose
		"bearer is a word, not a header here",
		"the quick brown fox jumps over the do", // plain prose
	} {
		if out := ScanAndRedact(line); out != line {
			t.Errorf("anti-corpus line changed:\n in: %q\nout: %q", line, out)
		}
	}
}

// TestBearerTokenRedacted covers the Authorization header shape: before this
// change the sensitive key spent its one forced slot on the word "Bearer" and
// the credential after it went out in the clear.
func TestBearerTokenRedacted(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, line := range []string{
		"Authorization: Bearer " + aRun24,
		"bearer " + aRun24,
		`{"header":"Bearer ` + aRun24 + `"}`,
	} {
		out := ScanAndRedact(line)
		if strings.Contains(out, aRun24) {
			t.Errorf("bearer credential leaked: %q -> %q", line, out)
		}
	}

	// One token only: the cascade stays broken (B1).
	out := ScanAndRedact("Bearer " + aRun24 + " retry scheduled later")
	for _, word := range []string{"retry", "scheduled", "later"} {
		if !strings.Contains(out, word) {
			t.Errorf("bearer forced too much, %q missing: %q", word, out)
		}
	}
}

// TestPrivateKeyBlock covers the PEM case: the framing lines are marked, the
// body is redacted by the entropy engine, and the line count is preserved.
func TestPrivateKeyBlock(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, line := range []string{
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----END PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----",
	} {
		out := ScanAndRedact(line)
		if !strings.Contains(out, "[HIDDEN:private-key:") {
			t.Errorf("private key framing not marked: %q -> %q", line, out)
		}
	}

	// Whole block, scanned the way the CLI and the sidecar feed it — one line at
	// a time: framing marked, body redacted by entropy, nothing in the clear.
	block := []string{
		"-----BEGIN PRIVATE KEY-----",
		"MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAyRQ2mQpVoMxOgSDF",
		"kJ1kmY8DcYlLxOQwmqLtqPuWfMBmYIQxSdgTQVCzYrJHhHhOEXAMPLEEXAMPLEEX",
		"-----END PRIVATE KEY-----",
	}
	for _, line := range block {
		out := ScanAndRedact(line)
		if strings.Contains(out, "MII") || strings.Contains(out, "kJ1kmY8") {
			t.Errorf("private key body left in the clear: %q -> %q", line, out)
		}
		if !strings.Contains(out, "[HIDDEN:") {
			t.Errorf("private key line not redacted: %q -> %q", line, out)
		}
	}

	// The framing rule itself, at unit level. The negative cases matter more
	// than the positive ones: a whole key block handed over as a single string
	// must NOT match, or it would collapse into one marker and lose the line
	// count. (Callers split lines themselves — see the WASM multi-line fix
	// #184; ScanAndRedact scores whatever it is given as one line.)
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"-----BEGIN PRIVATE KEY-----", true},
		{"-----BEGIN RSA PRIVATE KEY-----", true},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", true},
		{"-----BEGIN ENCRYPTED PRIVATE KEY-----", true},
		{"  -----END EC PRIVATE KEY-----  ", true},
		{"-----BEGIN PUBLIC KEY-----", false},
		{"-----BEGIN CERTIFICATE-----", false},
		{"-----BEGIN PRIVATE KEY----- trailing words", false},
		{"log: -----BEGIN RSA PRIVATE KEY-----", false},
		{strings.Join(block, "\n"), false},
		{"", false},
	} {
		if got := isPrivateKeyMarker(tc.line); got != tc.want {
			t.Errorf("isPrivateKeyMarker(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestSignatureRespectsSafeRules keeps the operator's own rules ahead of the
// built-in ones: a token explicitly whitelisted must survive.
func TestSignatureRespectsSafeRules(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)

	cfg := campaignConfig()
	if err := cfg.ApplySafeRegexes([]CustomRegexConfig{{Pattern: "^" + awsLowEntropy + "$", Name: "known-test-key"}}); err != nil {
		t.Fatalf("ApplySafeRegexes: %v", err)
	}
	UpdateConfig(cfg)

	tok := awsLowEntropy
	if out := ScanAndRedact("value " + tok); !strings.Contains(out, tok) {
		t.Errorf("safe rule did not protect the token: %q", out)
	}
}
