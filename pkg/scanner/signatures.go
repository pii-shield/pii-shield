package scanner

import (
	"regexp"
	"strings"
)

// Built-in signature detectors for secrets that carry a hard, issuer-defined
// prefix. Entropy scoring already catches most real instances of these formats,
// but only because real ones look random: a valid-format low-entropy token
// (AKIAAAAAAAAAAAAAAAAA, ghp_ followed by 36 a's) scores below the threshold
// and passes, and so does every one of them once an operator raises the
// threshold. A signature match is deterministic and threshold-independent, and
// it names the issuer in the redaction marker when entity labels are on.
//
// Scope: these run per token, so they cover single-line secrets only. A PEM
// private key is handled at line level by isPrivateKeyMarker — its body lines
// are high-entropy base64 and are already redacted by the entropy engine, so
// only the BEGIN/END framing lines need a rule of their own.

var (
	// AWS access key IDs: AKIA (long-lived) and ASIA (temporary), 16 more
	// uppercase alphanumerics.
	awsKeyRe = regexp.MustCompile(`^(?:AKIA|ASIA)[0-9A-Z]{16}$`)

	// Google API keys: AIza plus 35 characters of the URL-safe alphabet.
	gcpKeyRe = regexp.MustCompile(`^AIza[0-9A-Za-z_-]{35}$`)

	// GitHub tokens: ghp_ (personal), gho_ (OAuth), ghs_ (server-to-server),
	// ghu_ (user-to-server), ghr_ (refresh).
	githubTokenRe = regexp.MustCompile(`^gh[pousr]_[0-9A-Za-z]{36,255}$`)

	// Slack tokens: xoxb/xoxa/xoxp/xoxr/xoxs/xoxe followed by dash-separated
	// numeric and alphanumeric parts.
	slackTokenRe = regexp.MustCompile(`^xox[abepsr]-[0-9A-Za-z-]{10,}$`)

	// Stripe secret and restricted keys. Publishable keys (pk_) are meant to
	// be public and are deliberately not matched.
	stripeKeyRe = regexp.MustCompile(`^(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}$`)

	// JWT: three base64url segments, the header starting with the encoded
	// `{"alg":`. The signature segment may be empty (alg=none).
	jwtRe = regexp.MustCompile(`^eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]*$`)
)

// signatureRule pairs the label written into the marker with its matcher. The
// prefix is a cheap pre-filter so the regexp only runs on plausible tokens.
type signatureRule struct {
	label  string
	prefix []string
	re     *regexp.Regexp
}

var signatureRules = []signatureRule{
	{"aws-key", []string{"AKIA", "ASIA"}, awsKeyRe},
	{"gcp-key", []string{"AIza"}, gcpKeyRe},
	{"github-token", []string{"ghp_", "gho_", "ghs_", "ghu_", "ghr_"}, githubTokenRe},
	{"slack-token", []string{"xox"}, slackTokenRe},
	{"stripe-key", []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"}, stripeKeyRe},
	{"jwt", []string{"eyJ"}, jwtRe},
}

// minSignatureLength is the shortest token any rule above can match (an AWS
// key ID, 20 characters). Tokens shorter than this skip the whole check.
const minSignatureLength = 20

// minBearerCredentialLength is how long the token after the "Bearer" auth
// scheme must be before it is treated as a credential. Real bearer tokens are
// far longer; the bound is what keeps ordinary prose ("the bearer of this
// note") from losing its next word.
const minBearerCredentialLength = 16

// matchSignature returns the label of the first signature rule that matches the
// token, or "" when none does.
func matchSignature(token string) string {
	if len(token) < minSignatureLength {
		return ""
	}
	for i := range signatureRules {
		rule := &signatureRules[i]
		for _, p := range rule.prefix {
			if strings.HasPrefix(token, p) {
				if rule.re.MatchString(token) {
					return rule.label
				}
				break
			}
		}
	}
	return ""
}

// isPrivateKeyMarker reports whether the line is the BEGIN or END framing line
// of a PEM private key block, with or without a key type in the middle
// ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
// "-----BEGIN OPENSSH PRIVATE KEY-----", and their END counterparts).
//
// The line carries no secret material itself; redacting it marks the event so
// it is counted and attributable. The key body is base64 with high entropy and
// is already redacted line by line by the entropy engine.
func isPrivateKeyMarker(line string) bool {
	s := strings.TrimSpace(line)
	const suffix = "PRIVATE KEY-----"
	prefix := ""
	switch {
	case strings.HasPrefix(s, "-----BEGIN "):
		prefix = "-----BEGIN "
	case strings.HasPrefix(s, "-----END "):
		prefix = "-----END "
	default:
		return false
	}
	if !strings.HasSuffix(s, suffix) || len(s) < len(prefix)+len(suffix) {
		return false
	}
	// Whatever sits between the two is the key type ("RSA ", "EC ", "OPENSSH ",
	// "ENCRYPTED ", or nothing at all). Restricting it to upper-case letters,
	// digits and spaces keeps a whole key block handed over as one string —
	// framing plus base64 body plus newlines — from matching as a single line
	// and collapsing into one marker.
	for i := len(prefix); i < len(s)-len(suffix); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' {
			continue
		}
		return false
	}
	return true
}
