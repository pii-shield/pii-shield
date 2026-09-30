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

	// Telegram bot tokens: the numeric bot id, a colon, and a 35-character
	// secret that starts with A. The colon is why no other rule sees it: the
	// pair splitter cuts the token in two before scoring, so the check runs
	// ahead of the splitters (processTokenLogic) and on URL path segments,
	// where the token sits after "bot" in every Bot API call.
	telegramBotTokenRe = regexp.MustCompile(`^[0-9]{5,16}:A[0-9A-Za-z_-]{34}$`)
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
	if c := token[0]; c >= '0' && c <= '9' && telegramBotTokenRe.MatchString(token) {
		return "telegram-bot-token"
	}
	return ""
}

// hasTelegramShape is the cheap pre-filter for the only signature that carries
// a colon: somewhere in s, at least five digits, a colon, then 'A'. It keeps
// the per-token cost of the colon-signature path to one IndexByte scan on
// ordinary tokens such as "ts":1700000000.
func hasTelegramShape(s string) bool {
	if len(s) < minSignatureLength {
		return false
	}
	for i := 0; ; {
		j := strings.IndexByte(s[i:], ':')
		if j < 0 {
			return false
		}
		i += j
		if i >= 5 && i+1 < len(s) && s[i+1] == 'A' {
			digits := 0
			for k := i - 1; k >= 0 && s[k] >= '0' && s[k] <= '9'; k-- {
				digits++
			}
			if digits >= 5 {
				return true
			}
		}
		i++
	}
}

// urlPathSignature reports how a URL path segment carries a signature secret:
// the length of a literal prefix to keep ("bot" in a Telegram Bot API path,
// otherwise 0) and the signature label, or "" when the segment holds none.
func urlPathSignature(seg string) (keep int, label string) {
	if label = matchSignature(seg); label != "" {
		return 0, label
	}
	if strings.HasPrefix(seg, "bot") && matchSignature(seg[3:]) == "telegram-bot-token" {
		return 3, "telegram-bot-token"
	}
	return 0, ""
}

// hasPathSignature reports whether any '/'-separated segment of s carries a
// signature secret.
func hasPathSignature(s string) bool {
	if len(s) < minSignatureLength {
		return false
	}
	for seg := range strings.SplitSeq(s, "/") {
		if _, label := urlPathSignature(seg); label != "" {
			return true
		}
	}
	return false
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

// isEmailAddress reports whether s has the shape of one e-mail address:
// a local part of letters, digits and . _ % + -, one '@', and a domain of
// two or more dot-separated labels whose last label is letters only. An
// address was scored by entropy alone, so one with a word-like local part
// (marcosantos@corp.example, lena_santos@example.com) passed while
// lena.becker@example.com was hidden: 27 of 4 212 generated first-name plus
// last-name addresses, and 1 to 4 of 60 runs in four leak-radar entries. A
// hostname with a user (ubuntu@ip-10-0-0-1.ec2.internal) has the same shape
// and is hidden too; a package version (react@18.2.0) has a numeric last
// label and is not.
func isEmailAddress(s string) bool {
	at := strings.IndexByte(s, '@')
	if at < 1 || at > 64 || strings.IndexByte(s[at+1:], '@') != -1 {
		return false
	}
	local, domain := s[:at], s[at+1:]
	if local[0] == '.' || local[len(local)-1] == '.' {
		return false
	}
	for i := 0; i < len(local); i++ {
		c := local[i]
		if !isAlnumByte(c) && c != '.' && c != '_' && c != '%' && c != '+' && c != '-' {
			return false
		}
	}
	labels := 0
	for domain != "" {
		label, rest, _ := strings.Cut(domain, ".")
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !isAlnumByte(label[i]) && label[i] != '-' {
				return false
			}
		}
		labels++
		if rest == "" {
			// The last label: letters only, at least two.
			if len(label) < 2 {
				return false
			}
			for i := 0; i < len(label); i++ {
				if c := label[i]; (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
					return false
				}
			}
			break
		}
		domain = rest
	}
	return labels >= 2
}

func isAlnumByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
