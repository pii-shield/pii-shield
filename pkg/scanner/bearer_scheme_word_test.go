package scanner

import (
	"regexp"
	"strings"
	"testing"
)

// markedShape turns a line with the secret in [[...]] into the input and a
// regexp of the expected output: each [[...]] part becomes one [HIDDEN...]
// marker, everything else stays byte for byte.
func markedShape(line string) (string, *regexp.Regexp) {
	var in, want strings.Builder
	want.WriteString("^")
	for {
		i := strings.Index(line, "[[")
		if i < 0 {
			break
		}
		j := i + strings.Index(line[i:], "]]")
		in.WriteString(line[:i] + line[i+2:j])
		want.WriteString(regexp.QuoteMeta(line[:i]) + `\[HIDDEN(?::[^\]]*)?\]`)
		line = line[j+2:]
	}
	in.WriteString(line)
	want.WriteString(regexp.QuoteMeta(line) + "$")
	return in.String(), regexp.MustCompile(want.String())
}

// TestBearerSchemeWordKept: after an authorization key the word Bearer is
// the scheme, as Basic is, and the token after it is the credential. On
// 940f3fd8 the key's forced slot went to the word Bearer (six letters, so the
// short-word rule that frees Basic did not free it), and the token after it
// was forced only from 16 characters: "Authorization: Bearer abc123" came out
// as "Authorization: [HIDDEN:…] abc123", and "authorization=Bearer abc123"
// came out whole.
func TestBearerSchemeWordKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, line := range []string{
		"Authorization: Bearer [[abc123]]",
		"authorization: bearer [[abc123]]",
		"Proxy-Authorization: Bearer [[test-token-1]]",
		"authorization=Bearer [[abc123]]",
		// A quoted value with a space in it is hidden whole, scheme and all.
		`{"Authorization": "[[Bearer abc123]]"}`,
		`{"authorization":"[[Bearer abc123]]"}`,
		"Authorization: Bearer [[x9Qm2pL7vR4tZ8wKa1b2]] user=anna",
		"Authorization: Negotiate [[YIIGhgYJKoZIhvcSAQICAQBuggZ1MIIGcaADAgEFoQMCAQ6iBwMF]]",
		// Not a credential after the scheme: words and scheme parameters
		// stay, and so does the scheme.
		"Authorization: Bearer missing",
		"authorization: Bearer token expired",
		`WWW-Authenticate: Bearer realm="api"`,
		`WWW-Authenticate: Bearer realm="api", error="invalid_token"`,
		`Authorization: Digest username="bob", realm="api"`,
	} {
		in, want := markedShape(line)
		if out := ScanAndRedact(in); !want.MatchString(out) {
			t.Errorf("ScanAndRedact(%q)\n got: %q\nwant: %s", in, out, want)
		}
	}
}
