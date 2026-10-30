package scanner

import "testing"

// TestSessionTokenUnderSessionKey: a session id written as a name=value pair
// under a session or cookie name is hidden when it has the shape of a token.
// On 940f3fd8 "Cookie: sid=abc123" came out unchanged: the pair was scored
// like any other and a short token stays under the entropy threshold. Words,
// counts, dates and other cookies keep their values.
func TestSessionTokenUnderSessionKey(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, line := range []string{
		"Cookie: sid=[[abc123]]",
		"Cookie: theme=dark; sid=[[abc123]]",
		"Cookie: sid=[[abc123]]; theme=dark",
		"Set-Cookie: sid=[[abc123]]; Path=/; HttpOnly",
		"Cookie: JSESSIONID=[[a1b2c3d4e5]]",
		"PHPSESSID=[[9f8e7d6c5b4a]]",
		"session_id=[[s1234ab]] user=anna",
		"GET /checkout?sid=[[abc123]]&page=2 HTTP/1.1",
		"sid: [[abc123]]",
		"sid:[[abc123]] user=anna",
		`{"sid": "[[abc123]]"}`,
		`{"session_id":"[[abc123]]","user":"anna"}`,
		`session_id="[[abc123]]"`,
		"sid: [[YWJjMTIzNA==]]",
		// Not a token: a word, a count, a date, a flag, a short value.
		"session=default count=3",
		"session=3 sid=2026-10-30",
		"cookie_consent=true",
		"sid=a1b2 retry=2",
		"session_count=a1b2c3d4",
		"GET /search?session=default&page=2 HTTP/1.1",
		"sid: 2026-10-30",
		`{"session": "default", "cookie": "accepted"}`,
		// A cookie list is judged pair by pair, not as one token.
		`{"Cookie": "theme=dark; lang=en-GB"}`,
	} {
		in, want := markedShape(line)
		if out := ScanAndRedact(in); !want.MatchString(out) {
			t.Errorf("ScanAndRedact(%q)\n got: %q\nwant: %s", in, out, want)
		}
	}
}
