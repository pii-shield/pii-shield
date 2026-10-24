package scanner

import (
	"strings"
	"testing"
)

// TestValueEndingInQuestionMarkHidden: a logfmt value that ends in a question
// mark is a value, not a URL. password=Kaffee1977? kept the password while
// password=Kaffee1977 hid it (godror's dpiConn_create debug line, leak-radar
// repo-risks 2026-10-05, 58 of 60 hidden): the '?' and the '=' made the token
// look like a URL with a query, and the URL handling found no parameter in
// it and wrote it out whole.
func TestValueEndingInQuestionMarkHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, secret, keep string }{
		{"password=Kaffee1977? passwordLen=11", "Kaffee1977", "password=[HIDDEN:"},
		{"password=Kaffee1977?", "Kaffee1977", "password=[HIDDEN:"},
		{`password="Kaffee1977?" user=bob`, "Kaffee1977", `password="[HIDDEN:`},
		{"password=Kaffee1977?! next", "Kaffee1977", "] next"},
		{"username=lena? password=Kaffee1977?", "Kaffee1977", "username=lena? password=[HIDDEN:"},
		{"secret=Kaffee1977?x", "Kaffee1977", "secret=[HIDDEN:"},
		{"password=hunter2?", "hunter2", "password=[HIDDEN:"},
		{"time=2026-10-05T10:00:00.123+02:00 level=DEBUG msg=dpiConn_create username=scott usernameLen=5 password=Kaffee1977? passwordLen=11", "Kaffee1977", " passwordLen="},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) || !strings.Contains(out, tc.keep) {
			t.Errorf("value not hidden or the line changed around it:\n in: %s\nout: %s", tc.in, out)
		}
	}
}

// TestQueryShapeStillAURL pins what still goes to the URL handling: a '?'
// with a name=value pair after it, with or without a scheme, and what stays
// as prose: a question mark after an ordinary value.
func TestQueryShapeStillAURL(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, secret string }{
		{"/login?user=bob&password=Kaffee1977", "Kaffee1977"},
		{"GET /a?token=Ywq3SUV3eVpQgBTwK_w2VV HTTP/1.1", "Ywq3SUV3eVpQgBTwK_w2VV"},
		{"http://x.com/cb?state=ok?token=AbC123XyZ987qwerty", "AbC123XyZ987qwerty"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) || !strings.Contains(out, "?") {
			t.Errorf("URL query not handled: %q -> %q", tc.in, out)
		}
	}
	for _, in := range []string{
		"why=not? ok",
		"msg=done? retry=3",
		"connected?=yes",
		"token=abc?def=1",
		"ready? status=ok",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", in, out)
		}
	}
	for s, want := range map[string]bool{
		"/a?b=c": true, "a=1?b=2": true, "x?y=": true, "?a=b": true,
		"password=Kaffee1977?": false, "a=b?": false, "what?": false, "a=b": false, "?": false, "": false, "a?b": false,
	} {
		if got := hasQueryShape(s); got != want {
			t.Errorf("hasQueryShape(%q) = %v, want %v", s, got, want)
		}
	}
}
