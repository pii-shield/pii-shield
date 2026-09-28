package scanner

import (
	"strings"
	"testing"
)

// TestForcedShortTokenInProse: a bare sensitive word forces its next token,
// and a one- or two-character token got hidden with it: the 0 in
// self.auth[0], "the password 0 is". In prose such a token is an index or a
// count. Three characters stay forced (cvv 123), and so does a short value
// right after "password:" or "password=".
func TestForcedShortTokenInProse(t *testing.T) {
	useDefaultConfig(t)

	for _, in := range []string{
		"return self.auth[0]",
		"the password 0 is",
		"auth 1 ok",
		"password was rejected",
		"token to the",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("prose after a sensitive word redacted: in=%q out=%q", in, out)
		}
	}
	for _, tc := range []struct{ in, secret string }{
		{"cvv 123", "123"},
		{"password hunter2xyz", "hunter2xyz"},
		{"password: 12", "12"},
		{`{"password": 12}`, "12"},
		{"password=12", "=12"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(withoutMarkers(out), tc.secret) || !strings.Contains(out, "[HIDDEN:") {
			t.Errorf("value not hidden: in=%q out=%q", tc.in, out)
		}
	}
}

// TestSnakeCaseIdentifierValue: lowercase words joined by underscores
// (token_value, not_found, read_write) sit at the entropy threshold and were
// hidden in value position: `x = token_value` came back as x = [HIDDEN:…].
// They are identifiers. Anything with a digit or an uppercase letter, an
// issuer prefix, or a sensitive key in front is still hidden.
func TestSnakeCaseIdentifierValue(t *testing.T) {
	useDefaultConfig(t)

	for _, in := range []string{
		"token = token_value",
		"x = not_found",
		"status read_write",
		`{"mode": "read_write"}`,
		"event request_id done",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("snake_case identifier redacted: in=%q out=%q", in, out)
		}
	}
	for _, tc := range []struct{ in, secret string }{
		{"password=secret_value", "secret_value"},
		{"x = hqw55CTBeUqNyfgG89hH_mA", "hqw55CTBeUqNyfgG89hH_mA"},
		{"x " + stripeLowEntropy, stripeLowEntropy},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) {
			t.Errorf("secret passed as an identifier: in=%q out=%q", tc.in, out)
		}
	}
	for tok, want := range map[string]bool{
		"token_value": true, "a_b": true, "not_found_at_all": true,
		"_x": false, "x_": false, "a__b": false, "Token_value": false, "token_v2": false, "tokenvalue": false,
	} {
		if got := isSnakeCaseWords(tok); got != want {
			t.Errorf("isSnakeCaseWords(%q) = %v, want %v", tok, got, want)
		}
	}
}
