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

// TestShortValueAfterSecretKey: a short all-letter value is freed after a
// sensitive key (B12), which kept "author": None and "keywords": None intact
// but also let {"password": "ab"} through while the compact
// {"password":"ab"} was hidden. After a quoted key that names a secret
// outright the value is hidden; a key that only contains a sensitive word
// inside another word, a lone weak word, an unquoted key (type annotations,
// docstrings) and a literal keep the relaxation.
func TestShortValueAfterSecretKey(t *testing.T) {
	useDefaultConfig(t)

	for _, tc := range []struct{ in, secret string }{
		{`{"password": "ab"}`, `"ab"`},
		{`{"x-api-key": "abc"}`, `"abc"`},
		{`{"db_password": "hello"}`, "hello"},
		{`{"cvv": "abc"}`, `"abc"`},
		{`{"csrfToken": "abc"}`, `"abc"`},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) || !strings.Contains(out, "[HIDDEN:") {
			t.Errorf("short value after a secret key not hidden: in=%q out=%q", tc.in, out)
		}
	}
	for _, in := range []string{
		`{"author": "Bob"}`,
		`"ClientAuth-Enforced": "PASS",`,
		`{"keywords": None}`,
		`{"key": "value"}`,
		`{"auth": "xy"}`,
		`{"token": true}`,
		`{"password": null}`,
		"password: bool = False,",
		"key: str,",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("value redacted: in=%q out=%q", in, out)
		}
	}

	st := cfgState()
	for k, want := range map[string]bool{
		"password": true, "x-api-key": true, "X-Api-Key": true, "db_password": true, "csrfToken": true, "cvv": true,
		"author": false, "keywords": false, "ClientAuth-Enforced": false, "key": false, "auth": false, "monkey": false,
	} {
		if got := st.keyNamesSecret(k); got != want {
			t.Errorf("keyNamesSecret(%q) = %v, want %v", k, got, want)
		}
	}
}
