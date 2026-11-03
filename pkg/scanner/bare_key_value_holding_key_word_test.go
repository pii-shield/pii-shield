package scanner

import (
	"strings"
	"testing"
)

// TestValueHoldingKeyWordAfterBareKey: the token after a bare sensitive word
// in prose is its value even when a sensitive word sits inside it (monKEY,
// TOKENizer, AUTHority, byPASS). "password Wintermonkey73" came back
// unchanged on every line, because Wintermonkey73 was read as a key of its
// own and the word after it was forced instead, while "password Kaffee1977"
// was hidden. A token that carries the word as a whole component (api_key,
// apiKey7, Key2) or ends in a separator (Authorization:) is still a key.
func TestValueHoldingKeyWordAfterBareKey(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	hidden := []string{
		"password Wintermonkey73",
		"pass Wintermonkey73",
		"my password is Wintermonkey73",
		"login failed for lena, password Wintermonkey73",
		"2026-10-25 10:01:02,117 - app - WARNING - password Wintermonkey73 rejected",
		"WARNING:app.views:password Wintermonkey73 rejected",
		"password Hockey99",
		"password tokenizer7",
		"password authority12",
		"password Secretariat7",
		"password bypass99",
		"secret Monkey73",
	}
	for _, in := range hidden {
		out := ScanAndRedact(in)
		if !strings.Contains(out, "[HIDDEN") {
			t.Errorf("value holding a key word after a bare key passed: in=%q out=%q", in, out)
		}
		for _, w := range []string{"Wintermonkey73", "Hockey99", "tokenizer7", "authority12", "Secretariat7", "bypass99", "Monkey73"} {
			if strings.Contains(out, w) {
				t.Errorf("value survived: in=%q out=%q", in, out)
			}
		}
	}

	// The value spends the forced slot: the words after it are prose.
	in := "password Wintermonkey73 was rejected for lena"
	out := ScanAndRedact(in)
	if strings.Contains(out, "Wintermonkey73") || !strings.HasSuffix(out, " was rejected for lena") {
		t.Errorf("the words after the value were not kept: in=%q out=%q", in, out)
	}

	// A key name in the slot is still a key, and forces the token after it.
	keys := map[string]string{
		"secret api_key abc12345 end":                                        "api_key",
		"password apiKey7 abc12345 end":                                      "apiKey7",
		"password x-api-key abc12345 end":                                    "x-api-key",
		"password Key2 abc12345 end":                                         "Key2",
		"Missing token Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234": "Authorization:",
	}
	for in, key := range keys {
		out := ScanAndRedact(in)
		if !strings.Contains(out, key) {
			t.Errorf("key in the forced slot was hidden: in=%q out=%q", in, out)
		}
		if strings.Contains(out, "abc12345") || strings.Contains(out, "abcdefghijklmnopqrstuvwxyz1234") {
			t.Errorf("value after the key survived: in=%q out=%q", in, out)
		}
	}

	// Prose after the bare word stays prose (B1, B12 and the dictionary-word
	// rule), and a value after a separator is hidden as before.
	for _, in := range []string{"password reset", "password changed", "password summer", "token expired for lena"} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("prose after a bare key changed: in=%q out=%q", in, out)
		}
	}
	for _, in := range []string{"password: Wintermonkey73", "password=Wintermonkey73", `{"password": "Hockey99"}`} {
		if out := ScanAndRedact(in); strings.Contains(out, "Wintermonkey73") || strings.Contains(out, "Hockey99") {
			t.Errorf("value after a separator survived: in=%q out=%q", in, out)
		}
	}
}

func TestSensitiveWordOnlyInside(t *testing.T) {
	st := cfgState()
	cases := map[string]bool{
		"Wintermonkey73": true, "Hockey99": true, "tokenizer7": true, "authority12": true,
		"Secretariat7": true, "bypass99": true, "Passkey9": true, "Keyboard7": true,
		"api_key": false, "apiKey7": false, "Key2": false, "x-api-key": false, "PASSWORD": false,
		"tokenAuth": false, "keyVault9": false, "TOKEN123": false, "abc12345": false, "密码x": false,
		// Field names after a false bare key on a docs corpus ("passport",
		// "Signing", "-sign"), and plurals: names, not values.
		"passport_number": false, "sensitive_keys": false, "keys**": false, "-inkey": false,
		"PII_SENSITIVE_KEYS": false, "Keys7": false, "tokens9": false, "Winter-monkey73": false,
	}
	for tok, want := range cases {
		if got := st.sensitiveWordOnlyInside(tok); got != want {
			t.Errorf("sensitiveWordOnlyInside(%q) = %v, want %v", tok, got, want)
		}
	}
}
