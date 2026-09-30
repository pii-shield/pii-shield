package scanner

import (
	"strings"
	"testing"
)

// TestPwKeyIsSensitive: the short forms of "password" count as sensitive keys
// when they are a whole component of the key. Before, PW:maple248 (the
// TiddlyServer failed-login line) kept the password whenever its score was
// low, while password:maple248 hid it.
func TestPwKeyIsSensitive(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"authorization invalid - UN:lena - PW:maple248",
		"PW:maple248",
		"pw:maple248",
		"PW=maple248",
		"db_pw=maple248",
		"dbPwd: maple248",
		"smtp_pwd=maple248",
		"user-pw=maple248",
		`{"pw":"maple248"}`,
	} {
		out := ScanAndRedact(in)
		if strings.Contains(out, "maple248") || !strings.Contains(out, "[HIDDEN") {
			t.Errorf("password after a pw key leaked:\n in: %s\nout: %s", in, out)
		}
	}
	// The username on the same line is not a secret.
	if out := ScanAndRedact("authorization invalid - UN:lena - PW:maple248"); !strings.Contains(out, "UN:lena") || !strings.Contains(out, "invalid") {
		t.Errorf("username or prose lost: %q", out)
	}

	// A bare pwd is the shell's working directory, and a longer key that
	// merely contains the letters is not a password key.
	for _, in := range []string{
		"PWD=/home/lena",
		"pwd: /home/lena",
		"pwd",
		"shipway=north",
		"mapwidth=640",
		"httpwrapper=default",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestProseAfterBareSensitiveWordKept: a bare sensitive word in prose used to
// hide the next token whenever it was long enough, so "token expired" and
// "authentication failed" lost their second word. An all-letter word that
// reads as English is kept; a value with a digit or a symbol, or any value
// after a separator, is hidden as before.
func TestProseAfterBareSensitiveWordKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"authorization invalid",
		"authentication failed",
		"authorization required",
		"token expired",
		"secret missing",
		"key rotation done",
		"signature verification failed",
		"auth denied for bob",
		"the token expires in an hour",
		"password invalid for user bob",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("prose changed:\n in: %s\nout: %s", in, out)
		}
	}

	for _, in := range []string{
		"password hunter2",
		"password maple248",
		"password Tr0ub4dor",
		"password: swordfish",
		"password=swordfish",
		"cvv 123",
		"my password is maple248",
	} {
		out := ScanAndRedact(in)
		value := in[strings.LastIndexAny(in, " =:")+1:]
		if strings.Contains(out, value) || !strings.Contains(out, "[HIDDEN") {
			t.Errorf("secret after a sensitive word leaked:\n in: %s\nout: %s", in, out)
		}
	}
}
