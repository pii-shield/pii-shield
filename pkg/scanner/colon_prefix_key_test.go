package scanner

import (
	"strings"
	"testing"
)

// TestKeyGluedToColonPrefix: Python's default log format (logging.basicConfig)
// writes LEVEL:logger:message with no space, so a message that starts with a
// key arrives as one token with the prefix: "DEBUG:pkg.module:Password:". The
// colon splitter consumed the prefix and dropped the key it ended in, and the
// entropy guard in isSensitiveKey took "INFO:root:password" for a random
// token, so a word-like value passed while the same line with a space before
// the key was hidden.
func TestKeyGluedToColonPrefix(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ kept, secret string }{
		{"DEBUG:huawei_lte_api.Connection:Password: ", "Wintermonkey73"},
		{"INFO:root:password=", "Wintermonkey73"},
		{"DEBUG:app.auth:token: ", "Wintermonkey73"},
		{"root:Password: ", "Wintermonkey73"},
		{"WARNING:myapp.db:api_key: ", "Sommerberlin42"},
		{"ERROR:svc:secret=", "Sommerberlin42"},
		{"INFO:pubsub:key=", "Wintermonkey73"},
		{"INFO:root:password= ", "Wintermonkey73"},
		{"10:15:32:Password: ", "Wintermonkey73"},
	} {
		in := tc.kept + tc.secret
		out := ScanAndRedact(in)
		if strings.Contains(out, tc.secret) || !strings.HasPrefix(out, tc.kept+"[HIDDEN:") {
			t.Errorf("value after a glued key not hidden, or the prefix changed:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestGluedPrefixMatchesBareMessage: with the prefix glued on, a message is
// redacted exactly as it is on its own. This pins both directions: a key is
// seen behind the prefix, and nothing else in the message starts being hidden
// because of it.
func TestGluedPrefixMatchesBareMessage(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, msg := range []string{
		"Password: Wintermonkey73",
		"password=Wintermonkey73",
		"api_key: Sommerberlin42",
		"Authorization: Bearer abcdefghijklmnopqrstuvwx",
		"Status: ok",
		"Retry: 3",
		"User logged in",
		"connected to db-01:5432 as lena",
		"Starting new HTTPS connection (1): api.example.com:443",
	} {
		for _, prefix := range []string{"INFO:root:", "DEBUG:urllib3.connectionpool:"} {
			want := prefix + ScanAndRedact(msg)
			if got := ScanAndRedact(prefix + msg); got != want {
				t.Errorf("glued prefix changed the result:\n  in: %s\n got: %s\nwant: %s", prefix+msg, got, want)
			}
		}
	}
}

// TestCompletePairStillFreesNextToken: a colon pair whose value was consumed
// in the same token reports no pending key, so the token after it is scored
// on its own. The value here is word-like and passes by its score; it would
// be hidden only if the pair forced it.
func TestCompletePairStillFreesNextToken(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"INFO:root:Status: Wintermonkey73",
		"level:info Wintermonkey73",
		"token:abc Wintermonkey73",
		"INFO:root:Wintermonkey73",
	} {
		if out := ScanAndRedact(in); !strings.Contains(out, "Wintermonkey73") {
			t.Errorf("token after a complete pair was forced:\n in: %s\nout: %s", in, out)
		}
	}

	in := `{"password":"hunter2x","query":"a=b"}`
	if out := ScanAndRedact(in); !strings.Contains(out, `"query":"a=b"`) || strings.Contains(out, "hunter2x") {
		t.Errorf("compact JSON neighbour changed:\n in: %s\nout: %s", in, out)
	}
}
