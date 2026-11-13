package scanner

import (
	"strings"
	"testing"
)

// TestSentenceEndPunctuation covers a word that closes a sentence. The '.',
// '!' or '?' after it was scored as part of the token: one more distinct
// character and a second character class, which lifted Tuesday (3.31) to
// Tuesday. (4.00) over the 3.60 threshold. One capitalised dictionary word in
// three was hidden at the end of a sentence, and Russian words too.
func TestSentenceEndPunctuation(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		`Your order has shipped and arrives on Tuesday.`,
		`See you on Friday!`,
		`Is it Thursday?`,
		`Pushed the branch to GitHub.`,
		`Restarting Docker.`,
		`The release moved to November.`,
		`is it really Wednesday...`,
		`Tuesday?!`,
		`msg="Delivered on Tuesday."`,
		`(arrives Tuesday.)`,
		`2026-10-18 12:01:02,123 [INFO] util.sms: Sending SMS: Your order arrives on Tuesday.`,
		`Привет.`,
		`Встреча в Понедельник.`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("a word that ends a sentence was hidden:\n in:  %s\n out: %s", in, out)
		}
	}
}

// TestSentenceEndStillHidden pins the other side: the punctuation is only
// left out of the score of a word made of letters, and only when nothing
// around the token asks for it to be hidden.
func TestSentenceEndStillHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, secret string }{
		// A random run of letters scores over the threshold on its own.
		{`the key is qWzXvKpLmNtRbYc.`, "qWzXvKpLmNtRbYc"},
		// A short run of letters that does not read like a word keeps the
		// full stop in its score, which is what hides it.
		{`Your temporary password is kXqWzRtP.`, "kXqWzRtP"},
		{`Your verification code is kxqwzrtp!`, "kxqwzrtp"},
		// A digit or a symbol inside: the token is scored whole, as before.
		{`use Welcome1! to log in`, "Welcome1!"},
		{`the code is xK9mP2qLw7.`, "xK9mP2qLw7"},
		{`the code is Tr0ub4dor?`, "Tr0ub4dor"},
		// Under a sensitive key the value is forced whatever it looks like.
		{`password=Tuesday.`, "Tuesday"},
		{`password: Sunshine!`, "Sunshine"},
		{`{"password": "Tuesday."}`, "Tuesday"},
	} {
		if out := ScanAndRedact(tc.in); strings.Contains(out, tc.secret) {
			t.Errorf("secret leaked:\n in:  %s\n out: %s", tc.in, out)
		}
	}
}
