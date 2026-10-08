package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestQuotedPhraseWithURLIsScannedWordByWord: a quoted phrase that holds a URL
// (a curl command as an MCP tool argument, a logfmt msg) contains "://", so the
// whole phrase went to the URL handling, which only looks at the query and the
// password, and every other word passed (the inercia/MCPShell request body
// shape of leak-radar repo-risks 2026-10-08).
func TestQuotedPhraseWithURLIsScannedWordByWord(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	key := "sk-u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd"
	for _, tc := range []struct {
		in   string
		keep []string
		json bool
	}{
		{`{"command": "curl -H 'Authorization: Bearer ` + key + `' https://api.example.com/v1/me"}`, []string{"curl -H 'Authorization: ", "' https://api.example.com/v1/me\"}"}, true},
		{`{"command":"curl -H 'Authorization: Bearer ` + key + `' https://api.example.com/v1/me"}`, []string{`{"command":"curl -H`, "' https://api.example.com/v1/me\"}"}, true},
		{`{"command": "token=` + key + ` https://api.example.com/"}`, []string{`"token=[HIDDEN:`, ` https://api.example.com/"}`}, true},
		{`"see https://api.example.com/ ` + key + `"`, []string{`"see https://api.example.com/ [HIDDEN:`}, false},
		{`level=info msg="fetched https://api.example.com/x with Bearer ` + key + `"`, []string{`msg="fetched https://api.example.com/x with`}, false},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, key) {
			t.Errorf("secret passed through: %q", out)
		}
		for _, k := range tc.keep {
			if !strings.Contains(out, k) {
				t.Errorf("lost %q: %q", k, out)
			}
		}
		if tc.json && !json.Valid([]byte(out)) {
			t.Errorf("JSON broken: %q", out)
		}
	}

	// A phrase under a sensitive key is still hidden whole.
	for _, in := range []string{
		`{"password":"my secret https://x.example.com/a"}`,
		`password="my secret https://x.example.com/a"`,
	} {
		if out := ScanAndRedact(in); strings.Contains(out, "my secret") || !strings.Contains(out, "[HIDDEN:") {
			t.Errorf("sensitive key: %q", out)
		}
	}

	// Plain prose with a link, a URL password and a URL query keep working.
	for in, want := range map[string]string{
		`msg="open https://example.com/docs/getting-started now"`: `msg="open https://example.com/docs/getting-started now"`,
		`url="https://user:` + key + `@db.example.com/x"`:         `url="https://user:[HIDDEN:`,
		`"https://api.example.com/x?token=` + key + `"`:           `"https://api.example.com/x?token=[HIDDEN:`,
	} {
		if out := ScanAndRedact(in); strings.Contains(out, key) || !strings.Contains(out, want) {
			t.Errorf("got %q, want it to contain %q", out, want)
		}
	}

	// A quoted User-Agent with a bot's URL stays with the URL handling: its
	// product tokens are not scored one by one.
	ua := `"Mozilla/5.0 (compatible; AhrefsBot/6.1; +http://ahrefs.com/robot/)"`
	if out := ScanAndRedact(ua); out != ua {
		t.Errorf("User-Agent changed: %q", out)
	}
}
