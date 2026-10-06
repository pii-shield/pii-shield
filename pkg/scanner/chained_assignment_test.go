package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fake secrets in the issuer formats, assembled at runtime so no matchable
// literal sits in the source (see signatures_test.go).
var (
	chainOpenAIKey   = "sk-" + "proj-" + "Zq8Lw2Xn5Rt7Yb3Kd9Fh1Jm4Pv6Sc0Ga2Te8UiQoWx5Nz7Lp"
	chainGitHubToken = "gh" + "p_" + "Zq8Lw2Xn5Rt7Yb3Kd9Fh1Jm4Pv6Sc0Ga2Te8"
	chainPassword    = "kItUz28amKMEasO6VXqZJqe6"
	chainSecret      = "Zq8Lw2Xn5Rt7Yb3Kd9Fh1Jm4Pv6Sc0Ga2Te8UiQo"
)

// TestEnvDumpInJSONStringIsCutAtLineBreaks: the lines of a .env file inside a
// JSON string are one token, joined by a literal "\n". The key=value splitter
// took "<secret>\nDEBUG" as a key name and wrote it out unscored, so a key on
// a middle line passed whole (seen in matdev83/go-llm-interactive-proxy#714:
// a tool result with "$ cat .env").
func TestEnvDumpInJSONStringIsCutAtLineBreaks(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, secret string }{
		{`{"role": "tool", "content": "$ cat .env\nOPENAI_API_KEY=` + chainOpenAIKey + `\nDEBUG=false\n"}`, chainOpenAIKey},
		{`{"role": "tool", "content": "$ cat .env\nGITHUB_TOKEN=` + chainGitHubToken + `\nDEBUG=false\n"}`, chainGitHubToken},
		{`{"env":"A=1\nGITHUB_TOKEN=` + chainGitHubToken + `\nDEBUG=false"}`, chainGitHubToken},
		{`{"env": "A=1\nGITHUB_TOKEN=` + chainGitHubToken + `\nDEBUG=false"}`, chainGitHubToken},
		// An escaped quote makes the scanner decode the string first, and the
		// line breaks are real ones there.
		{`{"content": "$ cat .env\nOPENAI_API_KEY=\"` + chainOpenAIKey + `\"\nDEBUG=false\n"}`, chainOpenAIKey},
		// Not JSON: the same dump as Python or Go prints it.
		{`output='PORT=8080\nGITHUB_TOKEN=` + chainGitHubToken + `\nDEBUG=false\n'`, chainGitHubToken},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) {
			t.Errorf("secret passed through: %q", out)
		}
		if !strings.Contains(out, "DEBUG=false") {
			t.Errorf("the line after the secret was hidden with it: %q", out)
		}
		if strings.Count(out, `\n`) != strings.Count(tc.in, `\n`) {
			t.Errorf("line breaks changed: %q -> %q", tc.in, out)
		}
		if json.Valid([]byte(tc.in)) && !json.Valid([]byte(out)) {
			t.Errorf("JSON broken: %q -> %q", tc.in, out)
		}
	}
}

// TestFormBodyIsCutAtAmpersands: a form-urlencoded body logged with no '?' in
// front is one token. A secret between two pairs was the unscored key half
// "<secret>&RememberMe" (seen in curiosus-dev/Curiosus.Utils#64: a login form
// body in the request log).
func TestFormBodyIsCutAtAmpersands(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, secret, kept string }{
		{`Login=tom.doe&Password=` + chainPassword + `&RememberMe=true`, chainPassword, "RememberMe=true"},
		{`Login=tom.doe&Password=Winter7413#&RememberMe=true`, "Winter7413#", "RememberMe=true"},
		{`grant_type=client_credentials&client_secret=` + chainSecret + `&scope=api`, chainSecret, "scope=api"},
		{`[REQUEST BODY] Login=tom.doe&Password=` + chainPassword + `&RememberMe=true`, chainPassword, "RememberMe=true"},
		{`{"body":"Login=tom.doe&Password=` + chainPassword + `&RememberMe=true"}`, chainPassword, "RememberMe=true"},
		{`{"body": "Login=tom.doe&Password=` + chainPassword + `&RememberMe=true"}`, chainPassword, "RememberMe=true"},
		{`body='grant_type=client_credentials&client_secret=` + chainSecret + `&scope=api'`, chainSecret, "scope=api"},
		// No sensitive name: the value in the middle is scored on its own.
		{`a=1&state=` + chainSecret + `&b=2`, chainSecret, "b=2"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) {
			t.Errorf("secret passed through: %q", out)
		}
		if !strings.Contains(out, tc.kept) {
			t.Errorf("the pair after the secret was hidden with it: %q", out)
		}
		if strings.Count(out, "&") != strings.Count(tc.in, "&") {
			t.Errorf("separators changed: %q -> %q", tc.in, out)
		}
		if json.Valid([]byte(tc.in)) && !json.Valid([]byte(out)) {
			t.Errorf("JSON broken: %q -> %q", tc.in, out)
		}
	}
}

// TestChainBoundaryLeavesOtherTokensAlone pins what the two rules must not
// touch.
func TestChainBoundaryLeavesOtherTokensAlone(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// Unchanged lines: a Windows path with "\n" in it, an ordinary query
	// chain, an HTML-escaped one, and a quoted one with nothing to hide.
	for _, in := range []string{
		`path=C:\new\table\name.txt ok`,
		`dir=C:\node_modules\next\dist loaded`,
		`rows=10&page=1`,
		`a=1&amp;b=2`,
		`msg="a=1&b=2"`,
		`{"query":"rows=10&page=1&sort=name"}`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed: %q -> %q", in, out)
		}
	}

	// A URL keeps its own parameter handling.
	in := `GET /a?x=1&token=AbC123XyZ987qwerty&y=2 HTTP/1.1`
	if out := ScanAndRedact(in); strings.Contains(out, "AbC123XyZ987qwerty") ||
		!strings.HasPrefix(out, "GET /a?x=1&token=[HIDDEN:") || !strings.HasSuffix(out, "&y=2 HTTP/1.1") {
		t.Errorf("URL query: %q", out)
	}

	// A value under a sensitive key is still hidden whole, chain or not.
	for _, in := range []string{`{"password":"a=1&b=2"}`, `{"password": "a=1&b=2"}`, `password="a=1&b=2"`} {
		out := ScanAndRedact(in)
		if strings.Contains(out, "a=") || strings.Contains(out, "b=2") || strings.Count(out, "[HIDDEN:") != 1 {
			t.Errorf("value under a sensitive key: %q -> %q", in, out)
		}
	}
}

func TestChainBoundary(t *testing.T) {
	for _, tc := range []struct {
		seg  string
		i    int
		want int
	}{
		{`a=1\nB=2`, 3, 2},
		{"a=1\nB=2", 3, 1},
		{`a=1&b=2`, 3, 1},
		{`.env\nKEY=x`, 4, 2},
		{`C:\new\table`, 2, 0},        // no assignment after "\n"
		{`a=1\n=2`, 3, 0},             // no name
		{`a=1\n9x=2`, 3, 0},           // a name does not start with a digit
		{`a=1&amp;b=2`, 3, 0},         // HTML entity
		{`a&b=2`, 1, 0},               // no assignment on the left
		{`/p?a=1&b=2`, 6, 0},          // URL query
		{`http://h/p#a=1&b=2`, 14, 0}, // URL
		{`&b=2`, 0, 0},                // nothing on the left
		{`a=1&b`, 3, 0},               // no '=' after the name
	} {
		if got := chainBoundary(tc.seg, 0, tc.i); got != tc.want {
			t.Errorf("chainBoundary(%q, 0, %d) = %d, want %d", tc.seg, tc.i, got, tc.want)
		}
	}
	if hasChainBoundary(`rows=10`) || !hasChainBoundary(`rows=10&page=1`) {
		t.Errorf("hasChainBoundary")
	}
}

// TestEnvDumpWithURLLineIsCutToo: a .env dump that holds a URL line
// (DATABASE_URL=postgres://...) contains "://", so the whole quoted value went
// to the URL handling before the chain was cut, and only the URL password was
// hidden (the lp_tool_result shape of leak-radar complaints 2026-10-04).
func TestEnvDumpWithURLLineIsCutToo(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	pw := "giM72rwT7VuBqAwQoeDZ"
	for _, in := range []string{
		`{"role": "tool", "content": "$ cat .env\nOPENAI_API_KEY=` + chainOpenAIKey + `\nDATABASE_URL=postgres://app:` + pw + `@db.internal:5432/app\nDEBUG=false\n"}`,
		`{"content":"DATABASE_URL=postgres://app:` + pw + `@db.internal:5432/app\nGITHUB_TOKEN=` + chainGitHubToken + `\nDEBUG=false"}`,
	} {
		out := ScanAndRedact(in)
		for _, secret := range []string{chainOpenAIKey, chainGitHubToken, pw} {
			if strings.Contains(in, secret) && strings.Contains(out, secret) {
				t.Errorf("secret passed through: %q", out)
			}
		}
		if !strings.Contains(out, "DEBUG=false") || !strings.Contains(out, "@db.internal:5432/app") {
			t.Errorf("neighbouring text lost: %q", out)
		}
		if !json.Valid([]byte(out)) {
			t.Errorf("JSON broken: %q", out)
		}
	}

	// A quoted URL with a query chain still goes to the URL handling as one.
	in := `msg="GET https://host/a?x=1&token=AbC123XyZ987qwerty&y=2 done"`
	if out := ScanAndRedact(in); strings.Contains(out, "AbC123XyZ987qwerty") || !strings.Contains(out, "?x=1&token=[HIDDEN:") || !strings.Contains(out, "&y=2 done") {
		t.Errorf("quoted URL: %q", out)
	}
}
