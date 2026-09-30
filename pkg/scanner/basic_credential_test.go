package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// basicLowScore is base64 of "lena:jr0XQgUiZRF3": a real-looking HTTP Basic
// credential whose body scores below the entropy threshold, so it passed
// whenever only the score decided (python-swat shape, 1 of 120 random runs).
const basicLowScore = "bGVuYTpqcjBYUWdVaVpSRjM="

// TestBasicCredentialRedacted: the value after the Basic auth scheme is hidden
// whatever its score, in the header shapes loggers and clients print, and
// its '=' padding no longer turns it into an unscored key half.
func TestBasicCredentialRedacted(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"Authorization: Basic " + basicLowScore,
		"authorization: basic " + basicLowScore,
		"Proxy-Authorization: Basic " + basicLowScore,
		"> Authorization: Basic " + basicLowScore,
		`curl -H "Authorization: Basic ` + basicLowScore + `" http://example.org/`,
		"Authorization: Basic " + basicLowScore + " user=bob",
		"Authorization: Basic dXNlcjpwYXNz",
		"Authorization: Basic Zm9vOmJhcg==",
		`{"authorization": "Basic ` + basicLowScore + `"}`,
		`{"authorization":"Basic ` + basicLowScore + `"}`,
		`{'authorization':'Basic ` + basicLowScore + `'}`,
		`headers={"Authorization":"Basic ` + basicLowScore + `"}`,
		"Authorization: Bearer " + basicLowScore,
	} {
		out := ScanAndRedact(in)
		leaked := !strings.Contains(out, "[HIDDEN")
		for _, body := range []string{strings.TrimRight(basicLowScore, "="), "dXNlcjpwYXNz", "Zm9vOmJhcg"} {
			leaked = leaked || strings.Contains(out, body)
		}
		if leaked {
			t.Errorf("credential leaked:\n in: %s\nout: %s", in, out)
		}
		if strings.Count(out, `"`) != strings.Count(in, `"`) || strings.Count(out, "'") != strings.Count(in, "'") {
			t.Errorf("quotes changed:\n in: %s\nout: %s", in, out)
		}
		if strings.Contains(out, "]=") {
			t.Errorf("padding left outside the marker:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestBasicWordInProseKept: "basic" is an auth scheme only right after an
// authorization key. As a word it keeps its neighbours, and a realm after
// WWW-Authenticate: Basic is not a credential.
func TestBasicWordInProseKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"basic internationalization support added",
		"the basic authentication_backend is configured",
		`WWW-Authenticate: Basic realm="restricted"`,
		"Authorization: Basic",
		"Authorization: Basic realm=x",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestCompactJSONPairWithEqualsInValue: a compact JSON pair whose quoted value
// holds an '=' is split as a colon pair, not at the '='. Before, the key half
// ran up to the '=' and the value under a sensitive key leaked, half leaked,
// or the token was cut at a space and the JSON broke.
func TestCompactJSONPairWithEqualsInValue(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	hidden := []struct{ in, secret string }{
		{`{"password":"hunter2=x"}`, "hunter2"},
		{`{"password":"a=b"}`, `"a=`},
		{`{"token":"abc def=1"}`, "abc"},
		{`{"a":"b","password":"x y=z"}`, "x y"},
		{`{"authorization":"Basic ` + basicLowScore + `"}`, strings.TrimRight(basicLowScore, "=")},
	}
	for _, c := range hidden {
		out := ScanAndRedact(c.in)
		if strings.Contains(out, c.secret) || !strings.Contains(out, "[HIDDEN") {
			t.Errorf("leaked:\n in: %s\nout: %s", c.in, out)
		}
		if !json.Valid([]byte(out)) {
			t.Errorf("output is not valid JSON:\n in: %s\nout: %s", c.in, out)
		}
	}

	for _, in := range []string{
		`{"k":"value=1"}`,
		`{"msg":"retry a=b now"}`,
		`{"url":"http://x/y?a=b"}`,
		`{"level":"info","msg":"ok"}`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed:\n in: %s\nout: %s", in, out)
		}
	}

	// The word-by-word scan of a quoted phrase (#253) still finds a secret
	// under a key that is not sensitive.
	in := `{"msg":"retry for ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa attempt=2"}`
	out := ScanAndRedact(in)
	if strings.Contains(out, "ghp_") || !strings.Contains(out, "attempt=2") || !json.Valid([]byte(out)) {
		t.Errorf("phrase scan regressed:\n in: %s\nout: %s", in, out)
	}
}
