package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestQuotedURLKeepsClosingQuote covers a quoted URL whose last query value
// is hidden. Only a bare quote at the very end of the token was peeled off, so
// `\"` lost its backslash and `":` was hashed together with the value. In
// compact JSON the lost backslash ended the string early: 0 of 20 lines stayed
// valid JSON in three shapes on 2.2.6. A Go url.Error lost the closing quote
// and the colon in 20 of 20 lines.
func TestQuotedURLKeepsClosingQuote(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	const key = "gGMLNl0ybuRbNtGyGEITSzCY"
	const url = "https://tiles.example.com/7/31/44.png?key="

	// The marker the key gets on its own. Every shape below must give the same
	// one: nothing but the value may go into the hash.
	marker := strings.TrimPrefix(ScanAndRedact(url+key), url)
	if !isRedacted(marker) {
		t.Fatalf("key not hidden in a bare URL: %q", marker)
	}

	cases := []struct {
		name   string
		in     string
		isJSON bool
	}{
		{"Go url.Error", `Get "` + url + key + `": dial tcp 10.0.3.7:443: connect: connection refused`, false},
		{"slog text, url.Error", `time=2026-10-05T01:14:18.311Z level=WARN msg="Get \"` + url + key + `\": dial tcp 10.0.3.7:443: connect: connection refused" layer=main`, false},
		{"slog text, quote before a word", `level=WARN msg="fetch \"` + url + key + `\" failed"`, false},
		{"compact JSON, url.Error", `{"level":"ERROR","msg":"provider error","err":"Get \"` + url + key + `\": dial tcp 10.0.3.7:443: connect: connection refused"}`, true},
		{"compact JSON, quote before a word", `{"level":"WARN","msg":"fetch \"` + url + key + `\" failed"}`, true},
		{"compact JSON, quote ends the string", `{"level":"WARN","msg":"fetch failed for \"` + url + key + `\""}`, true},
		{"compact JSON, more fields after", `{"level":"WARN","msg":"fetch failed for \"` + url + key + `\"","layer":"main"}`, true},
		{"compact JSON, quote and comma", `{"level":"WARN","msg":"tried \"` + url + key + `\", gave up"}`, true},
		{"spaced JSON", `{"level": "WARN", "msg": "fetch \"` + url + key + `\" failed"}`, true},
		{"plain quote before a word", `fetch "` + url + key + `" failed`, false},
		{"single quotes and a colon", `fetch '` + url + key + `': timeout`, false},
		{"escaped backslash, then a plain quote", `open "` + url + key + `&dir=C:\\" failed`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := ScanAndRedact(c.in)
			if want := strings.Replace(c.in, key, marker, 1); out != want {
				t.Errorf("only the key may change:\n  in=%s\n out=%s\nwant=%s", c.in, out, want)
			}
			if c.isJSON && !json.Valid([]byte(out)) {
				t.Errorf("output is not valid JSON: %s", out)
			}
		})
	}

	// Nothing here is a secret, so each line comes back byte for byte.
	unchanged := []string{
		`Get "https://tiles.example.com/7/31/44.png?page=2": dial tcp 10.0.3.7:443: connect: connection refused`,
		`{"level":"WARN","msg":"fetch \"https://tiles.example.com/7/31/44.png?page=2\" failed"}`,
		`level=WARN msg="Get \"https://tiles.example.com/7/31/44.png\": dial tcp 10.0.3.7:443" layer=main`,
	}
	for _, in := range unchanged {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("benign line changed:\n in=%s\nout=%s", in, out)
		}
	}

	// An unencoded quote inside the query is not the end of the URL: the
	// parameters after it are still scored.
	in := `GET /search?q="blue"&token=AbC123XyZ987qwerty`
	out := ScanAndRedact(in)
	if strings.Contains(out, "AbC123XyZ987qwerty") || !strings.Contains(out, "token=[HIDDEN") {
		t.Errorf("secret after a quote inside the query not hidden: %s", out)
	}
}

func TestURLClosingTail(t *testing.T) {
	cases := []struct {
		url  string
		tail string
	}{
		{`"https://h/a?k=v"`, `"`},
		{`'https://h/a?k=v'`, `'`},
		{`\"https://h/a?k=v\"`, `\"`},
		{`"https://h/a?k=v":`, `":`},
		{`\"https://h/a?k=v\":`, `\":`},
		{`\"https://h/a?k=v\",`, `\",`},
		{`"https://h/a?k=v").`, `").`},
		{`"https://h/a?k=v\\"`, `"`},
		{`"https://h/a?k=v\\\"`, `\"`},
		// No closing quote after the query: nothing to peel.
		{`https://h/a?k=v`, ``},
		{`"https://h/a?k=v`, ``},
		{`https://h/a?k=v:`, ``},
		{`"quoted"/a?k=v`, ``},
		// A quote followed by more query text is part of the query.
		{`/s?q="a"&token=x`, ``},
		{`/s?name=O'Brien`, ``},
	}
	for _, c := range cases {
		if got := c.url[urlClosingTail(c.url):]; got != c.tail {
			t.Errorf("urlClosingTail(%s): tail %q, want %q", c.url, got, c.tail)
		}
	}
}
