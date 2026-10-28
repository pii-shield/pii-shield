package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pii-shield/pii-shield/v2/pkg/scanner"
)

func TestValidateDraft(t *testing.T) {
	ts := newTestServer(t, Config{AdminToken: admin, PolicyRate: 1000})
	do(t, ts, call{method: "POST", path: "/api/orgs", token: admin, body: `{"slug": "acme"}`})
	do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets", token: admin, body: `{"slug": "payments"}`})
	base := "/api/orgs/acme/sets/payments"

	// The same refusal as a version create, nothing stored.
	code, _, body, _ := do(t, ts, call{method: "POST", path: base + "/validate", token: admin,
		body: `{"content": {"custom_regexes": [{"pattern": "("}]}}`})
	if code != 422 || !strings.Contains(body["error"].(string), "custom_regexes[0]") {
		t.Errorf("bad regex: %d %v", code, body)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: base + "/validate", token: admin, body: `{"content": {"salt": "x"}}`}); code != 422 {
		t.Errorf("salt: %d", code)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: base + "/validate", token: admin, body: `{}`}); code != 400 {
		t.Errorf("no content: %d", code)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: base + "/validate", token: admin, body: `{"content": {}}`}); code != 200 {
		t.Errorf("empty draft: %d", code)
	}
	code, _, body, raw := do(t, ts, call{method: "GET", path: base + "/versions", token: admin})
	if vs, _ := body["versions"].([]any); code != 200 || len(vs) != 0 {
		t.Errorf("validate stored a version: %d %s", code, raw)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/nope/validate", token: admin, body: `{"content": {}}`}); code != 404 {
		t.Errorf("missing set: %d", code)
	}

	// An accepted draft comes back with the effective settings: the defaults
	// the sidecar fills in, and the counts of what the draft spelled out.
	code, _, body, raw = do(t, ts, call{method: "POST", path: base + "/validate", token: admin,
		body: `{"content": {"sensitive_keys": ["geheim", "clave"], "custom_regexes": [{"name": "tx", "pattern": "^TX-\\d{6}$"}], "min_secret_length": 8}}`})
	if code != 200 {
		t.Fatalf("validate: %d %s", code, raw)
	}
	def := scanner.DefaultConfig()
	want := map[string]any{
		"ok": true, "entropyThreshold": def.EntropyThreshold, "confidenceThreshold": def.ConfidenceThreshold,
		"minSecretLength": float64(8), "sensitiveKeys": float64(2), "customRegexes": float64(1), "safeRegexes": float64(0),
		"sensitiveKeyPatterns": float64(0), "disableBigramCheck": false, "adaptiveThreshold": false, "entityTypeLabels": false,
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v", k, body[k], v)
		}
	}
	if body["bytes"].(float64) <= 0 {
		t.Errorf("bytes = %v", body["bytes"])
	}
}

func TestPreviewScansWithTheDraftOnAnIsolatedScanner(t *testing.T) {
	ts := newTestServer(t, Config{AdminToken: admin, PolicyRate: 1000})
	do(t, ts, call{method: "POST", path: "/api/orgs", token: admin, body: `{"slug": "acme"}`})
	do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets", token: admin, body: `{"slug": "payments"}`})
	base := "/api/orgs/acme/sets/payments"

	// "geheim" is a sensitive key only in the draft, and its value is too
	// plain for the entropy check: only the draft's rules redact it.
	const secretLine = "login ok geheim=abcabcabc user=anna"
	const plainLine = "GET /health 200"
	req := `{"content": {"sensitive_keys": ["geheim"], "custom_regexes": [{"name": "tx", "pattern": "^TX-\\d{6}$"}]},
	         "lines": ["` + secretLine + `", "` + plainLine + `", "charged TX-123456 for order 7"]}`
	code, _, _, raw := do(t, ts, call{method: "POST", path: base + "/preview", token: admin, body: req})
	if code != 200 {
		t.Fatalf("preview: %d %s", code, raw)
	}
	var resp previewResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Source != "draft" || resp.Revision != 0 || resp.Changed != 2 || len(resp.Lines) != 3 {
		t.Errorf("summary: %+v", resp)
	}
	if l := resp.Lines[0]; !l.Changed || l.In != secretLine || strings.Contains(l.Out, "abcabcabc") || !strings.Contains(l.Out, "[HIDDEN") || !strings.Contains(l.Out, "user=anna") {
		t.Errorf("secret line: %+v", l)
	}
	if l := resp.Lines[1]; l.Changed || l.Out != plainLine {
		t.Errorf("plain line: %+v", l)
	}
	if l := resp.Lines[2]; !l.Changed || strings.Contains(l.Out, "TX-123456") || !strings.Contains(l.Out, "order 7") {
		t.Errorf("regex line: %+v", l)
	}
	if !strings.Contains(resp.Note, "preview salt") {
		t.Errorf("note: %q", resp.Note)
	}
	// Same draft, same preview salt: the hashes are stable between calls.
	_, _, _, raw2 := do(t, ts, call{method: "POST", path: base + "/preview", token: admin, body: req})
	var resp2 previewResponse
	_ = json.Unmarshal([]byte(raw2), &resp2)
	if resp2.Lines[0].Out != resp.Lines[0].Out {
		t.Errorf("hashes differ between previews: %q vs %q", resp.Lines[0].Out, resp2.Lines[0].Out)
	}
	// The process-wide scanner never saw the draft.
	if got := scanner.ScanAndRedact(secretLine); got != secretLine {
		t.Errorf("preview leaked into the package-level configuration: %q", got)
	}
}

func TestPreviewInputsAndPublishedFallback(t *testing.T) {
	ts := newTestServer(t, Config{AdminToken: admin, PolicyRate: 1000})
	do(t, ts, call{method: "POST", path: "/api/orgs", token: admin, body: `{"slug": "acme"}`})
	do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets", token: admin, body: `{"slug": "payments"}`})
	base := "/api/orgs/acme/sets/payments"
	draft := `"content": {"sensitive_keys": ["geheim"]}`

	for name, body := range map[string]string{
		"no lines":     `{` + draft + `}`,
		"both":         `{` + draft + `, "lines": ["a"], "text": "a"}`,
		"too many":     `{` + draft + `, "lines": [` + strings.Repeat(`"x",`, MaxPreviewLines) + `"x"]}`,
		"content null": `{"content": null, "lines": ["a"]}`,
	} {
		code, _, b, _ := do(t, ts, call{method: "POST", path: base + "/preview", token: admin, body: body})
		want := 400
		if name == "content null" {
			want = 404 // nothing published yet
		}
		if code != want {
			t.Errorf("%s: %d %v, want %d", name, code, b, want)
		}
	}
	if code, _, _, _ := do(t, ts, call{method: "POST", path: base + "/preview", token: admin, body: `{"content": {"custom_regexes": [{"pattern": "("}]}, "lines": ["a"]}`}); code != 422 {
		t.Errorf("bad draft: %d", code)
	}

	// "text" is split into lines; a trailing newline adds no empty line.
	code, _, _, raw := do(t, ts, call{method: "POST", path: base + "/preview", token: admin,
		body: `{` + draft + `, "text": "geheim=abcabcabc\nplain\n"}`})
	var resp previewResponse
	_ = json.Unmarshal([]byte(raw), &resp)
	if code != 200 || len(resp.Lines) != 2 || !resp.Lines[0].Changed || resp.Lines[1].Changed || resp.Changed != 1 {
		t.Errorf("text input: %d %+v", code, resp)
	}
	// Exactly the limit is fine.
	code, _, _, _ = do(t, ts, call{method: "POST", path: base + "/preview", token: admin,
		body: `{` + draft + `, "lines": [` + strings.Repeat(`"x",`, MaxPreviewLines-1) + `"x"]}`})
	if code != 200 {
		t.Errorf("at the limit: %d", code)
	}

	// Without a draft the published version runs, and the response says
	// which revision.
	do(t, ts, call{method: "POST", path: base + "/versions", token: admin, body: `{` + draft + `}`})
	do(t, ts, call{method: "POST", path: base + "/publish", token: admin, body: `{"revision": 1}`})
	code, _, _, raw = do(t, ts, call{method: "POST", path: base + "/preview", token: admin, body: `{"lines": ["geheim=abcabcabc"]}`})
	_ = json.Unmarshal([]byte(raw), &resp)
	if code != 200 || resp.Source != "published" || resp.Revision != 1 || !resp.Lines[0].Changed {
		t.Errorf("published fallback: %d %+v", code, resp)
	}

	// A draft with adaptive_threshold runs with it off and says so.
	code, _, _, raw = do(t, ts, call{method: "POST", path: base + "/preview", token: admin,
		body: `{"content": {"adaptive_threshold": true}, "lines": ["a"]}`})
	_ = json.Unmarshal([]byte(raw), &resp)
	if code != 200 || !strings.Contains(resp.Note, "adaptive_threshold is off") {
		t.Errorf("adaptive note: %d %q", code, resp.Note)
	}
}
