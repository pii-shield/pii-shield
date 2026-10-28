package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pii-shield/pii-shield/rules/internal/store"
)

const admin = "admin-secret"

func newTestServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(context.Background(), st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts
}

type call struct {
	method, path, token, body string
	headers                   map[string]string
}

func do(t *testing.T, ts *httptest.Server, c call) (int, http.Header, map[string]any, string) {
	t.Helper()
	req, _ := http.NewRequest(c.method, ts.URL+c.path, strings.NewReader(c.body))
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, resp.Header, body, string(raw)
}

func TestManagementAPIRequiresAdminToken(t *testing.T) {
	ts := newTestServer(t, Config{AdminToken: admin})
	for _, tok := range []string{"", "wrong"} {
		if code, _, _, _ := do(t, ts, call{method: "GET", path: "/api/orgs", token: tok}); code != 401 {
			t.Errorf("token %q: %d, want 401", tok, code)
		}
	}
	if code, _, _, _ := do(t, ts, call{method: "GET", path: "/api/orgs", token: admin}); code != 200 {
		t.Errorf("admin token: %d", code)
	}
	// No admin token and not single-tenant: nothing gets through.
	closed := newTestServer(t, Config{})
	if code, _, _, _ := do(t, closed, call{method: "GET", path: "/api/orgs"}); code != 401 {
		t.Errorf("no admin token configured: %d, want 401", code)
	}
	// Single-tenant: the default org exists and the API is open.
	open := newTestServer(t, Config{SingleTenant: true})
	code, _, body, _ := do(t, open, call{method: "GET", path: "/api/orgs"})
	if code != 200 || !strings.Contains(fmtAny(body["orgs"]), `default`) {
		t.Errorf("single-tenant orgs: %d %v", code, body)
	}
}

func fmtAny(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestPublishFlowAndPolicyPull(t *testing.T) {
	ts := newTestServer(t, Config{AdminToken: admin, PolicyRate: 1000})

	code, _, _, raw := do(t, ts, call{method: "POST", path: "/api/orgs", token: admin, body: `{"slug": "acme", "name": "ACME"}`})
	if code != 201 {
		t.Fatalf("create org: %d %s", code, raw)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: "/api/orgs", token: admin, body: `{"slug": "acme"}`}); code != 409 {
		t.Errorf("duplicate org: %d", code)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: "/api/orgs", token: admin, body: `{"slug": "Bad Slug"}`}); code != 400 {
		t.Errorf("bad slug: %d", code)
	}
	if code, _, _, raw = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets", token: admin, body: `{"slug": "payments"}`}); code != 201 {
		t.Fatalf("create set: %d %s", code, raw)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: "/api/orgs/nope/sets", token: admin, body: `{"slug": "x"}`}); code != 404 {
		t.Errorf("set in a missing org: %d", code)
	}

	// A bad rule set is refused with the scanner's reason; nothing is stored.
	code, _, body, _ := do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/payments/versions", token: admin,
		body: `{"content": {"custom_regexes": [{"pattern": "("}]}}`})
	if code != 422 || !strings.Contains(body["error"].(string), "custom_regexes[0]") {
		t.Errorf("bad rules: %d %v", code, body)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/payments/versions", token: admin, body: `{"comment": "no content"}`}); code != 400 {
		t.Errorf("missing content: %d", code)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/payments/versions", token: admin, body: `{"content": {"salt": "x"}}`}); code != 422 {
		t.Errorf("salt in rules: %d", code)
	}

	code, _, body, raw = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/payments/versions", token: admin,
		body: `{"content": {"sensitive_keys": ["geheim"], "entropy_threshold": 4.1}, "author": "alice", "comment": "first"}`})
	if code != 201 || body["revision"] != float64(1) {
		t.Fatalf("create version: %d %s", code, raw)
	}
	etag1 := body["etag"].(string)
	code, _, body, _ = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/payments/versions", token: admin,
		body: `{"content": {"sensitive_keys": ["geheim", "clave"]}, "author": "bob"}`})
	if code != 201 || body["revision"] != float64(2) {
		t.Fatalf("create version 2: %d %v", code, body)
	}
	etag2 := body["etag"].(string)

	// A token for the cluster: the value is shown once.
	code, _, body, _ = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/payments/tokens", token: admin, body: `{"name": "prod"}`})
	if code != 201 {
		t.Fatalf("create token: %d %v", code, body)
	}
	value := body["value"].(string)
	tokenID := int(body["token"].(map[string]any)["id"].(float64))
	if !strings.HasPrefix(value, store.TokenPrefix) {
		t.Errorf("token value %q", value)
	}
	if code, _, _, raw = do(t, ts, call{method: "GET", path: "/api/orgs/acme/sets/payments/tokens", token: admin}); code != 200 || strings.Contains(raw, value) {
		t.Errorf("token list must not carry the value: %d %s", code, raw)
	}

	// Nothing published yet.
	pull := call{method: "GET", path: "/v1/acme/payments/policy.json", token: value}
	if code, _, body, _ = do(t, ts, pull); code != 404 || !strings.Contains(body["error"].(string), "no published") {
		t.Errorf("unpublished: %d %v", code, body)
	}

	// Publish 2, pull it.
	if code, _, body, _ = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", token: admin, body: `{"revision": 2, "author": "alice"}`}); code != 200 || body["publishedRevision"] != float64(2) {
		t.Fatalf("publish: %d %v", code, body)
	}
	code, h, body, raw := do(t, ts, pull)
	if code != 200 || h.Get("ETag") != etag2 || h.Get("Cache-Control") != "no-cache" || h.Get("Content-Type") != "application/json" || h.Get("X-Policy-Revision") != "2" {
		t.Fatalf("pull: %d headers %v", code, h)
	}
	if body["revision"] != "2" || !strings.Contains(raw, `"clave"`) || strings.Contains(raw, "etag") {
		t.Errorf("pulled body: %s", raw)
	}
	// 304 on the ETag, strong, weak or in a list.
	for _, inm := range []string{etag2, "W/" + etag2, `"other", ` + etag2, "*"} {
		if code, h, _, raw = do(t, ts, call{method: "GET", path: pull.path, token: value, headers: map[string]string{"If-None-Match": inm}}); code != 304 || raw != "" || h.Get("ETag") != etag2 {
			t.Errorf("If-None-Match %q: %d %q", inm, code, raw)
		}
	}
	if code, _, _, _ = do(t, ts, call{method: "GET", path: pull.path, token: value, headers: map[string]string{"If-None-Match": etag1}}); code != 200 {
		t.Errorf("stale ETag must get the body: %d", code)
	}

	// Rollback: publish 1 again; the ETag changes back.
	if code, _, _, _ = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", token: admin, body: `{"revision": 1}`}); code != 200 {
		t.Fatalf("rollback: %d", code)
	}
	if code, h, _, raw = do(t, ts, pull); code != 200 || h.Get("ETag") != etag1 || strings.Contains(raw, "clave") {
		t.Errorf("after rollback: %d %s %s", code, h.Get("ETag"), raw)
	}
	if code, _, _, _ = do(t, ts, call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", token: admin, body: `{"revision": 9}`}); code != 404 {
		t.Errorf("publish a missing revision: %d", code)
	}
	code, _, body, _ = do(t, ts, call{method: "GET", path: "/api/orgs/acme/sets/payments/publications", token: admin})
	if code != 200 || len(body["publications"].([]any)) != 2 {
		t.Errorf("publications: %d %v", code, body)
	}
	code, _, body, _ = do(t, ts, call{method: "GET", path: "/api/orgs/acme/sets/payments", token: admin})
	if code != 200 || body["policyPath"] != "/v1/acme/payments/policy.json" || len(body["versions"].([]any)) != 2 {
		t.Errorf("get set: %d %v", code, body)
	}
	if code, _, body, _ = do(t, ts, call{method: "GET", path: "/api/orgs/acme/sets/payments/versions/2", token: admin}); code != 200 || body["author"] != "bob" {
		t.Errorf("get version: %d %v", code, body)
	}

	// Token problems: 401 without detail; a token on another set's path: 404.
	for name, c := range map[string]call{
		"no token":    {method: "GET", path: pull.path},
		"bad scheme":  {method: "GET", path: pull.path, headers: map[string]string{"Authorization": "Basic abc"}},
		"unknown":     {method: "GET", path: pull.path, token: "psr_unknown"},
		"admin token": {method: "GET", path: pull.path, token: admin},
	} {
		if code, h, _, _ := do(t, ts, c); code != 401 || !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _, _, _ = do(t, ts, call{method: "GET", path: "/v1/acme/other/policy.json", token: value}); code != 404 {
		t.Errorf("token on another set: %d", code)
	}
	if code, _, _, _ = do(t, ts, call{method: "GET", path: "/v1/evil/payments/policy.json", token: value}); code != 404 {
		t.Errorf("token on another org: %d", code)
	}

	// Revoked: 401 from then on; revoking is idempotent.
	if code, _, _, _ = do(t, ts, call{method: "DELETE", path: "/api/orgs/acme/sets/payments/tokens/" + itoa(tokenID), token: admin}); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _, _, _ = do(t, ts, pull); code != 401 {
		t.Errorf("revoked token: %d", code)
	}
	if code, _, _, _ = do(t, ts, call{method: "DELETE", path: "/api/orgs/acme/sets/payments/tokens/999", token: admin}); code != 404 {
		t.Errorf("revoke a missing token: %d", code)
	}
}

func TestPolicyPullIsRateLimitedPerToken(t *testing.T) {
	ts := newTestServer(t, Config{SingleTenant: true, PolicyRate: 0.001})
	do(t, ts, call{method: "POST", path: "/api/orgs/default/sets", body: `{"slug": "s"}`})
	do(t, ts, call{method: "POST", path: "/api/orgs/default/sets/s/versions", body: `{"content": {}}`})
	do(t, ts, call{method: "POST", path: "/api/orgs/default/sets/s/publish", body: `{"revision": 1}`})
	_, _, body, _ := do(t, ts, call{method: "POST", path: "/api/orgs/default/sets/s/tokens", body: `{"name": "a"}`})
	a := body["value"].(string)
	_, _, body, _ = do(t, ts, call{method: "POST", path: "/api/orgs/default/sets/s/tokens", body: `{"name": "b"}`})
	b := body["value"].(string)

	pull := func(tok string) int {
		code, _, _, _ := do(t, ts, call{method: "GET", path: "/v1/default/s/policy.json", token: tok})
		return code
	}
	for i := 0; i < 10; i++ {
		if code := pull(a); code != 200 {
			t.Fatalf("pull %d with the burst: %d", i, code)
		}
	}
	if code := pull(a); code != 429 {
		t.Errorf("eleventh pull: %d, want 429", code)
	}
	if code := pull(b); code != 200 {
		t.Errorf("another token has its own bucket: %d", code)
	}
}

func TestBodyLimitAndHealth(t *testing.T) {
	ts := newTestServer(t, Config{SingleTenant: true})
	huge := `{"content": {"sensitive_keys": ["` + strings.Repeat("k", maxBody) + `"]}}`
	do(t, ts, call{method: "POST", path: "/api/orgs/default/sets", body: `{"slug": "s"}`})
	if code, _, _, _ := do(t, ts, call{method: "POST", path: "/api/orgs/default/sets/s/versions", body: huge}); code != 413 {
		t.Errorf("huge body: %d, want 413", code)
	}
	if code, _, _, raw := do(t, ts, call{method: "GET", path: "/healthz"}); code != 200 || raw != "ok\n" {
		t.Errorf("healthz: %d %q", code, raw)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
