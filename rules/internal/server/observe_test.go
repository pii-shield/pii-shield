package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/pii-shield/pii-shield/rules/internal/store"
	"github.com/pii-shield/pii-shield/rules/internal/storetest"
)

// lockedBuffer is a log sink the server's goroutines may share.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newLoggedServer(t *testing.T, accessLog bool) (*httptest.Server, *lockedBuffer) {
	t.Helper()
	st, err := store.Open(storetest.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	buf := &lockedBuffer{}
	s, err := New(context.Background(), st, Config{AdminToken: admin, PolicyRate: 1000, AccessLog: accessLog,
		Logger: slog.New(slog.NewJSONHandler(buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts, buf
}

func TestPullCountsAccessLogAndMetrics(t *testing.T) {
	ts, logs := newLoggedServer(t, true)
	srv := func(c call) (int, map[string]any, string) {
		if c.token == "" {
			c.token = admin
		}
		code, _, body, raw := do(t, ts, c)
		return code, body, raw
	}
	srv(call{method: "POST", path: "/api/orgs", body: `{"slug": "acme"}`})
	srv(call{method: "POST", path: "/api/orgs/acme/sets", body: `{"slug": "payments"}`})
	srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/versions", body: `{"content": {"sensitive_keys": ["geheim"]}}`})
	srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", body: `{"revision": 1}`})
	_, body, _ := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/tokens", body: `{"name": "prod"}`})
	value := body["value"].(string)

	// A new file, then an unchanged one.
	_, hdr, _, _ := do(t, ts, call{method: "GET", path: "/v1/acme/payments/policy.json", token: value})
	if code, _, _, _ := do(t, ts, call{method: "GET", path: "/v1/acme/payments/policy.json", token: value,
		headers: map[string]string{"If-None-Match": hdr.Get("ETag")}}); code != 304 {
		t.Fatalf("conditional pull: %d", code)
	}
	// A refused pull is not counted.
	do(t, ts, call{method: "GET", path: "/v1/acme/payments/policy.json", token: "psr_wrong"})

	_, body, _ = srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/tokens"})
	tok := body["tokens"].([]any)[0].(map[string]any)
	if tok["pullsToday"] != float64(2) || tok["pullsWeek"] != float64(2) {
		t.Errorf("token pull counts: %v", tok)
	}
	code, body, raw := srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/pulls?days=7"})
	if code != 200 || !strings.Contains(raw, `"pulls": 2`) || !strings.Contains(raw, `"notModified": 1`) || body["days"] != float64(7) {
		t.Errorf("pulls: %d %s", code, raw)
	}
	for _, q := range []string{"days=0", "days=91", "days=x"} {
		if code, _, _ := srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/pulls?" + q}); code != 400 {
			t.Errorf("%s: %d", q, code)
		}
	}
	do(t, ts, call{method: "GET", path: "/healthz"})

	// The access log: one line per request with the route and the token
	// prefix or the caller, never a token value; health checks are not logged.
	out := logs.String()
	if strings.Contains(out, value) || strings.Contains(out, admin) {
		t.Fatal("the access log carries a token value")
	}
	for _, want := range []string{
		`"route":"GET /v1/{org}/{set}/policy.json","status":200`,
		`"route":"GET /v1/{org}/{set}/policy.json","status":304`,
		`"status":401`,
		`"token":"` + value[:12] + `"`,
		`"actor":"admin token"`,
		`"route":"POST /api/orgs/{org}/sets/{set}/publish"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("access log lacks %s", want)
		}
	}
	if strings.Contains(out, `"path":"/healthz"`) {
		t.Error("health checks must not be logged")
	}

	// The metrics.
	m := httptest.NewServer(MetricsHandler())
	defer m.Close()
	resp, err := http.Get(m.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	metrics := string(b)
	for _, want := range []string{
		`piishield_rules_requests_total{code="304",route="GET /v1/{org}/{set}/policy.json"}`,
		`piishield_rules_requests_total{code="200",route="GET /healthz"}`,
		`piishield_rules_policy_pulls_total{result="new"}`,
		`piishield_rules_policy_pulls_total{result="not_modified"}`,
		`piishield_rules_request_duration_seconds_bucket{route="GET /v1/{org}/{set}/policy.json"`,
		`go_goroutines`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	if strings.Contains(metrics, value[:12]) || strings.Contains(metrics, "acme") {
		t.Error("metrics must carry route patterns, not tokens or names")
	}
}

func TestAccessLogOff(t *testing.T) {
	ts, logs := newLoggedServer(t, false)
	do(t, ts, call{method: "GET", path: "/api/orgs", token: admin})
	do(t, ts, call{method: "GET", path: "/nothing-here"})
	if strings.Contains(logs.String(), `"msg":"request"`) {
		t.Errorf("access log written while off: %s", logs.String())
	}
}
