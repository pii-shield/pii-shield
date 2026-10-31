package server

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func reportJSON(cluster string, lines, entropy int, revision string, publication int) string {
	from := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	to := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf(`{"schema": "pii-shield-stats-v1", "cluster": %q, "policy": "apps/central", "from": %q, "to": %q, "mode": "redact",
		"podsReporting": 2, "podsTotal": 3, "revisions": {%q: 2}, "remote": {"revision": "2", "publication": %d, "signedBy": "abcd"},
		"lines": %d, "errors": 0, "redactions": {"entropy": %d, "regex": 1}}`, cluster, from, to, revision, publication, lines, entropy)
}

func TestStatsReports(t *testing.T) {
	pullToken, srv := signedSetup(t)
	srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", body: `{"revision": 2}`})

	if code, _, _ := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/tokens", body: `{"name": "x", "kind": "write"}`}); code != 400 {
		t.Errorf("unknown kind: %d", code)
	}
	code, body, raw := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/tokens", body: `{"name": "prod-eu stats", "kind": "report"}`})
	if code != 201 || !strings.HasPrefix(body["value"].(string), "pss_") || !strings.Contains(body["note"].(string), "stats.headerSecretRef") {
		t.Fatalf("report token: %d %s", code, raw)
	}
	reportToken := body["value"].(string)
	post := func(token, body string) (int, map[string]any) {
		code, b, _ := srv(call{method: "POST", path: "/v1/acme/payments/report", token: token, body: body})
		return code, b
	}

	// Each token does its own job only.
	if code, b := post(pullToken, reportJSON("prod-eu", 10, 1, "2+1", 2)); code != 403 || !strings.Contains(b["error"].(string), "cannot send") {
		t.Errorf("pull token sending a report: %d %v", code, b)
	}
	for _, p := range []string{"/v1/acme/payments/policy.json", "/v1/acme/payments/policy.json.sig"} {
		if code, b, _ := srv(call{method: "GET", path: p, token: reportToken}); code != 403 || !strings.Contains(b["error"].(string), "cannot read rules") {
			t.Errorf("report token reading %s: %d %v", p, code, b)
		}
	}
	if code, _ := post("pss_wrong", reportJSON("prod-eu", 1, 1, "2+1", 2)); code != 401 {
		t.Errorf("unknown token: %d", code)
	}

	// Bad reports are refused whole.
	for name, b := range map[string]string{
		"schema":   strings.Replace(reportJSON("c", 1, 1, "2+1", 2), "pii-shield-stats-v1", "v0", 1),
		"negative": strings.Replace(reportJSON("c", 1, 1, "2+1", 2), `"lines": 1`, `"lines": -1`, 1),
		"mode":     strings.Replace(reportJSON("c", 1, 1, "2+1", 2), `"redact"`, `"spy"`, 1),
		"pods":     strings.Replace(reportJSON("c", 1, 1, "2+1", 2), `"podsTotal": 3`, `"podsTotal": 1`, 1),
		"cluster":  reportJSON(strings.Repeat("x", 200), 1, 1, "2+1", 2),
	} {
		if code, _ := post(reportToken, b); code != 422 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := post(reportToken, `{"schema": "pii-shield-stats-v1", "pad": "`+strings.Repeat("a", 70<<10)+`"}`); code != 413 {
		t.Errorf("oversized report: %d", code)
	}

	// Two clusters on one token, three reports.
	for _, b := range []string{reportJSON("prod-eu", 100, 10, "2+1", 2), reportJSON("prod-eu", 50, 5, "2+1", 2), reportJSON("prod-us", 7, 0, "1+1", 1)} {
		if code, r := post(reportToken, b); code != 204 {
			t.Fatalf("report: %d %v", code, r)
		}
	}
	code, body, raw = srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/clusters"})
	if code != 200 || body["publishedRevision"] != float64(2) || body["publication"] != float64(1) {
		t.Fatalf("clusters: %d %s", code, raw)
	}
	clusters := body["clusters"].([]any)
	if len(clusters) != 2 {
		t.Fatalf("clusters = %s", raw)
	}
	byName := map[string]map[string]any{}
	for _, c := range clusters {
		m := c.(map[string]any)
		byName[m["cluster"].(string)] = m
	}
	eu, us := byName["prod-eu"], byName["prod-us"]
	if eu["reports"] != float64(2) || eu["lines"] != float64(150) || eu["redactions"].(map[string]any)["entropy"] != float64(15) || eu["tokenName"] != "prod-eu stats" {
		t.Errorf("prod-eu = %v", eu)
	}
	latest := us["latest"].(map[string]any)
	if latest["remotePublication"] != float64(1) || latest["revisions"].(map[string]any)["1+1"] != float64(2) || latest["podsTotal"] != float64(3) {
		t.Errorf("prod-us latest = %v", latest)
	}
	if code, _, _ := srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/clusters?hours=0"}); code != 400 {
		t.Errorf("hours=0: %d", code)
	}

	// Reports are not audit events, but the token remembers its last use.
	_, body, _ = srv(call{method: "GET", path: "/api/orgs/acme/audit?limit=1"})
	if a := body["events"].([]any)[0].(map[string]any)["action"]; a != "token.create" {
		t.Errorf("latest audit event = %v, want the token creation", a)
	}
	_, _, raw = srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/tokens"})
	if !strings.Contains(raw, `"kind": "report"`) || !strings.Contains(raw, `"lastUsedIp": "127.0.0.1"`) {
		t.Errorf("tokens: %s", raw)
	}
}
