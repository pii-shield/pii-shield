package server

import (
	"fmt"
	"strings"
	"testing"
)

func TestAuditLogRecordsChanges(t *testing.T) {
	value, srv := signedSetup(t)
	srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", body: `{"revision": 1, "author": "alice"}`})
	_, body, _ := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/tokens", body: `{"name": "staging"}`})
	tokenID := int(body["token"].(map[string]any)["id"].(float64))
	srv(call{method: "DELETE", path: fmt.Sprintf("/api/orgs/acme/sets/payments/tokens/%d", tokenID)})
	srv(call{method: "POST", path: "/api/orgs/acme/signing-keys", body: `{"name": "k", "publicKey": "ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="}`})
	// Refused: unsigned now that the organization has a key.
	srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", body: `{"revision": 2}`})

	code, body, raw := srv(call{method: "GET", path: "/api/orgs/acme/audit"})
	if code != 200 {
		t.Fatalf("audit: %d %s", code, raw)
	}
	var actions []string
	for _, e := range body["events"].([]any) {
		ev := e.(map[string]any)
		actions = append(actions, ev["action"].(string))
		if ev["actor"] != "admin token" {
			t.Errorf("actor of %v = %v", ev["action"], ev["actor"])
		}
	}
	want := "publish.refused key.add token.revoke token.create publish token.create version.create version.create set.create org.create"
	if got := strings.Join(actions, " "); got != want {
		t.Errorf("actions, newest first:\n got %s\nwant %s", got, want)
	}
	// No secret in the log: a token's value never, its prefix only.
	if strings.Contains(raw, value) || strings.Contains(raw, value[:20]) {
		t.Error("the audit log carries a token value")
	}
	if !strings.Contains(raw, `"reason": "unsigned"`) {
		t.Errorf("the refusal must say why: %s", raw)
	}

	// Paging.
	_, body, _ = srv(call{method: "GET", path: "/api/orgs/acme/audit?limit=4"})
	if len(body["events"].([]any)) != 4 || body["next"] == nil {
		t.Fatalf("page of 4: %v", body)
	}
	_, body, _ = srv(call{method: "GET", path: fmt.Sprintf("/api/orgs/acme/audit?limit=100&before=%d", int(body["next"].(float64)))})
	if len(body["events"].([]any)) != 6 || body["next"] != nil {
		t.Errorf("the rest: %v", body)
	}
	for _, q := range []string{"limit=0", "limit=x", "before=-1"} {
		if code, _, _ := srv(call{method: "GET", path: "/api/orgs/acme/audit?" + q}); code != 400 {
			t.Errorf("%s: %d", q, code)
		}
	}

	// A pull is not an event, but the token remembers it.
	srv(call{method: "GET", path: "/v1/acme/payments/policy.json", token: value})
	_, body, _ = srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/tokens"})
	first := body["tokens"].([]any)[0].(map[string]any)
	if first["lastUsedAt"] == nil || first["lastUsedIp"] != "127.0.0.1" {
		t.Errorf("token after a pull: %v", first)
	}
	_, body, _ = srv(call{method: "GET", path: "/api/orgs/acme/audit?limit=1"})
	if body["events"].([]any)[0].(map[string]any)["action"] != "publish.refused" {
		t.Error("a pull must not add an event")
	}
}

func TestAuditLogSessionsSeeTheirOwnOrganization(t *testing.T) {
	mails := &capture{}
	ts := newTestServer(t, Config{AdminToken: admin, Mailer: mails, BaseURL: "https://rules.example.test", Signup: true, InsecureCookies: true})
	u := tsURL{ts.URL}
	anna := signIn(t, u, mails, "anna@example.com")
	anna.do("POST", "/api/orgs/anna/sets", `{"slug": "payments"}`, nil)
	anna.do("POST", "/api/orgs/anna/members", `{"email": "ben@example.com"}`, nil)
	anna.do("POST", "/auth/logout", "", nil)
	eve := signIn(t, u, mails, "eve@example.com")

	anna = signIn(t, u, mails, "anna@example.com")
	code, _, body := anna.do("GET", "/api/orgs/anna/audit", "", nil)
	if code != 200 {
		t.Fatalf("audit: %d %s", code, body)
	}
	for _, want := range []string{`"action": "org.signup"`, `"action": "signin"`, `"action": "set.create"`, `"action": "member.invite"`, `"target": "ben@example.com"`, `"action": "signout"`, `"actor": "anna@example.com"`} {
		if !strings.Contains(body, want) {
			t.Errorf("anna's log lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "eve@example.com") {
		t.Error("anna's log shows another organization's sign-in")
	}
	if code, _, _ := eve.do("GET", "/api/orgs/anna/audit", "", nil); code != 404 {
		t.Errorf("eve reading anna's log: %d", code)
	}
}
