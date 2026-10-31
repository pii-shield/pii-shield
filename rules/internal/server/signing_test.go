package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/pii-shield/pii-shield/rules/internal/signing"
)

// signedSetup creates acme/payments with two versions and a pull token.
func signedSetup(t *testing.T) (value string, srv func(call) (int, map[string]any, string)) {
	t.Helper()
	s := newTestServer(t, Config{AdminToken: admin, PolicyRate: 1000})
	srv = func(c call) (int, map[string]any, string) {
		if c.token == "" {
			c.token = admin
		}
		code, _, body, raw := do(t, s, c)
		return code, body, raw
	}
	srv(call{method: "POST", path: "/api/orgs", body: `{"slug": "acme"}`})
	srv(call{method: "POST", path: "/api/orgs/acme/sets", body: `{"slug": "payments"}`})
	srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/versions", body: `{"content": {"sensitive_keys": ["geheim"]}}`})
	srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/versions", body: `{"content": {"sensitive_keys": ["geheim", "clave"]}}`})
	_, body, _ := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/tokens", body: `{"name": "prod"}`})
	return body["value"].(string), srv
}

func TestSignedPublish(t *testing.T) {
	value, srv := signedSetup(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyText := signing.FormatPublicKey(pub)
	keyID := signing.KeyID(pub)

	// Before any key, an unsigned publish works and the .sig is 404.
	if code, _, raw := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", body: `{"revision": 1}`}); code != 200 {
		t.Fatalf("unsigned publish without keys: %d %s", code, raw)
	}
	sigPull := call{method: "GET", path: "/v1/acme/payments/policy.json.sig", token: value}
	if code, body, _ := srv(sigPull); code != 404 || !strings.Contains(body["error"].(string), "not signed") {
		t.Errorf("unsigned .sig: %d %v", code, body)
	}

	// Register the key; a bad key and a nameless one are refused.
	if code, _, _ := srv(call{method: "POST", path: "/api/orgs/acme/signing-keys", body: `{"name": "x", "publicKey": "ed25519:AAAA"}`}); code != 400 {
		t.Errorf("bad key: %d", code)
	}
	if code, _, _ := srv(call{method: "POST", path: "/api/orgs/acme/signing-keys", body: fmt.Sprintf(`{"publicKey": %q}`, keyText)}); code != 400 {
		t.Errorf("nameless key: %d", code)
	}
	code, body, raw := srv(call{method: "POST", path: "/api/orgs/acme/signing-keys", body: fmt.Sprintf(`{"name": "alice laptop", "publicKey": %q}`, keyText)})
	if code != 201 || body["keyId"] != keyID {
		t.Fatalf("add key: %d %s", code, raw)
	}
	keyRowID := int(body["id"].(float64))

	// Now an unsigned publish is refused.
	if code, body, _ := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", body: `{"revision": 2}`}); code != 422 || !strings.Contains(body["error"].(string), "signs its publications") {
		t.Errorf("unsigned publish with a key: %d %v", code, body)
	}

	// The statement for revision 2 is publication 2.
	code, body, raw = srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/publish/statement?revision=2"})
	if code != 200 {
		t.Fatalf("statement: %d %s", code, raw)
	}
	text := body["text"].(string)
	if !strings.Contains(text, "set: acme/payments\npublication: 2\nrevision: 2\n") {
		t.Errorf("statement text %q", text)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(text)))
	publish := func(pubN int, sig string) (int, map[string]any) {
		code, body, _ := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish",
			body: fmt.Sprintf(`{"revision": 2, "publication": %d, "keyId": %q, "signature": %q}`, pubN, keyID, sig)})
		return code, body
	}

	// A signature of something else, a wrong number, half a signature: refused.
	other := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(strings.Replace(text, "revision: 2", "revision: 1", 1))))
	if code, body := publish(2, other); code != 422 || !strings.Contains(body["error"].(string), "does not verify") {
		t.Errorf("wrong signature: %d %v", code, body)
	}
	if code, _ := publish(5, sig); code != 409 {
		t.Errorf("wrong publication number: %d", code)
	}
	if code, _, _ := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", body: `{"revision": 2, "signature": "x"}`}); code != 400 {
		t.Errorf("half a signature: %d", code)
	}
	if code, body := publish(2, sig); code != 200 || body["publishedRevision"] != float64(2) {
		t.Fatalf("signed publish: %d %v", code, body)
	}
	// The same signature cannot be used twice: the number has moved on.
	if code, _ := publish(2, sig); code != 409 {
		t.Errorf("replayed signature: %d", code)
	}

	// The cluster gets the statement and the signature, and they verify
	// against the file it pulls.
	code, body, raw = srv(sigPull)
	if code != 200 || body["keyId"] != keyID || body["publication"] != float64(2) || body["signature"] != sig {
		t.Fatalf(".sig: %d %s", code, raw)
	}
	_, _, content := srv(call{method: "GET", path: "/v1/acme/payments/policy.json", token: value})
	st := signing.For("acme/payments", 2, 2, []byte(content))
	if st.SHA256 != body["sha256"] {
		t.Errorf("sha256 in .sig %v, of the served file %s", body["sha256"], st.SHA256)
	}
	if err := signing.Verify(pub, st, sig); err != nil {
		t.Errorf("the served signature does not verify: %v", err)
	}
	// The .sig takes the same token rules as the file.
	if code, _, _ := srv(call{method: "GET", path: "/v1/acme/payments/policy.json.sig", token: "psr_wrong"}); code != 401 {
		t.Errorf(".sig with a wrong token: %d", code)
	}

	// The publish history names the key.
	_, _, raw = srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/publications"})
	if !strings.Contains(raw, keyID) {
		t.Errorf("history without the key id: %s", raw)
	}

	// A revoked key cannot sign; with no key left, unsigned works again.
	if code, _, _ := srv(call{method: "DELETE", path: fmt.Sprintf("/api/orgs/acme/signing-keys/%d", keyRowID)}); code != 204 {
		t.Errorf("revoke key: %d", code)
	}
	_, body, _ = srv(call{method: "GET", path: "/api/orgs/acme/sets/payments/publish/statement?revision=1"})
	sig3 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(body["text"].(string))))
	code, body, _ = srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish",
		body: fmt.Sprintf(`{"revision": 1, "publication": 3, "keyId": %q, "signature": %q}`, keyID, sig3)})
	if code != 422 || !strings.Contains(body["error"].(string), "no active signing key") {
		t.Errorf("revoked key: %d %v", code, body)
	}
	if code, _, _ := srv(call{method: "POST", path: "/api/orgs/acme/sets/payments/publish", body: `{"revision": 1}`}); code != 200 {
		t.Errorf("unsigned after the last key is revoked: %d", code)
	}
}
