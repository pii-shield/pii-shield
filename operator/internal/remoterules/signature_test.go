package remoterules

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignatureURLAndExpectedSet(t *testing.T) {
	for _, tc := range []struct{ in, explicit, want string }{
		{"https://rules.example.com/v1/acme/payments/policy.json", "", "https://rules.example.com/v1/acme/payments/policy.json.sig"},
		{"https://bucket.example.com/rules/policy.json?x=1", "", "https://bucket.example.com/rules/policy.json.sig?x=1"},
		{"https://bucket.example.com/policy.json", "https://elsewhere.example.com/p.sig", "https://elsewhere.example.com/p.sig"},
	} {
		if got, err := SignatureURL(tc.in, tc.explicit); err != nil || got != tc.want {
			t.Errorf("SignatureURL(%q, %q) = %q, %v; want %q", tc.in, tc.explicit, got, err, tc.want)
		}
	}
	if got, err := ExpectedSet("https://rules.example.com/v1/acme/payments/policy.json", ""); err != nil || got != "acme/payments" {
		t.Errorf("ExpectedSet from a rule server URL = %q, %v", got, err)
	}
	if got, err := ExpectedSet("https://proxy.example.com/rules/v1/acme/payments/policy.json", ""); err != nil || got != "acme/payments" {
		t.Errorf("ExpectedSet behind a path prefix = %q, %v", got, err)
	}
	if _, err := ExpectedSet("https://bucket.example.com/policy.json", ""); err == nil {
		t.Error("a URL without /v1/<org>/<set>/ needs an explicit set")
	}
	if got, _ := ExpectedSet("https://bucket.example.com/policy.json", "team/prod"); got != "team/prod" {
		t.Errorf("explicit set = %q", got)
	}
}

func TestParseTrustedKeys(t *testing.T) {
	if _, err := ParseTrustedKeys(nil); err == nil {
		t.Error("an empty list must be refused")
	}
	for _, bad := range []string{"AAAA", "ed25519:!!", "ed25519:AAAA"} {
		if _, err := ParseTrustedKeys([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	keys, err := ParseTrustedKeys([]string{" ed25519:" + "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" + " "})
	if err != nil || len(keys) != 1 || len(keys[0].ID) != 16 {
		t.Errorf("good key: %+v %v", keys, err)
	}
}

const testSet = "acme/payments"

func signedFile(t *testing.T, priv ed25519.PrivateKey, set string, publication, revision int64, body []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(body)
	text := fmt.Sprintf("%s\nset: %s\npublication: %d\nrevision: %d\nsha256: %s\n", statementHeader, set, publication, revision, hex.EncodeToString(sum[:]))
	out, _ := json.Marshal(SignatureFile{Set: set, Publication: publication, Revision: revision, SHA256: hex.EncodeToString(sum[:]),
		KeyID: KeyID(priv.Public().(ed25519.PublicKey)), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(text)))})
	return out
}

func TestCheck(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	keys := []TrustedKey{{ID: KeyID(pub), Key: pub}}
	body := []byte(`{"revision":"3"}`)
	reason := func(err error) string {
		if e, ok := errors.AsType[*Error](err); ok {
			return e.Reason
		}
		return ""
	}

	v, err := Check(signedFile(t, priv, testSet, 5, 3, body), body, testSet, keys, 4)
	if err != nil || v.Publication != 5 || v.KeyID != KeyID(pub) {
		t.Fatalf("good file: %+v %v", v, err)
	}
	for name, tc := range map[string]struct {
		sig    []byte
		body   []byte
		set    string
		min    int64
		reason string
	}{
		"changed body":   {signedFile(t, priv, testSet, 5, 3, body), []byte(`{"revision":"4"}`), testSet, 0, ReasonSignatureInvalid},
		"other set":      {signedFile(t, priv, "acme/other", 6, 3, body), body, testSet, 0, ReasonSignatureInvalid},
		"unknown key":    {signedFile(t, stranger, testSet, 5, 3, body), body, testSet, 0, ReasonSignatureUntrusted},
		"replay":         {signedFile(t, priv, testSet, 5, 2, body), body, testSet, 6, ReasonSignatureReplayed},
		"not json":       {[]byte("nope"), body, testSet, 0, ReasonSignatureInvalid},
		"bad base64 sig": {[]byte(`{"keyId":"` + KeyID(pub) + `","signature":"!!"}`), body, testSet, 0, ReasonSignatureInvalid},
	} {
		if _, err := Check(tc.sig, tc.body, tc.set, keys, tc.min); reason(err) != tc.reason {
			t.Errorf("%s: %v, want %s", name, err, tc.reason)
		}
	}
	// The same publication again is not a replay: an operator restart pulls it anew.
	if _, err := Check(signedFile(t, priv, testSet, 5, 3, body), body, testSet, keys, 5); err != nil {
		t.Errorf("same publication: %v", err)
	}
}

func TestFetchSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t" || r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/p.json.sig" {
			_, _ = w.Write([]byte(`{"keyId":"x"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	src := Source{URL: srv.URL + "/p.json", Authorization: "Bearer t", AllowInsecure: true, ETag: `"etag of the file"`}
	body, err := FetchSignature(context.Background(), src, srv.URL+"/p.json.sig")
	if err != nil || string(body) != `{"keyId":"x"}` {
		t.Fatalf("signature: %q %v", body, err)
	}
	_, err = FetchSignature(context.Background(), src, srv.URL+"/missing.sig")
	if e, ok := errors.AsType[*Error](err); !ok || e.Reason != ReasonSignatureMissing {
		t.Errorf("missing signature: %v", err)
	}
}

func TestSignatureURLAndExpectedSetBadURL(t *testing.T) {
	if _, err := SignatureURL("http://%zz", ""); err == nil {
		t.Error("an unparsable URL must fail")
	}
	if _, err := ExpectedSet("http://%zz", ""); err == nil {
		t.Error("an unparsable URL must fail")
	}
	if got, _ := SignatureURL("https://x.test/a%2Fb/policy.json", ""); got != "https://x.test/a%2Fb/policy.json.sig" {
		t.Errorf("escaped path: %s", got)
	}
}
