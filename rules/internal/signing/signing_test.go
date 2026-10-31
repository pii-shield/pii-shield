package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func TestStatementText(t *testing.T) {
	st := For("acme/payments", 7, 3, []byte(`{"revision":"3"}`))
	want := "pii-shield-policy-signature-v1\n" +
		"set: acme/payments\n" +
		"publication: 7\n" +
		"revision: 3\n" +
		"sha256: " + st.SHA256 + "\n"
	if st.Text() != want {
		t.Errorf("Text() = %q, want %q", st.Text(), want)
	}
	if len(st.SHA256) != 64 {
		t.Errorf("sha256 %q", st.SHA256)
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	text := FormatPublicKey(pub)
	back, err := ParsePublicKey(text)
	if err != nil || !back.Equal(pub) {
		t.Fatalf("ParsePublicKey(FormatPublicKey) = %v, %v", back, err)
	}
	if len(KeyID(pub)) != 16 {
		t.Errorf("KeyID %q", KeyID(pub))
	}
	st := For("acme/payments", 1, 1, []byte(`{}`))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(st.Text())))
	if err := Verify(pub, st, sig); err != nil {
		t.Fatalf("good signature: %v", err)
	}
	// Every field is covered: changing any one breaks the signature.
	for name, other := range map[string]Statement{
		"set":         For("acme/other", 1, 1, []byte(`{}`)),
		"publication": For("acme/payments", 2, 1, []byte(`{}`)),
		"revision":    For("acme/payments", 1, 2, []byte(`{}`)),
		"content":     For("acme/payments", 1, 1, []byte(`{ }`)),
	} {
		if err := Verify(pub, other, sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("changed %s: %v", name, err)
		}
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if err := Verify(pub, st, bad); !errors.Is(err, ErrBadSignature) {
			t.Errorf("signature %q: %v", bad, err)
		}
	}
}

func TestParsePublicKeyRejects(t *testing.T) {
	for _, s := range []string{"", "AAAA", "ed25519:", "ed25519:!!", "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := ParsePublicKey(s); err == nil {
			t.Errorf("ParsePublicKey(%q) accepted", s)
		}
	}
}
