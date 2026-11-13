package remoterules

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// FuzzCheck attacks the signature check of a remote policy file. One file is
// signed once with a key the fuzzer never sees; every input is some other
// combination of signature file, body, set name and replay floor. Whatever
// Check accepts must be that one signed statement: the same body, the same
// set, the same publication number, and a floor not above it. Anything else
// accepted is a forged or replayed rule set reaching the pods.
func FuzzCheck(f *testing.F) {
	const signedPublication, signedRevision = 5, 3
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	keys := []TrustedKey{{ID: KeyID(pub), Key: pub}}

	body := []byte(`{"revision":"3","sensitive_keys":["session"]}`)
	good := signedFile(f, priv, testSet, signedPublication, signedRevision, body)

	// edit rewrites one field of the good signature file.
	edit := func(change func(*SignatureFile)) []byte {
		var sf SignatureFile
		if err := json.Unmarshal(good, &sf); err != nil {
			f.Fatal(err)
		}
		change(&sf)
		out, _ := json.Marshal(sf)
		return out
	}

	f.Add(good, body, testSet, int64(4))
	f.Add(good, body, testSet, int64(signedPublication))
	f.Add(good, body, testSet, int64(signedPublication+1))                         // replay
	f.Add(good, []byte(`{"revision":"3","sensitive_keys":[]}`), testSet, int64(0)) // body swapped
	f.Add(good, body, "acme/other", int64(0))                                      // signed for another set
	f.Add(good, body, testSet+"\npublication: 5", int64(0))                        // statement line smuggled into the set
	f.Add(edit(func(sf *SignatureFile) { sf.Publication = 6 }), body, testSet, int64(0))
	f.Add(edit(func(sf *SignatureFile) { sf.Revision = 4 }), body, testSet, int64(0))
	f.Add(edit(func(sf *SignatureFile) { sf.Set = "acme/other" }), body, testSet, int64(0))
	f.Add(edit(func(sf *SignatureFile) { sf.SHA256 = strings.Repeat("0", 64) }), body, testSet, int64(0))
	f.Add(edit(func(sf *SignatureFile) { sf.Signature = "" }), body, testSet, int64(0))
	f.Add(edit(func(sf *SignatureFile) { sf.Signature = "!!not base64!!" }), body, testSet, int64(0))
	f.Add(edit(func(sf *SignatureFile) { sf.Signature = sf.Signature[:len(sf.Signature)-4] }), body, testSet, int64(0))
	f.Add(edit(func(sf *SignatureFile) { sf.KeyID = "" }), body, testSet, int64(0))
	f.Add(edit(func(sf *SignatureFile) { sf.KeyID = strings.ToUpper(sf.KeyID) }), body, testSet, int64(0))
	f.Add(signedFile(f, stranger, testSet, signedPublication, signedRevision, body), body, testSet, int64(0)) // untrusted signer
	f.Add(edit(func(sf *SignatureFile) {                                                                      // stranger's signature under the trusted key id
		var other SignatureFile
		_ = json.Unmarshal(signedFile(f, stranger, testSet, signedPublication, signedRevision, body), &other)
		sf.Signature = other.Signature
	}), body, testSet, int64(0))
	f.Add([]byte(`{}`), body, testSet, int64(0))
	f.Add([]byte(`null`), body, testSet, int64(0))
	f.Add([]byte(`[]`), body, testSet, int64(0))
	f.Add([]byte(``), []byte(``), "", int64(-1))
	f.Add([]byte(`{"publication":1e400}`), body, testSet, int64(0))
	f.Add(append(append([]byte{}, good...), good...), body, testSet, int64(0)) // two objects in one file

	f.Fuzz(func(t *testing.T, sigBody, gotBody []byte, set string, minPublication int64) {
		v, err := Check(sigBody, gotBody, set, keys, minPublication)
		if err != nil {
			e, ok := errors.AsType[*Error](err)
			if !ok {
				t.Fatalf("Check failed with %T, not an *Error", err)
			}
			switch e.Reason {
			case ReasonSignatureInvalid, ReasonSignatureUntrusted, ReasonSignatureReplayed:
			default:
				t.Errorf("unexpected rejection reason %q", e.Reason)
			}
			if v != (Verified{}) {
				t.Errorf("a rejected file still returned %+v", v)
			}
			return
		}

		if !bytes.Equal(gotBody, body) {
			t.Errorf("a body that was never signed was accepted: %q", gotBody)
		}
		if set != testSet {
			t.Errorf("a file signed for %q was accepted as set %q", testSet, set)
		}
		if v.Publication != signedPublication || v.KeyID != keys[0].ID {
			t.Errorf("accepted as publication %d by key %q; signed was %d by %q", v.Publication, v.KeyID, signedPublication, keys[0].ID)
		}
		if minPublication > signedPublication {
			t.Errorf("publication %d accepted below the floor %d", signedPublication, minPublication)
		}
	})
}
