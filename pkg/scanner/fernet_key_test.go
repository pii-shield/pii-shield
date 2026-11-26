package scanner

import (
	"strings"
	"testing"
)

// Made-up 32-byte keys in URL-safe base64 (the Fernet key format), each with
// a '-' and a '_' in the body. Random values, not real keys.
var fernetShapedKeys = []string{
	"sGWvwf-dbGiPSkKclvQDCNfm2fi6mFHrv3olz_j0R6g=",
	"GgLXNGD7mXFHct06OZG_WkNUBb0W0qevm-szmUiURVg=",
	"lm_Ydxo1dPyE0d7NPoLCWgT-aulbxo5I9E1FvGN64Ik=",
}

// TestFernetKeyAfterPlainWords pins a miss found in a public project's logs:
// "Secret key is <fernet key>". The '=' padding was taken for a key=value
// separator, and a body with '-' or '_' looked like a field name, so the
// "key half" was written out unscored. On 3.0.0 the key was hidden in about
// one line of four, only when the random body happened to have neither.
func TestFernetKeyAfterPlainWords(t *testing.T) {
	useDefaultConfig(t)

	for _, key := range fernetShapedKeys {
		body := strings.TrimRight(key, "=")
		for _, in := range []string{
			"OLIAPI - 11:14:43 - INFO -  Secret key is " + key,
			"generated " + key + " ok",
			`{"msg":"` + key + `"}`,
			`{"msg": "key ` + key + `"}`,
			"fernet_key=" + key,
		} {
			out := ScanAndRedact(in)
			if strings.Contains(out, body) {
				t.Errorf("key passed through: in=%q out=%q", in, out)
			}
			if !strings.Contains(out, "[HIDDEN") {
				t.Errorf("expected a marker: in=%q out=%q", in, out)
			}
		}
	}
}

// TestPaddedKeyMaterialKeepsFieldNames: the new guard must not stop ordinary
// key=value pairs from splitting.
func TestPaddedKeyMaterialKeepsFieldNames(t *testing.T) {
	for _, s := range []string{
		"request_id=",              // field name, empty value
		"context_id=12345",         // ordinary pair
		"abcdefghijklmnopqrstuvw=", // 24 chars, no upper case or digits
		"ABCDEFGHIJKLMNOPQRSTUVW=", // no lower case or digits
		"userIdentifierValueXY1=",  // 23 chars, not whole groups of four
		"rows=10&page=1",
	} {
		if isPaddedKeyMaterial(s) {
			t.Errorf("isPaddedKeyMaterial(%q) = true, want false", s)
		}
	}
	for _, s := range fernetShapedKeys {
		if !isPaddedKeyMaterial(s) {
			t.Errorf("isPaddedKeyMaterial(%q) = false, want true", s)
		}
	}

	useDefaultConfig(t)
	for _, in := range []string{"request_id=abc", "status=ok user=bob", "page=2&rows=10"} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("benign pair changed: in=%q out=%q", in, out)
		}
	}
}
