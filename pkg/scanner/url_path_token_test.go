package scanner

import (
	"strings"
	"testing"
)

// TestSecretInURLPathHidden: a token used as a credential in a URL path was
// written as it is unless it matched an issuer signature. A random-looking
// segment is now scored like a value; public identifiers of a known shape
// and names keep their text.
func TestSecretInURLPathHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	hexKey := "4283fefc63f0cd0e873a0000c6d07ef7"
	b64Key := "Qm9vSzZyN3hQdmFMa2Rz8YzR"
	for _, c := range []struct{ in, secret string }{
		{"POST http://llm-gw.example.org/mathutrice/" + hexKey + "/v1/chat/completions", hexKey},
		{"POST https://api.example.org/v1/" + b64Key + "/messages", b64Key},
		{"GET https://hooks.example.org/services/" + b64Key + "?wait=true", b64Key},
		{`"POST http://llm-gw.example.org/mathutrice/` + hexKey + `/v1/chat/completions HTTP/1.1" 200`, hexKey},
	} {
		out := ScanAndRedact(c.in)
		if strings.Contains(out, c.secret) || !strings.Contains(out, "[HIDDEN") {
			t.Errorf("secret in a URL path leaked:\n in: %s\nout: %s", c.in, out)
		}
		// Only the secret segment changes: the path around it stays readable.
		for _, keep := range []string{"://", "example.org/"} {
			if !strings.Contains(out, keep) {
				t.Errorf("path text lost (%q):\n in: %s\nout: %s", keep, c.in, out)
			}
		}
	}
}

// TestPublicIdentifiersInURLPathKept: commits, object ids, UUIDs, slugs,
// versions and file names with a content hash are not credentials.
func TestPublicIdentifiersInURLPathKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"GET https://github.com/org/repo/commit/e83c5163316f89bfbde7d9ab23ca2e25604af290",
		"GET https://api.example.org/objects/507f1f77bcf86cd799439011",
		"GET https://api.example.org/users/123e4567-e89b-12d3-a456-426614174000/profile",
		"GET https://shop.example.org/product/31510/61526/%D9%85%D8%A7%DB%8C%DA%A9%D8%B1%D9%88%D9%81%D8%B1-DEM-341C0K",
		"GET https://cdn.example.org/static/app.4283fefc63f0cd0e873a0000c6d07ef7.js",
		"GET https://api.example.org/v2/customer_payment_methods/list",
		"GET https://docs.example.org/en/latest/getting-started-with-the-cli",
		"GET https://pkg.example.org/downloads/release-2.2.6-linux-amd64.tar.gz",
		"GET https://registry.example.org/v2/blobs/sha256/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed:\n in: %s\nout: %s", in, out)
		}
	}
}
