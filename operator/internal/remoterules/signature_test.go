package remoterules

import "testing"

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
