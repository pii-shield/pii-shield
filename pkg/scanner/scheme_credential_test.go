package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// qboxCredential has the shape of a Qiniu QBox credential, <access key>:<signature>=
// (fake values): base64url with a '_' in the first half, a ':' between the
// halves and '=' padding at the end, which is what sent it through the
// key:value splitters unscored.
const qboxCredential = "Ywq3SUV3eVpQgBTwK_w2VVdvxT85ypPc2C4N1Jkz:5oeaCEe_QAyodMJmrV52QhMk7Cu="

// TestSchemeCredentialAfterKeyHidden: a credential after a vendor auth scheme
// word in the value slot of a sensitive key is hidden whole, as after Basic
// and Bearer. "accessToken:  QBox <ak>:<sig>=" and "Authorization: QBox ..."
// (leak-radar repo-risks 2026-10-13 #2, yenche123/liubai) came back unchanged
// in 90 of 90 runs on 2.2.8.
func TestSchemeCredentialAfterKeyHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, tc := range []struct{ in, secret, keep string }{
		{"accessToken:  QBox " + qboxCredential, qboxCredential, "accessToken:  QBox "},
		{"Authorization: QBox " + qboxCredential, qboxCredential, "Authorization: QBox "},
		{"Authorization: QBox " + qboxCredential + " next", qboxCredential, " next"},
		{"authorization: Qiniu " + qboxCredential, qboxCredential, "authorization: Qiniu "},
		{"Authorization: AWS AKIAIOSFODNN7EXAMPLE:frJIUN8DYpKDtOLCwo//yllqDzg=", "frJIUN8DYpKDtOLCwo", "Authorization: AWS "},
		{"Authorization: SSWS 00Fe1XabcDEFghiJKLmnopQRstuVWxyz1234567890", "00Fe1XabcDEFghiJKL", "Authorization: SSWS "},
		{`{"accessToken": "QBox ` + qboxCredential + `"}`, qboxCredential, `{"accessToken": "`},
		{`{"Authorization":"QBox ` + qboxCredential + `"}`, qboxCredential, `{"Authorization":"`},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) {
			t.Errorf("credential passed through: %q", out)
		}
		if !strings.Contains(out, "[HIDDEN:key:") {
			t.Errorf("no key label: %q -> %q", tc.in, out)
		}
		if !strings.Contains(out, tc.keep) {
			t.Errorf("text around the credential changed: %q -> %q", tc.in, out)
		}
		if json.Valid([]byte(tc.in)) && !json.Valid([]byte(out)) {
			t.Errorf("JSON broken: %q -> %q", tc.in, out)
		}
	}
}

// TestForcedValueWithSeparatorHiddenWhole: a value forced by its key is one
// value even when it holds a ':' of its own. These went to the colon splitter
// and came back unchanged, while the same value in quotes was hidden. A
// trailing colon is a separator and stays (see TestSecretBeforeColonIsScored).
func TestForcedValueWithSeparatorHiddenWhole(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, tc := range []struct{ in, secret, want string }{
		{"password: abc:def", "abc:def", "password: [HIDDEN:key:"},
		{"secret: k1:v1 more", "k1:v1", "] more"},
		{"password hunter2:x", "hunter2:x", "password [HIDDEN:key:"},
		// The scheme word stays (it used to be hidden as the key's value).
		{"Authorization: Bearer " + qboxCredential, qboxCredential, "Authorization: Bearer [HIDDEN:key:"},
		{"api_key = " + qboxCredential, qboxCredential, "api_key = [HIDDEN:key:"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) {
			t.Errorf("value passed through: %q", out)
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("want %q in %q -> %q", tc.want, tc.in, out)
		}
	}
	// The quoted forms were already hidden whole and still are.
	for _, in := range []string{`{"password": "abc:def"}`, `password="abc:def"`} {
		if out := ScanAndRedact(in); strings.Contains(out, "abc:def") {
			t.Errorf("quoted value passed through: %q", out)
		}
	}
}

// TestSchemeCarryKeepsProse pins what the scheme carry must not touch: a
// word after a capitalised word in the value slot that is not shaped like a
// credential, a timestamp, a URL, the scheme word written in lower case in
// prose, and a WWW-Authenticate challenge.
func TestSchemeCarryKeepsProse(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, keep string }{
		{"Authorization: Missing header", " header"},
		{"password: Invalid value", " value"},
		{"token: Expired 2026-10-23T14:15:31.478Z", " 2026-10-23T14:15:31.478Z"},
		{"Authorization: Failed authentication-attempt-logged", " authentication-attempt-logged"},
		{"token: Rotated https://vault.example.com/v1/sys/rotate", " https://vault.example.com/v1/sys/rotate"},
		{"password: Winter7413 user=bob logged in", " user=bob logged in"},
		{"the bearer of this note is Qiniu account 42", "the bearer of this note is Qiniu account 42"},
		// scheme parameters are not swallowed as the credential: the name
		// stays and the value is scored as on any other line
		{"Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request", " Credential="},
		{`Authorization: Hawk id="dh37fgj492je", ts="1353832234"`, `, ts="1353832234"`},
	} {
		if out := ScanAndRedact(tc.in); !strings.Contains(out, tc.keep) {
			t.Errorf("prose changed: %q -> %q", tc.in, out)
		}
	}
	for _, in := range []string{
		"auth = basic support",
		`WWW-Authenticate: Basic realm="example"`,
		`WWW-Authenticate: Basic realm="restricted", charset="UTF-8"`,
		"key: value other=1",
		"password= user=bob",
		"Authorization: QBox",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", in, out)
		}
	}
}

func TestIsAuthSchemeWord(t *testing.T) {
	for _, s := range []string{"Basic", "Bearer", "QBox", "Qiniu", "AWS", "AWS4-HMAC-SHA256", "Hawk", "SSWS", "Negotiate", "NTLM", "OAuth", "HMAC-SHA256", "Token"} {
		if !isAuthSchemeWord(s) {
			t.Errorf("isAuthSchemeWord(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "Q", "qbox", "basic", "QBox:", "Q_Box", "QBox=1", "123", "Ywq3SUV3eVpQgBTwK_w2VVdvxT85ypPc2C4N1Jkz", "ThisIsFarTooLongForASchemeName"} {
		if isAuthSchemeWord(s) {
			t.Errorf("isAuthSchemeWord(%q) = true, want false", s)
		}
	}
}
