package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestOTPUnderKeyHidden: 4 to 8 digits under a key that names a one-time
// code are hidden with the key label. The first line is the reset-password
// shape from InsForge/InsForge-sdk-js#150, where the otp passed in 29 of 90
// runs while the password next to it was hidden (see otp.go).
func TestOTPUnderKeyHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, tc := range []struct{ in, code string }{
		{`{"email": "[REDACTED]", "newPassword": "[HIDDEN:abecfe]", "otp": "928283"}`, "928283"},
		{`{"otp":"928283","newPassword":"Winter7413#"}`, "928283"},
		{`otp=928283`, "928283"},
		{`otp: 928283 sent to user 42`, "928283"},
		{`{"otp_code": "928283"}`, "928283"},
		{`otpCode=928283`, "928283"},
		{`{"totp": "019283"}`, "019283"},
		{`verification_code=4821`, "4821"},
		{`verificationCode: 48213377`, "48213377"},
		{`mfa_code: 019283`, "019283"},
		{`reset_code="928283"`, "928283"},
		{`one_time_code='928283'`, "928283"},
		{`oneTimeCode=928283`, "928283"},
		{`confirmation_code=928283`, "928283"},
		{`sms_code=928283`, "928283"},
		{`passcode=928283`, "928283"},
		{`"otp": "123-456"`, "123-456"},
		{`GET /auth/verify?otp=928283&step=2 HTTP/1.1`, "928283"},
		{`POST /reset?email=x&verification_code=4821 HTTP/1.1`, "4821"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.code) {
			t.Errorf("code passed through: %q", out)
		}
		if !strings.Contains(out, "[HIDDEN:key:") {
			t.Errorf("no key label: %q -> %q", tc.in, out)
		}
		if json.Valid([]byte(tc.in)) && !json.Valid([]byte(out)) {
			t.Errorf("JSON broken: %q -> %q", tc.in, out)
		}
		if strings.Count(out, `"`) != strings.Count(tc.in, `"`) || strings.Count(out, `'`) != strings.Count(tc.in, `'`) {
			t.Errorf("quotes changed: %q -> %q", tc.in, out)
		}
	}

	// The words after a logfmt value are not part of it.
	if out := ScanAndRedact(`otp=928283 42 attempts`); !strings.HasSuffix(out, "] 42 attempts") {
		t.Errorf("value ran into the next word: %q", out)
	}
}

// TestOtherCodesAreNotOTPs pins what the detector must not touch: status,
// country and postal codes, keys that only start with otp, digit runs outside
// the 4-8 range, and a code in prose with no key in front of it.
func TestOtherCodesAreNotOTPs(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, in := range []string{
		`code=200`,
		`code=4821`,
		`status_code=404`,
		`http_code=500`,
		`error_code=1234`,
		`exit_code=1`,
		`zip_code=10001`,
		`postal_code=90210`,
		`country_code=49`,
		`pin_code=110001`,
		`currency_code=978`,
		`otp_attempts=3`,
		`otp_ttl=300`,
		`otp_length=6`,
		`otp=123`,
		`otp=123456789`,
		`otp_expires_at=1761300000`,
		`code_verifier=1234567`,
		`Entering TOTP authentication code: 235342`,
		`recovery code 235342 rejected for user 42`,
		`GET /a?code=4821 HTTP/1.1`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", in, out)
		}
	}
}

func TestIsOTPKey(t *testing.T) {
	for _, k := range []string{
		"otp", "OTP", "totp", "hotp", "otp_code", "otpCode", "verification_code", "verificationCode",
		"mfa_code", "mfaCode", "2fa_code", "reset_code", "recovery_code", "confirmation_code",
		"one_time_code", "oneTimeCode", "onetime_code", "sms_code", "login_code", "auth_code",
		"passcode", "user.otp", "auth.otp_code",
	} {
		if !isOTPKey(k) {
			t.Errorf("isOTPKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{
		"code", "status_code", "zip_code", "country_code", "pin_code", "error_code", "time_code",
		"otp_attempts", "otp_ttl", "otp_enabled", "code_verifier", "codes", "totp_secret", "id",
	} {
		if isOTPKey(k) {
			t.Errorf("isOTPKey(%q) = true, want false", k)
		}
	}
}
