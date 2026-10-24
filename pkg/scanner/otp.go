package scanner

// A one-time code - the six digits of an OTP, a TOTP, an SMS verification or a
// password-reset code - is a credential for the minutes it is valid, and it is
// digits only, so entropy never reaches the threshold. In the InsForge SDK's
// debug log of a password reset (leak-radar complaints 2026-10-10 #6,
// InsForge/InsForge-sdk-js#150) `{"email": "…", "newPassword": "…", "otp":
// "928283"}` hid the password and kept the otp in 29 of 90 runs: `otp` is not
// a sensitive key, and six digits score far below any threshold.
//
// So the code is known by its key, the way an identity number is: 4 to 8
// digits, compact or in two groups, as the value of a key whose last word
// names a one-time code (otp, totp, otp_code, verification_code, mfa_code,
// reset_code, one_time_code, passcode). A code in prose (`Entering TOTP
// authentication code: 235342`) has no such key in front of it and stays,
// like a bare number; digits under `code` alone (`code=200`, `status_code`,
// `zip_code`, `country_code`) stay too.

const (
	minOTPDigits = 4 // the shortest codes in use (bank and SMS PINs)
	maxOTPDigits = 8 // above this a digit run is an id, not a code
)

// otpKeyWords are the last word of a key that holds a one-time code on its
// own, as splitKeyWords lowercases it. The run-together forms cover keys
// with no word boundary to split on (otpcode, onetimecode).
var otpKeyWords = map[string]bool{
	"otp": true, "totp": true, "hotp": true, "passcode": true,
	"otpcode": true, "onetimecode": true, "mfacode": true, "smscode": true,
}

// otpCodeWords are the words that make "code" a one-time code rather than a
// status, a country or a postal code: otp_code, verification_code, mfaCode,
// reset_code, confirmation_code, sms_code.
var otpCodeWords = map[string]bool{
	"otp": true, "totp": true, "hotp": true, "mfa": true, "2fa": true, "tfa": true,
	"verification": true, "verify": true, "confirmation": true, "confirm": true,
	"reset": true, "recovery": true, "activation": true, "login": true, "signin": true,
	"auth": true, "security": true, "sms": true, "onetime": true, "pass": true,
}

// isOTPKey reports whether key names a one-time code.
func isOTPKey(key string) bool {
	var words [maxKeyWords]string
	n := splitKeyWords(key, &words)
	return n > 0 && isOTPKeyWords(words[:n])
}

// isOTPKeyWords judges a key by its last word (otp, passcode), by "code"
// after a word that says which code it is (otp_code, verification_code,
// mfa_code) or by "one time code". A key that only starts with such a word
// (otp_attempts, otp_ttl, code_verifier) is not one.
func isOTPKeyWords(parts []string) bool {
	np := len(parts)
	last := parts[np-1]
	if last != "code" {
		return otpKeyWords[last]
	}
	if np < 2 {
		return false
	}
	prev := parts[np-2]
	if prev == "time" {
		return np >= 3 && parts[np-3] == "one"
	}
	return otpCodeWords[prev]
}

// matchKeyedOTP matches 4-8 digits at line[i:], compact or in two groups
// separated by one '-' or, when quoted, one space (123-456, "123 456"). The
// caller has checked that the run is the value of a one-time-code key. It
// returns the end index or 0.
func matchKeyedOTP(line string, i int) int {
	return matchGroupedDigits(line, i, minOTPDigits, maxOTPDigits)
}

// isOTPValue reports whether val, a whole URL parameter value, is 4 to 8
// digits with an optional '-' group. The caller checks the key.
func isOTPValue(val string) bool {
	if val == "" || !isASCIIDigit(val[0]) {
		return false
	}
	return matchKeyedOTP(val, 0) == len(val)
}
