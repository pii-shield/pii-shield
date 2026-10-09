package scanner

import (
	"strings"
	"testing"
)

// A full-width colon (U+FF1A) separates a key from its value the way the
// ASCII colon does, and the Chinese and Japanese words for password,
// passphrase, secret key and token are sensitive keys by default.
func TestFullWidthColonSeparatesKeyAndValue(t *testing.T) {
	s := newFileNameScanner(t)
	for _, tc := range []struct{ line, secret string }{
		{"密码：hunter2x", "hunter2x"},
		{"密码： hunter2x", "hunter2x"},
		{"密码: hunter2x", "hunter2x"},
		{"口令：Winter7413#", "Winter7413#"},
		{"密钥：AbC9xY2kQ8pLmN0rZq7", "AbC9xY2kQ8pLmN0rZq7"},
		{"令牌：AbC9xY2kQ8pLmN0rZq7", "AbC9xY2kQ8pLmN0rZq7"},
		{"パスワード：hunter2x", "hunter2x"},
		{"password：hunter2x", "hunter2x"},
		{"用户 lena 密码 hunter2x", "hunter2x"},
	} {
		got := s.ScanAndRedact(tc.line)
		if strings.Contains(got, tc.secret) || !strings.Contains(got, "[HIDDEN") {
			t.Errorf("ScanAndRedact(%q) = %q, want the value hidden", tc.line, got)
		}
		if key := strings.SplitN(tc.line, "：", 2)[0]; strings.Contains(tc.line, "：") && !strings.HasPrefix(got, key+"：") {
			t.Errorf("ScanAndRedact(%q) = %q, key or colon lost", tc.line, got)
		}
	}
	for _, line := range []string{
		"时间：12:30",
		"用户：lena",
		"状态：成功",
		"错误：密码错误，请重试",
		"密码错误 请重试",
		"密码 错误",
	} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
}

// A user-set key list keeps its order, and a non-ASCII entry may stand
// anywhere in it: an ASCII key is matched against the ASCII entries only, and
// that split must not depend on the non-ASCII ones coming last (the default
// list has them last; PII_SENSITIVE_KEYS='密码,pin' does not).
func TestSensitiveKeyListOrderWithNonASCIIEntries(t *testing.T) {
	for _, tc := range []struct {
		keys  []string
		ascii int
	}{
		{[]string{"密码", "pin"}, 1},
		{[]string{"pin", "密码"}, 1},
		{[]string{"密码", "pin", "パスワード", "otp"}, 2},
	} {
		cfg := DefaultConfig()
		cfg.Salt = []byte("filename-test-salt-1234567890")
		cfg.SensitiveKeys = tc.keys
		s := NewScanner(cfg)
		for _, c := range []struct{ line, secret string }{
			{"pin: 123456", "123456"},
			{"密码：hunter2x", "hunter2x"},
		} {
			if got := s.ScanAndRedact(c.line); strings.Contains(got, c.secret) {
				t.Errorf("keys %v: ScanAndRedact(%q) = %q, want hidden", tc.keys, c.line, got)
			}
		}
		// The list replaces the default, so a key outside it is not sensitive.
		if got := s.ScanAndRedact("password: hunter2x"); got != "password: hunter2x" {
			t.Errorf("keys %v: ScanAndRedact(password: hunter2x) = %q, want unchanged", tc.keys, got)
		}
		if n := len(s.asciiSensitiveKeys); n != tc.ascii {
			t.Errorf("keys %v: asciiSensitiveKeys has %d entries, want %d", tc.keys, n, tc.ascii)
		}
	}
}
