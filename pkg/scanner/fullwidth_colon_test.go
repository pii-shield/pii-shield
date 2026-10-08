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
