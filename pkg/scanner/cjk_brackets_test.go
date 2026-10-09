package scanner

import (
	"strings"
	"testing"
)

// A plain label in CJK or full-width brackets at the start of a line stays,
// and a secret inside such brackets or after them is still hidden.
func TestCJKBracketsAreSeparators(t *testing.T) {
	s := newFileNameScanner(t)
	for _, line := range []string{
		"【acct_1】 ok",
		"「acct_1」 ok",
		"（acct_1） ok",
		"《acct_1》 ok",
		"【主账号】 登录成功",
	} {
		if got := s.ScanAndRedact(line); got != line {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", line, got)
		}
	}
	const hex = "0123456789abcdef0123456789abcdef"
	if got := s.ScanAndRedact("【acct_1】  1. cookie2: " + hex); !strings.HasPrefix(got, "【acct_1】  1. cookie2: [HIDDEN") {
		t.Errorf("label or cookie wrong: %q", got)
	}
	for _, line := range []string{"【AbC9xY2kQ8pLmN0rZq7】", "（AbC9xY2kQ8pLmN0rZq7）", "【acct_1】token=AbC9xY2kQ8pLmN0rZq7"} {
		if got := s.ScanAndRedact(line); strings.Contains(got, "AbC9xY2kQ8pLmN0rZq7") {
			t.Errorf("ScanAndRedact(%q) = %q, secret survived", line, got)
		}
	}
}
