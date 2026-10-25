package scanner

import (
	"strings"
	"testing"
)

// TestLoweredTokenMatchesToLower checks is, in and forBigrams against
// strings.ToLower on ASCII tokens, on a token over the stack buffer and on
// a non-ASCII token whose lowering is ASCII (the Kelvin sign), which takes
// the heap path.
func TestLoweredTokenMatchesToLower(t *testing.T) {
	words := map[string]bool{"key": true, "bearer": true, "error": true, "none": true, "setting": true}
	long := strings.Repeat("Ab", 40) + "key"
	for _, tok := range []string{"", "key", "KEY", "Key", "Bearer", "BEARER", "Error", "None", "nope", "keys", "Setting", long, "Key", "Straße", "密码"} {
		lt := newLoweredToken(tok)
		want := strings.ToLower(tok)
		for lit := range words {
			if got := lt.is(lit); got != (want == lit) {
				t.Errorf("newLoweredToken(%q).is(%q) = %v, want %v", tok, lit, got, want == lit)
			}
		}
		if got := lt.in(words); got != words[want] {
			t.Errorf("newLoweredToken(%q).in = %v, want %v", tok, got, words[want])
		}
		if got := lt.forBigrams(); strings.ToLower(got) != want {
			t.Errorf("newLoweredToken(%q).forBigrams() = %q, lowers to %q, want %q", tok, got, strings.ToLower(got), want)
		}
		if ascii := !hasNonASCII(tok) && len(tok) <= 64; lt.ascii != ascii {
			t.Errorf("newLoweredToken(%q).ascii = %v, want %v", tok, lt.ascii, ascii)
		}
	}
	if lt := newLoweredToken("Key"); !lt.is("key") || !lt.in(words) {
		t.Errorf("heap path lost the Kelvin-sign key: %q", lt.heap)
	}
}

// TestProcessAndAppendCaseInsensitiveWords pins the outcomes that depended
// on the lowered token: a context keyword and an auth scheme in any case.
func TestProcessAndAppendCaseInsensitiveWords(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Salt = []byte("lower-token-test-salt-1234567890")
	s := NewScanner(cfg)
	for _, tc := range []struct{ line, secret string }{
		{"Authorization: BEARER x9Qm2pL7vR4tZ8wK", "x9Qm2pL7vR4tZ8wK"},
		{"Authorization: Bearer x9Qm2pL7vR4tZ8wK", "x9Qm2pL7vR4tZ8wK"},
		{"ERROR Qz7mX2kLp9Rt4vWy8nBc", "Qz7mX2kLp9Rt4vWy8nBc"},
		{"Error Qz7mX2kLp9Rt4vWy8nBc", "Qz7mX2kLp9Rt4vWy8nBc"},
		{"password IS Wint3r!Sun", "Wint3r!Sun"},
	} {
		if got := s.ScanAndRedact(tc.line); strings.Contains(got, tc.secret) {
			t.Errorf("ScanAndRedact(%q) = %q, want the secret hidden", tc.line, got)
		}
	}
}
