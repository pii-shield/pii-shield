package scanner

import (
	"strings"
	"testing"
)

// TestLowEqLowInMatchToLower checks the stack-lowered path against
// strings.ToLower on ASCII tokens, and that the heap path is what
// processAndAppend falls back to for a token the stack path cannot take (a
// non-ASCII token whose lowering is ASCII, the Kelvin sign).
func TestLowEqLowInMatchToLower(t *testing.T) {
	words := map[string]bool{"key": true, "bearer": true, "error": true, "none": true}
	for _, tok := range []string{"", "key", "KEY", "Key", "Bearer", "BEARER", "Error", "None", "nope", "keys", "Setting"} {
		var buf [64]byte
		low := appendLowerASCII(buf[:0], tok)
		want := strings.ToLower(tok)
		if string(low) != want {
			t.Errorf("appendLowerASCII(%q) = %q, want %q", tok, low, want)
		}
		for lit := range words {
			if got := lowEq(low, "", lit); got != (want == lit) {
				t.Errorf("lowEq(%q, %q) = %v, want %v", tok, lit, got, want == lit)
			}
		}
		if got := lowIn(words, low, ""); got != words[want] {
			t.Errorf("lowIn(%q) = %v, want %v", tok, got, words[want])
		}
	}
	kelvin := "Key" // lowers to "key"
	if !hasNonASCII(kelvin) {
		t.Fatal("test token must be non-ASCII")
	}
	lowered := strings.ToLower(kelvin)
	if !lowEq(nil, lowered, "key") || !lowIn(words, nil, lowered) {
		t.Errorf("heap path lost the Kelvin-sign key: %q", lowered)
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
