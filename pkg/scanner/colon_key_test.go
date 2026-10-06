package scanner

import (
	"strings"
	"testing"
)

// TestSecretBeforeColonIsScored: a bare token in front of a colon was written
// out as the unscored key half of a colon pair, so "key <secret>: rejected"
// and the Go and Rust error form "for key <secret>: reason" passed whole,
// while the same value followed by a comma, a full stop or nothing was hidden
// (seen in soroban-forge-labs/soroban-forge#481).
func TestSecretBeforeColonIsScored(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	stellar := "SK5XWJ5M6SNIOSGFO3NT7DYNDTTN3A5U2PGKDYKB77X3B3YPACMUCI4L"
	hexToken := "4283fefc63f0cd0e873a0000c6d07ef7"
	for _, tc := range []struct{ in, secret string }{
		{"key " + stellar + ": rejected", stellar},
		{"token " + hexToken + ": rejected", hexToken},
		{"lookup failed for " + hexToken + ": not found", hexToken},
		{`{"message":"signing failed for key ` + stellar + `: bad seed"}`, stellar},
		{`level=error msg="for key ` + stellar + `: bad seed"`, stellar},
		{"AKIAIOSFODNN7EXAMPLE: access denied", "AKIAIOSFODNN7EXAMPLE"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) {
			t.Errorf("secret passed through: %q", out)
		}
		if !strings.Contains(out, "]: ") {
			t.Errorf("colon lost: %q -> %q", tc.in, out)
		}
	}
}

// TestFieldNameBeforeColonIsKept pins what the rule must not touch: names,
// levels, hosts, numbers, hashes that are safe anywhere, and Docker layer ids.
func TestFieldNameBeforeColonIsKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"ERROR: something failed",
		"WARN: low disk",
		"MainThread: idle",
		"worker3a: started",
		"server01: up",
		"web-7d9f8b6c5-x2k4q: ready",
		"10.0.0.1: ok",
		"12345: started",
		"1700000000123: tick",
		"x86_64: detected",
		"E1101: no member",
		"step3of5: running",
		"08:00:01: tick",
		"2026-10-05T08:00:00Z: tick",
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b: commit ok",
		"3f4e5d6c7b8a: Pull complete",
		"a1b2c3d4e5f6: Pulling fs layer",
		`"abc123XYZ789qwe": 5`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed: %q -> %q", in, out)
		}
	}

	// A sensitive name before the colon still forces the next token.
	if out := ScanAndRedact("Password: hunter2"); strings.Contains(out, "hunter2") || !strings.HasPrefix(out, "Password: [HIDDEN:") {
		t.Errorf("sensitive key: %q", out)
	}
}
