package scanner

import (
	"strings"
	"testing"
)

// SCN-F8: opt-in entity-type labels in redaction output,
// [HIDDEN:<type>:<hash>] instead of [HIDDEN:<hash>], off by default.

func withEntityLabels(t *testing.T, extra func(cfg *Config)) {
	t.Helper()
	oldCfg := activeCfg()
	t.Cleanup(func() { UpdateConfig(oldCfg) })

	cfg := oldCfg
	cfg.EntityTypeLabels = true
	if extra != nil {
		extra(&cfg)
	}
	UpdateConfig(cfg)
}

func TestEntityLabelsOffByDefault(t *testing.T) {
	out := ScanAndRedact("password=hunter2")
	if !strings.Contains(out, "[HIDDEN:") {
		t.Fatalf("expected redaction, got %q", out)
	}
	for _, label := range []string{":key:", ":card:", ":context:", ":url:", ":entropy:", ":regex:"} {
		if strings.Contains(out, label) {
			t.Errorf("entity label %q emitted with the flag off: %q", label, out)
		}
	}
}

func TestEntityLabelsPerDetector(t *testing.T) {
	withEntityLabels(t, nil)

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"sensitive key", "password=hunter2", "password=[HIDDEN:key:"},
		{"luhn card", "card 4539148803436467 end", "[HIDDEN:card:"},
		{"context keyword", "error: x7Kp2Q rejected", "[HIDDEN:context:"},
		{"plain entropy", "id a3f8K2pQ9xLmW0vNbT5cRdYe", "[HIDDEN:entropy:"},
		{"url sensitive key", "GET /v1/orders?token=abcdef&page=2", "token=[HIDDEN:key:"},
		{"url entropy param", "GET /v1/orders?session=E8s9d_2kL1&page=2", "session=[HIDDEN:url:"},
	}
	for _, c := range cases {
		out := ScanAndRedact(c.input)
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: want substring %q in output:\n in:  %q\n out: %q", c.name, c.want, c.input, out)
		}
	}
}

func TestEntityLabelsCustomRegex(t *testing.T) {
	withEntityLabels(t, func(cfg *Config) {
		if err := cfg.ApplyCustomRegexes([]CustomRegexConfig{
			{Pattern: "TICKET-[0-9]{6}", Name: "ticket"},
			{Pattern: "ZXQ[0-9]{8}", Name: ""},
		}); err != nil {
			t.Fatalf("ApplyCustomRegexes: %v", err)
		}
	})

	// A named rule keeps its own name as the label.
	out := ScanAndRedact("ref TICKET-123456 opened")
	if !strings.Contains(out, "[HIDDEN:ticket:") {
		t.Errorf("named rule lost its name: %q", out)
	}

	// An unnamed rule gets the generic regex label.
	out = ScanAndRedact("ref ZXQ12345678 opened")
	if !strings.Contains(out, "[HIDDEN:regex:") {
		t.Errorf("unnamed rule missing regex label: %q", out)
	}
}

// TestEntityLabelsHashStable proves the label does not change the hash:
// the HMAC covers the value only, so flipping the flag keeps tags
// correlatable across deployments.
func TestEntityLabelsHashStable(t *testing.T) {
	plain := ScanAndRedact("api_key=a3f8K2pQ9xLmW0vNbT5cRdYe")

	withEntityLabels(t, nil)
	labeled := ScanAndRedact("api_key=a3f8K2pQ9xLmW0vNbT5cRdYe")

	extract := func(s string) string {
		start := strings.LastIndex(s, ":")
		end := strings.LastIndex(s, "]")
		if start == -1 || end == -1 || end <= start {
			t.Fatalf("no [HIDDEN:...:hash] marker in %q", s)
		}
		return s[start+1 : end]
	}
	if extract(plain) != extract(labeled) {
		t.Errorf("hash changed when labels enabled: %q vs %q", plain, labeled)
	}
}

// TestEntityLabelsIdempotent: labeled markers must survive a second scan
// unchanged (invariant I3).
func TestEntityLabelsIdempotent(t *testing.T) {
	withEntityLabels(t, nil)

	inputs := []string{
		"card 4539148803436467 end",
		"id a3f8K2pQ9xLmW0vNbT5cRdYe",
		"GET /v1/orders?session=E8s9d_2kL1&page=2",
		"password=hunter2xyz token=abc123def456",
		`{"secret": "user=admin pass=x"}`,
	}
	for _, in := range inputs {
		once := ScanAndRedact(in)
		twice := ScanAndRedact(once)
		if once != twice {
			t.Errorf("double scan changed labeled output:\n once:  %q\n twice: %q", once, twice)
		}
	}
}

func TestEntityLabelsEnvParsing(t *testing.T) {
	t.Setenv("PII_SALT", "test_salt_1234567890")

	t.Setenv("PII_ENTITY_TYPE_LABELS", "yes")
	if cfg := loadConfig(); !cfg.EntityTypeLabels {
		t.Error("PII_ENTITY_TYPE_LABELS=yes not applied")
	}

	t.Setenv("PII_ENTITY_TYPE_LABELS", "0")
	if cfg := loadConfig(); cfg.EntityTypeLabels {
		t.Error("PII_ENTITY_TYPE_LABELS=0 should stay disabled")
	}

	t.Setenv("PII_ENTITY_TYPE_LABELS", "")
	if cfg := loadConfig(); cfg.EntityTypeLabels {
		t.Error("default must be disabled")
	}
}
