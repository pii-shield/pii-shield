package scanner

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// TestFalsePositives proves that the Confidence Threshold correctly skips UUIDs and Base64 blobs
func TestFalsePositives(t *testing.T) {
	// Preserve global config so we don't break other tests!
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)

	// Apply strict confidence testing config
	cfg := oldCfg
	cfg.ConfidenceThreshold = 1.5
	UpdateConfig(cfg)

	// 1. UUID Test
	t.Run("UUIDs should be skipped", func(t *testing.T) {
		uuids := []string{
			"123e4567-e89b-12d3-a456-426614174000",
			"550e8400-e29b-41d4-a716-446655440000",
			"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		}
		for _, uuid := range uuids {
			// Embedded without context
			input := fmt.Sprintf("User connected with id %s", uuid)
			output := ScanAndRedact(input)
			if output != input {
				t.Errorf("Expected raw uuid pass-through, got %s", output)
			}
		}
	})

	// 2. Base64 Image/Payload Test
	t.Run("Base64 blobs > 64 chars are skipped above confidence 1.2", func(t *testing.T) {
		// 100 pseudo-random bytes from a fixed seed: high entropy, and the
		// same input on every run.
		raw := make([]byte, 100)
		_, _ = rand.New(rand.NewSource(1)).Read(raw)
		b64 := base64.StdEncoding.EncodeToString(raw)

		input := fmt.Sprintf("Payload: %s", b64)
		output := ScanAndRedact(input)
		// Kept only because this test raises ConfidenceThreshold to 1.5. At the
		// default (1.0) such a blob is redacted even without a key (F3; see
		// base64_blob_test.go) — the absence of a sensitive key is not what
		// keeps it.
		if output != input {
			t.Errorf("Expected raw base64 pass-through, got %s", output)
		}
	})

	// 3. True Positive Confidence Trigger (Forced Masking)
	t.Run("Context overrides should still trigger redaction", func(t *testing.T) {
		uuid := "123e4567-e89b-12d3-a456-426614174000"
		// "token:" is a sensitive key, so the UUID is its forced value.
		input := fmt.Sprintf("token: %s", uuid)
		output := ScanAndRedact(input)
		if strings.Contains(output, uuid) {
			t.Errorf("Expected UUID under a sensitive key to be redacted, got %s", output)
		}
		// A context word ("error", "failed") before a bare UUID reaches the
		// UUID branch of processSingleToken with contextSensitive set, which
		// forces it. The sensitive-key case above never got there, so this
		// branch had no test at all (audit 2026-09-25).
		for _, word := range []string{"error", "failed"} {
			in := fmt.Sprintf("%s %s", word, uuid)
			if out := ScanAndRedact(in); strings.Contains(out, uuid) || !strings.Contains(out, "[HIDDEN:") {
				t.Errorf("UUID after context word %q not redacted: %s", word, out)
			}
		}
	})

	// 4. Luhn False Positives
	t.Run("Luhn False Positive suppression", func(t *testing.T) {
		// Just a 16-digit random number that happens to pass Luhn (we need a valid Luhn for this test)
		luhnValid := "4556737586899855"
		input := fmt.Sprintf("TraceId=%s", luhnValid)

		output := ScanAndRedact(input)
		// It should NOT redact because no CC context and threshold is high
		if output != input {
			t.Errorf("Expected plain traceId pass-through for Luhn FP, got %s", output)
		}

		// But WITH context it should redact
		inputWithCtx := fmt.Sprintf("visa card %s provided", luhnValid)
		outputCtx := ScanAndRedact(inputWithCtx)
		if outputCtx == inputWithCtx {
			t.Errorf("Expected Luhn redaction for context string, got %s", outputCtx)
		}
	})
}
