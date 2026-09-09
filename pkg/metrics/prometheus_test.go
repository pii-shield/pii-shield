package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestIncrementRedaction(t *testing.T) {
	// Reset counters if needed (for clean tests)
	RedactionEventsTotal.Reset()

	// Test valid strategies
	IncrementRedaction("entropy")
	IncrementRedaction("regex")
	IncrementRedaction("luhn")
	IncrementRedaction("signature")

	// Test invalid strategy mapping to "unknown"
	IncrementRedaction("malicious-label")

	// Validate count for "entropy"
	if count := testutil.ToFloat64(RedactionEventsTotal.WithLabelValues("entropy")); count != 1 {
		t.Errorf("Expected 1 for entropy, got %v", count)
	}

	// Validate count for "regex"
	if count := testutil.ToFloat64(RedactionEventsTotal.WithLabelValues("regex")); count != 1 {
		t.Errorf("Expected 1 for regex, got %v", count)
	}

	// Validate count for "luhn"
	if count := testutil.ToFloat64(RedactionEventsTotal.WithLabelValues("luhn")); count != 1 {
		t.Errorf("Expected 1 for luhn, got %v", count)
	}

	// Validate count for "signature"
	if count := testutil.ToFloat64(RedactionEventsTotal.WithLabelValues("signature")); count != 1 {
		t.Errorf("Expected 1 for signature, got %v", count)
	}

	// Validate fallback count for "unknown"
	if count := testutil.ToFloat64(RedactionEventsTotal.WithLabelValues("unknown")); count != 1 {
		t.Errorf("Expected 1 for unknown, got %v", count)
	}
}
