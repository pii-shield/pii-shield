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

func TestAuditCounters(t *testing.T) {
	AuditFindingsTotal.Reset()
	AuditLinesTotal.Reset()

	IncrementAuditFinding("signature")
	IncrementAuditFinding("signature")
	IncrementAuditFinding("made-up")
	RecordAuditLine(true)
	RecordAuditLine(false)
	RecordAuditLine(false)

	if n := testutil.ToFloat64(AuditFindingsTotal.WithLabelValues("signature")); n != 2 {
		t.Errorf("signature findings = %v, want 2", n)
	}
	if n := testutil.ToFloat64(AuditFindingsTotal.WithLabelValues("unknown")); n != 1 {
		t.Errorf("unknown findings = %v, want 1", n)
	}
	if n := testutil.ToFloat64(AuditLinesTotal.WithLabelValues("would_redact")); n != 1 {
		t.Errorf("would_redact lines = %v, want 1", n)
	}
	if n := testutil.ToFloat64(AuditLinesTotal.WithLabelValues("clean")); n != 2 {
		t.Errorf("clean lines = %v, want 2", n)
	}
}

func TestStartAuditCreatesTheSeries(t *testing.T) {
	AuditLinesTotal.Reset()
	AuditMode.Set(0)
	if n := testutil.CollectAndCount(AuditLinesTotal); n != 0 {
		t.Fatalf("series before StartAudit = %d, want 0", n)
	}
	StartAudit()
	if n := testutil.CollectAndCount(AuditLinesTotal); n != 2 {
		t.Errorf("series after StartAudit = %d, want 2 (clean, would_redact)", n)
	}
	if v := testutil.ToFloat64(AuditMode); v != 1 {
		t.Errorf("piishield_audit_mode = %v, want 1", v)
	}
	if v := testutil.ToFloat64(AuditLinesTotal.WithLabelValues("clean")); v != 0 {
		t.Errorf("clean series starts at %v, want 0", v)
	}
}
