package audit

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/pii-shield/pii-shield/v3/pkg/metrics"
	"github.com/pii-shield/pii-shield/v3/pkg/scanner"
)

func TestAuditorCountsWithoutRedacting(t *testing.T) {
	old := scanner.RedactionCallback
	t.Cleanup(func() { scanner.RedactionCallback = old })
	metrics.AuditLinesTotal.Reset()
	metrics.AuditFindingsTotal.Reset()
	metrics.RedactionEventsTotal.Reset()

	a := New()
	if v := testutil.ToFloat64(metrics.AuditMode); v != 1 {
		t.Errorf("piishield_audit_mode = %v, want 1", v)
	}
	lines := []string{
		"Log line with key=AKIAIOSFODNN7EXAMPLE and token=abcDEF123456",
		"GET /healthz 200 in 1ms",
		`{"password": "hunter2hunter2"}`,
	}
	for _, l := range lines {
		a.Line(l)
	}
	if a.Lines() != 3 || a.WouldRedact() != 2 {
		t.Errorf("lines = %d, wouldRedact = %d; want 3 and 2", a.Lines(), a.WouldRedact())
	}
	if n := testutil.ToFloat64(metrics.AuditLinesTotal.WithLabelValues("would_redact")); n != 2 {
		t.Errorf("would_redact series = %v, want 2", n)
	}
	if n := testutil.ToFloat64(metrics.AuditLinesTotal.WithLabelValues("clean")); n != 1 {
		t.Errorf("clean series = %v, want 1", n)
	}
	if n := testutil.ToFloat64(metrics.AuditFindingsTotal.WithLabelValues("signature")); n < 1 {
		t.Errorf("the AWS key must be a signature finding, got %v", n)
	}
	for _, typ := range []string{"entropy", "regex", "luhn", "signature", "unknown"} {
		if n := testutil.ToFloat64(metrics.RedactionEventsTotal.WithLabelValues(typ)); n != 0 {
			t.Errorf("redaction_events_total{%s} = %v in the audit agent, want 0", typ, n)
		}
	}
	s := a.Summary()
	for _, want := range []string{"PII-Shield audit:", "in 2 of 3 lines (66.7%)", "nothing was changed", "signatures"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q: %s", want, s)
		}
	}
}
