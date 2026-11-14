package stats

import (
	"math"
	"strings"
	"testing"
)

// FuzzParse feeds the /metrics reader arbitrary bytes. The body comes from a
// sidecar inside a workload pod, so the workload can shape it: the reader
// must not panic or hang on it, must give the same sample for the same body,
// and must skip what it does not understand rather than fail the scrape.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"",
		"# HELP piishield_errors_total Errors\n# TYPE piishield_errors_total counter\npiishield_errors_total 3\n",
		"piishield_processing_duration_seconds_count 1200\n",
		`piishield_redaction_events_total{type="entropy"} 7` + "\n" + `piishield_redaction_events_total{type="signature"} 2` + "\n",
		`piishield_audit_findings_total{type="custom"} 4` + "\npiishield_audit_mode 1\n",
		`piishield_config_revision_info{revision="2026-11-13.1"} 1` + "\n",
		`piishield_config_revision_info{revision="a\"b\\c\nd"} 1 1700000000000`,
		`piishield_redaction_events_total{type="entropy",} 1`,
		`piishield_redaction_events_total{type="entropy"`,
		`piishield_redaction_events_total{type=entropy} 1`,
		`piishield_redaction_events_total{type="entropy\`,
		`piishield_redaction_events_total{="x"} 1`,
		`piishield_redaction_events_total{} NaN`,
		"piishield_errors_total +Inf\npiishield_errors_total -Inf\n",
		"piishield_errors_total -5\n",
		"piishield_errors_total 1e999\n",
		"piishield_errors_total\n",
		"piishield_errors_total\t9\r\n",
		"{} 1\n",
		"\xff\xfe{\xff=\"\xff\"} 1\n",
		"piishield_errors_total " + strings.Repeat("9", 400) + "\n",
		strings.Repeat("x", 70_000) + " 1\n",
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		s := parse(body)

		if s.redactions == nil || s.auditFindings == nil {
			t.Fatalf("parse(%q) returned a nil map", body)
		}
		if !s.haveRevision && s.revision != "" {
			t.Errorf("a revision %q without haveRevision for %q", s.revision, body)
		}
		// A body with none of the series names carries nothing to count.
		if !strings.Contains(string(body), "piishield_") {
			if s.lines != 0 || s.errors != 0 || len(s.redactions) != 0 || len(s.auditFindings) != 0 || s.audit || s.haveRevision {
				t.Errorf("a body without any piishield_ series produced %+v: %q", s, body)
			}
		}

		again := parse(body)
		if !sameSample(s, again) {
			t.Errorf("two reads of %q differ:\n%+v\n%+v", body, s, again)
		}
	})
}

// sameSample compares two samples, treating NaN as equal to itself: the text
// format allows NaN and reflect.DeepEqual would call two NaN totals different.
func sameSample(a, b sample) bool {
	eq := func(x, y float64) bool { return x == y || (math.IsNaN(x) && math.IsNaN(y)) }
	eqMap := func(x, y map[string]float64) bool {
		if len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !eq(v, w) {
				return false
			}
		}
		return true
	}
	return eq(a.lines, b.lines) && eq(a.errors, b.errors) &&
		eqMap(a.redactions, b.redactions) && eqMap(a.auditFindings, b.auditFindings) &&
		a.audit == b.audit && a.revision == b.revision && a.haveRevision == b.haveRevision
}
