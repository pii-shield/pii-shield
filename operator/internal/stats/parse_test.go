package stats

import "testing"

func TestParse(t *testing.T) {
	body := []byte(`# HELP piishield_redaction_events_total Total number of secrets redacted
# TYPE piishield_redaction_events_total counter
piishield_redaction_events_total{type="entropy"} 12
piishield_redaction_events_total{type="regex"} 3
piishield_processing_duration_seconds_bucket{le="0.001"} 90
piishield_processing_duration_seconds_count 100
piishield_processing_duration_seconds_sum 0.05
piishield_errors_total 1
piishield_audit_findings_total{type="luhn"} 2
piishield_audit_mode 0
piishield_config_revision_info{revision="7+3 \"quoted\" back\\slash"} 1
go_goroutines 9
garbage line without a value
piishield_redaction_events_total{type="broken} 5
`)
	s := parse(body)
	if s.lines != 100 || s.errors != 1 || s.redactions["entropy"] != 12 || s.redactions["regex"] != 3 || s.auditFindings["luhn"] != 2 || s.audit {
		t.Errorf("sample = %+v", s)
	}
	if !s.haveRevision || s.revision != `7+3 "quoted" back\slash` {
		t.Errorf("revision = %q (%v)", s.revision, s.haveRevision)
	}
	if len(s.redactions) != 2 {
		t.Errorf("a broken series must be skipped: %v", s.redactions)
	}
	if empty := parse(nil); empty.haveRevision || empty.lines != 0 {
		t.Errorf("empty body = %+v", empty)
	}
}

func TestSplitSeriesEdges(t *testing.T) {
	for _, line := range []string{
		"name_without_value",
		`name{a="unterminated} 1`,
		`name{a=unquoted} 1`,
		`name{a="x"}`,
		`name{a="x"} not-a-number`,
		"name not-a-number",
	} {
		if _, _, _, ok := splitSeries(line); ok {
			t.Errorf("%q accepted", line)
		}
	}
	name, labels, v, ok := splitSeries(`m{a="1",b="x\ny"} 2 1700000000`)
	if !ok || name != "m" || labels["b"] != "x\ny" || v != 2 {
		t.Errorf("with a timestamp: %s %v %v %v", name, labels, v, ok)
	}
}
