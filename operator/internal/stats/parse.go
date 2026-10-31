package stats

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// sample is what one read of a sidecar's /metrics gives the stats channel:
// running totals since the sidecar started, and the revision it runs.
type sample struct {
	lines         float64
	errors        float64
	redactions    map[string]float64
	auditFindings map[string]float64
	audit         bool
	revision      string
	haveRevision  bool
}

// The series the channel reads; everything else on the endpoint is skipped.
const (
	metricLines         = "piishield_processing_duration_seconds_count"
	metricErrors        = "piishield_errors_total"
	metricRedactions    = "piishield_redaction_events_total"
	metricAuditFindings = "piishield_audit_findings_total"
	metricAuditMode     = "piishield_audit_mode"
	metricRevision      = "piishield_config_revision_info"
)

// parse reads the Prometheus text format the sidecar serves. It is a small
// reader for the few series above, not a general parser: a line it does not
// understand is skipped, so a newer sidecar with more series still works.
func parse(body []byte) sample {
	s := sample{redactions: map[string]float64{}, auditFindings: map[string]float64{}}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		name, labels, value, ok := splitSeries(line)
		if !ok {
			continue
		}
		switch name {
		case metricLines:
			s.lines += value
		case metricErrors:
			s.errors += value
		case metricRedactions:
			s.redactions[labels["type"]] += value
		case metricAuditFindings:
			s.auditFindings[labels["type"]] += value
		case metricAuditMode:
			s.audit = value == 1
		case metricRevision:
			if value == 1 {
				s.revision, s.haveRevision = labels["revision"], true
			}
		}
	}
	return s
}

// splitSeries splits `name{a="x",b="y"} 12 [timestamp]`.
func splitSeries(line string) (string, map[string]string, float64, bool) {
	labels := map[string]string{}
	var name, rest string
	if i := strings.IndexByte(line, '{'); i >= 0 {
		name = line[:i]
		end, ok := readLabels(line[i+1:], labels)
		if !ok {
			return "", nil, 0, false
		}
		rest = line[i+1+end:]
	} else {
		sp := strings.IndexAny(line, " \t")
		if sp < 0 {
			return "", nil, 0, false
		}
		name, rest = line[:sp], line[sp:]
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", nil, 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "", nil, 0, false
	}
	return name, labels, v, true
}

// readLabels reads `a="x",b="y"}` into labels and returns the offset just
// past the closing brace. Values carry the format's escapes: \\, \" and \n.
func readLabels(s string, labels map[string]string) (int, bool) {
	i := 0
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == ',') {
			i++
		}
		if i < len(s) && s[i] == '}' {
			return i + 1, true
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 || i+eq+1 >= len(s) || s[i+eq+1] != '"' {
			return 0, false
		}
		key := strings.TrimSpace(s[i : i+eq])
		i += eq + 2
		var val strings.Builder
		for {
			if i >= len(s) {
				return 0, false
			}
			c := s[i]
			if c == '"' {
				i++
				break
			}
			if c == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case 'n':
					val.WriteByte('\n')
				default:
					val.WriteByte(s[i+1])
				}
				i += 2
				continue
			}
			val.WriteByte(c)
			i++
		}
		labels[key] = val.String()
	}
}
