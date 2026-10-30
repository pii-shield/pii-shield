package main

import (
	"strings"
)

// Audit mode (PII_MODE=audit, #32) is the dry run of the sidecar: every line
// goes through the scanner as usual, but what is written out is the original
// line, byte for byte, and the redactions the scanner would have made are
// only counted (piishield_audit_lines_total{result},
// piishield_audit_findings_total{type}, and the stats summary when
// PII_STATS_LOG_INTERVAL is set). A team can run the sidecar on real traffic
// for a while, look at the counters, and only then switch to redact mode.
//
// What the counters hold is the fact of a finding and its detector, never
// the value, so audit mode does not record the secrets it saw. Nothing is
// dropped in audit mode: a line that panics the scanner and a stream that
// overflows the line buffer are both passed on or warned about, whatever
// PII_FAIL_POLICY says, because the mode's promise is an unchanged stream.
//
// In file mode the sidecar reads a file the application writes and cannot
// block it; in pipe and stdin modes the sidecar still sits in the stream's
// path, audit or not, and the documentation says so.

// auditMode is set once at start from PII_MODE and read on the hot path. It
// is a plain bool because it never changes after main has started reading.
var auditMode bool

const (
	modeRedact = "redact"
	modeAudit  = "audit"
)

// parseMode reads PII_MODE. Empty is redact; "audit" is the dry run; ok is
// false for anything else, and redact is returned with it so the caller can
// warn and carry on, as the other PII_* variables do.
func parseMode(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", modeRedact:
		return modeRedact, true
	case modeAudit:
		return modeAudit, true
	}
	return modeRedact, false
}

// overflowMarker is the stream marker for a line longer than the buffer:
// a DROP under a closed fail policy, a WARN otherwise. Audit mode never
// drops, so it always warns.
func overflowMarker(failPolicy string) string {
	if failPolicy == "closed" && !auditMode {
		return "[PII_SHIELD_DROP: BUFFER_OVERFLOW]"
	}
	return "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]"
}
