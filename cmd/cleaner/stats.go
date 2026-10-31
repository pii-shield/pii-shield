package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// stats, when non-nil, accumulates redaction counts for the periodic value-metrics
// log summary (STR-2.2). It is enabled only when PII_STATS_LOG_INTERVAL is set to a
// positive duration, so default log output is unchanged.
var stats *statsCollector

// statsCollector aggregates redaction counts by strategy plus processed volume.
// All counters are atomic: recordRedaction runs on the scanner hot path (via
// RedactionCallback) and recordLine runs once per processed line.
type statsCollector struct {
	entropy   atomic.Uint64
	regex     atomic.Uint64
	luhn      atomic.Uint64
	signature atomic.Uint64
	key       atomic.Uint64
	other     atomic.Uint64
	lines     atomic.Uint64
	bytes     atomic.Uint64

	// wouldRedact counts the lines audit mode would have changed; it is
	// only written in audit mode, and the summary then reads differently.
	wouldRedact atomic.Uint64
}

func newStatsCollector() *statsCollector { return &statsCollector{} }

// recordRedaction maps a scanner strategy ("entropy", "regex", "luhn",
// "signature", "key") to a counter. Unknown strategies fall into "other" so new
// detectors are not lost.
func (s *statsCollector) recordRedaction(strategy string) {
	switch strategy {
	case "entropy":
		s.entropy.Add(1)
	case "regex":
		s.regex.Add(1)
	case "luhn":
		s.luhn.Add(1)
	case "signature":
		s.signature.Add(1)
	case "key":
		s.key.Add(1)
	default:
		s.other.Add(1)
	}
}

func (s *statsCollector) recordLine(n int) {
	s.lines.Add(1)
	if n > 0 {
		s.bytes.Add(uint64(n))
	}
}

// recordAuditLine notes, in audit mode, whether the line would have changed.
func (s *statsCollector) recordAuditLine(wouldRedact bool) {
	if wouldRedact {
		s.wouldRedact.Add(1)
	}
}

// summary renders a single human-readable log line with cumulative counts since
// process start. Labels describe the actual detection strategy — we do not claim
// semantic categories (e.g. "emails") the scanner does not track.
func (s *statsCollector) summary() string {
	entropy := s.entropy.Load()
	regex := s.regex.Load()
	luhn := s.luhn.Load()
	signature := s.signature.Load()
	key := s.key.Load()
	other := s.other.Load()
	total := entropy + regex + luhn + signature + key + other

	parts := []string{
		fmt.Sprintf("%s high-entropy secrets", withThousands(entropy)),
		fmt.Sprintf("%s pattern matches", withThousands(regex)),
		fmt.Sprintf("%s card numbers", withThousands(luhn)),
		fmt.Sprintf("%s signatures", withThousands(signature)),
		fmt.Sprintf("%s sensitive-key values", withThousands(key)),
	}
	if other > 0 {
		parts = append(parts, fmt.Sprintf("%s other", withThousands(other)))
	}

	lines := s.lines.Load()
	if auditMode {
		would := s.wouldRedact.Load()
		pct := 0.0
		if lines > 0 {
			pct = 100 * float64(would) / float64(lines)
		}
		return fmt.Sprintf("PII-Shield audit: %s would-be redactions (%s) in %s of %s lines (%.1f%%) / %s processed; nothing was changed",
			withThousands(total), strings.Join(parts, ", "), withThousands(would), withThousands(lines), pct, humanBytes(s.bytes.Load()))
	}
	return fmt.Sprintf("PII-Shield stats: %s redactions (%s) across %s lines / %s processed",
		withThousands(total), strings.Join(parts, ", "), withThousands(lines), humanBytes(s.bytes.Load()))
}

// parseStatsInterval returns the configured summary interval. An empty value
// disables the summary; an invalid or non-positive value also disables it (the
// caller logs the warning) rather than failing the log pipeline.
func parseStatsInterval(raw string) time.Duration {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// withThousands formats n with comma separators (1240 -> "1,240").
func withThousands(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
		if len(s) > pre {
			b.WriteByte(',')
		}
	}
	for i := pre; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return b.String()
}

// humanBytes renders a byte count as B/KB/MB/GB with one decimal place.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
