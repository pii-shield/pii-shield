// Package audit runs the scanner over the lines the probe saw and keeps
// the counts: it is the sidecar's audit mode (PII_MODE=audit) without the
// output, because the agent never writes the stream, it only watched it.
package audit

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/pii-shield/pii-shield/v3/pkg/metrics"
	"github.com/pii-shield/pii-shield/v3/pkg/scanner"
)

// EventsTotal counts the records read from the kernel by what happened to
// them: "ok", "truncated" (a write longer than the kernel side copies, or
// a writev with more iovecs than it walks) and "overflow" (a stream that
// reached the line limit without a newline). Ring buffer drops are read
// from the kernel map and reported through DropsTotal.
var EventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "piishield_ebpf_events_total",
	Help: "Writes copied out of the kernel by the audit agent, by outcome",
}, []string{"result"})

// Attached is 1 once the eBPF program is loaded and attached, 0 when it
// could not be loaded and the agent runs without it (fail open).
var Attached = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "piishield_ebpf_attached",
	Help: "1 when the eBPF program is loaded and attached, 0 when the agent runs without it",
})

// DropsTotal is the number of records the ring buffer had no room for.
var DropsTotal = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "piishield_ebpf_dropped_records",
	Help: "Records the ring buffer had no room for since the agent started",
})

// Auditor counts lines and findings. One per agent.
type Auditor struct {
	lines       atomic.Uint64
	wouldRedact atomic.Uint64
	bytes       atomic.Uint64
	findings    atomic.Uint64
	byType      [5]atomic.Uint64
}

var typeNames = [5]string{"entropy", "regex", "luhn", "signature", "other"}

// New wires the scanner's callback to the findings counters and marks the
// process as running in audit mode (piishield_audit_mode = 1, the audit
// series created at zero), the same way the sidecar does.
func New() *Auditor {
	a := &Auditor{}
	scanner.RedactionCallback = func(strategy string) {
		metrics.IncrementAuditFinding(strategy)
		a.findings.Add(1)
		i := 4
		for j, n := range typeNames[:4] {
			if n == strategy {
				i = j
				break
			}
		}
		a.byType[i].Add(1)
	}
	metrics.StartAudit()
	return a
}

// Line scans one line and counts whether redaction would have changed it.
// The scanned text is thrown away.
func (a *Auditor) Line(line string) {
	a.lines.Add(1)
	a.bytes.Add(uint64(len(line)))
	metrics.ProcessedBytesTotal.Add(float64(len(line)))
	changed := scanner.ScanAndRedact(line) != line
	if changed {
		a.wouldRedact.Add(1)
	}
	metrics.RecordAuditLine(changed)
}

// Lines is the number of lines seen so far.
func (a *Auditor) Lines() uint64 { return a.lines.Load() }

// WouldRedact is the number of lines redaction would have changed.
func (a *Auditor) WouldRedact() uint64 { return a.wouldRedact.Load() }

// Summary is one log line with the counts since start, worded like the
// sidecar's audit summary.
func (a *Auditor) Summary() string {
	lines := a.lines.Load()
	would := a.wouldRedact.Load()
	pct := 0.0
	if lines > 0 {
		pct = 100 * float64(would) / float64(lines)
	}
	parts := []string{
		fmt.Sprintf("%d high-entropy secrets", a.byType[0].Load()),
		fmt.Sprintf("%d pattern matches", a.byType[1].Load()),
		fmt.Sprintf("%d card numbers", a.byType[2].Load()),
		fmt.Sprintf("%d signatures", a.byType[3].Load()),
	}
	if other := a.byType[4].Load(); other > 0 {
		parts = append(parts, fmt.Sprintf("%d other", other))
	}
	return fmt.Sprintf("PII-Shield audit: %d would-be redactions (%s) in %d of %d lines (%.1f%%) / %d bytes seen; nothing was changed",
		a.findings.Load(), strings.Join(parts, ", "), would, lines, pct, a.bytes.Load())
}
