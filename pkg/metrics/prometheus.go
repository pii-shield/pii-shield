package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ProcessedBytesTotal tracks the total volume of logs processed.
	ProcessedBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "piishield_processed_bytes_total",
		Help: "Total volume of logs processed by the sidecar",
	})

	// RedactionEventsTotal counts how many redactions occurred, split by strategy.
	RedactionEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_redaction_events_total",
		Help: "Total number of secrets redacted",
	}, []string{"type"}) // Strictly using "entropy", "regex", "luhn", "signature" to avoid high cardinality

	// ProcessingDuration seconds tracks the time spent sanitizing logs.
	ProcessingDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "piishield_processing_duration_seconds",
		Help:    "Time spent sanitizing logs",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	})

	// ErrorsTotal tracks any parser or processing errors.
	ErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "piishield_errors_total",
		Help: "Total number of errors encountered during processing",
	})

	// ConfigReloadsTotal counts policy files (PII_CONFIG_FILE) loaded and
	// applied, the first load included.
	ConfigReloadsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "piishield_config_reloads_total",
		Help: "Total number of policy file loads that were applied",
	})

	// ConfigReloadErrorsTotal counts policy files rejected (unreadable,
	// invalid JSON, invalid pattern); the previous config stays in force.
	ConfigReloadErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "piishield_config_reload_errors_total",
		Help: "Total number of policy file loads that were rejected",
	})

	// ConfigLastReloadTimestamp is the Unix time of the last applied policy
	// file load; 0 until the first one.
	ConfigLastReloadTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "piishield_config_last_reload_timestamp_seconds",
		Help: "Unix time of the last applied policy file load",
	})

	// AuditLinesTotal counts the lines seen in audit mode (PII_MODE=audit),
	// by whether redaction would have changed them: "clean" or
	// "would_redact". In redact mode it stays at zero.
	AuditLinesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_audit_lines_total",
		Help: "Lines seen in audit mode, by whether redaction would have changed them",
	}, []string{"result"})

	// AuditFindingsTotal counts the redactions audit mode would have made,
	// by detector, with the same bounded type label as RedactionEventsTotal.
	// In audit mode RedactionEventsTotal stays at zero: nothing is redacted.
	AuditFindingsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_audit_findings_total",
		Help: "Redactions audit mode would have made, by detector",
	}, []string{"type"})

	// AuditMode is 1 while the sidecar runs in audit mode, 0 otherwise, so
	// a dashboard can tell the pods that watch from the pods that redact.
	AuditMode = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "piishield_audit_mode",
		Help: "1 while the sidecar runs in audit mode (PII_MODE=audit), 0 otherwise",
	})
)

// StartAudit marks the process as running in audit mode and creates the
// audit series at zero, so an audit sidecar that never sees a line still
// exports piishield_audit_lines_total and a rate() of zero can alert on it;
// a vector series otherwise appears only with its first increment.
func StartAudit() {
	AuditMode.Set(1)
	AuditLinesTotal.WithLabelValues("clean").Add(0)
	AuditLinesTotal.WithLabelValues("would_redact").Add(0)
}

// boundStrategy maps a scanner strategy to the fixed label set of the
// counters, so an unexpected value cannot add a label value.
func boundStrategy(strategyType string) string {
	switch strategyType {
	case "entropy", "regex", "luhn", "signature":
		return strategyType
	}
	return "unknown"
}

// IncrementRedaction provides a safe interface to increment redactions
// strictly bounding to specific values to avoid OOM or cardinality explosions.
func IncrementRedaction(strategyType string) {
	RedactionEventsTotal.WithLabelValues(boundStrategy(strategyType)).Inc()
}

// IncrementAuditFinding counts a redaction that audit mode would have made,
// with the same bounded label set as IncrementRedaction.
func IncrementAuditFinding(strategyType string) {
	AuditFindingsTotal.WithLabelValues(boundStrategy(strategyType)).Inc()
}

// RecordAuditLine counts a line seen in audit mode.
func RecordAuditLine(wouldRedact bool) {
	result := "clean"
	if wouldRedact {
		result = "would_redact"
	}
	AuditLinesTotal.WithLabelValues(result).Inc()
}
