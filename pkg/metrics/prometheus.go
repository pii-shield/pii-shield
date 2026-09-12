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
)

// IncrementRedaction provides a safe interface to increment redactions
// strictly bounding to specific values to avoid OOM or cardinality explosions.
func IncrementRedaction(strategyType string) {
	switch strategyType {
	case "entropy", "regex", "luhn", "signature":
	default:
		strategyType = "unknown"
	}
	RedactionEventsTotal.WithLabelValues(strategyType).Inc()
}
