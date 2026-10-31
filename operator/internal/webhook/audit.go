package webhook

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

// Audit mode (spec.auditMode, #32 part 2) sets PII_MODE=audit on the
// sidecar: it scans every line, writes it out unchanged and counts what it
// would have redacted. The counters are the point of the mode, so the
// webhook also turns the sidecar's Prometheus endpoint on, on a fixed port
// the pod must leave free, and an hourly summary in the sidecar's log for a
// cluster without Prometheus. Scraping the port is the cluster's business
// (a PodMonitor, or the prometheus.io annotations on the workload).

const (
	// AuditMetricsPort is the sidecar's metrics port in audit mode.
	AuditMetricsPort int32 = 9090
	// AuditMetricsPortName names that port on the sidecar container.
	AuditMetricsPortName = "pii-metrics"
	// auditStatsInterval is how often the sidecar logs its audit summary.
	auditStatsInterval = "1h"
)

// auditEnv is the sidecar environment audit mode adds on top of scannerEnv
// (which carries PII_MODE itself).
func auditEnv() []corev1.EnvVar {
	return append(metricsEnv(), corev1.EnvVar{Name: "PII_STATS_LOG_INTERVAL", Value: auditStatsInterval})
}

// metricsEnv turns the sidecar's counters on, on AuditMetricsPort. Audit
// mode needs them, and so does the stats channel (spec.stats), whose
// operator reads them from inside the cluster.
func metricsEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "PII_METRICS_ENABLED", Value: "true"},
		{Name: "PII_METRICS_PORT", Value: strconv.Itoa(int(AuditMetricsPort))},
	}
}
