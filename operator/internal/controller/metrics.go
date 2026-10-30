package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Operator metrics for spec.remoteConfig, served on the manager's metrics
// endpoint next to the controller-runtime ones. The chart's PrometheusRule
// alerts when a policy's last successful pull is older than three intervals.
var (
	remoteSyncTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_operator_remote_sync_total",
		Help: "Pulls of spec.remoteConfig by result: updated, not_modified or error.",
	}, []string{"result"})

	remoteSyncLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "piishield_operator_remote_sync_last_success_timestamp_seconds",
		Help: "Unix time of the last successful pull (a new file or 304 Not Modified) per policy.",
	}, []string{"namespace", "policy"})

	remoteSyncInterval = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "piishield_operator_remote_sync_interval_seconds",
		Help: "Configured pull interval per policy, so an alert can compare the age of the last success with it.",
	}, []string{"namespace", "policy"})
)

func init() {
	metrics.Registry.MustRegister(remoteSyncTotal, remoteSyncLastSuccess, remoteSyncInterval)
}

// forgetRemoteMetrics drops the per-policy gauges of a policy that was
// deleted or lost its remote source, so a stale timestamp cannot alert.
func forgetRemoteMetrics(namespace, name string) {
	remoteSyncLastSuccess.DeleteLabelValues(namespace, name)
	remoteSyncInterval.DeleteLabelValues(namespace, name)
}
