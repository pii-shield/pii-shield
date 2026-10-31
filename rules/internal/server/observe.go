package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// What the server tells about its own traffic: Prometheus metrics on a
// separate listener (MetricsHandler), and, with Config.AccessLog, one log
// line per request. Neither carries a secret: a token appears by its
// prefix, a session by the address it belongs to, and no header, cookie,
// query string or body is recorded.

var (
	metricsRegistry = prometheus.NewRegistry()

	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_rules_requests_total",
		Help: "HTTP requests by route pattern and status code.",
	}, []string{"route", "code"})
	requestSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "piishield_rules_request_duration_seconds",
		Help:    "Time to answer a request, by route pattern.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route"})
	policyPullsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_rules_policy_pulls_total",
		Help: "Successful policy.json pulls: new (200) or not_modified (304).",
	}, []string{"result"})
	reportsReceivedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "piishield_rules_reports_received_total",
		Help: "Stats reports accepted from clusters.",
	})
)

func init() {
	metricsRegistry.MustRegister(requestsTotal, requestSeconds, policyPullsTotal, reportsReceivedTotal,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// MetricsHandler serves the server's metrics in the Prometheus format. It
// belongs on a listener of its own (--metrics-listen), not on the public
// one.
func MetricsHandler() http.Handler {
	return promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{})
}

// reqInfo collects, while a request is served, what the access log names:
// the token prefix or the caller. Handlers fill it through the context.
type reqInfo struct {
	token string
	actor string
}

type reqInfoKey struct{}

func infoOf(r *http.Request) *reqInfo {
	if i, ok := r.Context().Value(reqInfoKey{}).(*reqInfo); ok {
		return i
	}
	return &reqInfo{}
}

// statusRecorder remembers the status a handler set. It only wraps
// WriteHeader: a handler that writes a body without one answers 200, which
// observe assumes when no status was set, and the body goes straight to the
// real writer.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

// observe serves the request through the mux and records it: the metrics
// always, the log line with Config.AccessLog. Health checks are counted but
// not logged.
func (s *Server) observe(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	info := &reqInfo{}
	r = r.WithContext(context.WithValue(r.Context(), reqInfoKey{}, info))
	rec := &statusRecorder{ResponseWriter: w}
	s.mux.ServeHTTP(rec, r)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	route := r.Pattern // set by the mux on this request
	if route == "" {
		route = "unmatched"
	}
	elapsed := time.Since(start)
	code := strconv.Itoa(rec.status)
	requestsTotal.WithLabelValues(route, code).Inc()
	requestSeconds.WithLabelValues(route).Observe(elapsed.Seconds())
	if !s.cfg.AccessLog || route == "GET /healthz" {
		return
	}
	attrs := []any{"method", r.Method, "path", r.URL.Path, "route", route, "status", rec.status,
		"ms", elapsed.Milliseconds(), "ip", s.clientIP(r)}
	if info.token != "" {
		attrs = append(attrs, "token", info.token)
	}
	if info.actor != "" {
		attrs = append(attrs, "actor", info.actor)
	}
	s.log.Info("request", attrs...)
}
