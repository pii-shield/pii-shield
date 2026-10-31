// Package stats is the operator's stats channel (spec.stats): it reads the
// counters of a policy's sidecars inside the cluster every Period, keeps the
// growth since the last report, and every spec.stats.intervalSeconds POSTs
// one summary to the receiver. Only counters leave the cluster, and only the
// operator sends: no sidecar needs a way out or a credential.
//
// A sidecar's counters are totals since it started. The reporter keeps the
// last value it read per pod and adds the difference; a lower value means
// the sidecar restarted and counts from zero again. A pod's first read only
// sets the starting point, so an operator restart never counts the same
// lines twice; the cost is that a pod living less than one Period is missed.
package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
	"github.com/pii-shield/pii-shield/operator/internal/remoterules"
)

// +kubebuilder:rbac:groups="",resources=pods,verbs=list

// Schema names the report format; a receiver checks it.
const Schema = "pii-shield-stats-v1"

const (
	// DefaultPeriod is how often the counters are read.
	DefaultPeriod = 30 * time.Second
	// DefaultInterval and MinInterval bound spec.stats.intervalSeconds.
	DefaultInterval = 5 * time.Minute
	MinInterval     = time.Minute
	// metricsPort and metricsPortName are where the webhook opens the
	// sidecar's counters (webhook.AuditMetricsPort and its name).
	metricsPort     = 9090
	metricsPortName = "pii-metrics"
	// scrapeTimeout bounds one read of a sidecar; scrapeParallel bounds how
	// many run at once.
	scrapeTimeout  = 2 * time.Second
	scrapeParallel = 8
	maxScrapeBody  = 1 << 20

	labelInject      = "pii-shield.io/inject"
	annotationPolicy = "pii-shield.io/policy"
)

// Report is the JSON body sent to the receiver. Counters only.
type Report struct {
	Schema  string    `json:"schema"`
	Cluster string    `json:"cluster,omitempty"`
	Policy  string    `json:"policy"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	// Mode is "redact" or "audit" (spec.auditMode).
	Mode          string `json:"mode"`
	PodsReporting int    `json:"podsReporting"`
	PodsTotal     int    `json:"podsTotal"`
	// Revisions counts the reporting pods by the rule revision they run.
	Revisions map[string]int `json:"revisions"`
	// Remote is the last good pull of spec.remoteConfig, if any.
	Remote *RemoteRef `json:"remote,omitempty"`
	// Lines, Errors, Redactions and AuditFindings grew by this much between
	// From and To; Redactions and AuditFindings are by detector type.
	Lines         int64            `json:"lines"`
	Errors        int64            `json:"errors"`
	Redactions    map[string]int64 `json:"redactions"`
	AuditFindings map[string]int64 `json:"auditFindings,omitempty"`
}

// RemoteRef says which remote rules the operator last accepted.
type RemoteRef struct {
	Revision    string `json:"revision,omitempty"`
	Publication int64  `json:"publication,omitempty"`
	SignedBy    string `json:"signedBy,omitempty"`
}

// Reporter is the stats channel; it runs on the leader only.
type Reporter struct {
	// Client reads policies and patches their status.
	Client client.Client
	// APIReader lists pods and reads Secrets without caching them.
	APIReader client.Reader
	// Period is how often the counters are read; zero means DefaultPeriod.
	Period time.Duration
	// Scrape reads one sidecar's /metrics; nil means plain HTTP to the pod.
	Scrape func(ctx context.Context, url string) ([]byte, error)
	// Send posts a report; nil means remoterules.Post.
	Send func(ctx context.Context, src remoterules.Source, body []byte) error
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu    sync.Mutex
	state map[types.NamespacedName]*policyState
}

type totals struct {
	lines, errors             float64
	redactions, auditFindings map[string]float64
}

func newTotals() totals {
	return totals{redactions: map[string]float64{}, auditFindings: map[string]float64{}}
}

type policyState struct {
	pods          map[types.UID]sample
	acc           totals
	windowStart   time.Time
	revisions     map[string]int
	podsReporting int
	podsTotal     int
	lastStatus    corev1alpha1.StatsStatus
}

var (
	reportsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "piishield_operator_stats_reports_total",
		Help: "Stats reports by result: sent or error.",
	}, []string{"result"})
	podsReportingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "piishield_operator_stats_pods_reporting",
		Help: "Pods of a policy whose counters were read at the latest pass.",
	}, []string{"namespace", "policy"})
)

func init() {
	metrics.Registry.MustRegister(reportsTotal, podsReportingGauge)
}

// NeedLeaderElection keeps the channel on one replica, so a report is sent
// once.
func (r *Reporter) NeedLeaderElection() bool { return true }

// Start runs a pass every Period until ctx ends.
func (r *Reporter) Start(ctx context.Context) error {
	period := r.Period
	if period <= 0 {
		period = DefaultPeriod
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.Pass(ctx)
		}
	}
}

func (r *Reporter) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Interval returns the report interval for intervalSeconds.
func Interval(seconds int32) time.Duration {
	if seconds <= 0 {
		return DefaultInterval
	}
	return max(time.Duration(seconds)*time.Second, MinInterval)
}

// Pass reads every stats-enabled policy's pods once and sends the reports
// that are due.
func (r *Reporter) Pass(ctx context.Context) {
	log := logf.FromContext(ctx).WithName("stats")
	var list corev1alpha1.PiiPolicyList
	if err := r.Client.List(ctx, &list); err != nil {
		log.Error(err, "list policies")
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == nil {
		r.state = map[types.NamespacedName]*policyState{}
	}
	seen := map[types.NamespacedName]bool{}
	for i := range list.Items {
		p := &list.Items[i]
		if p.Spec.Stats == nil {
			continue
		}
		key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
		seen[key] = true
		st := r.state[key]
		if st == nil {
			st = &policyState{pods: map[types.UID]sample{}, acc: newTotals(), windowStart: r.now()}
			r.state[key] = st
		}
		r.passPolicy(ctx, p, st)
	}
	for key := range r.state {
		if !seen[key] {
			delete(r.state, key)
			podsReportingGauge.DeleteLabelValues(key.Namespace, key.Name)
		}
	}
}

func (r *Reporter) passPolicy(ctx context.Context, p *corev1alpha1.PiiPolicy, st *policyState) {
	status := st.lastStatus
	pods, err := r.policyPods(ctx, p)
	if err != nil {
		status.LastError = "list pods: " + err.Error()
		r.patchStatus(ctx, p, st, status)
		return
	}
	samples := r.scrapeAll(ctx, pods)
	alive := map[types.UID]bool{}
	revisions := map[string]int{}
	for i, pod := range pods {
		s, ok := samples[i]
		if !ok {
			continue
		}
		alive[pod.UID] = true
		if s.haveRevision {
			revisions[s.revision]++
		} else {
			revisions[""]++
		}
		prev, known := st.pods[pod.UID]
		st.pods[pod.UID] = s
		if !known {
			continue // the first read only sets the starting point
		}
		st.acc.lines += grow(prev.lines, s.lines)
		st.acc.errors += grow(prev.errors, s.errors)
		for k, v := range s.redactions {
			st.acc.redactions[k] += grow(prev.redactions[k], v)
		}
		for k, v := range s.auditFindings {
			st.acc.auditFindings[k] += grow(prev.auditFindings[k], v)
		}
	}
	for uid := range st.pods {
		if !alive[uid] {
			delete(st.pods, uid)
		}
	}
	st.revisions, st.podsReporting, st.podsTotal = revisions, len(alive), len(pods)
	podsReportingGauge.WithLabelValues(p.Namespace, p.Name).Set(float64(len(alive)))
	status.PodsReporting, status.PodsTotal = int32(len(alive)), int32(len(pods))

	now := r.now()
	if now.Sub(st.windowStart) >= Interval(p.Spec.Stats.IntervalSeconds) {
		if err := r.send(ctx, p, st, now); err != nil {
			reportsTotal.WithLabelValues("error").Inc()
			status.LastError = err.Error()
			logf.FromContext(ctx).WithName("stats").Info("stats report not sent; the counts are kept for the next one",
				"policy", p.Namespace+"/"+p.Name, "err", err.Error())
		} else {
			reportsTotal.WithLabelValues("sent").Inc()
			sent := metav1.NewTime(now)
			status.LastReportTime, status.LastError = &sent, ""
			st.acc, st.windowStart = newTotals(), now
		}
	}
	r.patchStatus(ctx, p, st, status)
}

// grow is how much a counter grew: the difference, or the whole new value
// after a restart reset it.
func grow(prev, cur float64) float64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// policyPods returns the running pods injected for the policy that expose
// the counters port.
func (r *Reporter) policyPods(ctx context.Context, p *corev1alpha1.PiiPolicy) ([]corev1.Pod, error) {
	var pods corev1.PodList
	if err := r.APIReader.List(ctx, &pods, client.InNamespace(p.Namespace), client.MatchingLabels{labelInject: "true"}); err != nil {
		return nil, err
	}
	var out []corev1.Pod
	for _, pod := range pods.Items {
		name := pod.Annotations[annotationPolicy]
		if name == "" {
			name = "default"
		}
		if name != p.Name || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" {
			continue
		}
		out = append(out, pod)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func hasMetricsPort(pod *corev1.Pod) bool {
	for _, cs := range [][]corev1.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for _, c := range cs {
			for _, port := range c.Ports {
				if port.Name == metricsPortName {
					return true
				}
			}
		}
	}
	return false
}

// scrapeAll reads the pods' counters, a few at a time; the result is keyed
// by the pod's index and lacks the pods that could not be read.
func (r *Reporter) scrapeAll(ctx context.Context, pods []corev1.Pod) map[int]sample {
	scrape := r.Scrape
	if scrape == nil {
		scrape = httpScrape
	}
	out := map[int]sample{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, scrapeParallel)
	for i := range pods {
		if !hasMetricsPort(&pods[i]) {
			continue
		}
		url := "http://" + net.JoinHostPort(pods[i].Status.PodIP, strconv.Itoa(metricsPort)) + "/metrics"
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, url string) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, scrapeTimeout)
			defer cancel()
			body, err := scrape(cctx, url)
			if err != nil {
				return
			}
			s := parse(body)
			mu.Lock()
			out[i] = s
			mu.Unlock()
		}(i, url)
	}
	wg.Wait()
	return out
}

func httpScrape(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxScrapeBody))
}

// send builds the report of the window that ends now and posts it.
func (r *Reporter) send(ctx context.Context, p *corev1alpha1.PiiPolicy, st *policyState, now time.Time) error {
	sc := p.Spec.Stats
	rep := Report{
		Schema: Schema, Cluster: sc.ClusterName, Policy: p.Namespace + "/" + p.Name,
		From: st.windowStart.UTC(), To: now.UTC(), Mode: "redact",
		PodsReporting: st.podsReporting, PodsTotal: st.podsTotal, Revisions: st.revisions,
		Lines: int64(st.acc.lines), Errors: int64(st.acc.errors), Redactions: map[string]int64{},
	}
	if rep.Revisions == nil {
		rep.Revisions = map[string]int{}
	}
	if p.Spec.AuditMode {
		rep.Mode = "audit"
		rep.AuditFindings = map[string]int64{}
		for k, v := range st.acc.auditFindings {
			rep.AuditFindings[k] = int64(v)
		}
	}
	for k, v := range st.acc.redactions {
		rep.Redactions[k] = int64(v)
	}
	if rs := p.Status.Remote; rs != nil {
		rep.Remote = &RemoteRef{Revision: rs.Revision, Publication: rs.Publication, SignedBy: rs.SignedBy}
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	src := remoterules.Source{URL: sc.URL, AllowInsecure: sc.AllowInsecure}
	if sc.HeaderSecretRef != nil {
		v, err := r.secretValue(ctx, p.Namespace, sc.HeaderSecretRef)
		if err != nil {
			return fmt.Errorf("headerSecretRef: %w", err)
		}
		src.Authorization = strings.TrimSpace(string(v))
	}
	if sc.CABundleSecretRef != nil {
		v, err := r.secretValue(ctx, p.Namespace, sc.CABundleSecretRef)
		if err != nil {
			return fmt.Errorf("caBundleSecretRef: %w", err)
		}
		src.CABundle = v
	}
	sendFn := r.Send
	if sendFn == nil {
		sendFn = remoterules.Post
	}
	return sendFn(ctx, src, body)
}

func (r *Reporter) secretValue(ctx context.Context, namespace string, ref *corev1.SecretKeySelector) ([]byte, error) {
	secret := &corev1.Secret{}
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("secret %s/%s not found", namespace, ref.Name)
		}
		return nil, fmt.Errorf("secret %s/%s: %w", namespace, ref.Name, err)
	}
	v, ok := secret.Data[ref.Key]
	if !ok || len(v) == 0 {
		return nil, fmt.Errorf("secret %s/%s has no key %q", namespace, ref.Name, ref.Key)
	}
	return v, nil
}

// patchStatus writes status.stats when it changed, with a merge patch that
// touches nothing else, so it never races the reconciler's conditions.
func (r *Reporter) patchStatus(ctx context.Context, p *corev1alpha1.PiiPolicy, st *policyState, status corev1alpha1.StatsStatus) {
	if statusEqual(st.lastStatus, status) {
		return
	}
	// Every field is spelled out, an empty one as null: a merge patch
	// leaves a field it does not mention as it was, so a cleared error
	// would otherwise stay.
	fields := map[string]any{"lastReportTime": nil, "lastError": nil, "podsReporting": status.PodsReporting, "podsTotal": status.PodsTotal}
	if status.LastReportTime != nil {
		fields["lastReportTime"] = status.LastReportTime
	}
	if status.LastError != "" {
		fields["lastError"] = status.LastError
	}
	body, err := json.Marshal(map[string]any{"status": map[string]any{"stats": fields}})
	if err == nil {
		err = r.Client.Status().Patch(ctx, p, client.RawPatch(types.MergePatchType, body))
	}
	if err != nil && !apierrors.IsNotFound(err) {
		logf.FromContext(ctx).WithName("stats").Error(err, "patch status.stats", "policy", p.Namespace+"/"+p.Name)
		return
	}
	st.lastStatus = status
}

func statusEqual(a, b corev1alpha1.StatsStatus) bool {
	if a.LastError != b.LastError || a.PodsReporting != b.PodsReporting || a.PodsTotal != b.PodsTotal {
		return false
	}
	if (a.LastReportTime == nil) != (b.LastReportTime == nil) {
		return false
	}
	return a.LastReportTime == nil || a.LastReportTime.Equal(b.LastReportTime)
}
