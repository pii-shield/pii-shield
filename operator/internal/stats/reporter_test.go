package stats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
	"github.com/pii-shield/pii-shield/operator/internal/remoterules"
)

const (
	testNS   = "apps"
	testMode = "file"
)

// fakePods serves a /metrics body per pod IP and records sent reports.
type fakePods struct {
	mu      sync.Mutex
	bodies  map[string]string
	sent    []Report
	sentSrc []remoterules.Source
	sendErr error
}

func (f *fakePods) set(ip string, lines, entropy int, revision string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies[ip] = fmt.Sprintf("piishield_processing_duration_seconds_count %d\npiishield_redaction_events_total{type=\"entropy\"} %d\npiishield_config_revision_info{revision=%q} 1\n", lines, entropy, revision)
}

func (f *fakePods) scrape(_ context.Context, url string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ip, b := range f.bodies {
		if strings.Contains(url, "//"+ip+":9090/") {
			return []byte(b), nil
		}
	}
	return nil, errors.New("connection refused")
}

func (f *fakePods) send(_ context.Context, src remoterules.Source, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	var r Report
	if err := json.Unmarshal(body, &r); err != nil {
		return err
	}
	f.sent, f.sentSrc = append(f.sent, r), append(f.sentSrc, src)
	return nil
}

func pod(name, ip, policy string, withPort bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNS, UID: types.UID("uid-" + name),
			Labels: map[string]string{"pii-shield.io/inject": "true"}, Annotations: map[string]string{}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip},
	}
	if policy != "" {
		p.Annotations["pii-shield.io/policy"] = policy
	}
	if withPort {
		p.Spec.InitContainers = []corev1.Container{{Name: "pii-shield", Ports: []corev1.ContainerPort{{Name: "pii-metrics", ContainerPort: 9090}}}}
	}
	return p
}

func TestReporterCountsGrowthAndSends(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	policy := &corev1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "central", Namespace: testNS},
		Spec: corev1alpha1.PiiPolicySpec{InjectionMode: testMode, Stats: &corev1alpha1.StatsConfig{
			URL: "https://rules.example.test/v1/acme/payments/report", IntervalSeconds: 60, ClusterName: "prod-eu",
			HeaderSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "stats-token"}, Key: "authorization"},
		}},
		Status: corev1alpha1.PiiPolicyStatus{Remote: &corev1alpha1.RemoteStatus{Revision: "4", Publication: 9, SignedBy: "abcd"}},
	}
	other := &corev1alpha1.PiiPolicy{ObjectMeta: metav1.ObjectMeta{Name: "quiet", Namespace: testNS}, Spec: corev1alpha1.PiiPolicySpec{InjectionMode: testMode}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "stats-token", Namespace: testNS}, Data: map[string][]byte{"authorization": []byte("Bearer pss_x\n")}}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithRuntimeObjects(policy, other, secret,
			pod("a", "10.0.0.1", "central", true),
			pod("b", "10.0.0.2", "central", true),
			pod("old", "10.0.0.3", "central", false), // injected before stats: no port
			pod("elsewhere", "10.0.0.4", "", true),   // policy "default"
		).WithStatusSubresource(&corev1alpha1.PiiPolicy{}).Build()

	f := &fakePods{bodies: map[string]string{}}
	f.set("10.0.0.1", 100, 10, "4+1")
	f.set("10.0.0.2", 50, 5, "4+1")
	f.set("10.0.0.4", 999, 999, "x")
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	r := &Reporter{Client: c, APIReader: c, Scrape: f.scrape, Send: f.send, Now: func() time.Time { return now }}

	// First pass: starting points only, nothing to send yet.
	r.Pass(ctx)
	if len(f.sent) != 0 {
		t.Fatalf("sent before the interval: %+v", f.sent)
	}
	// Growth: a +20 lines/+2, b restarted (counts from 0 again: 7 lines, 1).
	now = now.Add(30 * time.Second)
	f.set("10.0.0.1", 120, 12, "4+1")
	f.set("10.0.0.2", 7, 1, "5+1")
	r.Pass(ctx)
	// Interval reached: the report covers both passes' growth.
	now = now.Add(30 * time.Second)
	f.set("10.0.0.1", 130, 13, "4+1")
	r.Pass(ctx)
	if len(f.sent) != 1 {
		t.Fatalf("reports sent = %d", len(f.sent))
	}
	rep := f.sent[0]
	if rep.Schema != Schema || rep.Cluster != "prod-eu" || rep.Policy != "apps/central" || rep.Mode != "redact" {
		t.Errorf("header %+v", rep)
	}
	if rep.Lines != 20+7+10 || rep.Redactions["entropy"] != 2+1+1 {
		t.Errorf("counts lines=%d redactions=%v", rep.Lines, rep.Redactions)
	}
	if rep.PodsReporting != 2 || rep.PodsTotal != 3 || rep.Revisions["4+1"] != 1 || rep.Revisions["5+1"] != 1 {
		t.Errorf("pods %d/%d revisions %v", rep.PodsReporting, rep.PodsTotal, rep.Revisions)
	}
	if rep.Remote == nil || rep.Remote.Publication != 9 || rep.Remote.SignedBy != "abcd" {
		t.Errorf("remote %+v", rep.Remote)
	}
	if f.sentSrc[0].Authorization != "Bearer pss_x" {
		t.Errorf("authorization %q", f.sentSrc[0].Authorization)
	}
	if rep.To.Sub(rep.From) != time.Minute {
		t.Errorf("window %v to %v", rep.From, rep.To)
	}
	got := &corev1alpha1.PiiPolicy{}
	_ = c.Get(ctx, client.ObjectKeyFromObject(policy), got)
	if got.Status.Stats == nil || got.Status.Stats.LastReportTime == nil || got.Status.Stats.PodsReporting != 2 || got.Status.Stats.PodsTotal != 3 || got.Status.Stats.LastError != "" {
		t.Errorf("status.stats = %+v", got.Status.Stats)
	}
	if got.Status.Remote == nil || got.Status.Remote.Publication != 9 {
		t.Error("the status patch must leave status.remote alone")
	}

	// A failed send keeps the counts for the next report.
	f.sendErr = errors.New("HTTP 503")
	now = now.Add(time.Minute)
	f.set("10.0.0.1", 140, 13, "4+1")
	r.Pass(ctx)
	_ = c.Get(ctx, client.ObjectKeyFromObject(policy), got)
	if got.Status.Stats.LastError != "HTTP 503" {
		t.Errorf("status after a failed send: %+v", got.Status.Stats)
	}
	f.sendErr = nil
	now = now.Add(30 * time.Second)
	f.set("10.0.0.1", 145, 13, "4+1")
	r.Pass(ctx)
	if len(f.sent) != 2 || f.sent[1].Lines != 15 {
		t.Errorf("the report after a failure must carry the kept counts: %+v", f.sent)
	}
	_ = c.Get(ctx, client.ObjectKeyFromObject(policy), got)
	if got.Status.Stats.LastError != "" {
		t.Errorf("a success clears the error: %+v", got.Status.Stats)
	}

	// Stats turned off: the policy's state is dropped.
	_ = c.Get(ctx, client.ObjectKeyFromObject(policy), got)
	got.Spec.Stats = nil
	_ = c.Update(ctx, got)
	r.Pass(ctx)
	if len(r.state) != 0 {
		t.Errorf("state kept for a policy without stats: %v", r.state)
	}
}

func TestReporterSendErrorsNameTheSecret(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	policy := &corev1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "central", Namespace: testNS},
		Spec: corev1alpha1.PiiPolicySpec{InjectionMode: testMode, AuditMode: true, Stats: &corev1alpha1.StatsConfig{
			URL: "https://x.test/report", HeaderSecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "missing"}, Key: "k"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(policy).WithStatusSubresource(&corev1alpha1.PiiPolicy{}).Build()
	f := &fakePods{bodies: map[string]string{}}
	now := time.Now()
	r := &Reporter{Client: c, APIReader: c, Scrape: f.scrape, Send: f.send, Now: func() time.Time { return now }}
	r.Pass(ctx)
	now = now.Add(DefaultInterval)
	r.Pass(ctx)
	got := &corev1alpha1.PiiPolicy{}
	_ = c.Get(ctx, client.ObjectKeyFromObject(policy), got)
	if got.Status.Stats == nil || !strings.Contains(got.Status.Stats.LastError, "secret apps/missing not found") {
		t.Errorf("status.stats = %+v", got.Status.Stats)
	}
}

func TestInterval(t *testing.T) {
	for in, want := range map[int32]time.Duration{0: 5 * time.Minute, 10: time.Minute, 600: 10 * time.Minute} {
		if got := Interval(in); got != want {
			t.Errorf("Interval(%d) = %v, want %v", in, got, want)
		}
	}
}
