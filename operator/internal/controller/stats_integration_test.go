//go:build integration

package controller

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
	"github.com/pii-shield/pii-shield/operator/internal/remoterules"
	"github.com/pii-shield/pii-shield/operator/internal/stats"
)

// The new spec fields against the real API server: the CRD's own checks,
// and status.stats written by the stats channel next to the reconciler's
// status without either wiping the other.
var _ = Describe("PiiPolicy signature and stats fields", func() {
	ctx := context.Background()
	name := types.NamespacedName{Name: "signed-stats", Namespace: "default"}
	const key = "ed25519:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

	policy := func() *corev1alpha1.PiiPolicy {
		return &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace},
			Spec: corev1alpha1.PiiPolicySpec{
				InjectionMode: "file",
				RemoteConfig: &corev1alpha1.RemoteConfig{
					URL:       "https://rules.example.test/v1/acme/payments/policy.json",
					Signature: &corev1alpha1.RemoteSignature{PublicKeys: []string{key}},
				},
				Stats: &corev1alpha1.StatsConfig{URL: "https://rules.example.test/v1/acme/payments/report", IntervalSeconds: 60, ClusterName: "kind"},
			},
		}
	}

	AfterEach(func() {
		resource := &corev1alpha1.PiiPolicy{}
		if err := k8sClient.Get(ctx, name, resource); err == nil {
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		}
	})

	It("enforces the CRD limits of the new fields", func() {
		for what, mutate := range map[string]func(*corev1alpha1.PiiPolicy){
			"empty publicKeys":   func(p *corev1alpha1.PiiPolicy) { p.Spec.RemoteConfig.Signature.PublicKeys = nil },
			"stats interval 30":  func(p *corev1alpha1.PiiPolicy) { p.Spec.Stats.IntervalSeconds = 30 },
			"stats url ftp":      func(p *corev1alpha1.PiiPolicy) { p.Spec.Stats.URL = "ftp://x.example.test/report" },
			"cluster name > 128": func(p *corev1alpha1.PiiPolicy) { p.Spec.Stats.ClusterName = string(make([]byte, 129)) },
		} {
			p := policy()
			mutate(p)
			err := k8sClient.Create(ctx, p)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%s: expected Invalid, got %v", what, err)
		}
		Expect(k8sClient.Create(ctx, policy())).To(Succeed())
		got := &corev1alpha1.PiiPolicy{}
		Expect(k8sClient.Get(ctx, name, got)).To(Succeed())
		Expect(got.Spec.RemoteConfig.Signature.PublicKeys).To(Equal([]string{key}))
		Expect(got.Spec.Stats.ClusterName).To(Equal("kind"))
	})

	It("keeps status.stats and the reconciler's status apart", func() {
		Expect(k8sClient.Create(ctx, policy())).To(Succeed())
		now := time.Now()
		var sendErr error
		r := &stats.Reporter{Client: k8sClient, APIReader: k8sClient, Now: func() time.Time { return now },
			Scrape: func(context.Context, string) ([]byte, error) { return nil, errors.New("no pods here") },
			Send:   func(context.Context, remoterules.Source, []byte) error { return sendErr }}

		r.Pass(ctx)
		now = now.Add(time.Minute)
		sendErr = errors.New("HTTP 503")
		r.Pass(ctx)
		got := &corev1alpha1.PiiPolicy{}
		Expect(k8sClient.Get(ctx, name, got)).To(Succeed())
		Expect(got.Status.Stats).NotTo(BeNil())
		Expect(got.Status.Stats.LastError).To(Equal("HTTP 503"))

		// A success clears the error through the merge patch's null.
		sendErr = nil
		now = now.Add(time.Minute)
		r.Pass(ctx)
		Expect(k8sClient.Get(ctx, name, got)).To(Succeed())
		Expect(got.Status.Stats.LastError).To(BeEmpty())
		Expect(got.Status.Stats.LastReportTime).NotTo(BeNil())

		// The reconciler writes its conditions and leaves status.stats.
		reconciler := &PiiPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, name, got)).To(Succeed())
		Expect(got.Status.Conditions).NotTo(BeEmpty())
		Expect(got.Status.Stats).NotTo(BeNil())
		Expect(got.Status.Stats.LastReportTime).NotTo(BeNil())

		// The channel writes status.stats and leaves the conditions.
		conditions := len(got.Status.Conditions)
		now = now.Add(time.Minute)
		r.Pass(ctx)
		Expect(k8sClient.Get(ctx, name, got)).To(Succeed())
		Expect(got.Status.Conditions).To(HaveLen(conditions))

		// Stats turned off: the reconciler clears status.stats.
		got.Spec.Stats = nil
		Expect(k8sClient.Update(ctx, got)).To(Succeed())
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, name, got)).To(Succeed())
		Expect(got.Status.Stats).To(BeNil())
	})
})
