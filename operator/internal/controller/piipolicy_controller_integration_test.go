//go:build integration

package controller

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

var _ = Describe("PiiPolicy Controller integration", func() {
	const resourceName = "test-resource"

	ctx := context.Background()
	typeNamespacedName := types.NamespacedName{
		Name:      resourceName,
		Namespace: "default",
	}

	AfterEach(func() {
		resource := &corev1alpha1.PiiPolicy{}
		err := k8sClient.Get(ctx, typeNamespacedName, resource)
		if err == nil {
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		}
	})

	It("sets Available status for an accepted policy", func() {
		resource := &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resourceName,
				Namespace: "default",
			},
			Spec: corev1alpha1.PiiPolicySpec{
				InjectionMode: "file",
			},
		}
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())

		controllerReconciler := &PiiPolicyReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}

		_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: typeNamespacedName,
		})
		Expect(err).NotTo(HaveOccurred())

		updated := &corev1alpha1.PiiPolicy{}
		Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
		condition := meta.FindStatusCondition(updated.Status.Conditions, "Available")
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionTrue))
		Expect(condition.Reason).To(Equal("PolicyAccepted"))
	})

	// What a real API server adds over the fake client of the unit tests:
	// the CRD schema and the status subresource.

	It("reconciles every accepted mode through the status subresource without touching the spec", func() {
		for _, mode := range []string{"file", "pipe", "ebpf"} {
			resource := &corev1alpha1.PiiPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: "default"},
				// ebpf is the audit agent and is only accepted with auditMode.
				Spec: corev1alpha1.PiiPolicySpec{InjectionMode: mode, AuditMode: mode == "ebpf"},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed(), "mode %s", mode)
			created := &corev1alpha1.PiiPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, created)).To(Succeed())

			reconciler := &PiiPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred(), "mode %s", mode)

			updated := &corev1alpha1.PiiPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			condition := meta.FindStatusCondition(updated.Status.Conditions, "Available")
			Expect(condition).NotTo(BeNil(), "mode %s", mode)
			Expect(condition.Status).To(Equal(metav1.ConditionTrue), "mode %s", mode)
			Expect(updated.Spec).To(Equal(created.Spec), "mode %s: spec changed", mode)
			Expect(updated.Generation).To(Equal(created.Generation), "mode %s: a status write bumped the generation", mode)

			Expect(k8sClient.Delete(ctx, updated)).To(Succeed())
		}
	})

	// A CEL rule on the spec refuses ebpf without auditMode at admission
	// (the eBPF agent only observes), so a cluster with the current CRD
	// never has such a policy; the webhook's denial and the controller's
	// AuditModeRequired branch exist for a policy created under an older
	// CRD and are covered by the unit tests.
	It("rejects injection mode ebpf without auditMode at admission and accepts auditMode with file", func() {
		rejected := &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: "default"},
			Spec:       corev1alpha1.PiiPolicySpec{InjectionMode: "ebpf"},
		}
		err := k8sClient.Create(ctx, rejected)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid, got %v", err)
		Expect(err.Error()).To(ContainSubstring("#96"))

		accepted := &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: "default"},
			Spec:       corev1alpha1.PiiPolicySpec{InjectionMode: "file", AuditMode: true},
		}
		Expect(k8sClient.Create(ctx, accepted)).To(Succeed())
		reconciler := &PiiPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
		Expect(err).NotTo(HaveOccurred())
		updated := &corev1alpha1.PiiPolicy{}
		Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
		condition := meta.FindStatusCondition(updated.Status.Conditions, "Available")
		Expect(condition).NotTo(BeNil())
		Expect(condition.Status).To(Equal(metav1.ConditionTrue))
		Expect(condition.Message).To(ContainSubstring("audit mode: logs are not modified"))
		Expect(updated.Spec.AuditMode).To(BeTrue())
	})

	// The CRD makes injectionMode a required enum, so an empty or unknown mode
	// never reaches the controller; its default-mode and InvalidInjectionMode
	// branches are exercised only by the fake-client unit tests.
	It("rejects an empty or unknown injection mode at admission", func() {
		for _, mode := range []string{"", "unknown"} {
			resource := &corev1alpha1.PiiPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: "default"},
				Spec:       corev1alpha1.PiiPolicySpec{InjectionMode: mode},
			}
			err := k8sClient.Create(ctx, resource)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "mode %q: expected Invalid, got %v", mode, err)
		}
	})
})

var _ = Describe("PiiPolicy rendered ConfigMap", func() {
	ctx := context.Background()
	name := types.NamespacedName{Name: "rendered-policy", Namespace: "default"}

	AfterEach(func() {
		resource := &corev1alpha1.PiiPolicy{}
		if err := k8sClient.Get(ctx, name, resource); err == nil {
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		}
	})

	It("renders the rules into an owned ConfigMap and re-renders on a spec change", func() {
		resource := &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace},
			Spec: corev1alpha1.PiiPolicySpec{
				InjectionMode: "file",
				Salt:          "0123456789abcdef0123456789abcdef",
				SensitiveKeys: []string{"geheim"},
			},
		}
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())

		reconciler := &PiiPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())

		cm := &corev1.ConfigMap{}
		cmName := types.NamespacedName{Name: "pii-shield-policy-rendered-policy", Namespace: "default"}
		Expect(k8sClient.Get(ctx, cmName, cm)).To(Succeed())
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"geheim"`))
		Expect(cm.Data["policy.json"]).NotTo(ContainSubstring("0123456789abcdef"), "the salt must not be rendered")
		Expect(cm.OwnerReferences).To(HaveLen(1))
		Expect(cm.OwnerReferences[0].Kind).To(Equal("PiiPolicy"))

		updated := &corev1alpha1.PiiPolicy{}
		Expect(k8sClient.Get(ctx, name, updated)).To(Succeed())
		Expect(updated.Status.RenderedPolicyConfigMap).To(Equal(cmName.Name))
		firstHash := updated.Status.RenderedPolicyHash
		Expect(firstHash).NotTo(BeEmpty())
		rendered := meta.FindStatusCondition(updated.Status.Conditions, "Rendered")
		Expect(rendered).NotTo(BeNil())
		Expect(rendered.Status).To(Equal(metav1.ConditionTrue))

		updated.Spec.SensitiveKeys = []string{"clave"}
		Expect(k8sClient.Update(ctx, updated)).To(Succeed())
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, cmName, cm)).To(Succeed())
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"clave"`))
		Expect(cm.Data["policy.json"]).NotTo(ContainSubstring(`"geheim"`))
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"revision": "2"`), "the revision is the generation")

		again := &corev1alpha1.PiiPolicy{}
		Expect(k8sClient.Get(ctx, name, again)).To(Succeed())
		Expect(again.Status.RenderedPolicyHash).NotTo(Equal(firstHash))
	})

	It("reports a render failure in the status and keeps the policy available", func() {
		longName := types.NamespacedName{Name: "p" + strings.Repeat("x", 240), Namespace: "default"}
		resource := &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: longName.Name, Namespace: longName.Namespace},
			Spec:       corev1alpha1.PiiPolicySpec{InjectionMode: "file"},
		}
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		defer func() { Expect(k8sClient.Delete(ctx, resource)).To(Succeed()) }()

		reconciler := &PiiPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: longName})
		Expect(err).To(HaveOccurred())

		updated := &corev1alpha1.PiiPolicy{}
		Expect(k8sClient.Get(ctx, longName, updated)).To(Succeed())
		Expect(meta.FindStatusCondition(updated.Status.Conditions, "Available").Status).To(Equal(metav1.ConditionTrue))
		rendered := meta.FindStatusCondition(updated.Status.Conditions, "Rendered")
		Expect(rendered).NotTo(BeNil())
		Expect(rendered.Status).To(Equal(metav1.ConditionFalse))
		Expect(rendered.Reason).To(Equal("RenderFailed"))
	})
})

var _ = Describe("PiiPolicy remote rules", func() {
	ctx := context.Background()
	name := types.NamespacedName{Name: "remote-policy", Namespace: "default"}
	cmName := types.NamespacedName{Name: "pii-shield-policy-remote-policy", Namespace: "default"}

	var (
		srv   *httptest.Server
		body  atomic.Value
		fails atomic.Bool
	)

	BeforeEach(func() {
		body.Store(`{"revision": "central-1", "entropy_threshold": 4.4, "sensitive_keys": ["central"]}`)
		fails.Store(false)
		srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer envtest-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if fails.Load() {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.Header().Set("ETag", `"central-1"`)
			if r.Header.Get("If-None-Match") == `"central-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write([]byte(body.Load().(string)))
		}))
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "rules-ca", Namespace: "default"},
			Data:       map[string][]byte{"ca.crt": ca},
		})).To(Succeed())
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "rules-token", Namespace: "default"},
			StringData: map[string]string{"authorization": "Bearer envtest-token"},
		})).To(Succeed())
	})

	AfterEach(func() {
		srv.Close()
		for _, obj := range []client.Object{
			&corev1alpha1.PiiPolicy{ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "rules-ca", Namespace: "default"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "rules-token", Namespace: "default"}},
		} {
			_ = k8sClient.Delete(ctx, obj)
		}
	})

	It("pulls the rules over TLS with the CA and token from Secrets, keeps the last good copy while the source is down, and falls back to the local policy when remoteConfig is removed", func() {
		resource := &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace},
			Spec: corev1alpha1.PiiPolicySpec{
				InjectionMode:   "file",
				Salt:            "0123456789abcdef0123456789abcdef",
				MinSecretLength: 9,
				RemoteConfig: &corev1alpha1.RemoteConfig{
					URL:             srv.URL + "/policy.json",
					IntervalSeconds: 60,
					HeaderSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "rules-token"},
						Key:                  "authorization",
					},
					CABundleSecretRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "rules-ca"},
						Key:                  "ca.crt",
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())

		reconciler := &PiiPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), APIReader: k8sClient}
		res, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(time.Minute))

		cm := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, cmName, cm)).To(Succeed())
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"entropy_threshold": 4.4`), "remote rule")
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"central"`), "remote list kept when the local policy does not set it")
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"min_secret_length": 9`), "local rule")
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"revision": "central-1+1"`))
		Expect(cm.Data["remote.json"]).To(ContainSubstring(`"central-1"`))
		Expect(cm.Annotations["pii-shield.io/remote-etag"]).To(Equal(`"central-1"`))

		updated := &corev1alpha1.PiiPolicy{}
		Expect(k8sClient.Get(ctx, name, updated)).To(Succeed())
		synced := meta.FindStatusCondition(updated.Status.Conditions, "RemoteSynced")
		Expect(synced).NotTo(BeNil())
		Expect(synced.Status).To(Equal(metav1.ConditionTrue))
		Expect(synced.Message).NotTo(ContainSubstring("allowInsecure"))
		Expect(updated.Status.Remote).NotTo(BeNil())
		Expect(updated.Status.Remote.Revision).To(Equal("central-1"))
		Expect(updated.Status.Remote.ETag).To(Equal(`"central-1"`))
		Expect(updated.Status.Remote.LastSyncTime).NotTo(BeNil())

		By("a second pull answers 304 and leaves the ConfigMap alone")
		rv := cm.ResourceVersion
		_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, cmName, cm)).To(Succeed())
		Expect(cm.ResourceVersion).To(Equal(rv))

		By("the source goes down while the local policy is edited")
		fails.Store(true)
		Expect(k8sClient.Get(ctx, name, updated)).To(Succeed())
		updated.Spec.SensitiveKeys = []string{"local"}
		Expect(k8sClient.Update(ctx, updated)).To(Succeed())
		res, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(time.Minute), "retry at the interval, which is under the cap")
		Expect(k8sClient.Get(ctx, cmName, cm)).To(Succeed())
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"entropy_threshold": 4.4`), "last good remote rule kept")
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"local"`), "local edit applied on top")
		Expect(cm.Data["policy.json"]).NotTo(ContainSubstring(`"central"`), "local list replaces the remote list")
		Expect(k8sClient.Get(ctx, name, updated)).To(Succeed())
		synced = meta.FindStatusCondition(updated.Status.Conditions, "RemoteSynced")
		Expect(synced.Status).To(Equal(metav1.ConditionFalse))
		Expect(synced.Reason).To(Equal("FetchFailed"))
		Expect(synced.Message).To(ContainSubstring("HTTP 502"))
		Expect(updated.Status.Remote.Revision).To(Equal("central-1"), "status.remote still names the last good pull")
		Expect(meta.FindStatusCondition(updated.Status.Conditions, "Rendered").Status).To(Equal(metav1.ConditionTrue))

		By("removing remoteConfig renders the local policy alone")
		updated.Spec.RemoteConfig = nil
		Expect(k8sClient.Update(ctx, updated)).To(Succeed())
		res, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(BeZero())
		Expect(k8sClient.Get(ctx, cmName, cm)).To(Succeed())
		Expect(cm.Data).NotTo(HaveKey("remote.json"))
		Expect(cm.Data["policy.json"]).NotTo(ContainSubstring("entropy_threshold"))
		Expect(cm.Data["policy.json"]).To(ContainSubstring(`"revision": "3"`))
		Expect(k8sClient.Get(ctx, name, updated)).To(Succeed())
		Expect(meta.FindStatusCondition(updated.Status.Conditions, "RemoteSynced")).To(BeNil())
		Expect(updated.Status.Remote).To(BeNil())
	})

	It("rejects an http:// URL without allowInsecure and an interval under 30 seconds at admission", func() {
		insecure := &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace},
			Spec: corev1alpha1.PiiPolicySpec{
				InjectionMode: "file",
				RemoteConfig:  &corev1alpha1.RemoteConfig{URL: "ftp://rules.invalid/policy.json"},
			},
		}
		Expect(k8sClient.Create(ctx, insecure)).NotTo(Succeed(), "the CRD pattern admits http(s) only")

		short := &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name.Name, Namespace: name.Namespace},
			Spec: corev1alpha1.PiiPolicySpec{
				InjectionMode: "file",
				RemoteConfig:  &corev1alpha1.RemoteConfig{URL: "https://rules.invalid/policy.json", IntervalSeconds: 5},
			},
		}
		Expect(k8sClient.Create(ctx, short)).NotTo(Succeed(), "the CRD minimum is 30 seconds")
	})
})
