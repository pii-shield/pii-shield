//go:build integration

package controller

import (
	"context"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
				Spec:       corev1alpha1.PiiPolicySpec{InjectionMode: mode},
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
