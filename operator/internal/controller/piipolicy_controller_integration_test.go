//go:build integration

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
