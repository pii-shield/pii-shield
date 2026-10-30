package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

func TestPiiPolicyReconcileSetsAvailableCondition(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	policy := &corev1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "strict-policy",
			Namespace:  "default",
			Generation: 3,
		},
		Spec: corev1alpha1.PiiPolicySpec{
			InjectionMode: "file",
		},
	}
	reconciler := newTestReconciler(t, scheme, policy)

	_, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	got := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	cond := meta.FindStatusCondition(got.Status.Conditions, "Available")
	if cond == nil {
		t.Fatalf("expected Available condition, got none")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Available=True, got %s: %s", cond.Status, cond.Message)
	}
	if cond.Reason != "PolicyAccepted" {
		t.Fatalf("expected PolicyAccepted reason, got %q", cond.Reason)
	}
	if cond.ObservedGeneration != policy.Generation {
		t.Fatalf("expected observed generation %d, got %d", policy.Generation, cond.ObservedGeneration)
	}
}

func TestPiiPolicyReconcileUsesDefaultModeWithoutMutatingSpec(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	policy := &corev1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "defaulted-policy",
			Namespace: "default",
		},
	}
	reconciler := newTestReconciler(t, scheme, policy)

	_, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	got := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	if got.Spec.InjectionMode != "" {
		t.Fatalf("expected spec injectionMode to remain empty, got %q", got.Spec.InjectionMode)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, "Available")
	if cond == nil {
		t.Fatalf("expected Available condition, got none")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Available=True, got %s", cond.Status)
	}
	if !strings.Contains(cond.Message, "Effective injection mode: file") {
		t.Fatalf("expected default file mode in message, got %q", cond.Message)
	}
}

func TestPiiPolicyReconcileMarksUnknownModeUnavailable(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	policy := &corev1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bad-policy",
			Namespace: "default",
		},
		Spec: corev1alpha1.PiiPolicySpec{
			InjectionMode: "unknown",
		},
	}
	reconciler := newTestReconciler(t, scheme, policy)

	_, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	got := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	cond := meta.FindStatusCondition(got.Status.Conditions, "Available")
	if cond == nil {
		t.Fatalf("expected Available condition, got none")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Fatalf("expected Available=False, got %s", cond.Status)
	}
	if cond.Reason != "InvalidInjectionMode" {
		t.Fatalf("expected InvalidInjectionMode reason, got %q", cond.Reason)
	}
}

func TestPiiPolicyReconcileIgnoresNotFound(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	reconciler := newTestReconciler(t, scheme)

	_, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("expected NotFound to be ignored, got %v", err)
	}
}

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add PiiPolicy scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add core scheme: %v", err)
	}
	return scheme
}

func newTestReconciler(t *testing.T, scheme *runtime.Scheme, objects ...runtime.Object) *PiiPolicyReconciler {
	t.Helper()
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(objects...).
		WithStatusSubresource(&corev1alpha1.PiiPolicy{}).
		Build()

	return &PiiPolicyReconciler{
		Client: client,
		Scheme: scheme,
	}
}

func fetchPolicy(t *testing.T, ctx context.Context, reconciler *PiiPolicyReconciler, name, namespace string) *corev1alpha1.PiiPolicy {
	t.Helper()
	policy := &corev1alpha1.PiiPolicy{}
	if err := reconciler.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, policy); err != nil {
		t.Fatalf("failed to fetch policy: %v", err)
	}
	return policy
}

func TestPiiPolicyReconcileRendersConfigMap(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme(t)
	policy := &corev1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "strict", Namespace: "apps", Generation: 2, UID: "uid-1"},
		Spec: corev1alpha1.PiiPolicySpec{
			InjectionMode: "file",
			Salt:          "0123456789abcdef0123456789abcdef",
			SensitiveKeys: []string{"geheim"},
		},
	}
	reconciler := newTestReconciler(t, scheme, policy)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}}

	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	cm := &corev1.ConfigMap{}
	if err := reconciler.Get(ctx, types.NamespacedName{Name: "pii-shield-policy-strict", Namespace: "apps"}, cm); err != nil {
		t.Fatalf("expected the rendered ConfigMap: %v", err)
	}
	data := cm.Data["policy.json"]
	if !strings.Contains(data, `"geheim"`) || !strings.Contains(data, `"revision": "2"`) {
		t.Fatalf("rendered file missing the rules or the revision:\n%s", data)
	}
	if strings.Contains(data, "0123456789abcdef") {
		t.Fatalf("the salt must never be rendered into the ConfigMap:\n%s", data)
	}
	if len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Name != "strict" || cm.OwnerReferences[0].Controller == nil || !*cm.OwnerReferences[0].Controller {
		t.Fatalf("expected the policy as controller owner, got %+v", cm.OwnerReferences)
	}
	if cm.Labels["pii-shield.io/policy"] != "strict" || cm.Annotations["pii-shield.io/policy-hash"] == "" {
		t.Fatalf("expected policy label and hash annotation, got labels %v annotations %v", cm.Labels, cm.Annotations)
	}

	got := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	if got.Status.RenderedPolicyConfigMap != "pii-shield-policy-strict" || got.Status.RenderedPolicyHash != cm.Annotations["pii-shield.io/policy-hash"] {
		t.Fatalf("status does not name the ConfigMap and its hash: %+v", got.Status)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, "Rendered")
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "ConfigMapUpToDate" {
		t.Fatalf("expected Rendered=True ConfigMapUpToDate, got %+v", cond)
	}

	// A rule change re-renders with a new hash; an unrelated reconcile leaves
	// the ConfigMap's resourceVersion alone.
	before := cm.ResourceVersion
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("second Reconcile returned error: %v", err)
	}
	if err := reconciler.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: "apps"}, cm); err != nil {
		t.Fatal(err)
	}
	if cm.ResourceVersion != before {
		t.Fatalf("an unchanged policy must not rewrite the ConfigMap (resourceVersion %s -> %s)", before, cm.ResourceVersion)
	}

	got.Spec.SensitiveKeys = []string{"clave"}
	got.Generation = 3
	if err := reconciler.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, req); err != nil {
		t.Fatalf("third Reconcile returned error: %v", err)
	}
	if err := reconciler.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: "apps"}, cm); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cm.Data["policy.json"], `"clave"`) || strings.Contains(cm.Data["policy.json"], `"geheim"`) {
		t.Fatalf("ConfigMap not re-rendered after a spec change:\n%s", cm.Data["policy.json"])
	}
	after := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
	if after.Status.RenderedPolicyHash == got.Status.RenderedPolicyHash {
		t.Fatal("status hash must change with the rules")
	}
}

// Audit mode is named in the Available condition, so kubectl shows that the
// logs of this policy are not being modified; the eBPF agent only observes,
// so ebpf without auditMode is not available.
func TestPiiPolicyReconcileReportsAuditMode(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		mode    string
		audit   bool
		status  metav1.ConditionStatus
		reason  string
		message string
	}{
		{"file", true, metav1.ConditionTrue, "PolicyAccepted", "audit mode: logs are not modified"},
		{"pipe", true, metav1.ConditionTrue, "PolicyAccepted", "audit mode: logs are not modified"},
		{"ebpf", true, metav1.ConditionTrue, "PolicyAccepted", "eBPF audit agent: logs are observed, not modified"},
		{"ebpf", false, metav1.ConditionFalse, "AuditModeRequired", "#96"},
		{"file", false, metav1.ConditionTrue, "PolicyAccepted", "Effective injection mode: file"},
	} {
		scheme := newTestScheme(t)
		policy := &corev1alpha1.PiiPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("audit-%s-%v", tc.mode, tc.audit), Namespace: "default"},
			Spec:       corev1alpha1.PiiPolicySpec{InjectionMode: tc.mode, AuditMode: tc.audit},
		}
		reconciler := newTestReconciler(t, scheme, policy)
		if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}}); err != nil {
			t.Fatalf("%s: Reconcile: %v", tc.mode, err)
		}
		got := fetchPolicy(t, ctx, reconciler, policy.Name, policy.Namespace)
		cond := meta.FindStatusCondition(got.Status.Conditions, "Available")
		if cond == nil {
			t.Fatalf("%s: no Available condition", tc.mode)
		}
		if cond.Status != tc.status || cond.Reason != tc.reason || !strings.Contains(cond.Message, tc.message) {
			t.Errorf("%s: Available = %s/%s %q; want %s/%s containing %q", tc.mode, cond.Status, cond.Reason, cond.Message, tc.status, tc.reason, tc.message)
		}
		if got.Spec.AuditMode != tc.audit {
			t.Errorf("%s: reconcile changed the spec", tc.mode)
		}
	}
}
