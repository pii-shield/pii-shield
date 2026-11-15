package webhook

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

// The webhook is called for pod updates as well as creations, and a pod's
// containers cannot change after it is created. An update is therefore let
// through untouched: with the sidecar already there nothing is said, and a
// labelled pod that has none gets a warning, because nothing can add one.
func TestHandleDoesNotMutateOnUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, corev1.AddToScheme(scheme))
	assert.NoError(t, piishieldv1alpha1.AddToScheme(scheme))
	policy := &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "test-ns"},
		Spec:       piishieldv1alpha1.PiiPolicySpec{InjectionMode: "file"},
	}
	m := &PodMutator{
		Client:  fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build(),
		Decoder: admission.NewDecoder(scheme),
	}
	handle := func(op admissionv1.Operation, pod *corev1.Pod) admission.Response {
		raw, err := json.Marshal(pod)
		assert.NoError(t, err)
		return m.Handle(context.Background(), admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{Namespace: "test-ns", Operation: op, Object: runtime.RawExtension{Raw: raw}},
		})
	}
	pod := func(injected bool) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "test-ns", Labels: map[string]string{"pii-shield.io/inject": "true"}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		}
		if injected {
			p.Spec.InitContainers = []corev1.Container{{Name: injectedContainerName}}
		}
		return p
	}

	resp := handle(admissionv1.Create, pod(false))
	assert.True(t, resp.Allowed)
	assert.NotEmpty(t, resp.Patches, "a new pod is injected")

	resp = handle(admissionv1.Update, pod(true))
	assert.True(t, resp.Allowed)
	assert.Empty(t, resp.Patches, "an injected pod is not injected again on update")
	assert.Empty(t, resp.Warnings)

	resp = handle(admissionv1.Update, pod(false))
	assert.True(t, resp.Allowed)
	assert.Empty(t, resp.Patches, "a sidecar cannot be added to a running pod")
	assert.Len(t, resp.Warnings, 1)
	assert.Contains(t, resp.Warnings[0], "NOT redacted")

	// Strict mode refuses a new pod without a policy; it does not start
	// refusing updates of pods that already run.
	m.StrictMode = true
	m.Client = fake.NewClientBuilder().WithScheme(scheme).Build()
	assert.False(t, handle(admissionv1.Create, pod(false)).Allowed)
	assert.True(t, handle(admissionv1.Update, pod(true)).Allowed)
}
