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

// STRICT_MODE decides whether a pod that asks for a sidecar and cannot get
// one is refused or started unprotected. The variable wins over the field in
// both directions, and only "true" and "false" (any letter case) are values.
func TestStrictModeEnvWinsBothWays(t *testing.T) {
	for _, tc := range []struct {
		env        string
		field      bool
		wantStrict bool
	}{
		{"true", false, true},
		{"TRUE", false, true},
		{"false", true, false},
		{"False", true, false},
		{"", true, true},
		{"", false, false},
		{"yes", true, true},
		{"yes", false, false},
	} {
		t.Setenv("STRICT_MODE", tc.env)
		m := newEmptyMutator(t)
		m.StrictMode = tc.field
		resp := handleForMissingPolicy(t, m)
		if resp.Allowed == tc.wantStrict {
			t.Errorf("STRICT_MODE=%q, field %v: allowed = %v, want strict = %v", tc.env, tc.field, resp.Allowed, tc.wantStrict)
		}
	}
}

func handlePod(t *testing.T, pod *corev1.Pod, policy *piishieldv1alpha1.PiiPolicy) admission.Response {
	t.Helper()
	scheme := runtime.NewScheme()
	assert.NoError(t, corev1.AddToScheme(scheme))
	assert.NoError(t, piishieldv1alpha1.AddToScheme(scheme))
	m := &PodMutator{
		Client:  fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build(),
		Decoder: admission.NewDecoder(scheme),
	}
	raw, err := json.Marshal(pod)
	assert.NoError(t, err)
	return m.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{Namespace: pod.Namespace, Object: runtime.RawExtension{Raw: raw}},
	})
}

// A pod with several containers must say which one to protect. Without the
// annotation it is refused, never injected into a guessed container; with it
// the sidecar is added.
func TestMultiContainerPodNeedsTargetAnnotation(t *testing.T) {
	policy := &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "test-ns"},
		Spec:       piishieldv1alpha1.PiiPolicySpec{InjectionMode: "file"},
	}
	pod := func(annotations map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "app", Namespace: "test-ns",
				Labels:      map[string]string{"pii-shield.io/inject": "true"},
				Annotations: annotations,
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "proxy"}}},
		}
	}

	resp := handlePod(t, pod(nil), policy)
	assert.False(t, resp.Allowed, "two containers and no target must be refused")
	assert.Contains(t, resp.Result.Message, "target-container")

	resp = handlePod(t, pod(map[string]string{"pii-shield.io/target-container": "app"}), policy)
	assert.True(t, resp.Allowed, "two containers with a target must be accepted")
	assert.NotEmpty(t, resp.Patches, "the sidecar must be injected")
}

// The sidecar image comes from AGENT_IMAGE; unset, it is the built-in name,
// never an empty image.
func TestSidecarImage(t *testing.T) {
	m := &PodMutator{}
	policy := &piishieldv1alpha1.PiiPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"}}

	t.Setenv("AGENT_IMAGE", "")
	assert.Equal(t, "pii-shield-agent:enterprise", m.buildSidecar("file", policy, "/var/log/app.log").Image)

	t.Setenv("AGENT_IMAGE", "registry.example.com/pii-shield:3.0.0")
	assert.Equal(t, "registry.example.com/pii-shield:3.0.0", m.buildSidecar("file", policy, "/var/log/app.log").Image)
}

// The smallest minimum secret length a policy can set reaches the sidecar.
func TestScannerEnvSmallestMinSecretLength(t *testing.T) {
	policy := &piishieldv1alpha1.PiiPolicy{Spec: piishieldv1alpha1.PiiPolicySpec{MinSecretLength: 1}}
	var got string
	for _, e := range scannerEnv(policy) {
		if e.Name == "PII_MIN_SECRET_LENGTH" {
			got = e.Value
		}
	}
	assert.Equal(t, "1", got)
}
