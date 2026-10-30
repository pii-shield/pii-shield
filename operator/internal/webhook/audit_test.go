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

func envValue(env []corev1.EnvVar, name string) (string, bool) {
	for _, e := range env {
		if e.Name == name {
			return e.Value, true
		}
	}
	return "", false
}

// Audit mode reaches the sidecar as PII_MODE=audit, with the metrics on a
// named port and the hourly summary, in file and pipe mode alike.
func TestAuditModeSidecarEnvAndPort(t *testing.T) {
	mutator := &PodMutator{}
	for _, mode := range []string{"file", "pipe"} {
		policy := &piishieldv1alpha1.PiiPolicy{Spec: piishieldv1alpha1.PiiPolicySpec{InjectionMode: mode, AuditMode: true}}
		pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Command: []string{"node", "app.js"}}}}}
		var mutated *corev1.Pod
		var err error
		if mode == "file" {
			mutated, err = mutator.injectFileMode(pod, policy, "app")
		} else {
			mutated, err = mutator.injectPipeMode(pod, policy, "app")
		}
		assert.NoError(t, err, mode)
		sidecar := findContainer(mutated.Spec.InitContainers, "pii-shield-sidecar")
		if !assert.NotNil(t, sidecar, mode) {
			continue
		}
		for name, want := range map[string]string{
			"PII_MODE":               "audit",
			"PII_METRICS_ENABLED":    "true",
			"PII_METRICS_PORT":       "9090",
			"PII_STATS_LOG_INTERVAL": "1h",
		} {
			got, ok := envValue(sidecar.Env, name)
			assert.True(t, ok, "%s: %s missing", mode, name)
			assert.Equal(t, want, got, "%s: %s", mode, name)
		}
		if assert.Len(t, sidecar.Ports, 1, mode) {
			assert.Equal(t, AuditMetricsPortName, sidecar.Ports[0].Name)
			assert.Equal(t, AuditMetricsPort, sidecar.Ports[0].ContainerPort)
		}
		// The app container is not touched by the audit extras.
		app := findContainer(mutated.Spec.Containers, "app")
		if assert.NotNil(t, app) {
			assert.Empty(t, app.Ports)
			if _, ok := envValue(app.Env, "PII_MODE"); ok {
				t.Errorf("%s: PII_MODE leaked into the app container", mode)
			}
		}
	}
}

// Without auditMode nothing of the above is set: no PII_MODE, no metrics,
// no port, so a policy that does not ask for the audit is injected as before.
func TestNoAuditModeLeavesSidecarAsBefore(t *testing.T) {
	mutator := &PodMutator{}
	policy := &piishieldv1alpha1.PiiPolicy{Spec: piishieldv1alpha1.PiiPolicySpec{InjectionMode: "file"}}
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	mutated, err := mutator.injectFileMode(pod, policy, "app")
	assert.NoError(t, err)
	sidecar := findContainer(mutated.Spec.InitContainers, "pii-shield-sidecar")
	if !assert.NotNil(t, sidecar) {
		return
	}
	for _, name := range []string{"PII_MODE", "PII_METRICS_ENABLED", "PII_METRICS_PORT", "PII_STATS_LOG_INTERVAL"} {
		if _, ok := envValue(sidecar.Env, name); ok {
			t.Errorf("%s set without auditMode", name)
		}
	}
	assert.Empty(t, sidecar.Ports)
}

func auditHandle(t *testing.T, policy *piishieldv1alpha1.PiiPolicy) admission.Response {
	t.Helper()
	scheme := runtime.NewScheme()
	assert.NoError(t, corev1.AddToScheme(scheme))
	assert.NoError(t, piishieldv1alpha1.AddToScheme(scheme))
	mutator := &PodMutator{
		Client:  fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build(),
		Decoder: admission.NewDecoder(scheme),
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "test-ns",
			Labels:    map[string]string{"pii-shield.io/inject": "true"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Command: []string{"node", "app.js"}}}},
	}
	raw, err := json.Marshal(pod)
	assert.NoError(t, err)
	return mutator.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{Namespace: "test-ns", Object: runtime.RawExtension{Raw: raw}},
	})
}

// A pod under an audit policy is admitted with a warning that its logs are
// not redacted; in pipe mode the experimental warning comes first.
func TestHandleAuditModeWarns(t *testing.T) {
	resp := auditHandle(t, &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "test-ns"},
		Spec:       piishieldv1alpha1.PiiPolicySpec{InjectionMode: "file", AuditMode: true},
	})
	assert.True(t, resp.Allowed)
	assert.NotEmpty(t, resp.Patches)
	if assert.Len(t, resp.Warnings, 1) {
		assert.Contains(t, resp.Warnings[0], "auditMode")
		assert.Contains(t, resp.Warnings[0], "NOT redacted")
	}

	resp = auditHandle(t, &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "test-ns"},
		Spec:       piishieldv1alpha1.PiiPolicySpec{InjectionMode: "pipe", AuditMode: true},
	})
	assert.True(t, resp.Allowed)
	if assert.Len(t, resp.Warnings, 2) {
		assert.Contains(t, resp.Warnings[0], "experimental")
		assert.Contains(t, resp.Warnings[1], "auditMode")
	}
}

// The eBPF agent only observes, so an ebpf policy without auditMode is
// denied with the issue to follow; with auditMode the agent is injected
// and the admission warning says the logs are not redacted.
func TestHandleEBPFRequiresAuditMode(t *testing.T) {
	resp := auditHandle(t, &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "test-ns"},
		Spec:       piishieldv1alpha1.PiiPolicySpec{InjectionMode: "ebpf"},
	})
	assert.False(t, resp.Allowed)
	assert.Empty(t, resp.Patches)
	if assert.NotNil(t, resp.Result) {
		assert.Contains(t, resp.Result.Message, "auditMode: true")
		assert.Contains(t, resp.Result.Message, "#96")
	}

	resp = auditHandle(t, &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "test-ns"},
		Spec:       piishieldv1alpha1.PiiPolicySpec{InjectionMode: "ebpf", AuditMode: true},
	})
	assert.True(t, resp.Allowed)
	assert.NotEmpty(t, resp.Patches)
	if assert.Len(t, resp.Warnings, 1) {
		assert.Contains(t, resp.Warnings[0], "eBPF audit agent")
		assert.Contains(t, resp.Warnings[0], "NOT redacted")
	}
}

// The eBPF agent: the image from EBPF_AGENT_IMAGE, the pod's pid namespace
// shared, capabilities instead of privileged, no hostPath, the metrics
// port, the scanner env; the application container untouched.
func TestInjectEBPFModeAddsTheAuditAgent(t *testing.T) {
	t.Setenv("EBPF_AGENT_IMAGE", "ghcr.io/pii-shield/pii-shield-ebpf:test")
	mutator := &PodMutator{}
	policy := &piishieldv1alpha1.PiiPolicy{Spec: piishieldv1alpha1.PiiPolicySpec{
		InjectionMode: "ebpf", AuditMode: true, SensitiveKeys: []string{"geheim"},
	}}
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Command: []string{"node", "app.js"}}}}}
	mutated, err := mutator.injectEBPFMode(pod, policy, "app")
	assert.NoError(t, err)
	if assert.NotNil(t, mutated.Spec.ShareProcessNamespace) {
		assert.True(t, *mutated.Spec.ShareProcessNamespace)
	}
	assert.Empty(t, mutated.Spec.Volumes, "no hostPath or other volume")
	agent := findContainer(mutated.Spec.InitContainers, "pii-shield-sidecar")
	if !assert.NotNil(t, agent, "the agent is a native sidecar") {
		return
	}
	assert.Equal(t, "ghcr.io/pii-shield/pii-shield-ebpf:test", agent.Image)
	assert.Equal(t, []string{"/pii-shield-ebpf"}, agent.Command)
	assert.Empty(t, agent.VolumeMounts)
	if assert.NotNil(t, agent.SecurityContext) {
		assert.Nil(t, agent.SecurityContext.Privileged)
		if assert.NotNil(t, agent.SecurityContext.Capabilities) {
			assert.ElementsMatch(t, []corev1.Capability{"BPF", "PERFMON", "SYS_RESOURCE"}, agent.SecurityContext.Capabilities.Add)
			assert.Equal(t, []corev1.Capability{"ALL"}, agent.SecurityContext.Capabilities.Drop)
		}
		if assert.NotNil(t, agent.SecurityContext.RunAsUser) {
			assert.Equal(t, int64(0), *agent.SecurityContext.RunAsUser)
		}
	}
	if assert.Len(t, agent.Ports, 1) {
		assert.Equal(t, AuditMetricsPort, agent.Ports[0].ContainerPort)
	}
	if v, ok := envValue(agent.Env, "PII_SENSITIVE_KEYS"); assert.True(t, ok) {
		assert.Equal(t, "geheim", v)
	}
	if v, ok := envValue(agent.Env, "PII_STATS_LOG_INTERVAL"); assert.True(t, ok) {
		assert.Equal(t, "1h", v)
	}
	app := findContainer(mutated.Spec.Containers, "app")
	if assert.NotNil(t, app) {
		assert.Equal(t, []string{"node", "app.js"}, app.Command)
		assert.Empty(t, app.Env)
	}

	// Without the env var the default image is used.
	t.Setenv("EBPF_AGENT_IMAGE", "")
	assert.Equal(t, "ghcr.io/pii-shield/pii-shield-ebpf:latest", ebpfAgentImage())
}
