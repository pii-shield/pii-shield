package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

func TestInjectFileMode(t *testing.T) {
	mutator := &PodMutator{
		LegacySidecarMode: false,
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-pod",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "main-app",
				},
			},
		},
	}
	policy := &piishieldv1alpha1.PiiPolicy{
		Spec: piishieldv1alpha1.PiiPolicySpec{
			InjectionMode: "file",
			LogPath:       "/var/log/app",
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU: resource.MustParse("100m"),
				},
			},
		},
	}

	mutated, err := mutator.injectFileMode(pod, policy, "main-app")
	assert.NoError(t, err)

	// Verify volumes
	foundShared := false
	foundTmp := false
	for _, v := range mutated.Spec.Volumes {
		if v.Name == "pii-shared" {
			foundShared = true
		}
		if v.Name == "pii-tmp" {
			foundTmp = true
		}
	}
	assert.True(t, foundShared)
	assert.True(t, foundTmp)

	// Verify main container mount
	assert.Len(t, mutated.Spec.Containers[0].VolumeMounts, 1)
	assert.Equal(t, "/var/log", mutated.Spec.Containers[0].VolumeMounts[0].MountPath)

	// Verify Native Sidecar in InitContainers
	assert.Len(t, mutated.Spec.InitContainers, 1)
	sidecar := mutated.Spec.InitContainers[0]
	assert.Equal(t, "pii-shield-sidecar", sidecar.Name)
	assert.Equal(t, corev1.ContainerRestartPolicyAlways, *sidecar.RestartPolicy)

	// Verify Security Context
	assert.NotNil(t, sidecar.SecurityContext)
	assert.True(t, *sidecar.SecurityContext.RunAsNonRoot)
	assert.True(t, *sidecar.SecurityContext.ReadOnlyRootFilesystem)
	assert.False(t, *sidecar.SecurityContext.AllowPrivilegeEscalation)
	assert.Equal(t, []corev1.Capability{"ALL"}, sidecar.SecurityContext.Capabilities.Drop)
	assert.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, sidecar.SecurityContext.SeccompProfile.Type)

	// Verify Resources
	cpuLimit, ok := sidecar.Resources.Limits[corev1.ResourceCPU]
	assert.True(t, ok)
	assert.Equal(t, "100m", cpuLimit.String())
}

func TestGetTargetContainerIndex(t *testing.T) {
	mutator := &PodMutator{}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "istio-proxy"},
				{Name: "app"},
			},
		},
	}
	idx := mutator.getTargetContainerIndex(pod, "app")
	assert.Equal(t, 1, idx)
}

func TestInjectPipeMode_NoOriginalCommand(t *testing.T) {
	mutator := &PodMutator{}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app"}, // missing command
			},
		},
	}
	policy := &piishieldv1alpha1.PiiPolicy{
		Spec: piishieldv1alpha1.PiiPolicySpec{
			InjectionMode: "pipe",
		},
	}
	_, err := mutator.injectPipeMode(pod, policy, "app")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "originalCommand is required")
}

func TestInjectPipeMode(t *testing.T) {
	mutator := &PodMutator{
		LegacySidecarMode: true,
	}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Command: []string{"node", "app.js"}},
			},
		},
	}
	policy := &piishieldv1alpha1.PiiPolicy{
		Spec: piishieldv1alpha1.PiiPolicySpec{
			InjectionMode: "pipe",
		},
	}
	mutated, err := mutator.injectPipeMode(pod, policy, "app")
	assert.NoError(t, err)

	// Contains init container for mkfifo
	assert.Len(t, mutated.Spec.InitContainers, 1)
	assert.Equal(t, "pii-mkfifo", mutated.Spec.InitContainers[0].Name)
	joinedArgs := strings.Join(mutated.Spec.InitContainers[0].Args, " ")
	assert.Contains(t, joinedArgs, "mkfifo /shared/log.pipe")

	// Main container command wrapped
	mainApp := mutated.Spec.Containers[0]
	assert.Equal(t, []string{"/bin/sh", "-c"}, mainApp.Command)
	assert.Equal(t, []string{"exec node app.js > /shared/log.pipe"}, mainApp.Args)

	// Sidecar was injected to Containers since LegacySidecarMode = true
	assert.Len(t, mutated.Spec.Containers, 2)
	sidecar := mutated.Spec.Containers[1]
	assert.Equal(t, "pii-shield-sidecar", sidecar.Name)
}

func TestHandlePipeModeReturnsExperimentalWarning(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, corev1.AddToScheme(scheme))
	assert.NoError(t, piishieldv1alpha1.AddToScheme(scheme))

	policy := &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "test-ns"},
		Spec:       piishieldv1alpha1.PiiPolicySpec{InjectionMode: "pipe"},
	}
	mutator := &PodMutator{
		Client:            fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build(),
		Decoder:           admission.NewDecoder(scheme),
		LegacySidecarMode: true,
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "test-ns",
			Labels:    map[string]string{"pii-shield.io/inject": "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Command: []string{"node", "app.js"}}},
		},
	}
	raw, err := json.Marshal(pod)
	assert.NoError(t, err)

	resp := mutator.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: "test-ns",
			Object:    runtime.RawExtension{Raw: raw},
		},
	})
	assert.True(t, resp.Allowed)
	assert.NotEmpty(t, resp.Patches)
	assert.Len(t, resp.Warnings, 1)
	assert.Contains(t, resp.Warnings[0], "experimental")
	assert.Contains(t, resp.Warnings[0], "/bin/sh -c")
}

// handleInjectPod builds an admission request for a pod that requests injection
// but for which the given mutator's client has no matching PiiPolicy (unless one
// is seeded). Used by the strict-mode tests below.
func handleForMissingPolicy(t *testing.T, mutator *PodMutator) admission.Response {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "test-ns",
			Labels:    map[string]string{"pii-shield.io/inject": "true"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	assert.NoError(t, err)
	return mutator.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: "test-ns",
			Object:    runtime.RawExtension{Raw: raw},
		},
	})
}

func newEmptyMutator(t *testing.T) *PodMutator {
	t.Helper()
	scheme := runtime.NewScheme()
	assert.NoError(t, corev1.AddToScheme(scheme))
	assert.NoError(t, piishieldv1alpha1.AddToScheme(scheme))
	return &PodMutator{
		Client:  fake.NewClientBuilder().WithScheme(scheme).Build(),
		Decoder: admission.NewDecoder(scheme),
	}
}

func TestHandleMissingPolicyPermissiveAllowsWithWarning(t *testing.T) {
	m := newEmptyMutator(t) // StrictMode defaults to false
	resp := handleForMissingPolicy(t, m)

	assert.True(t, resp.Allowed, "permissive mode should allow the pod")
	assert.Empty(t, resp.Patches, "no sidecar should be injected")
	assert.Len(t, resp.Warnings, 1)
	assert.Contains(t, resp.Warnings[0], "NOT injected")
}

func TestHandleMissingPolicyStrictDenies(t *testing.T) {
	m := newEmptyMutator(t)
	m.StrictMode = true
	resp := handleForMissingPolicy(t, m)

	assert.False(t, resp.Allowed, "strict mode should deny the pod")
	assert.Contains(t, resp.Result.Message, "strict mode")
	assert.Contains(t, resp.Result.Message, "not found")
}

func TestHandleStrictModeEnvOverridesField(t *testing.T) {
	// STRICT_MODE env is authoritative even when the struct field is false.
	t.Setenv("STRICT_MODE", "true")
	m := newEmptyMutator(t) // field false
	resp := handleForMissingPolicy(t, m)
	assert.False(t, resp.Allowed, "STRICT_MODE=true env should force denial")
}

func TestHandleInvalidInjectionModeErrors(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, corev1.AddToScheme(scheme))
	assert.NoError(t, piishieldv1alpha1.AddToScheme(scheme))
	policy := &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "test-ns"},
		Spec:       piishieldv1alpha1.PiiPolicySpec{InjectionMode: "bogus"},
	}
	m := &PodMutator{
		Client:  fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build(),
		Decoder: admission.NewDecoder(scheme),
	}
	resp := handleForMissingPolicy(t, m) // policy exists, but mode is invalid

	assert.False(t, resp.Allowed, "an unknown injection mode should not be allowed")
	assert.Contains(t, resp.Result.Message, "unknown injection mode")
}

func TestBuildSidecarPassesScannerEnv(t *testing.T) {
	policy := &piishieldv1alpha1.PiiPolicy{
		Spec: piishieldv1alpha1.PiiPolicySpec{
			FailPolicy:           "closed",
			ConfidenceThreshold:  0.8,
			Salt:                 "0123456789abcdef",
			EntropyThreshold:     4.5,
			MinSecretLength:      12,
			SensitiveKeys:        []string{"token", "secret"},
			SensitiveKeyPatterns: []string{"^x_api_.*"},
			CustomRegexList:      []piishieldv1alpha1.RegexRule{{Name: "ticket", Pattern: "T-[0-9]+"}},
			SafeRegexList:        []piishieldv1alpha1.RegexRule{{Name: "build", Pattern: "B-[0-9]+"}},
		},
	}
	sidecar := (&PodMutator{}).buildSidecar("file", policy, "/shared/app.log")

	got := map[string]string{}
	for _, e := range sidecar.Env {
		got[e.Name] = e.Value
	}
	assert.Equal(t, "0123456789abcdef", got["PII_SALT"])
	assert.Equal(t, "closed", got["PII_FAIL_POLICY"])
	assert.Equal(t, "0.8", got["PII_CONFIDENCE_THRESHOLD"])
	assert.Equal(t, "4.5", got["PII_ENTROPY_THRESHOLD"])
	assert.Equal(t, "12", got["PII_MIN_SECRET_LENGTH"])
	assert.Equal(t, "token,secret", got["PII_SENSITIVE_KEYS"])
	assert.Equal(t, "^x_api_.*", got["PII_SENSITIVE_KEY_PATTERNS"])
	assert.JSONEq(t, `[{"name":"ticket","pattern":"T-[0-9]+"}]`, got["PII_CUSTOM_REGEX_LIST"])
	assert.JSONEq(t, `[{"name":"build","pattern":"B-[0-9]+"}]`, got["PII_SAFE_REGEX_LIST"])
}

func TestBuildSidecarEmptyPolicyHasNoScannerEnv(t *testing.T) {
	sidecar := (&PodMutator{}).buildSidecar("file", &piishieldv1alpha1.PiiPolicy{}, "/shared/app.log")
	assert.Empty(t, sidecar.Env)
}

func findContainer(containers []corev1.Container, name string) *corev1.Container {
	for i := range containers {
		if containers[i].Name == name {
			return &containers[i]
		}
	}
	return nil
}

func scannerEnvPolicySpec(mode string) piishieldv1alpha1.PiiPolicySpec {
	return piishieldv1alpha1.PiiPolicySpec{
		InjectionMode: mode,
		FailPolicy:    "closed",
		SaltSecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "pii-shield-salt"},
			Key:                  "salt",
		},
		SensitiveKeys:   []string{"token"},
		CustomRegexList: []piishieldv1alpha1.RegexRule{{Name: "ticket", Pattern: "T-[0-9]+"}},
	}
}

func assertScannerEnvPropagated(t *testing.T, sidecar *corev1.Container) {
	t.Helper()
	got := map[string]corev1.EnvVar{}
	for _, e := range sidecar.Env {
		got[e.Name] = e
	}
	assert.Equal(t, "pii-shield-salt", got["PII_SALT"].ValueFrom.SecretKeyRef.Name)
	assert.Equal(t, "closed", got["PII_FAIL_POLICY"].Value)
	assert.Equal(t, "token", got["PII_SENSITIVE_KEYS"].Value)
	assert.JSONEq(t, `[{"name":"ticket","pattern":"T-[0-9]+"}]`, got["PII_CUSTOM_REGEX_LIST"].Value)
}

func TestInjectFileModePropagatesScannerEnv(t *testing.T) {
	mutator := &PodMutator{LegacySidecarMode: false}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	policy := &piishieldv1alpha1.PiiPolicy{Spec: scannerEnvPolicySpec("file")}

	mutated, err := mutator.injectFileMode(pod, policy, "app")
	assert.NoError(t, err)

	sidecar := findContainer(mutated.Spec.InitContainers, "pii-shield-sidecar")
	assert.NotNil(t, sidecar, "native sidecar must be in initContainers")
	assertScannerEnvPropagated(t, sidecar)
}

func TestInjectPipeModePropagatesScannerEnv(t *testing.T) {
	mutator := &PodMutator{LegacySidecarMode: false}
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Command: []string{"node", "app.js"}}}},
	}
	policy := &piishieldv1alpha1.PiiPolicy{Spec: scannerEnvPolicySpec("pipe")}

	mutated, err := mutator.injectPipeMode(pod, policy, "app")
	assert.NoError(t, err)

	sidecar := findContainer(mutated.Spec.InitContainers, "pii-shield-sidecar")
	assert.NotNil(t, sidecar, "native sidecar must be in initContainers")
	assertScannerEnvPropagated(t, sidecar)

	// The mkfifo init container is unrelated plumbing and must stay untouched.
	mkfifo := findContainer(mutated.Spec.InitContainers, "pii-mkfifo")
	assert.NotNil(t, mkfifo)
	assert.Empty(t, mkfifo.Env)
}

func TestScannerEnvSaltPrecedence(t *testing.T) {
	secretRef := &corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "pii-salt"},
		Key:                  "hashing-salt",
	}

	t.Run("policy secret ref wins over plaintext salt", func(t *testing.T) {
		env := scannerEnv(&piishieldv1alpha1.PiiPolicy{Spec: piishieldv1alpha1.PiiPolicySpec{
			Salt:             "plaintext-salt-16chars",
			SaltSecretKeyRef: secretRef,
		}})
		assert.Len(t, env, 1)
		assert.Equal(t, "PII_SALT", env[0].Name)
		assert.Empty(t, env[0].Value)
		assert.Equal(t, "pii-salt", env[0].ValueFrom.SecretKeyRef.Name)
		assert.Equal(t, "hashing-salt", env[0].ValueFrom.SecretKeyRef.Key)
	})

	t.Run("plaintext salt wins over operator default", func(t *testing.T) {
		t.Setenv("AGENT_SALT_SECRET_NAME", "cluster-salt")
		env := scannerEnv(&piishieldv1alpha1.PiiPolicy{Spec: piishieldv1alpha1.PiiPolicySpec{
			Salt: "plaintext-salt-16chars",
		}})
		assert.Len(t, env, 1)
		assert.Equal(t, "plaintext-salt-16chars", env[0].Value)
		assert.Nil(t, env[0].ValueFrom)
	})

	t.Run("operator default secret used when policy is silent", func(t *testing.T) {
		t.Setenv("AGENT_SALT_SECRET_NAME", "cluster-salt")
		env := scannerEnv(&piishieldv1alpha1.PiiPolicy{})
		assert.Len(t, env, 1)
		assert.Equal(t, "PII_SALT", env[0].Name)
		assert.Equal(t, "cluster-salt", env[0].ValueFrom.SecretKeyRef.Name)
		assert.Equal(t, "salt", env[0].ValueFrom.SecretKeyRef.Key)
	})

	t.Run("operator default respects custom key", func(t *testing.T) {
		t.Setenv("AGENT_SALT_SECRET_NAME", "cluster-salt")
		t.Setenv("AGENT_SALT_SECRET_KEY", "custom-key")
		env := scannerEnv(&piishieldv1alpha1.PiiPolicy{})
		assert.Len(t, env, 1)
		assert.Equal(t, "custom-key", env[0].ValueFrom.SecretKeyRef.Key)
	})
}
