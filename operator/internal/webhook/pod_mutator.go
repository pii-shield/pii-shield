package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

// PodMutator mutates Pods
type PodMutator struct {
	Client            client.Client
	Decoder           admission.Decoder
	LegacySidecarMode bool
	// StrictMode denies pods that request injection but have no resolvable
	// PiiPolicy. It is off by default: cmd/main.go leaves the field false and
	// the chart ships webhook.strictMode: false. The STRICT_MODE env var (set
	// from that chart value) overrides the field at runtime.
	StrictMode bool
}

// strictMode reports whether the webhook should deny pods that request
// injection but have no resolvable PiiPolicy. The STRICT_MODE env var is
// authoritative when set; otherwise the struct field (used by tests) applies.
func (m *PodMutator) strictMode() bool {
	switch strings.ToLower(os.Getenv("STRICT_MODE")) {
	case "true":
		return true
	case "false":
		return false
	default:
		return m.StrictMode
	}
}

// +kubebuilder:webhook:path=/mutate-v1-pod,mutating=true,failurePolicy=ignore,groups="",resources=pods,verbs=create;update,versions=v1,name=mpod.kb.io,sideEffects=None,admissionReviewVersions=v1

func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	err := m.Decoder.Decode(req, pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if pod.Labels["pii-shield.io/inject"] != "true" {
		return admission.Allowed("Skipping pod: no inject label")
	}

	policyName := pod.Annotations["pii-shield.io/policy"]
	if policyName == "" {
		policyName = "default"
	}

	log := logf.FromContext(ctx)
	policy := &piishieldv1alpha1.PiiPolicy{}
	if err := m.Client.Get(ctx, client.ObjectKey{Name: policyName, Namespace: req.Namespace}, policy); err != nil {
		if m.strictMode() {
			log.Info("strict mode: denying pod that requests injection but has no PiiPolicy",
				"pod", pod.Name, "namespace", req.Namespace, "policy", policyName)
			return admission.Denied(fmt.Sprintf(
				"PII-Shield strict mode: pod requires PiiPolicy %q in namespace %q, but it was not found",
				policyName, req.Namespace))
		}
		log.Info("permissive mode: skipping injection for pod with no PiiPolicy",
			"pod", pod.Name, "namespace", req.Namespace, "policy", policyName)
		resp := admission.Allowed("Policy not found, skipping injection")
		resp.Warnings = append(resp.Warnings, fmt.Sprintf(
			"PII-Shield: no PiiPolicy %q found in namespace %q; sidecar NOT injected and logs are NOT redacted. Enable webhook strict mode to deny such pods.",
			policyName, req.Namespace))
		return resp
	}

	targetContainerName := pod.Annotations["pii-shield.io/target-container"]
	if len(pod.Spec.Containers) > 1 && targetContainerName == "" {
		return admission.Denied("Pod has multiple containers. Please specify target using pii-shield.io/target-container annotation")
	}

	mode := policy.Spec.InjectionMode
	if mode == "" {
		mode = "file" // fallback to MVP
	}

	var mutatedPod *corev1.Pod
	switch mode {
	case "file":
		mutatedPod, err = m.injectFileMode(pod, policy, targetContainerName)
	case "pipe":
		mutatedPod, err = m.injectPipeMode(pod, policy, targetContainerName)
	case "ebpf":
		mutatedPod, err = m.injectEBPFMode(pod, policy, targetContainerName)
	default:
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("unknown injection mode: %s", mode))
	}

	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	marshaledPod, err := json.Marshal(mutatedPod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	resp := admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
	if mode == "pipe" {
		resp.Warnings = append(resp.Warnings,
			"PiiPolicy injectionMode \"pipe\" is experimental: it rewrites the target container command through /bin/sh -c and can break distroless images, argument quoting, signal handling, and the app lifecycle")
	}
	return resp
}

func (m *PodMutator) getTargetContainerIndex(pod *corev1.Pod, targetName string) int {
	if len(pod.Spec.Containers) == 1 {
		return 0
	}
	for i, c := range pod.Spec.Containers {
		if c.Name == targetName {
			return i
		}
	}
	return -1 // Should not happen due to prior validation ideally
}

func (m *PodMutator) injectFileMode(pod *corev1.Pod, policy *piishieldv1alpha1.PiiPolicy, target string) (*corev1.Pod, error) {
	podCopy := pod.DeepCopy()
	targetIdx := m.getTargetContainerIndex(podCopy, target)
	if targetIdx == -1 {
		return nil, fmt.Errorf("target container %s not found", target)
	}

	// Ensure fsGroup is set so nonroot sidecar can read emptyDir volumes
	if podCopy.Spec.SecurityContext == nil {
		podCopy.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if podCopy.Spec.SecurityContext.FSGroup == nil {
		fsGroupStr := os.Getenv("AGENT_FSGROUP")
		if fsGroupStr == "" {
			fsGroupStr = "65532" // default to nonroot
		}
		fsGroup, err := strconv.ParseInt(fsGroupStr, 10, 64)
		if err == nil {
			podCopy.Spec.SecurityContext.FSGroup = ptr.To(fsGroup)
		} else {
			podCopy.Spec.SecurityContext.FSGroup = ptr.To(int64(65532))
		}
	}

	// Add volume
	podCopy.Spec.Volumes = append(podCopy.Spec.Volumes, corev1.Volume{
		Name:         "pii-shared",
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	})
	podCopy.Spec.Volumes = append(podCopy.Spec.Volumes, corev1.Volume{
		Name:         "pii-tmp",
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	})

	// Mount volume to main container
	logPath := policy.Spec.LogPath
	if logPath == "" {
		logPath = "/app/logs/log.txt"
	}
	mountPathBase := logPath
	if strings.Contains(mountPathBase, "/") {
		lastSlash := strings.LastIndex(mountPathBase, "/")
		mountPathBase = mountPathBase[:lastSlash]
		if mountPathBase == "" {
			mountPathBase = "/"
		}
	}

	podCopy.Spec.Containers[targetIdx].VolumeMounts = append(podCopy.Spec.Containers[targetIdx].VolumeMounts, corev1.VolumeMount{
		Name:      "pii-shared",
		MountPath: mountPathBase,
	})

	fileName := logPath[strings.LastIndex(logPath, "/")+1:]
	if fileName == "" {
		fileName = "log.txt"
	}
	sidecarTargetFile := "/shared/" + fileName

	sidecar := m.buildSidecar("file", policy, sidecarTargetFile)
	m.addSidecar(podCopy, sidecar)

	return podCopy, nil
}

func (m *PodMutator) injectPipeMode(pod *corev1.Pod, policy *piishieldv1alpha1.PiiPolicy, target string) (*corev1.Pod, error) {
	podCopy := pod.DeepCopy()
	targetIdx := m.getTargetContainerIndex(podCopy, target)
	if targetIdx == -1 {
		return nil, fmt.Errorf("target container %s not found", target)
	}

	// Ensure fsGroup is set so nonroot sidecar can read emptyDir volumes
	if podCopy.Spec.SecurityContext == nil {
		podCopy.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if podCopy.Spec.SecurityContext.FSGroup == nil {
		fsGroupStr := os.Getenv("AGENT_FSGROUP")
		if fsGroupStr == "" {
			fsGroupStr = "65532" // default to nonroot
		}
		fsGroup, err := strconv.ParseInt(fsGroupStr, 10, 64)
		if err == nil {
			podCopy.Spec.SecurityContext.FSGroup = ptr.To(fsGroup)
		} else {
			podCopy.Spec.SecurityContext.FSGroup = ptr.To(int64(65532))
		}
	}

	// Add volumes
	podCopy.Spec.Volumes = append(podCopy.Spec.Volumes, corev1.Volume{
		Name:         "pii-pipe-dir",
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	})
	podCopy.Spec.Volumes = append(podCopy.Spec.Volumes, corev1.Volume{
		Name:         "pii-tmp",
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	})

	// Init container to mkfifo in emptyDir (survives main restart)
	podCopy.Spec.InitContainers = append(podCopy.Spec.InitContainers, corev1.Container{
		Name:    "pii-mkfifo",
		Image:   "alpine",
		Command: []string{"/bin/sh", "-c"},
		Args:    []string{"mkfifo /shared/log.pipe && chmod 666 /shared/log.pipe"},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "pii-pipe-dir", MountPath: "/shared"},
		},
	})

	// Patch Main Container: alter command
	origCmd := policy.Spec.OriginalCommand
	if origCmd == "" {
		// Best effort, fallback to parsing container.Command if specified
		if len(podCopy.Spec.Containers[targetIdx].Command) > 0 {
			origCmd = strings.Join(podCopy.Spec.Containers[targetIdx].Command, " ")
		} else {
			return nil, fmt.Errorf("originalCommand is required for pipe mode if container lacks explicit command")
		}
	}

	podCopy.Spec.Containers[targetIdx].Command = []string{"/bin/sh", "-c"}
	podCopy.Spec.Containers[targetIdx].Args = []string{"exec " + origCmd + " > /shared/log.pipe"}
	podCopy.Spec.Containers[targetIdx].VolumeMounts = append(podCopy.Spec.Containers[targetIdx].VolumeMounts, corev1.VolumeMount{
		Name:      "pii-pipe-dir",
		MountPath: "/shared",
	})

	sidecar := m.buildSidecar("pipe", policy, "/shared/log.pipe")
	m.addSidecar(podCopy, sidecar)

	return podCopy, nil
}

func (m *PodMutator) injectEBPFMode(pod *corev1.Pod, policy *piishieldv1alpha1.PiiPolicy, target string) (*corev1.Pod, error) {
	podCopy := pod.DeepCopy()

	// Share Process Namespace to scan PIDs
	podCopy.Spec.ShareProcessNamespace = ptr.To(true)

	appName := target
	if appName == "" && len(podCopy.Spec.Containers) > 0 {
		appName = podCopy.Spec.Containers[0].Name
	}

	sidecar := corev1.Container{
		Name:    "pii-shield-sidecar",
		Image:   "ghcr.io/pii-shield/pii-shield:v2.0.0-ebpf",
		Command: []string{"/bin/sh", "-c"},
		Args:    []string{fmt.Sprintf("pii-shield-ebpf --target-process=\"%s\"", appName)},
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.To(true),
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "kernel-debug", MountPath: "/sys/kernel/debug"},
		},
		Resources: policy.Spec.Resources,
	}

	podCopy.Spec.Volumes = append(podCopy.Spec.Volumes, corev1.Volume{
		Name: "kernel-debug",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{
			Path: "/sys/kernel/debug",
		}},
	})

	m.addSidecar(podCopy, sidecar)

	return podCopy, nil
}

func (m *PodMutator) buildSidecar(mode string, policy *piishieldv1alpha1.PiiPolicy, sidecarTargetFile string) corev1.Container {
	agentImage := os.Getenv("AGENT_IMAGE")
	if agentImage == "" {
		agentImage = "pii-shield-agent:enterprise"
	}

	sidecar := corev1.Container{
		Name:            "pii-shield-sidecar",
		Image:           agentImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/pii-shield"},
		Args:            []string{"--watch-file", sidecarTargetFile},
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             ptr.To(true),
			ReadOnlyRootFilesystem:   ptr.To(true),
			AllowPrivilegeEscalation: ptr.To(false),
		},
		Resources: policy.Spec.Resources,
		Env:       scannerEnv(policy),
	}

	if mode == "file" {
		sidecar.VolumeMounts = append(sidecar.VolumeMounts, corev1.VolumeMount{Name: "pii-shared", MountPath: "/shared"}, corev1.VolumeMount{Name: "pii-tmp", MountPath: "/tmp"})
	} else if mode == "pipe" {
		sidecar.VolumeMounts = append(sidecar.VolumeMounts, corev1.VolumeMount{Name: "pii-pipe-dir", MountPath: "/shared"}, corev1.VolumeMount{Name: "pii-tmp", MountPath: "/tmp"})
	}

	return sidecar
}

// scannerEnv translates PiiPolicy scanner settings into the PII_* environment
// variables read by the sidecar agent (cmd/cleaner) and pkg/scanner.
//
// Effective config precedence, most specific wins:
//  1. PiiPolicy fields (saltSecretKeyRef over salt within the policy);
//  2. operator-level defaults (AGENT_SALT_SECRET_NAME/KEY env on the
//     operator, normally set from chart values) — used when the policy is
//     silent;
//  3. scanner built-in defaults — anything still unset produces no env var.
//
// Pod annotations select the policy and target container but deliberately
// cannot override individual scanner fields: redaction settings must stay
// auditable through PiiPolicy objects instead of being scattered over pods.
func scannerEnv(policy *piishieldv1alpha1.PiiPolicy) []corev1.EnvVar {
	spec := policy.Spec
	var env []corev1.EnvVar
	add := func(name, value string) {
		if value != "" {
			env = append(env, corev1.EnvVar{Name: name, Value: value})
		}
	}

	switch {
	case spec.SaltSecretKeyRef != nil:
		env = append(env, corev1.EnvVar{
			Name:      "PII_SALT",
			ValueFrom: &corev1.EnvVarSource{SecretKeyRef: spec.SaltSecretKeyRef},
		})
	case spec.Salt != "":
		add("PII_SALT", spec.Salt)
	default:
		if name := os.Getenv("AGENT_SALT_SECRET_NAME"); name != "" {
			key := os.Getenv("AGENT_SALT_SECRET_KEY")
			if key == "" {
				key = "salt"
			}
			env = append(env, corev1.EnvVar{
				Name: "PII_SALT",
				ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: name},
					Key:                  key,
				}},
			})
		}
	}
	add("PII_FAIL_POLICY", spec.FailPolicy)
	if spec.ConfidenceThreshold != 0 {
		add("PII_CONFIDENCE_THRESHOLD", strconv.FormatFloat(float64(spec.ConfidenceThreshold), 'f', -1, 32))
	}
	if spec.EntropyThreshold != 0 {
		add("PII_ENTROPY_THRESHOLD", strconv.FormatFloat(float64(spec.EntropyThreshold), 'f', -1, 32))
	}
	if spec.MinSecretLength > 0 {
		add("PII_MIN_SECRET_LENGTH", strconv.Itoa(spec.MinSecretLength))
	}
	add("PII_SENSITIVE_KEYS", strings.Join(spec.SensitiveKeys, ","))
	add("PII_SENSITIVE_KEY_PATTERNS", strings.Join(spec.SensitiveKeyPatterns, ","))
	add("PII_CUSTOM_REGEX_LIST", marshalRegexRules(spec.CustomRegexList))
	add("PII_SAFE_REGEX_LIST", marshalRegexRules(spec.SafeRegexList))

	return env
}

// marshalRegexRules serializes policy regex rules into the JSON format of the
// scanner's CustomRegexConfig ({"pattern": ..., "name": ...}).
func marshalRegexRules(rules []piishieldv1alpha1.RegexRule) string {
	if len(rules) == 0 {
		return ""
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return ""
	}
	return string(b)
}

func (m *PodMutator) addSidecar(pod *corev1.Pod, sidecar corev1.Container) {
	legacyModeStr := os.Getenv("LEGACY_SIDECAR_MODE")
	legacyMode := m.LegacySidecarMode
	if strings.ToLower(legacyModeStr) == "true" {
		legacyMode = true
	}

	if !legacyMode {
		// Native sidecar in initContainers
		sidecar.RestartPolicy = ptr.To(corev1.ContainerRestartPolicyAlways)
		pod.Spec.InitContainers = append(pod.Spec.InitContainers, sidecar)
	} else {
		// Standard container
		pod.Spec.Containers = append(pod.Spec.Containers, sidecar)
	}
}
