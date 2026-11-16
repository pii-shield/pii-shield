//go:build integration

package webhook

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
	"github.com/pii-shield/pii-shield/operator/internal/policyfile"
)

const sidecarName = injectedContainerName

var nsCounter atomic.Int32

// newNamespace gives each spec its own namespace, so a policy named
// "default" in one spec is not seen by another.
func newNamespace(ctx context.Context) string {
	name := fmt.Sprintf("inject-%d", nsCounter.Add(1))
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})).To(Succeed())
	return name
}

func appPod(ns, name string, containers ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns,
			Labels: map[string]string{"pii-shield.io/inject": "true"},
		},
	}
	for _, c := range containers {
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: c, Image: "registry.example.com/app:1", Command: []string{"node", "app.js"}})
	}
	return pod
}

func createPolicy(ctx context.Context, ns, name string, spec piishieldv1alpha1.PiiPolicySpec) *piishieldv1alpha1.PiiPolicy {
	if spec.InjectionMode == "" {
		spec.InjectionMode = "file"
	}
	p := &piishieldv1alpha1.PiiPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: spec}
	Expect(k8sClient.Create(ctx, p)).To(Succeed())
	return p
}

// sidecars returns every injected sidecar of the pod as the API server
// stored it, wherever it was put.
func sidecars(pod *corev1.Pod) []corev1.Container {
	var out []corev1.Container
	for _, list := range [][]corev1.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for _, c := range list {
			if c.Name == sidecarName {
				out = append(out, c)
			}
		}
	}
	return out
}

func envOf(c corev1.Container, name string) *corev1.EnvVar {
	for i := range c.Env {
		if c.Env[i].Name == name {
			return &c.Env[i]
		}
	}
	return nil
}

func stored(ctx context.Context, pod *corev1.Pod) *corev1.Pod {
	got := &corev1.Pod{}
	Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pod), got)).To(Succeed())
	return got
}

var _ = Describe("Pod admission through the API server", func() {
	ctx := context.Background()

	BeforeEach(func() {
		warnings.drain()
		DeferCleanup(os.Unsetenv, "STRICT_MODE")
	})

	It("injects one native sidecar and its volumes into a labelled pod under a file-mode policy", func() {
		ns := newNamespace(ctx)
		createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{LogPath: "/var/log/app/out.log"})

		pod := appPod(ns, "app", "app")
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		got := stored(ctx, pod)

		Expect(sidecars(got)).To(HaveLen(1))
		Expect(got.Spec.InitContainers).To(HaveLen(1), "the sidecar is a native one, in initContainers")
		sc := got.Spec.InitContainers[0]
		Expect(sc.RestartPolicy).NotTo(BeNil())
		Expect(*sc.RestartPolicy).To(Equal(corev1.ContainerRestartPolicyAlways))

		Expect(got.Spec.Containers).To(HaveLen(1), "the application container is still the only main container")
		app := got.Spec.Containers[0]
		Expect(app.Image).To(Equal("registry.example.com/app:1"))
		Expect(app.Command).To(Equal([]string{"node", "app.js"}), "file mode leaves the command alone")
		Expect(app.VolumeMounts).To(ContainElement(HaveField("MountPath", "/var/log/app")))

		names := map[string]bool{}
		for _, v := range got.Spec.Volumes {
			Expect(names[v.Name]).To(BeFalse(), "volume %q appears twice", v.Name)
			names[v.Name] = true
		}
		Expect(names).To(HaveKey("pii-shared"))
		Expect(names).To(HaveKey("pii-tmp"))
		Expect(got.Spec.SecurityContext).NotTo(BeNil())
		Expect(got.Spec.SecurityContext.FSGroup).NotTo(BeNil())
	})

	It("leaves a pod without the inject label exactly as submitted", func() {
		ns := newNamespace(ctx)
		createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{})

		pod := appPod(ns, "plain", "app")
		pod.Labels = map[string]string{"app": "plain"}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		got := stored(ctx, pod)

		Expect(sidecars(got)).To(BeEmpty())
		Expect(got.Spec.InitContainers).To(BeEmpty())
		for _, v := range got.Spec.Volumes {
			Expect(v.Name).NotTo(HavePrefix("pii-"))
		}
	})

	It("uses the policy the pod names, not the namespace default", func() {
		ns := newNamespace(ctx)
		createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{MinSecretLength: 6})
		createPolicy(ctx, ns, "payments", piishieldv1alpha1.PiiPolicySpec{MinSecretLength: 21})

		pod := appPod(ns, "pay", "app")
		pod.Annotations = map[string]string{"pii-shield.io/policy": "payments"}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		sc := sidecars(stored(ctx, pod))
		Expect(sc).To(HaveLen(1))

		// Either the rule travels in the env or the pod mounts the policy's
		// own file; both must point at "payments".
		if e := envOf(sc[0], "PII_MIN_SECRET_LENGTH"); e != nil {
			Expect(e.Value).To(Equal("21"))
		}
		var mounted []string
		for _, v := range stored(ctx, pod).Spec.Volumes {
			if v.ConfigMap != nil {
				mounted = append(mounted, v.ConfigMap.Name)
			}
		}
		Expect(mounted).To(ConsistOf(policyfile.ConfigMapName("payments")))
	})

	It("starts a labelled pod unprotected, with a warning, when its policy is missing and strict mode is off", func() {
		ns := newNamespace(ctx)
		pod := appPod(ns, "orphan", "app")
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())

		Expect(sidecars(stored(ctx, pod))).To(BeEmpty())
		Expect(warnings.drain()).To(ContainElement(ContainSubstring("NOT injected")))
	})

	It("refuses a labelled pod whose policy is missing when strict mode is on", func() {
		ns := newNamespace(ctx)
		Expect(os.Setenv("STRICT_MODE", "true")).To(Succeed())

		pod := appPod(ns, "orphan", "app")
		err := k8sClient.Create(ctx, pod)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("strict mode"))
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(pod), &corev1.Pod{}))).To(BeTrue(), "the refused pod must not exist")

		// Strict mode refuses only what asked for a sidecar.
		plain := appPod(ns, "plain", "app")
		plain.Labels = nil
		Expect(k8sClient.Create(ctx, plain)).To(Succeed())
	})

	It("refuses a multi-container pod without a target and injects when the target is named", func() {
		ns := newNamespace(ctx)
		createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{})

		err := k8sClient.Create(ctx, appPod(ns, "two", "app", "proxy"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("target-container"))

		pod := appPod(ns, "two-named", "app", "proxy")
		pod.Annotations = map[string]string{"pii-shield.io/target-container": "proxy"}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		got := stored(ctx, pod)
		Expect(sidecars(got)).To(HaveLen(1))
		for _, c := range got.Spec.Containers {
			mounted := false
			for _, m := range c.VolumeMounts {
				mounted = mounted || m.Name == "pii-shared"
			}
			Expect(mounted).To(Equal(c.Name == "proxy"), "only the named container shares the log volume, container %q", c.Name)
		}
	})

	It("takes the salt from the Secret the policy references and never writes it into the pod", func() {
		ns := newNamespace(ctx)
		createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{
			SaltSecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "pii-salt"}, Key: "salt",
			},
		})
		pod := appPod(ns, "salted", "app")
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())

		sc := sidecars(stored(ctx, pod))
		Expect(sc).To(HaveLen(1))
		salt := envOf(sc[0], "PII_SALT")
		Expect(salt).NotTo(BeNil())
		Expect(salt.Value).To(BeEmpty(), "the salt must be a reference, not a literal")
		Expect(salt.ValueFrom).NotTo(BeNil())
		Expect(salt.ValueFrom.SecretKeyRef.Name).To(Equal("pii-salt"))
		Expect(salt.ValueFrom.SecretKeyRef.Key).To(Equal("salt"))
	})

	It("passes the rules in env before the policy file exists and through the mounted file once it is rendered", func() {
		ns := newNamespace(ctx)
		policy := createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{
			SensitiveKeys:   []string{"session"},
			CustomRegexList: []piishieldv1alpha1.RegexRule{{Name: "tx", Pattern: "^TX-[0-9]+$"}},
		})

		By("waiting for the controller to render the policy ConfigMap")
		cmKey := types.NamespacedName{Name: policyfile.ConfigMapName(policy.Name), Namespace: ns}
		Eventually(func() string {
			cm := &corev1.ConfigMap{}
			if err := k8sClient.Get(ctx, cmKey, cm); err != nil {
				return ""
			}
			return cm.Data[policyfile.Key]
		}, 20*time.Second, 200*time.Millisecond).Should(ContainSubstring("session"))

		pod := appPod(ns, "after-render", "app")
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		got := stored(ctx, pod)
		sc := sidecars(got)
		Expect(sc).To(HaveLen(1))

		// With the file rendered the rules must not also sit in env: the
		// sidecar lays env over the file on every reload, so a rule left in
		// env would pin the pod to the rules of the day it started.
		for _, name := range []string{"PII_SENSITIVE_KEYS", "PII_CUSTOM_REGEX_LIST", "PII_SAFE_REGEX_LIST", "PII_MIN_SECRET_LENGTH", "PII_ENTROPY_THRESHOLD"} {
			Expect(envOf(sc[0], name)).To(BeNil(), "%s must not be set once the policy file is rendered", name)
		}
		file := envOf(sc[0], "PII_CONFIG_FILE")
		Expect(file).NotTo(BeNil(), "the sidecar must be pointed at the policy file")

		var cmVolume string
		for _, v := range got.Spec.Volumes {
			if v.ConfigMap != nil && v.ConfigMap.Name == cmKey.Name {
				cmVolume = v.Name
				Expect(v.ConfigMap.Optional).NotTo(BeNil())
				Expect(*v.ConfigMap.Optional).To(BeTrue(), "a missing ConfigMap must not keep the pod from starting")
			}
		}
		Expect(cmVolume).NotTo(BeEmpty(), "the policy ConfigMap must be a volume of the pod")
		Expect(sc[0].VolumeMounts).To(ContainElement(HaveField("Name", cmVolume)))
		Expect(strings.HasPrefix(file.Value, "/")).To(BeTrue())
	})

	It("accepts an update of an injected pod and does not inject a second sidecar", func() {
		ns := newNamespace(ctx)
		createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{})
		pod := appPod(ns, "updated", "app")
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		before := stored(ctx, pod)
		Expect(sidecars(before)).To(HaveLen(1))

		// Labels and annotations of a running pod change all the time
		// (kubectl label, a rollout controller, a mesh). The webhook is
		// called for every such update and must let it through.
		patch := client.MergeFrom(before.DeepCopy())
		before.Annotations = map[string]string{"example.com/touched": "yes"}
		Expect(k8sClient.Patch(ctx, before, patch)).To(Succeed(), "an annotation update of an injected pod must be accepted")

		after := stored(ctx, pod)
		Expect(after.Annotations).To(HaveKeyWithValue("example.com/touched", "yes"))
		Expect(sidecars(after)).To(HaveLen(1), "still exactly one sidecar after an update")
		Expect(after.Spec.Volumes).To(HaveLen(len(before.Spec.Volumes)))
	})

	It("accepts an update of a labelled pod that started without a sidecar and says it is not protected", func() {
		ns := newNamespace(ctx)
		pod := appPod(ns, "late", "app")
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		Expect(sidecars(stored(ctx, pod))).To(BeEmpty())

		// The policy arrives after the pod. A running pod cannot gain a
		// container, so the update goes through unchanged, with a warning.
		createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{})
		warnings.drain()
		current := stored(ctx, pod)
		patch := client.MergeFrom(current.DeepCopy())
		current.Annotations = map[string]string{"example.com/touched": "yes"}
		Expect(k8sClient.Patch(ctx, current, patch)).To(Succeed())

		Expect(sidecars(stored(ctx, pod))).To(BeEmpty())
		Expect(warnings.drain()).To(ContainElement(ContainSubstring("recreated")))
	})

	It("wraps the command and warns that pipe mode is experimental", func() {
		ns := newNamespace(ctx)
		createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{InjectionMode: "pipe"})

		pod := appPod(ns, "piped", "app")
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		got := stored(ctx, pod)

		Expect(sidecars(got)).To(HaveLen(1))
		var app corev1.Container
		for _, c := range got.Spec.Containers {
			if c.Name == "app" {
				app = c
			}
		}
		Expect(app.Command).To(HaveExactElements("/bin/sh", "-c"), "pipe mode runs the command through a shell")
		Expect(strings.Join(app.Args, " ")).To(ContainSubstring("node"))
		Expect(warnings.drain()).To(ContainElement(ContainSubstring("experimental")))
	})

	It("warns on every pod of an audit-mode policy that logs are not redacted", func() {
		ns := newNamespace(ctx)
		createPolicy(ctx, ns, "default", piishieldv1alpha1.PiiPolicySpec{AuditMode: true})

		pod := appPod(ns, "audited", "app")
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		Expect(sidecars(stored(ctx, pod))).To(HaveLen(1))
		Expect(warnings.drain()).To(ContainElement(ContainSubstring("NOT redacted")))
	})
})
