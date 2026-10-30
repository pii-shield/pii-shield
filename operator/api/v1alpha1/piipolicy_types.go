/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RegexRule is a named regular expression passed to the scanner.
type RegexRule struct {
	// Name identifies the rule in redaction output and metrics
	// +optional
	Name string `json:"name,omitempty"`

	// Pattern is an RE2 regular expression
	// +kubebuilder:validation:MinLength=1
	Pattern string `json:"pattern"`
}

// RemoteConfig points the controller at a central rule repository: a JSON
// policy file in the SDK init_config format (entropy_threshold,
// sensitive_keys, custom_regexes, ... plus an informational revision),
// served over HTTPS by anything that can answer a GET — a static file on an
// object store, an internal web server, or a rule server. The controller
// pulls the file every IntervalSeconds with If-None-Match, lays the rule
// fields set in this PiiPolicy over it and renders the result into the
// policy's ConfigMap, so the sidecars pick the new rules up without a
// restart. Nothing is ever sent to the source except the request itself.
//
// Only rules are accepted from the source: entropy_threshold,
// confidence_score, min_secret_length, sensitive_keys,
// sensitive_key_patterns, custom_regexes, safe_regexes,
// disable_bigram_check, adaptive_threshold, entity_type_labels and
// revision. A salt or fail_policy in the file is ignored; injectionMode,
// logPath and resources are pod settings and cannot come from outside.
// When the source is unreachable or serves an invalid file, the last good
// copy stays in use and the RemoteSynced condition says why.
type RemoteConfig struct {
	// URL of the policy file. Must be https:// unless AllowInsecure is set.
	// +kubebuilder:validation:Pattern=`^https?://`
	// +kubebuilder:validation:MinLength=8
	URL string `json:"url"`

	// IntervalSeconds is how often the file is pulled. Default 300,
	// minimum 30. A failed pull is retried after at most 60 seconds.
	// +kubebuilder:validation:Minimum=30
	// +optional
	IntervalSeconds int32 `json:"intervalSeconds,omitempty"`

	// HeaderSecretRef names a key in a Secret in the policy's namespace whose
	// value is sent as the whole Authorization header, for example
	// "Bearer <token>". The value never appears in the policy or its status.
	// +optional
	HeaderSecretRef *corev1.SecretKeySelector `json:"headerSecretRef,omitempty"`

	// CABundleSecretRef names a key in a Secret in the policy's namespace
	// that holds a PEM bundle used to verify the server certificate instead
	// of the system roots.
	// +optional
	CABundleSecretRef *corev1.SecretKeySelector `json:"caBundleSecretRef,omitempty"`

	// AllowInsecure permits an http:// URL and skips certificate
	// verification for https://. For tests and air-gapped lab clusters only;
	// the RemoteSynced condition carries a warning while it is set.
	// +optional
	AllowInsecure bool `json:"allowInsecure,omitempty"`
}

// PiiPolicySpec defines the desired state of PiiPolicy
// +kubebuilder:validation:XValidation:rule="self.injectionMode != 'ebpf' || (has(self.auditMode) && self.auditMode)",message="injectionMode ebpf is the eBPF audit agent, which only observes; set auditMode: true (there is no eBPF redaction, see #96)"
type PiiPolicySpec struct {
	// FailPolicy determines the sidecar behavior when sanitization fails:
	// "open" passes the raw line through (default), "closed" drops it.
	// Exported to the sidecar as PII_FAIL_POLICY.
	// +kubebuilder:validation:Enum=open;closed
	// +optional
	FailPolicy string `json:"failPolicy,omitempty"`

	// ConfidenceThreshold is the threshold for the PII scanner.
	// Exported to the sidecar as PII_CONFIDENCE_THRESHOLD.
	ConfidenceThreshold float32 `json:"confidenceThreshold,omitempty"`

	// Salt is the deterministic hashing salt, exported to the sidecar as
	// PII_SALT. Use at least 16 characters. The value is stored in plain
	// text in the policy object — prefer SaltSecretKeyRef in production.
	// +optional
	Salt string `json:"salt,omitempty"`

	// SaltSecretKeyRef references a key in a Secret that holds the
	// deterministic hashing salt. Takes precedence over Salt. The Secret is
	// resolved in the namespace of each injected pod, and the sidecar
	// receives it as PII_SALT via a secretKeyRef, so the value never appears
	// in the PiiPolicy object or the mutated pod spec.
	// +optional
	SaltSecretKeyRef *corev1.SecretKeySelector `json:"saltSecretKeyRef,omitempty"`

	// EntropyThreshold overrides the scanner entropy threshold.
	// Exported to the sidecar as PII_ENTROPY_THRESHOLD.
	// +optional
	EntropyThreshold float32 `json:"entropyThreshold,omitempty"`

	// MinSecretLength is the minimum token length considered a secret.
	// Exported to the sidecar as PII_MIN_SECRET_LENGTH.
	// +kubebuilder:validation:Minimum=1
	// +optional
	MinSecretLength int `json:"minSecretLength,omitempty"`

	// SensitiveKeys replaces the scanner's default sensitive key list.
	// Exported to the sidecar as comma-separated PII_SENSITIVE_KEYS.
	// +optional
	SensitiveKeys []string `json:"sensitiveKeys,omitempty"`

	// SensitiveKeyPatterns are case-insensitive regexes matched against keys.
	// Exported to the sidecar as comma-separated PII_SENSITIVE_KEY_PATTERNS.
	// +optional
	SensitiveKeyPatterns []string `json:"sensitiveKeyPatterns,omitempty"`

	// CustomRegexList adds redaction rules on top of the built-in detectors.
	// Exported to the sidecar as JSON in PII_CUSTOM_REGEX_LIST.
	// +optional
	CustomRegexList []RegexRule `json:"customRegexList,omitempty"`

	// SafeRegexList whitelists matches that must never be redacted.
	// Exported to the sidecar as JSON in PII_SAFE_REGEX_LIST.
	// +optional
	SafeRegexList []RegexRule `json:"safeRegexList,omitempty"`

	// InjectionMode defines the mode: "file", "pipe", or "ebpf".
	// "pipe" mode is EXPERIMENTAL: it rewrites the target container command
	// through "/bin/sh -c", which can break distroless images (no shell),
	// argument quoting, signal handling, and the app lifecycle. Not
	// recommended for production; see KNOWN_LIMITATIONS.md.
	// "ebpf" is EXPERIMENTAL and observation only: the eBPF audit agent
	// shares the pod's pid namespace and counts what it would have redacted
	// in the pod's stdout and stderr, so it requires auditMode: true. It
	// needs a kernel of 5.8 or newer with BTF and the BPF and PERFMON
	// capabilities; there is no eBPF redaction.
	// +kubebuilder:validation:Enum=file;pipe;ebpf
	InjectionMode string `json:"injectionMode"`

	// LogPath is the path where the application writes logs (for "file" mode)
	LogPath string `json:"logPath,omitempty"`

	// OriginalCommand is the original app command (for the experimental
	// "pipe" mode); it is executed through "/bin/sh -c"
	OriginalCommand string `json:"originalCommand,omitempty"`

	// Resources allows configuration of compute resources for the injected sidecar
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// RemoteConfig pulls the rules from a central rule repository and lays
	// the rule fields set in this policy over them. See RemoteConfig.
	// +optional
	RemoteConfig *RemoteConfig `json:"remoteConfig,omitempty"`

	// AuditMode is the dry run: the sidecar scans every line as usual but
	// writes it out unchanged, byte for byte, and only counts what it would
	// have redacted (PII_MODE=audit; the counters are
	// piishield_audit_lines_total and piishield_audit_findings_total, so the
	// webhook also turns the sidecar's metrics on, on port 9090, and an
	// hourly summary in its log). Run a policy in audit mode on real traffic
	// first, look at the numbers, then set it to false; the change needs a
	// pod restart. Works with injectionMode file and pipe (in pipe mode the
	// sidecar still sits in the stream's path), and is required with ebpf,
	// whose agent only observes (#96).
	// +optional
	AuditMode bool `json:"auditMode,omitempty"`
}

// RemoteStatus reports the last good pull from spec.remoteConfig.
type RemoteStatus struct {
	// LastSyncTime is when the source last answered with a valid file or a
	// 304 Not Modified.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ETag is the entity tag of the last good file, sent back as
	// If-None-Match on the next pull.
	// +optional
	ETag string `json:"etag,omitempty"`

	// Revision is the revision field of the last good file, if it has one.
	// +optional
	Revision string `json:"revision,omitempty"`

	// Hash is a content hash of the last good file.
	// +optional
	Hash string `json:"hash,omitempty"`
}

// PiiPolicyStatus defines the observed state of PiiPolicy.
type PiiPolicyStatus struct {
	// conditions represent the current state of the PiiPolicy resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// RenderedPolicyConfigMap is the name of the ConfigMap in this namespace
	// that holds the rendered rules file (policy.json) mounted into every
	// sidecar injected for this policy. The sidecar reloads the file when it
	// changes, so a spec edit reaches running pods without a restart.
	// +optional
	RenderedPolicyConfigMap string `json:"renderedPolicyConfigMap,omitempty"`

	// RenderedPolicyHash is a content hash of the rendered rules file; it
	// changes only when the rules do.
	// +optional
	RenderedPolicyHash string `json:"renderedPolicyHash,omitempty"`

	// Remote describes the last good pull from spec.remoteConfig; unset when
	// the policy has no remote source or no pull has succeeded yet. The
	// RemoteSynced condition carries the outcome of the latest pull.
	// +optional
	Remote *RemoteStatus `json:"remote,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// PiiPolicy is the Schema for the piipolicies API
type PiiPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PiiPolicy
	// +required
	Spec PiiPolicySpec `json:"spec"`

	// status defines the observed state of PiiPolicy
	// +optional
	Status PiiPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PiiPolicyList contains a list of PiiPolicy
type PiiPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PiiPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PiiPolicy{}, &PiiPolicyList{})
}
