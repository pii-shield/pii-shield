// Package policyfile renders a PiiPolicy into the JSON policy file the
// sidecar reads from PII_CONFIG_FILE and reloads when it changes. The
// controller writes the rendering into a ConfigMap next to the policy and the
// webhook mounts that ConfigMap into every sidecar injected for the policy,
// so an edit to the policy reaches running pods without a restart.
//
// The file carries rules only. The salt (a Secret), the fail policy, the
// injection mode, the log path and the resources are settings of the pod and
// keep going through the pod spec; the sidecar ignores a salt in the file.
package policyfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

const (
	// Key is the ConfigMap key and the file name under MountPath.
	Key = "policy.json"
	// MountPath is where the ConfigMap is mounted in the sidecar.
	MountPath = "/etc/pii-shield"
	// FilePath is the value of PII_CONFIG_FILE in the sidecar.
	FilePath = MountPath + "/" + Key
	// VolumeName names the ConfigMap volume in the mutated pod.
	VolumeName = "pii-policy"

	// LabelPolicy marks the ConfigMap with the policy it was rendered from.
	LabelPolicy = "pii-shield.io/policy"
	// AnnotationHash carries Hash of the rendered file, so a watcher can tell
	// a real change from a no-op update.
	AnnotationHash = "pii-shield.io/policy-hash"

	prefix = "pii-shield-policy-"
	// maxNameLength is the Kubernetes limit on a ConfigMap name.
	maxNameLength = 253
)

// ConfigMapName returns the name of the ConfigMap rendered for the policy.
func ConfigMapName(policyName string) string {
	return prefix + policyName
}

// document is the file's JSON shape: the keys of the SDK's init_config
// payload that a PiiPolicy can set, plus the revision. Zero values are left
// out so the sidecar keeps its default for them, the same as an unset
// PiiPolicy field produces no env var.
type document struct {
	Revision             string   `json:"revision,omitempty"`
	EntropyThreshold     float64  `json:"entropy_threshold,omitempty"`
	ConfidenceThreshold  float64  `json:"confidence_score,omitempty"`
	MinSecretLength      int      `json:"min_secret_length,omitempty"`
	SensitiveKeys        []string `json:"sensitive_keys,omitempty"`
	SensitiveKeyPatterns []string `json:"sensitive_key_patterns,omitempty"`
	CustomRegexes        []rule   `json:"custom_regexes,omitempty"`
	SafeRegexes          []rule   `json:"safe_regexes,omitempty"`
}

type rule struct {
	Pattern string `json:"pattern"`
	Name    string `json:"name,omitempty"`
}

// Render builds the policy file for the policy. The revision is the
// policy's generation, which the API server bumps on every spec change, so
// the sidecar's reload log names the edit it applied.
func Render(policy *piishieldv1alpha1.PiiPolicy) ([]byte, error) {
	if len(ConfigMapName(policy.Name)) > maxNameLength {
		return nil, fmt.Errorf("policy name %q is too long for a ConfigMap name with the %q prefix", policy.Name, prefix)
	}
	spec := policy.Spec
	doc := document{
		Revision:             strconv.FormatInt(policy.Generation, 10),
		EntropyThreshold:     shortest(spec.EntropyThreshold),
		ConfidenceThreshold:  shortest(spec.ConfidenceThreshold),
		MinSecretLength:      spec.MinSecretLength,
		SensitiveKeys:        spec.SensitiveKeys,
		SensitiveKeyPatterns: spec.SensitiveKeyPatterns,
		CustomRegexes:        rules(spec.CustomRegexList),
		SafeRegexes:          rules(spec.SafeRegexList),
	}
	return json.MarshalIndent(doc, "", "  ")
}

// shortest widens a CRD float32 to the float64 the file holds by way of its
// shortest decimal form, so 4.2 in the policy is 4.2 in the file and not
// 4.199999809265137, the same number the env path writes with
// strconv.FormatFloat(..., 32).
func shortest(f float32) float64 {
	v, err := strconv.ParseFloat(strconv.FormatFloat(float64(f), 'f', -1, 32), 64)
	if err != nil {
		return float64(f)
	}
	return v
}

func rules(in []piishieldv1alpha1.RegexRule) []rule {
	if len(in) == 0 {
		return nil
	}
	out := make([]rule, len(in))
	for i, r := range in {
		out[i] = rule{Pattern: r.Pattern, Name: r.Name}
	}
	return out
}

// Hash returns a short content hash of a rendered file.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
