// Package policyfile renders a PiiPolicy into the JSON policy file the
// sidecar reads from PII_CONFIG_FILE and reloads when it changes. The
// controller writes the rendering into a ConfigMap next to the policy and the
// webhook mounts that ConfigMap into every sidecar injected for the policy,
// so an edit to the policy reaches running pods without a restart.
//
// The file carries rules only. The salt (a Secret), the fail policy, the
// injection mode, the log path and the resources are settings of the pod and
// keep going through the pod spec; the sidecar ignores a salt in the file.
//
// With spec.remoteConfig the rules come from a central source in the same
// format: Parse validates the remote file the way the sidecar does, Merge
// lays the rule fields set in the local policy over it, and Encode writes
// the result.
package policyfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

const (
	// Key is the ConfigMap key and the file name under MountPath.
	Key = "policy.json"
	// RemoteKey is the ConfigMap key that keeps the last good remote file as
	// fetched, so a pull that fails after an operator restart can still be
	// merged with the current local policy.
	RemoteKey = "remote.json"
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
	// AnnotationRemoteETag carries the ETag the source returned with the
	// last good remote file; it goes back as If-None-Match.
	AnnotationRemoteETag = "pii-shield.io/remote-etag"
	// AnnotationRemoteHash carries Hash of the last good remote file.
	AnnotationRemoteHash = "pii-shield.io/remote-hash"
	// AnnotationRemotePublication and AnnotationRemoteSignedBy record the
	// publication number and key of the last good remote file when the
	// policy requires signatures; an empty signer means it was not checked.
	AnnotationRemotePublication = "pii-shield.io/remote-publication"
	AnnotationRemoteSignedBy    = "pii-shield.io/remote-signed-by"

	// MaxMinSecretLength mirrors the scanner's limit on min_secret_length.
	MaxMinSecretLength = 1024

	prefix = "pii-shield-policy-"
	// maxNameLength is the Kubernetes limit on a ConfigMap name.
	maxNameLength = 253
)

// ConfigMapName returns the name of the ConfigMap rendered for the policy.
func ConfigMapName(policyName string) string {
	return prefix + policyName
}

// CheckName reports whether the policy name fits a ConfigMap name.
func CheckName(policyName string) error {
	if len(ConfigMapName(policyName)) > maxNameLength {
		return fmt.Errorf("policy name %q is too long for a ConfigMap name with the %q prefix", policyName, prefix)
	}
	return nil
}

// Document is the file's JSON shape: the keys of the SDK's init_config
// payload that are rules, plus the revision. Zero values are left out so the
// sidecar keeps its default for them, the same as an unset PiiPolicy field
// produces no env var.
type Document struct {
	Revision             string   `json:"revision,omitempty"`
	EntropyThreshold     float64  `json:"entropy_threshold,omitempty"`
	ConfidenceThreshold  float64  `json:"confidence_score,omitempty"`
	MinSecretLength      int      `json:"min_secret_length,omitempty"`
	SensitiveKeys        []string `json:"sensitive_keys,omitempty"`
	SensitiveKeyPatterns []string `json:"sensitive_key_patterns,omitempty"`
	CustomRegexes        []Rule   `json:"custom_regexes,omitempty"`
	SafeRegexes          []Rule   `json:"safe_regexes,omitempty"`
	DisableBigramCheck   *bool    `json:"disable_bigram_check,omitempty"`
	AdaptiveThreshold    *bool    `json:"adaptive_threshold,omitempty"`
	EntityTypeLabels     *bool    `json:"entity_type_labels,omitempty"`
}

// Rule is one custom or safe regex rule in the file.
type Rule struct {
	Pattern string `json:"pattern"`
	Name    string `json:"name,omitempty"`
}

// Reasons a remote file is rejected, used as condition reasons.
const (
	ReasonInvalidJSON  = "InvalidJSON"
	ReasonInvalidRegex = "InvalidRegex"
	ReasonInvalidValue = "InvalidValue"
)

// ValidationError says why a remote file was rejected.
type ValidationError struct {
	Reason string
	Err    error
}

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

func invalid(reason, format string, args ...any) error {
	return &ValidationError{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// remoteFile is what Parse reads: a Document plus the two keys a file may
// carry that are never accepted from outside.
type remoteFile struct {
	Document
	Salt       string `json:"salt"`
	FailPolicy string `json:"fail_policy"`
}

// Parse validates a remote policy file the way the sidecar validates
// PII_CONFIG_FILE: all or nothing. The first invalid JSON, pattern or value
// is a ValidationError and nothing is used. salt and fail_policy are not
// rules and are dropped; their keys are returned in ignored so the status
// can say so. Unknown keys are ignored for forward compatibility.
func Parse(b []byte) (doc Document, ignored []string, err error) {
	var f remoteFile
	if err := json.Unmarshal(b, &f); err != nil {
		return Document{}, nil, invalid(ReasonInvalidJSON, "invalid json: %w", err)
	}
	if f.Salt != "" {
		ignored = append(ignored, "salt")
	}
	if f.FailPolicy != "" {
		ignored = append(ignored, "fail_policy")
	}
	doc = f.Document
	if doc.EntropyThreshold < 0 {
		return Document{}, nil, invalid(ReasonInvalidValue, "entropy_threshold must not be negative")
	}
	if doc.ConfidenceThreshold < 0 {
		return Document{}, nil, invalid(ReasonInvalidValue, "confidence_score must not be negative")
	}
	if doc.MinSecretLength < 0 || doc.MinSecretLength > MaxMinSecretLength {
		return Document{}, nil, invalid(ReasonInvalidValue, "min_secret_length must be between 1 and %d", MaxMinSecretLength)
	}
	if len(doc.SensitiveKeys) > 0 {
		keys := make([]string, 0, len(doc.SensitiveKeys))
		for _, k := range doc.SensitiveKeys {
			k = strings.ToLower(strings.TrimSpace(k))
			if k == "" {
				return Document{}, nil, invalid(ReasonInvalidValue, "sensitive_keys holds an empty entry")
			}
			keys = append(keys, k)
		}
		doc.SensitiveKeys = keys
	}
	for _, p := range doc.SensitiveKeyPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return Document{}, nil, invalid(ReasonInvalidRegex, "sensitive_key_patterns: invalid regex %q: %w", p, err)
		}
	}
	if err := checkRules("custom_regexes", doc.CustomRegexes); err != nil {
		return Document{}, nil, err
	}
	if err := checkRules("safe_regexes", doc.SafeRegexes); err != nil {
		return Document{}, nil, err
	}
	return doc, ignored, nil
}

// checkRules rejects a rule with an empty or invalid pattern. An empty
// pattern matches every token, so a misspelled key ("regex" for "pattern")
// must not slip through as a rule that hides the whole line.
func checkRules(field string, rules []Rule) error {
	for i, r := range rules {
		if r.Pattern == "" {
			return invalid(ReasonInvalidRegex, "%s[%d]: empty pattern", field, i)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return invalid(ReasonInvalidRegex, "%s[%d]: invalid regex %q: %w", field, i, r.Pattern, err)
		}
	}
	return nil
}

// Local builds the document for a policy without a remote source. The
// revision is the policy's generation, which the API server bumps on every
// spec change, so the sidecar's reload log names the edit it applied.
func Local(policy *piishieldv1alpha1.PiiPolicy) Document {
	return Merge(Document{}, policy)
}

// Merge lays the rule fields set in the policy over the remote document: a
// set field replaces the remote value of that field (a list replaces the
// whole list, the same as PII_SENSITIVE_KEYS replaces the default list), an
// unset field keeps what the source said. The local administrator can
// therefore always pin a value in their namespace, and nothing but rules
// comes from the source. The revision is the remote revision (or nothing)
// followed by "+" and the policy's generation.
func Merge(remote Document, policy *piishieldv1alpha1.PiiPolicy) Document {
	doc := remote
	spec := policy.Spec
	if spec.EntropyThreshold != 0 {
		doc.EntropyThreshold = shortest(spec.EntropyThreshold)
	}
	if spec.ConfidenceThreshold != 0 {
		doc.ConfidenceThreshold = shortest(spec.ConfidenceThreshold)
	}
	if spec.MinSecretLength > 0 {
		doc.MinSecretLength = spec.MinSecretLength
	}
	if len(spec.SensitiveKeys) > 0 {
		doc.SensitiveKeys = spec.SensitiveKeys
	}
	if len(spec.SensitiveKeyPatterns) > 0 {
		doc.SensitiveKeyPatterns = spec.SensitiveKeyPatterns
	}
	if len(spec.CustomRegexList) > 0 {
		doc.CustomRegexes = rules(spec.CustomRegexList)
	}
	if len(spec.SafeRegexList) > 0 {
		doc.SafeRegexes = rules(spec.SafeRegexList)
	}
	gen := strconv.FormatInt(policy.Generation, 10)
	if remote.Revision != "" {
		doc.Revision = remote.Revision + "+" + gen
	} else {
		doc.Revision = gen
	}
	return doc
}

// Encode writes the document as the file.
func Encode(doc Document) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}

// Render builds the policy file for a policy without a remote source.
func Render(policy *piishieldv1alpha1.PiiPolicy) ([]byte, error) {
	if err := CheckName(policy.Name); err != nil {
		return nil, err
	}
	return Encode(Local(policy))
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

func rules(in []piishieldv1alpha1.RegexRule) []Rule {
	if len(in) == 0 {
		return nil
	}
	out := make([]Rule, len(in))
	for i, r := range in {
		out[i] = Rule{Pattern: r.Pattern, Name: r.Name}
	}
	return out
}

// Hash returns a short content hash of a file.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
