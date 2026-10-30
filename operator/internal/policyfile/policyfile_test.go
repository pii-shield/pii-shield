package policyfile

import (
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

func TestRenderCarriesRulesOnly(t *testing.T) {
	policy := &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "strict", Generation: 7},
		Spec: piishieldv1alpha1.PiiPolicySpec{
			InjectionMode:        "file",
			FailPolicy:           "closed",
			Salt:                 "0123456789abcdef0123456789abcdef",
			LogPath:              "/var/log/app.log",
			EntropyThreshold:     4.2,
			ConfidenceThreshold:  1.1,
			MinSecretLength:      8,
			SensitiveKeys:        []string{"geheim"},
			SensitiveKeyPatterns: []string{"^x_"},
			CustomRegexList:      []piishieldv1alpha1.RegexRule{{Name: "tx", Pattern: `^TX-\d{5}$`}},
			SafeRegexList:        []piishieldv1alpha1.RegexRule{{Pattern: `^[a-f0-9]{7}$`}},
		},
	}
	b, err := Render(policy)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("rendered file is not JSON: %v\n%s", err, b)
	}
	for _, k := range []string{"salt", "fail_policy", "injection_mode", "log_path"} {
		if _, ok := got[k]; ok {
			t.Errorf("rendered file must not carry %q:\n%s", k, b)
		}
	}
	if got["revision"] != "7" {
		t.Errorf("revision = %v, want the generation 7", got["revision"])
	}
	if got["entropy_threshold"] != 4.2 || got["min_secret_length"] != float64(8) {
		t.Errorf("thresholds not rendered:\n%s", b)
	}
	if !strings.Contains(string(b), `"pattern": "^TX-\\d{5}$"`) || !strings.Contains(string(b), `"name": "tx"`) {
		t.Errorf("custom rule not rendered in the SDK shape:\n%s", b)
	}
}

func TestRenderLeavesUnsetFieldsOut(t *testing.T) {
	policy := &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "defaults"},
		Spec:       piishieldv1alpha1.PiiPolicySpec{InjectionMode: "file"},
	}
	b, err := Render(policy)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["revision"] != "0" {
		t.Errorf("an empty spec must render only the revision, got %v", got)
	}
}

func TestRenderIsStableAndHashChangesWithContent(t *testing.T) {
	policy := &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Generation: 1},
		Spec:       piishieldv1alpha1.PiiPolicySpec{SensitiveKeys: []string{"a", "b"}},
	}
	a, _ := Render(policy)
	b, _ := Render(policy)
	if Hash(a) != Hash(b) {
		t.Error("the same policy must render to the same hash")
	}
	policy.Spec.SensitiveKeys = []string{"b", "a"}
	c, _ := Render(policy)
	if Hash(a) == Hash(c) {
		t.Error("a different rule set must hash differently")
	}
	if len(Hash(a)) != 16 {
		t.Errorf("hash length = %d, want 16", len(Hash(a)))
	}
}

func TestConfigMapNameAndLimit(t *testing.T) {
	if ConfigMapName("default") != "pii-shield-policy-default" {
		t.Errorf("unexpected name %q", ConfigMapName("default"))
	}
	policy := &piishieldv1alpha1.PiiPolicy{ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("n", 250)}}
	if _, err := Render(policy); err == nil {
		t.Error("a policy name that overflows the ConfigMap name limit must be an error")
	}
}
