package policyfile

import (
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

func reasonOf(t *testing.T, err error) string {
	t.Helper()
	var e *ValidationError
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not a *ValidationError", err)
	}
	return e.Reason
}

func TestParseAcceptsRulesAndDropsRuntimeKeys(t *testing.T) {
	doc, ignored, err := Parse([]byte(`{
		"revision": "2026-10-28",
		"salt": "never", "fail_policy": "closed", "future_key": 1,
		"entropy_threshold": 4.1, "confidence_score": 1.0, "min_secret_length": 8,
		"sensitive_keys": [" Geheim ", "clave"],
		"sensitive_key_patterns": ["^x_"],
		"custom_regexes": [{"name": "tx", "pattern": "^TX-\\d{5}$"}],
		"safe_regexes": [{"pattern": "^[a-f0-9]{7}$"}],
		"disable_bigram_check": true, "entity_type_labels": false
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if strings.Join(ignored, ",") != "salt,fail_policy" {
		t.Errorf("ignored = %v, want salt and fail_policy", ignored)
	}
	if doc.Revision != "2026-10-28" || doc.EntropyThreshold != 4.1 || doc.MinSecretLength != 8 {
		t.Errorf("scalars not parsed: %+v", doc)
	}
	if strings.Join(doc.SensitiveKeys, ",") != "geheim,clave" {
		t.Errorf("sensitive keys must be lowercased and trimmed, got %v", doc.SensitiveKeys)
	}
	if len(doc.CustomRegexes) != 1 || doc.CustomRegexes[0].Name != "tx" || len(doc.SafeRegexes) != 1 {
		t.Errorf("rules not parsed: %+v", doc)
	}
	if doc.DisableBigramCheck == nil || !*doc.DisableBigramCheck || doc.EntityTypeLabels == nil || *doc.EntityTypeLabels {
		t.Errorf("bool switches not parsed: %+v", doc)
	}
	if doc.AdaptiveThreshold != nil {
		t.Error("an absent switch must stay nil")
	}
}

func TestParseRejectsBadFilesWhole(t *testing.T) {
	cases := map[string]struct {
		body   string
		reason string
	}{
		"not json":           {`{"sensitive_keys": [`, ReasonInvalidJSON},
		"array":              {`[]`, ReasonInvalidJSON},
		"negative entropy":   {`{"entropy_threshold": -1}`, ReasonInvalidValue},
		"negative score":     {`{"confidence_score": -0.5}`, ReasonInvalidValue},
		"min length high":    {`{"min_secret_length": 1025}`, ReasonInvalidValue},
		"empty key":          {`{"sensitive_keys": ["a", " "]}`, ReasonInvalidValue},
		"bad key pattern":    {`{"sensitive_key_patterns": ["("]}`, ReasonInvalidRegex},
		"bad custom":         {`{"custom_regexes": [{"pattern": "("}]}`, ReasonInvalidRegex},
		"empty custom":       {`{"custom_regexes": [{"regex": "x"}]}`, ReasonInvalidRegex},
		"bad safe":           {`{"safe_regexes": [{"pattern": "["}]}`, ReasonInvalidRegex},
		"valid then invalid": {`{"custom_regexes": [{"pattern": "ok"}, {"pattern": ")"}]}`, ReasonInvalidRegex},
	}
	for name, c := range cases {
		doc, _, err := Parse([]byte(c.body))
		if err == nil {
			t.Errorf("%s: expected an error, got %+v", name, doc)
			continue
		}
		if got := reasonOf(t, err); got != c.reason {
			t.Errorf("%s: reason = %s, want %s (%v)", name, got, c.reason, err)
		}
		if len(doc.CustomRegexes) != 0 && len(doc.SensitiveKeys) != 0 {
			t.Errorf("%s: a rejected file must yield an empty document", name)
		}
	}
}

func TestMergeLaysLocalFieldsOverRemote(t *testing.T) {
	on := true
	remote := Document{
		Revision:             "r7",
		EntropyThreshold:     4.5,
		MinSecretLength:      10,
		SensitiveKeys:        []string{"central"},
		SensitiveKeyPatterns: []string{"^c_"},
		CustomRegexes:        []Rule{{Pattern: "^C-"}},
		SafeRegexes:          []Rule{{Pattern: "^safe$"}},
		DisableBigramCheck:   &on,
	}
	policy := &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "local", Generation: 3},
		Spec: piishieldv1alpha1.PiiPolicySpec{
			InjectionMode:    "file",
			Salt:             "0123456789abcdef0123456789abcdef",
			FailPolicy:       "closed",
			EntropyThreshold: 3.9,
			SensitiveKeys:    []string{"local"},
			CustomRegexList:  []piishieldv1alpha1.RegexRule{{Pattern: "^L-"}},
		},
	}
	doc := Merge(remote, policy)
	if doc.Revision != "r7+3" {
		t.Errorf("revision = %q, want r7+3", doc.Revision)
	}
	if doc.EntropyThreshold != 3.9 || strings.Join(doc.SensitiveKeys, ",") != "local" || doc.CustomRegexes[0].Pattern != "^L-" {
		t.Errorf("a set local field must replace the remote one: %+v", doc)
	}
	if doc.MinSecretLength != 10 || strings.Join(doc.SensitiveKeyPatterns, ",") != "^c_" || doc.SafeRegexes[0].Pattern != "^safe$" || doc.DisableBigramCheck != &on {
		t.Errorf("an unset local field must keep the remote value: %+v", doc)
	}
	b, err := Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"salt", "fail_policy", "0123456789abcdef"} {
		if strings.Contains(string(b), k) {
			t.Errorf("the merged file must not carry %q:\n%s", k, b)
		}
	}
	if Local(policy).Revision != "3" {
		t.Errorf("without a remote the revision is the generation, got %q", Local(policy).Revision)
	}
}

func TestMergeDoesNotAliasRemoteSlices(t *testing.T) {
	remote := Document{SensitiveKeys: []string{"a"}}
	policy := &piishieldv1alpha1.PiiPolicy{Spec: piishieldv1alpha1.PiiPolicySpec{SensitiveKeys: []string{"b"}}}
	_ = Merge(remote, policy)
	if remote.SensitiveKeys[0] != "a" {
		t.Error("Merge must not modify the remote document")
	}
}
