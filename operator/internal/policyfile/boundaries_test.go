package policyfile

import (
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	piishieldv1alpha1 "github.com/pii-shield/pii-shield/operator/api/v1alpha1"
)

// The longest policy name is the one whose ConfigMap name is exactly the
// Kubernetes limit; one character more is refused.
func TestCheckNameLimitIsInclusive(t *testing.T) {
	fits := strings.Repeat("p", maxNameLength-len(prefix))
	if err := CheckName(fits); err != nil {
		t.Errorf("a name that gives a %d-character ConfigMap name must be accepted: %v", maxNameLength, err)
	}
	if err := CheckName(fits + "p"); err == nil {
		t.Error("a name one character over the limit must be refused")
	}
}

// A remote file is held to the sidecar's own limits, or the operator would
// write a file every pod then rejects.
func TestParseAcceptsTheSidecarsLimits(t *testing.T) {
	doc, _, err := Parse([]byte(`{"min_secret_length": 1024, "sensitive_keys": [" Session "]}`))
	if err != nil {
		t.Fatalf("min_secret_length 1024 with one key: %v", err)
	}
	if doc.MinSecretLength != MaxMinSecretLength {
		t.Errorf("min_secret_length = %d", doc.MinSecretLength)
	}
	// One key is a list: it is normalized like any other, or the file would
	// carry " Session " and the sidecar would look for "session".
	if !reflect.DeepEqual(doc.SensitiveKeys, []string{"session"}) {
		t.Errorf("sensitive_keys = %q, want [session]", doc.SensitiveKeys)
	}
	if _, _, err := Parse([]byte(`{"min_secret_length": 1025}`)); err == nil {
		t.Error("min_secret_length 1025 must be rejected")
	}
}

// Merge is the rule for who decides what a pod runs: a field the local
// PiiPolicy sets wins over the remote file, down to the smallest value and a
// list of one entry, and a field it leaves unset keeps what the remote file
// said. Nothing else in the tree states that rule per field.
func TestMergeLocalFieldWinsAndUnsetKeepsRemote(t *testing.T) {
	remote := Document{
		Revision:             "r9",
		EntropyThreshold:     4.5,
		ConfidenceThreshold:  2,
		MinSecretLength:      12,
		SensitiveKeys:        []string{"remote_key"},
		SensitiveKeyPatterns: []string{"^remote$"},
		CustomRegexes:        []Rule{{Pattern: "^R-\\d+$", Name: "remote"}},
		SafeRegexes:          []Rule{{Pattern: "^safe-remote$"}},
	}

	unset := &piishieldv1alpha1.PiiPolicy{ObjectMeta: metav1.ObjectMeta{Generation: 3}}
	got := Merge(remote, unset)
	want := remote
	want.Revision = got.Revision
	if !reflect.DeepEqual(got, want) {
		t.Errorf("a policy with no rule fields changed the remote rules:\n got  %+v\n want %+v", got, want)
	}
	if !strings.HasPrefix(got.Revision, "r9") || !strings.HasSuffix(got.Revision, "3") {
		t.Errorf("revision = %q, want the remote revision and the generation", got.Revision)
	}

	local := &piishieldv1alpha1.PiiPolicy{
		ObjectMeta: metav1.ObjectMeta{Generation: 4},
		Spec: piishieldv1alpha1.PiiPolicySpec{
			EntropyThreshold:     0.5,
			ConfidenceThreshold:  0.25,
			MinSecretLength:      1,
			SensitiveKeys:        []string{"local_key"},
			SensitiveKeyPatterns: []string{"^local$"},
			CustomRegexList:      []piishieldv1alpha1.RegexRule{{Pattern: "^L-\\d+$", Name: "local"}},
			SafeRegexList:        []piishieldv1alpha1.RegexRule{{Pattern: "^safe-local$"}},
		},
	}
	got = Merge(remote, local)
	if got.EntropyThreshold != 0.5 || got.ConfidenceThreshold != 0.25 || got.MinSecretLength != 1 {
		t.Errorf("local numbers did not win: %v, %v, %d", got.EntropyThreshold, got.ConfidenceThreshold, got.MinSecretLength)
	}
	if !reflect.DeepEqual(got.SensitiveKeys, []string{"local_key"}) || !reflect.DeepEqual(got.SensitiveKeyPatterns, []string{"^local$"}) {
		t.Errorf("local keys or patterns did not win: %v, %v", got.SensitiveKeys, got.SensitiveKeyPatterns)
	}
	if len(got.CustomRegexes) != 1 || got.CustomRegexes[0].Name != "local" || len(got.SafeRegexes) != 1 || got.SafeRegexes[0].Pattern != "^safe-local$" {
		t.Errorf("local rules did not win: %+v, %+v", got.CustomRegexes, got.SafeRegexes)
	}
}
