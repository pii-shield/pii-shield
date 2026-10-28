package policy

import (
	"strings"
	"testing"
)

func TestCanonicalInjectsRevisionAndSortsKeys(t *testing.T) {
	doc, err := Canonical([]byte(`{"sensitive_keys": ["b", "a"], "entropy_threshold": 4.20, "custom_regexes": [{"name": "tx", "pattern": "^TX-\\d+$"}]}`), 7)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	got := string(doc.Content)
	want := `{"custom_regexes":[{"name":"tx","pattern":"^TX-\\d+$"}],"entropy_threshold":4.20,"revision":"7","sensitive_keys":["b","a"]}`
	if got != want {
		t.Errorf("content =\n%s\nwant\n%s", got, want)
	}
	if doc.ETag != ETag(doc.Content) || !strings.HasPrefix(doc.ETag, `"`) || len(doc.ETag) != 34 {
		t.Errorf("ETag = %q", doc.ETag)
	}
	again, _ := Canonical([]byte(`{"entropy_threshold": 4.20, "custom_regexes": [{"pattern": "^TX-\\d+$", "name": "tx"}], "sensitive_keys": ["b", "a"]}`), 7)
	if again.ETag != doc.ETag {
		t.Error("the same rules in another key order must give the same ETag")
	}
	if other, _ := Canonical(doc.Content, 8); other.ETag == doc.ETag {
		t.Error("another revision must give another ETag")
	}
}

func TestCanonicalRejectsWhatTheSidecarRejects(t *testing.T) {
	cases := map[string]string{
		"not an object": `[]`,
		"null":          `null`,
		"trailing data": `{} {}`,
		"bad regex":     `{"custom_regexes": [{"pattern": "("}]}`,
		"empty pattern": `{"safe_regexes": [{"regex": "x"}]}`,
		"negative":      `{"entropy_threshold": -1}`,
		"min length":    `{"min_secret_length": 0, "sensitive_keys": [""]}`,
		"salt":          `{"salt": "abc"}`,
		"fail_policy":   `{"fail_policy": "closed"}`,
		"too large":     `{"sensitive_keys": ["` + strings.Repeat("k", MaxBytes) + `"]}`,
	}
	for name, body := range cases {
		if _, err := Canonical([]byte(body), 1); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Canonical([]byte(`{"salt": "", "fail_policy": null, "future": 1}`), 1); err != nil {
		t.Errorf("an empty salt, a null fail_policy and an unknown key must pass: %v", err)
	}
}
