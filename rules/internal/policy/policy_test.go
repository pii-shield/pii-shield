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
		"Salt":          `{"Salt": "abc"}`,
		"SALT":          `{"SALT": "abc"}`,
		"long-s salt":   `{"\u017falt": "abc"}`,
		"Fail_Policy":   `{"Fail_Policy": "closed"}`,
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

// The sidecar matches JSON keys to fields in any letter case, and of two
// keys for one field the later one wins. Keys are served sorted, so a
// "revision" spelled to sort after the real one (a long s is past every ASCII
// letter) used to replace the version number the server wrote. Every spelling
// is dropped and the server's own revision is the only one served.
func TestCanonicalKeepsOnlyItsOwnRevision(t *testing.T) {
	for _, body := range []string{
		`{"revision": "mine"}`,
		`{"Revision": "mine"}`,
		`{"REVISION": "mine", "revision": "also mine"}`,
		`{"revi\u017fion": "mine"}`,
	} {
		doc, err := Canonical([]byte(body), 7)
		if err != nil {
			t.Errorf("%s: %v", body, err)
			continue
		}
		if got := string(doc.Content); got != `{"revision":"7"}` {
			t.Errorf("%s: served %s", body, got)
		}
	}
	doc, err := Canonical([]byte(`{"Salt": "", "FAIL_POLICY": null, "min_secret_length": 8}`), 1)
	if err != nil || string(doc.Content) != `{"min_secret_length":8,"revision":"1"}` {
		t.Errorf("an empty Salt and a null FAIL_POLICY must be dropped: %s, %v", doc.Content, err)
	}
}
