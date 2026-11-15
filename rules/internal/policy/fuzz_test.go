package policy

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/pii-shield/pii-shield/v3/pkg/scanner"
)

// FuzzCanonical feeds the rule server's validator arbitrary bytes, the way an
// account holder can through the API. What the server accepts it serves to
// every cluster of the set, so an accepted rule set must be one the sidecar's
// own parser loads, must carry the revision it was published under and no pod
// setting, and must already be in canonical form: canonicalizing the served
// bytes again changes nothing, or the ETag would not name the content.
func FuzzCanonical(f *testing.F) {
	for _, s := range []string{
		`{}`,
		`null`,
		`[]`,
		``,
		`{`,
		`{} {}`,
		`{"sensitive_keys": ["b", "a"], "entropy_threshold": 4.20, "custom_regexes": [{"name": "tx", "pattern": "^TX-\\d+$"}]}`,
		`{"revision":"client-side","min_secret_length":8,"confidence_score":1.50}`,
		`{"safe_regexes":[{"pattern":"^build-\\d+$"}],"sensitive_key_patterns":["^x-.*-token$"]}`,
		`{"disable_bigram_check":true,"adaptive_threshold":false,"entity_type_labels":true}`,
		`{"salt":"abc"}`,
		`{"salt":""}`,
		`{"salt":null,"fail_policy":null}`,
		`{"Salt":"case"}`,
		`{"revi\u017fion":"mine","REVISION":"x"}`,
		`{"\u017falt":"abc"}`,
		`{"salt":["list"]}`,
		`{"fail_policy":"closed"}`,
		`{"custom_regexes": [{"pattern": "("}]}`,
		`{"safe_regexes": [{"regex": "x"}]}`,
		`{"entropy_threshold": -1}`,
		`{"entropy_threshold": 1e400}`,
		`{"entropy_threshold": 4.2000000000000000000000001}`,
		`{"min_secret_length": 0, "sensitive_keys": [""]}`,
		`{"min_secret_length": 8.0}`,
		`{"a":1,"a":2,"sensitive_keys":["x"],"sensitive_keys":["y"]}`,
		`{"unknown":{"z":1,"a":[{"k":" <>&"}]}}`,
		"{\"sensitive_keys\":[\"\xff\xfe\"]}",
	} {
		f.Add([]byte(s), int64(7))
	}
	f.Add([]byte(`{}`), int64(0))
	f.Add([]byte(`{}`), int64(-1))
	f.Add([]byte(`{}`), int64(9223372036854775807))

	f.Fuzz(func(t *testing.T, content []byte, revision int64) {
		doc, err := Canonical(content, revision)
		if err != nil {
			if doc.Content != nil || doc.ETag != "" {
				t.Errorf("a rejected rule set still returned content for %q", content)
			}
			return
		}

		if len(content) > MaxBytes {
			t.Errorf("a rule set of %d bytes was accepted, the limit is %d", len(content), MaxBytes)
		}
		if doc.ETag != ETag(doc.Content) {
			t.Errorf("ETag %s does not name the served bytes", doc.ETag)
		}

		// The sidecar loads exactly these bytes.
		cfg, rev, err := scanner.ParsePolicyJSON(doc.Content)
		if err != nil {
			t.Fatalf("the server accepted %q but the sidecar rejects what it serves: %v\n%s", content, err, doc.Content)
		}
		if rev != strconv.FormatInt(revision, 10) {
			t.Errorf("served revision %q, published as %d", rev, revision)
		}
		if len(cfg.Salt) != 0 {
			t.Errorf("a salt reached the served config from %q", content)
		}

		var served map[string]json.RawMessage
		if err := json.Unmarshal(doc.Content, &served); err != nil {
			t.Fatalf("served content is not a JSON object: %v", err)
		}
		// The sidecar matches keys in any letter case, so the check does too.
		revisions := 0
		for k := range served {
			if strings.EqualFold(k, "salt") || strings.EqualFold(k, "fail_policy") {
				t.Errorf("%s is served to clusters: %s", k, doc.Content)
			}
			if strings.EqualFold(k, "revision") {
				revisions++
			}
		}
		if revisions != 1 {
			t.Errorf("%d revision keys are served: %s", revisions, doc.Content)
		}

		again, err := Canonical(doc.Content, revision)
		if err != nil {
			t.Fatalf("the served bytes are rejected when submitted back: %v\n%s", err, doc.Content)
		}
		if !bytes.Equal(again.Content, doc.Content) || again.ETag != doc.ETag {
			t.Errorf("canonical form is not stable.\nfirst:  %s\nsecond: %s", doc.Content, again.Content)
		}
	})
}
