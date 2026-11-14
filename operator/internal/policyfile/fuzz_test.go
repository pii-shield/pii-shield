package policyfile

import (
	"bytes"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// FuzzParse feeds the remote policy file parser arbitrary bytes. The file
// comes from a URL the operator pulls, and what Parse accepts is written into
// a ConfigMap every pod of the policy reads, so the properties are: a
// rejected file yields nothing and names a known reason; an accepted one holds
// only values the sidecar accepts too, never a salt or a fail policy, and
// survives being written out and read back unchanged.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		`{}`,
		`null`,
		`[]`,
		``,
		`{`,
		`{"revision":"7","entropy_threshold":4.2,"confidence_score":1.5,"min_secret_length":8}`,
		`{"sensitive_keys":["Session"," Card "],"sensitive_key_patterns":["^x-.*-token$"]}`,
		`{"custom_regexes":[{"name":"tx","pattern":"^TX-\\d+$"}],"safe_regexes":[{"pattern":"^build-\\d+$"}]}`,
		`{"disable_bigram_check":true,"adaptive_threshold":false,"entity_type_labels":true}`,
		`{"salt":"from-the-file","fail_policy":"closed"}`,
		`{"entropy_threshold":-1}`,
		`{"confidence_score":-0.5}`,
		`{"min_secret_length":-3}`,
		`{"min_secret_length":1025}`,
		`{"min_secret_length":1e400}`,
		`{"entropy_threshold":1e308}`,
		`{"sensitive_keys":[""]}`,
		`{"sensitive_key_patterns":["("]}`,
		`{"custom_regexes":[{"pattern":"("}]}`,
		`{"custom_regexes":[{"regex":"x"}]}`,
		`{"custom_regexes":[{"name":"line\nbreak","pattern":"^TX$"}]}`,
		`{"safe_regexes":[{"name":"\r","pattern":"^TX$"}]}`,
		`{"safe_regexes":[{"pattern":""}]}`,
		`{"sensitive_keys":"not-a-list"}`,
		"{\"sensitive_keys\":[\"\xff\xfe\"]}",
		`{"Salt":"case","FAIL_POLICY":"open","unknown":{"deep":[1]}}`,
		`{} {}`,
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		doc, ignored, err := Parse(data)
		if err != nil {
			ve, ok := errors.AsType[*ValidationError](err)
			if !ok {
				t.Fatalf("Parse(%q) failed with %T, not a ValidationError", data, err)
			}
			switch ve.Reason {
			case ReasonInvalidJSON, ReasonInvalidRegex, ReasonInvalidValue:
			default:
				t.Errorf("unknown rejection reason %q for %q", ve.Reason, data)
			}
			if !reflect.DeepEqual(doc, Document{}) || ignored != nil {
				t.Errorf("a rejected file still returned %+v, ignored %v", doc, ignored)
			}
			return
		}

		if doc.EntropyThreshold < 0 || doc.ConfidenceThreshold < 0 ||
			doc.MinSecretLength < 0 || doc.MinSecretLength > MaxMinSecretLength {
			t.Errorf("out-of-range value accepted from %q: %+v", data, doc)
		}
		for _, k := range doc.SensitiveKeys {
			if k == "" || k != strings.ToLower(strings.TrimSpace(k)) {
				t.Errorf("sensitive key %q is empty or not normalized, from %q", k, data)
			}
		}
		for _, p := range doc.SensitiveKeyPatterns {
			if _, err := regexp.Compile(p); err != nil {
				t.Errorf("pattern %q accepted from %q does not compile", p, data)
			}
		}
		for _, rules := range [][]Rule{doc.CustomRegexes, doc.SafeRegexes} {
			for _, r := range rules {
				if strings.ContainsAny(r.Name, "\r\n") {
					t.Errorf("rule name %q with a line break accepted from %q", r.Name, data)
				}
				if r.Pattern == "" {
					t.Errorf("empty pattern accepted from %q", data)
				} else if _, err := regexp.Compile(r.Pattern); err != nil {
					t.Errorf("rule %q accepted from %q does not compile", r.Pattern, data)
				}
			}
		}
		for _, k := range ignored {
			if k != "salt" && k != "fail_policy" {
				t.Errorf("ignored key %q is not one Parse drops", k)
			}
		}

		// What the operator writes into the ConfigMap is Encode(doc): it must
		// carry no pod setting and must read back as the same document.
		out, err := Encode(doc)
		if err != nil {
			t.Fatalf("Encode of an accepted document from %q: %v", data, err)
		}
		again, ignoredAgain, err := Parse(out)
		if err != nil {
			t.Fatalf("the file written for %q is rejected on the way back: %v\n%s", data, err, out)
		}
		if len(ignoredAgain) != 0 {
			t.Errorf("the written file carries %v:\n%s", ignoredAgain, out)
		}
		// Compared as written bytes: an empty list is left out of the file
		// and reads back as an absent one, which is the same rule set.
		if outAgain, err := Encode(again); err != nil || !bytes.Equal(outAgain, out) {
			t.Errorf("the written file reads back differently (%v).\nfirst:\n%s\nsecond:\n%s", err, out, outAgain)
		}
	})
}
