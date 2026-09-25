package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCompactJSONSafeValues guards a tokenizer bug where compact JSON ("k":"v")
// fed quoted values into the safety whitelist, so safe values like ISO-8601
// timestamps were redacted while the spaced form ("k": "v") kept them.
func TestCompactJSONSafeValues(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		mustKeep   []string // substrings that must survive untouched
		mustRedact []string // keys whose value must become [HIDDEN:...]
		mustBeGone []string // values that must not survive anywhere
	}{
		{
			name:     "compact ISO timestamp is preserved",
			input:    `{"timestamp":"2026-06-19T10:30:00Z"}`,
			mustKeep: []string{"2026-06-19T10:30:00Z"},
		},
		{
			name:     "spaced ISO timestamp is preserved",
			input:    `{"timestamp": "2026-06-19T10:30:00Z"}`,
			mustKeep: []string{"2026-06-19T10:30:00Z"},
		},
		{
			name:     "compact IPv6 is preserved",
			input:    `{"ip":"::1"}`,
			mustKeep: []string{"::1"},
		},
		{
			name:       "email redacted, timestamp kept (article example payload)",
			input:      `{"action":"retrieve_customer","customer_email":"alice@company.com","timestamp":"2026-06-19T10:30:00Z"}`,
			mustKeep:   []string{"retrieve_customer", "2026-06-19T10:30:00Z"},
			mustRedact: []string{"customer_email"},
			mustBeGone: []string{"alice@company.com", "alice"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := ScanAndRedact(tt.input)
			for _, keep := range tt.mustKeep {
				if !strings.Contains(out, keep) {
					t.Errorf("expected %q to be preserved, got: %s", keep, out)
				}
			}
			for _, key := range tt.mustRedact {
				marker := `"` + key + `":"[HIDDEN`
				if !strings.Contains(out, marker) {
					t.Errorf("expected %q value to be redacted, got: %s", key, out)
				}
			}
			for _, secret := range tt.mustBeGone {
				if strings.Contains(out, secret) {
					t.Errorf("expected %q to be gone, got: %s", secret, out)
				}
			}
		})
	}
}

// TestCompactJSONPairAfterSensitiveKey guards a regression from B7: a complete
// compact pair such as "password":"x" still reported itself as a key, so the
// next pair arrived force-redacted. When that pair's value held a '=', the
// quoted branch hid "query":"a=b" whole, key and quotes included, and the line
// stopped being valid JSON: {"password":"[HIDDEN]","[HIDDEN]"}.
func TestCompactJSONPairAfterSensitiveKey(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	tests := []struct {
		in, secret, keep string
	}{
		{`{"password":"abc123xyz","query":"a=b"}`, "abc123xyz", `"query":"a=b"`},
		{`{"token":"abc123xyz","url":"x=1&y=2"}`, "abc123xyz", `"url":"x=1&y=2"`},
		{`{"password":"abc123xyz","user":"bob"}`, "abc123xyz", `"user":"bob"`},
	}
	for _, tt := range tests {
		out := ScanAndRedact(tt.in)
		if !json.Valid([]byte(out)) {
			t.Errorf("output is no longer valid JSON: in=%q out=%q", tt.in, out)
		}
		if strings.Contains(out, tt.secret) {
			t.Errorf("secret leaked: in=%q out=%q", tt.in, out)
		}
		if !strings.Contains(out, tt.keep) {
			t.Errorf("neighbouring pair changed: in=%q out=%q", tt.in, out)
		}
	}
}
