package scanner

import (
	"strings"
	"testing"
)

// TestTokenDescriptorKeys covers keys that contain the word "token" but
// describe tokens instead of holding one: the usage counters of a language
// model answer (prompt_tokens, max_tokens, totalTokenCount) and the fields
// that sit next to a credential (token_type, token_status). The substring
// match on "token" forced their values, so every line with a model answer
// came back with its counters hidden and turned from numbers into strings,
// and {"token_type":"Bearer"} lost the scheme word.
func TestTokenDescriptorKeys(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		`{"usage": {"prompt_tokens": 812, "completion_tokens": 96, "total_tokens": 908}}`,
		`{"usage":{"prompt_tokens":812,"completion_tokens":96,"total_tokens":908}}`,
		`{"usage":{"input_tokens":812,"output_tokens":96,"cache_read_input_tokens":0,"cache_creation_input_tokens":40}}`,
		`{"completion_tokens_details":{"reasoning_tokens":64,"cached_tokens":0,"accepted_prediction_tokens":0}}`,
		`{"usageMetadata":{"promptTokenCount":812,"candidatesTokenCount":96,"totalTokenCount":908}}`,
		`{"model":"gpt-4o-mini","max_tokens":4096,"max_completion_tokens":512,"maxTokens":256,"max_new_tokens":128}`,
		`prompt_tokens=812 completion_tokens=96 total_tokens=908`,
		`usage: input_tokens: 812 output_tokens: 96`,
		`{"expires_in":3600,"token_type":"Bearer"}`,
		`{"token_type": "bearer", "expires_in": 3600}`,
		`{"tokenType":"Bearer"}`,
		`{"token_count":1532,"token_limit":"high","token_status":"expired","token_expired":true}`,
		`token_count=1532 token_limit=8000 token_ttl=3600`,
		`{"token_expires_in":3600,"refresh_token_expires_in":86400}`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("a key that describes tokens forced its value:\n in:  %s\n out: %s", in, out)
		}
	}
}

// TestTokenKeysStillForced pins the other side: a key that holds a token, in
// the singular or the plural, still forces a low-entropy value, and so does a
// descriptor key that the user listed or that carries another secret word.
func TestTokenKeysStillForced(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, secret string }{
		{`{"token":"hunter"}`, "hunter"},
		{`{"access_token":"hunter"}`, "hunter"},
		{`{"accessToken": "hunter"}`, "hunter"},
		{`aws_session_token=hunter`, "hunter"},
		{`{"csrf-token":"hunter"}`, "hunter"},
		{`{"tokens":"hunter"}`, "hunter"},
		{`{"refresh_tokens":"hunter"}`, "hunter"},
		{`{"api_tokens": "hunter"}`, "hunter"},
		{`device_tokens=hunter`, "hunter"},
		{`{"token_value":"hunter"}`, "hunter"},
		{`{"token_secret":"hunter"}`, "hunter"},
		{`{"secret_token_type":"hunter"}`, "hunter"},
		{`{"password_tokens":"hunter"}`, "hunter"},
		{`{"token_id":"hunter"}`, "hunter"},
	} {
		if out := ScanAndRedact(tc.in); strings.Contains(out, tc.secret) {
			t.Errorf("value under a token key leaked:\n in:  %s\n out: %s", tc.in, out)
		}
	}

	// A real token under a counter key is still hidden by its own score.
	real := `{"max_tokens":"q7Lx2VbN9sTz4KpWm8YcR3hJ"}`
	if out := ScanAndRedact(real); strings.Contains(out, "q7Lx2VbN9sTz4KpWm8YcR3hJ") {
		t.Errorf("a high-entropy value under a counter key leaked: %s", out)
	}

	// A key the user listed is sensitive by the user's own word.
	cfg := campaignConfig()
	cfg.SensitiveKeys = append(append([]string{}, cfg.SensitiveKeys...), "max_tokens")
	UpdateConfig(cfg)
	if out := ScanAndRedact(`{"max_tokens":"hunter"}`); strings.Contains(out, "hunter") {
		t.Errorf("a listed key did not force its value: %s", out)
	}
}
