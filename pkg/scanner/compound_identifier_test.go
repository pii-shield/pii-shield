package scanner

import (
	"strings"
	"testing"
)

// TestCompoundIdentifierNotRedacted: a model id or a dotted setting key is a
// compound of words, and scored whole it looked random (Shannon across words,
// the separator as a character class, unknown bigrams at every separator).
// These lines came from an LLM research app; on 2.2.4 each lost its model or
// setting name.
func TestCompoundIdentifierNotRedacted(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ in, keep string }{
		{"Using provider openai model gpt-4o-mini temperature=0.7", "gpt-4o-mini"},
		{"ERROR: Rate limit exceeded for model claude-sonnet-5, retrying in 20s", "claude-sonnet-5"},
		{"Embedding model sentence-transformers/all-MiniLM-L6-v2 loaded", "sentence-transformers/all-MiniLM-L6-v2"},
		{"Settings changed: search.max_results 10 -> 20", "search.max_results"},
		{`{"model":"claude-opus-4-1-20250805","max_tokens":1024}`, "claude-opus-4-1-20250805"},
		{"model=gemini-2.5-flash-lite", "gemini-2.5-flash-lite"},
		{"loading meta-llama/Llama-3.1-8B-Instruct", "meta-llama/Llama-3.1-8B-Instruct"},
		{"reranker BAAI/bge-reranker-v2-m3 ready", "BAAI/bge-reranker-v2-m3"},
		{"spring.datasource.hikari.maximum-pool-size=20", "spring.datasource.hikari.maximum-pool-size"},
		{"label app.kubernetes.io/managed-by=Helm", "app.kubernetes.io/managed-by"},
		{"request_id=42 commit_sha=abc", "commit_sha"},
		{`"GET / HTTP/1.1" 200 5 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/71.0.3578.98 Safari/537.36"`, "AppleWebKit/537.36 Chrome/71.0.3578.98 Safari/537.36"},
	} {
		if out := ScanAndRedact(tc.in); !strings.Contains(out, tc.keep) {
			t.Errorf("%q hidden: %q", tc.keep, out)
		}
	}
}

// TestCompoundSecretStillRedacted: the compound rule must not open a hole for
// secrets whose format carries a separator.
func TestCompoundSecretStillRedacted(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// Issuer formats, assembled at runtime so no matchable literal sits in the
	// source (see signatures_test.go).
	for _, secret := range []string{
		"sk-" + "proj-" + "Qm7xK2pLr9Vt4Ny8Rb3Hc6Jw1Fs5Gd0Mzq7Ke2Lp4Xv9Tn3Wb",
		"sk-" + "ant-api03-" + "x7Kq2Lp9Vt4Ny8Rb3Hc6Jw1Fs5Gd0Mzq-Rb3Hc6AA",
		"gl" + "pat-" + "x7Kq2Lp9Vt4Ny8Rb3Hc6",
		"SG" + ".x7Kq2Lp9Vt4Ny8Rb3Hc6J.w1Fs5Gd0Mzq7Ke2Lp4Xv9Tn3WbQm7xK2pLr9Vt4Ny8",
		"ya29" + ".a0AfH6SMBx7Kq2Lp9Vt4Ny8Rb3Hc6Jw1Fs5Gd0Mzq",
		// Generated codes: equal groups, or chunks whose letters are not words.
		"wxqz-rkvt-mpdh-bjln",
		"pdgw-mln1-45zz-52wl",
		"YABIC-PXZ7P-YU7BP-ZEL97-TWBDL",
		"GyiVU1-ZnxU4s-UZDFcu",
	} {
		for _, line := range []string{secret, "value " + secret + " end", "model=" + secret} {
			if out := ScanAndRedact(line); strings.Contains(out, secret) {
				t.Errorf("secret passed through: %q", out)
			}
		}
	}

	// A compound that names a secret keeps the whole-token score:
	// CZIenvzL alone scores 3.5, below the 3.6 threshold.
	if out := ScanAndRedact("model=auth_CZIenvzL"); strings.Contains(out, "CZIenvzL") {
		t.Errorf("secret behind a sensitive word passed: %q", out)
	}

	// A word-shaped password under a key is still forced.
	for _, in := range []string{"password=blue-Tiger-42", `{"secret": "Dragon-Fire-88"}`} {
		if out := ScanAndRedact(in); !strings.Contains(out, "[HIDDEN") {
			t.Errorf("keyed password passed: %q", out)
		}
	}
}

// TestIsWordCompound pins the shape rules one at a time.
func TestIsWordCompound(t *testing.T) {
	st := buildConfigState(campaignConfig())
	for tok, want := range map[string]bool{
		"gpt-4o-mini":                 true,
		"search.max_results":          true,
		"Qwen/Qwen2.5-7B-Instruct":    true,
		"gpt-4o-2024-08-06":           true,  // two letter pairs: too few to judge
		"gpt":                         false, // no separator
		"4o-2024":                     false, // no word of three letters
		"XkQpZm-mini":                 false, // lone lowercase letter between capitals
		"8x7b-mixtral":                false, // 8x7b is not letters, digits, letters
		"abcd-efgh-ijkl":              false, // equal groups
		"pdgw-mln1-45zz-52wl":         false, // letter pairs average below the English band
		"llm.openai.api_key":          false, // names a secret
		"averyveryveryverylongpart-x": false, // part over 24 characters
	} {
		if got := st.isWordCompound(tok); got != want {
			t.Errorf("isWordCompound(%q) = %v, want %v", tok, got, want)
		}
	}

	st = buildConfigState(func() Config { c := campaignConfig(); c.DisableBigramCheck = true; return c }())
	if st.isWordCompound("gpt-4o-mini") {
		t.Error("compound scoring must stay off when the bigram check is disabled")
	}
}
