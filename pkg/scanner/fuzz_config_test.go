package scanner

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Rule sets arrive from outside the process: a policy file the operator or a
// rule server wrote (ParsePolicyJSON) and the JSON an SDK caller passes to
// init_config (ConfigFromSDKJSON). These targets feed both parsers arbitrary
// bytes and then run the scanner under whatever config came out, because a
// config that parses and then breaks the first line is the failure that
// matters.

// fuzzConfigSeeds are shared by both targets: valid rule sets, every way a
// file is rejected today, and shapes that are valid JSON of the wrong type.
var fuzzConfigSeeds = []string{
	`{}`,
	`null`,
	`[]`,
	`"text"`,
	``,
	`{`,
	`{"revision":"7","entropy_threshold":4.2,"confidence_score":1.5,"min_secret_length":8}`,
	`{"sensitive_keys":["Session"," Card "],"sensitive_key_patterns":["^x-.*-token$"]}`,
	`{"custom_regexes":[{"name":"tx","pattern":"^TX-\\d+$"}],"safe_regexes":[{"pattern":"^build-\\d+$"}]}`,
	`{"disable_bigram_check":true,"adaptive_threshold":true,"entity_type_labels":true}`,
	`{"salt":"from-the-file","fail_policy":"closed"}`,
	`{"entropy_threshold":-1}`,
	`{"confidence_score":-0.5}`,
	`{"min_secret_length":-3}`,
	`{"min_secret_length":1025}`,
	`{"min_secret_length":1e400}`,
	`{"entropy_threshold":1e308,"confidence_score":1e308}`,
	`{"sensitive_keys":[""]}`,
	`{"sensitive_keys":[" \t"]}`,
	`{"sensitive_key_patterns":["("]}`,
	`{"custom_regexes":[{"pattern":"("}]}`,
	`{"custom_regexes":[{"regex":"x"}]}`,
	`{"safe_regexes":[{"pattern":""}]}`,
	`{"custom_regexes":[{"pattern":".*"}],"safe_regexes":[{"pattern":".*"}]}`,
	`{"custom_regexes":[{"name":"a]b[HIDDEN:","pattern":"\\S+"}],"entity_type_labels":true}`,
	`{"custom_regexes":[{"name":"\u0000\n","pattern":"(?i)secret"}]}`,
	`{"sensitive_keys":"not-a-list"}`,
	`{"custom_regexes":{"pattern":"x"}}`,
	"{\"sensitive_keys\":[\"\xff\xfe\"]}",
	`{"unknown_key":{"deep":[1,2,3]}}`,
	`{} {}`,
}

// fuzzProbeLines are scanned under every config a parser returns: the log
// shapes the scanner tokenizes differently, plus bytes that are not UTF-8.
var fuzzProbeLines = []string{
	`level=info msg="login ok" user=lena password=Wintermonkey73 session=9f8a7b6c5d4e3f2a`,
	`{"ts":"2026-11-13T10:00:00Z","token":"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB","n":42}`,
	`203.0.113.7 - - [13/Nov/2026:10:00:00 +0000] "GET /a?api_key=TX-12345&x=build-77 HTTP/1.1" 200 512`,
	"card 4539148803436467 \xff\xfe key value ::1",
}

// scanUnderConfig runs the probe lines through a scanner built from cfg and
// checks what holds for any config: no panic, valid UTF-8 out, no newline
// added to a single line, output bounded by the input.
func scanUnderConfig(t *testing.T, cfg Config, source string) {
	t.Helper()
	sc := NewScanner(cfg)
	for _, line := range fuzzProbeLines {
		out := sc.ScanAndRedact(line)
		if !utf8.ValidString(out) {
			t.Errorf("invalid UTF-8 under a config from %q\nline: %q\nout:  %q", source, line, out)
		}
		if strings.ContainsAny(out, "\r\n") {
			t.Errorf("line break added under a config from %q\nline: %q\nout:  %q", source, line, out)
		}
		// A custom rule's name is copied into each marker, so the bound
		// grows with the config, not only with the line.
		if limit := (len(line) + 1) * (len(source) + 100); len(out) > limit {
			t.Errorf("output of %d bytes for a %d-byte line under a config from %q", len(out), len(line), source)
		}
	}
}

// FuzzParsePolicyJSON checks the sidecar's policy-file parser. A file is all
// or nothing: a rejected one yields no config and no revision, an accepted one
// yields a config with every value inside its documented range, no salt, and
// only rules that compiled.
func FuzzParsePolicyJSON(f *testing.F) {
	for _, s := range fuzzConfigSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, rev, err := ParsePolicyJSON(data)
		if err != nil {
			if rev != "" || cfg.SensitiveKeys != nil || cfg.CustomRegexes != nil || cfg.SafeRegexes != nil ||
				cfg.EntropyThreshold != 0 || cfg.MinSecretLength != 0 {
				t.Fatalf("a rejected file still returned config or revision %q for %q", rev, data)
			}
			return
		}

		if len(cfg.Salt) != 0 {
			t.Errorf("a salt came out of the file %q", data)
		}
		if cfg.EntropyThreshold <= 0 || cfg.ConfidenceThreshold <= 0 {
			t.Errorf("thresholds %v / %v accepted from %q", cfg.EntropyThreshold, cfg.ConfidenceThreshold, data)
		}
		if cfg.MinSecretLength < 1 || cfg.MinSecretLength > MaxMinSecretLength {
			t.Errorf("min_secret_length %d accepted from %q", cfg.MinSecretLength, data)
		}
		for _, k := range cfg.SensitiveKeys {
			if k == "" || k != strings.ToLower(strings.TrimSpace(k)) {
				t.Errorf("sensitive key %q is empty or not normalized, from %q", k, data)
			}
		}
		for _, rules := range [][]CustomRegexRule{cfg.CustomRegexes, cfg.SafeRegexes} {
			for _, r := range rules {
				if r.Regexp == nil || r.Regexp.String() == "" {
					t.Errorf("a rule without a pattern was accepted from %q", data)
				}
			}
		}

		// The same bytes must be accepted again and mean the same thing.
		again, rev2, err := ParsePolicyJSON(data)
		if err != nil || rev2 != rev || again.EntropyThreshold != cfg.EntropyThreshold ||
			len(again.CustomRegexes) != len(cfg.CustomRegexes) || len(again.SafeRegexes) != len(cfg.SafeRegexes) {
			t.Errorf("the second parse of %q differs: %v", data, err)
		}

		cfg.Salt = []byte("fuzz-salt-0123456789abcdef")
		scanUnderConfig(t, cfg, string(data))
	})
}

// FuzzConfigFromSDKJSON checks the SDK path, which never fails: bad JSON gives
// the defaults and a bad entry is skipped, so the host Node or Python process
// always gets a working scanner with a salt.
func FuzzConfigFromSDKJSON(f *testing.F) {
	for _, s := range fuzzConfigSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := ConfigFromSDKJSON(data)

		if len(cfg.Salt) == 0 {
			t.Errorf("no salt for %q: tags would be computable by anyone", data)
		}
		if cfg.EntropyThreshold <= 0 || cfg.ConfidenceThreshold <= 0 || cfg.MinSecretLength <= 0 {
			t.Errorf("non-positive threshold or length (%v, %v, %d) from %q",
				cfg.EntropyThreshold, cfg.ConfidenceThreshold, cfg.MinSecretLength, data)
		}
		if len(cfg.SensitiveKeys) == 0 {
			t.Errorf("no sensitive keys left for %q", data)
		}
		for _, rules := range [][]CustomRegexRule{cfg.CustomRegexes, cfg.SafeRegexes} {
			for _, r := range rules {
				if r.Regexp == nil {
					t.Errorf("a rule that did not compile was kept from %q", data)
				}
			}
		}

		scanUnderConfig(t, cfg, string(data))
	})
}
