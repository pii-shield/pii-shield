package scanner

import (
	"reflect"
	"strings"
	"testing"
)

// strategiesOf scans line under cfg and returns the strategies reported to
// RedactionCallback, which is what piishield_redaction_events_total{type},
// the stats summary and the rule server's Clusters tab are split by.
func strategiesOf(t *testing.T, cfg Config, line string) (string, []string) {
	t.Helper()
	oldCfg := activeCfg()
	oldCallback := RedactionCallback
	t.Cleanup(func() {
		UpdateConfig(oldCfg)
		RedactionCallback = oldCallback
	})
	UpdateConfig(cfg)
	var got []string
	RedactionCallback = func(strategy string) { got = append(got, strategy) }
	return ScanAndRedact(line), got
}

// A value hidden because of its key is counted as "key". It used to be
// counted as "entropy": a policy whose only rule was sensitive_keys
// ["geheim", "clave"] on plain-word values reported every hide as entropy.
func TestStrategyKeyForPolicySensitiveKeys(t *testing.T) {
	cfg, _, err := ParsePolicyJSON([]byte(`{"sensitive_keys": ["geheim", "clave"]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Salt = campaignConfig().Salt
	for _, line := range []string{
		`geheim=apfelbaum`,
		`{"clave": "naranja"}`,
		`clave: naranja`,
		`GET /api/orders?geheim=apfelbaum HTTP/1.1`,
	} {
		out, got := strategiesOf(t, cfg, line)
		if strings.Contains(out, "apfelbaum") || strings.Contains(out, "naranja") {
			t.Errorf("%q: value not hidden: %q", line, out)
		}
		if want := []string{"key"}; !reflect.DeepEqual(got, want) {
			t.Errorf("%q: strategies = %v, want %v", line, got, want)
		}
	}
}

func TestStrategyKeyForBuiltInKeysAndPositions(t *testing.T) {
	for _, line := range []string{
		`password=hunter2hunter2`,
		`{"password": "ab"}`,
		`my password is 123456`,
		`Authorization: Bearer abcdefghijklmnopqrst`,
		`Authorization: Basic bGVuYTpqcjBYUWdVaVpSRjM=`,
		`postgres://lena:maple248@db.internal:5432/app`,
		`GET /login?user=lena&password=maple248 HTTP/1.1`,
	} {
		out, got := strategiesOf(t, campaignConfig(), line)
		if out == line {
			t.Errorf("%q: nothing hidden", line)
		}
		if want := []string{"key"}; !reflect.DeepEqual(got, want) {
			t.Errorf("%q: strategies = %v, want %v (out %q)", line, got, want, out)
		}
	}
}

// A value hidden by its score alone stays "entropy", and the detectors keep
// their own strategy even under a sensitive key.
func TestStrategyEntropyAndSignatureUnchanged(t *testing.T) {
	cases := map[string]string{
		`request 8fK2pQ9xZ7mW3vB1nL5tRq4Y done`:                    "entropy",
		`GET /x?state=8fK2pQ9xZ7mW3vB1nL5tRq4Y HTTP/1.1`:           "entropy",
		`token=AKIAIOSFODNN7EXAMPLE`:                               "signature",
		`{"password": "ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"}`: "signature",
	}
	for line, want := range cases {
		out, got := strategiesOf(t, campaignConfig(), line)
		if out == line {
			t.Errorf("%q: nothing hidden", line)
		}
		if !reflect.DeepEqual(got, []string{want}) {
			t.Errorf("%q: strategies = %v, want [%s] (out %q)", line, got, want, out)
		}
	}
}
