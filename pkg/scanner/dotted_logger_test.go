package scanner

import "testing"

// TestDottedLoggerNamesKept: a Python or Java logger name with a version
// prefix inside a part (v2restapi, s3client, Http2FrameCodec) or with two
// parts of equal length (flaskUI.restapi) was scored whole and hidden on
// every line of the log. Such a name is a compound of words and is scored
// part by part like any other. Not in the list: myapp.handlers.oauth2, which
// names "auth" and keeps its whole-token score by the namesSecret rule.
func TestDottedLoggerNamesKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, name := range []string{
		"flaskUI.v2restapi",
		"api.v2restapi",
		"services.v1client",
		"MyApp.v3Handler",
		"flaskUI.restapi",
		"lights.v2api",
		"app.v2",
		"aws.s3client",
		"HueEmulator3.Config",
		"org.apache.kafka.clients.NetworkClient",
		"io.netty.handler.codec.http2.Http2FrameCodec",
		"com.fasterxml.jackson.databind.ObjectMapper",
		"org.springframework.web.servlet.DispatcherServlet",
	} {
		in := "2026-09-30 10:00:01 - " + name + " - INFO - GET /api/lights"
		if out := ScanAndRedact(in); out != in {
			t.Errorf("logger name hidden:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestGeneratedCodesStillScoredWhole: the shapes the compound rule was
// fenced against keep their whole-token score.
func TestGeneratedCodesStillScoredWhole(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())
	st := cfgState()

	for _, tok := range []string{
		"pdgw-mln1-45zz-52wl",
		"abcd-efgh-ijkl-mnop",
		"XXXXX-XXXXX-XXXXX",
		"x9k2q.p7m3z",
		"zqxj.vkwp",
		"a1b2c3.d4e5f6",
	} {
		if st.isWordCompound(tok) {
			t.Errorf("isWordCompound(%q) = true, want false", tok)
		}
	}
}

func TestWordShapedPartVersionPrefix(t *testing.T) {
	yes := []string{"v2restapi", "v1client", "s3client", "Http2FrameCodec", "v3Handler", "restapi", "v2", "Qwen2", "20250805"}
	no := []string{"x9k2q", "abcde5words", "ab123cdef", "v22222word", "a1b2c3", "note9blue", "y5prime", "cm6hlrso"}
	for _, p := range yes {
		if _, ok := wordShapedPart(p, true); !ok {
			t.Errorf("wordShapedPart(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if _, ok := wordShapedPart(p, true); ok {
			t.Errorf("wordShapedPart(%q) = true, want false", p)
		}
	}
}

// TestStandaloneCamelCaseNamesKept: a letters-only camelCase name with no
// separator was scored as one run, so an abbreviated word (Ctrlr) broke the
// English pairs and the OCPP 2.0.1 component name SecurityCtrlr was hidden
// while SecurityController was not. Such a name is scored word by word, as a
// camelCase part of a dotted name already is. A run of capitals with single
// lowercase letters between them still fails the word rule and is scored
// whole.
func TestStandaloneCamelCaseNamesKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		`[{"component":{"name":"SecurityCtrlr"},"variable":{"name":"BasicAuthPassword"}}]`,
		"component SecurityCtrlr ready",
		"TxCtrlr SampledDataCtrlr SecurityCtrl",
		"GET /search?sort=productModel&page=2",
		"HttpClientFactory RetryPolicyConfig dbRowsAffected",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("camelCase name hidden:\n in: %s\nout: %s", in, out)
		}
	}

	st := cfgState()
	for _, tok := range []string{"XkQpZmWvRt", "aBcDeFgHiJkL"} {
		if st.calculateComplexity(tok) != st.calculateRawComplexity(tok) {
			t.Errorf("%q scored word by word, want one run", tok)
		}
	}
}
