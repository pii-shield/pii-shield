package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUserAgentProductTokensKept: in a quoted User-Agent the product tokens
// (bot names, browser and WebKit versions, the iOS build after Mobile/) and a
// bot's contact address in its comment are written as they are. On main
// "Mozilla/5.0 (compatible; AhrefsBot/6.1)" came back as "(compatible;
// [HIDDEN:...])", and the same happened to MJ12bot/v1.4.8;, Mobile/11A465 and
// crawler@parsijoo.ir (tracker 2026-10-09, found while fixing PR #278).
func TestUserAgentProductTokensKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, ua := range []string{
		"Mozilla/5.0 (compatible; AhrefsBot/6.1)",
		"Mozilla/5.0 (compatible; MJ12bot/v1.4.8;)",
		"Mozilla/5.0 (compatible; SemrushBot/7~bl)",
		"Mozilla/5.0 (compatible; DotBot/1.2)",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 12_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/16B92 MobileSafari/604.1",
		"MobileSafari/604.1 CFNetwork/976 Darwin/18.2.0",
		"Parsijoo-bot/1.0 (crawler@parsijoo.ir)",
		"Mozilla/5.0 (compatible; AhrefsBot/6.1; +http://ahrefs.com/robot/)",
	} {
		for _, line := range []string{
			`1.2.3.4 - - [08/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "` + ua + `"`,
			`{"ua": "` + ua + `"}`,
			`{"ua":"` + ua + `"}`,
			`user_agent="` + ua + `" status=200`,
		} {
			out := ScanAndRedact(line)
			if out != line {
				t.Errorf("User-Agent changed:\n in: %s\nout: %s", line, out)
			}
			if json.Valid([]byte(line)) && !json.Valid([]byte(out)) {
				t.Errorf("JSON broken: %s", out)
			}
		}
	}
}

// TestUserAgentStillScanned: only product tokens and a contact address in
// the comment are exempt. A secret written into a User-Agent, a value after a
// sensitive word, and an e-mail outside the comment are still hidden.
func TestUserAgentStillScanned(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tc := range []struct{ ua, secret string }{
		{"MyClient/1.0 token Ywq3SUV3eVpQgBTwK_w2VVdvxT85ypPc2C4N1Jkz", "Ywq3SUV3eVpQgBTwK_w2VVdvxT85ypPc2C4N1Jkz"},
		{"curl/8.4.0 lena@example.com", "lena@example.com"},
		{"MyClient/1.0 (key=Ywq3SUV3eVpQgBTwK_w2VVdvxT85ypPc2C4N1Jkz)", "Ywq3SUV3eVpQgBTwK_w2VVdvxT85ypPc2C4N1Jkz"},
		{"MyClient/1.0 AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
	} {
		line := `"GET / HTTP/1.1" 200 512 "-" "` + tc.ua + `"`
		out := ScanAndRedact(line)
		if strings.Contains(out, tc.secret) || !strings.Contains(out, "[HIDDEN") {
			t.Errorf("secret in a User-Agent passed:\n in: %s\nout: %s", line, out)
		}
		if !strings.Contains(out, `"`+strings.Fields(tc.ua)[0]) {
			t.Errorf("product token lost: %s", out)
		}
	}
}

func TestIsUserAgentProduct(t *testing.T) {
	for _, s := range []string{
		"Mozilla/5.0", "AhrefsBot/6.1", "MJ12bot/v1.4.8", "Mobile/11A465", "SemrushBot/7~bl",
		"AppleWebKit/605.1.15", "AppleWebKit/537.36+", "CFNetwork/976", "Darwin/18.2.0", "Parsijoo-bot/1.0", "curl/8.4.0",
	} {
		if !isUserAgentProduct(s) {
			t.Errorf("isUserAgentProduct(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"Build/R16NW", "SM-J700F", "Mozilla", "/5.0", "9bot/1.0", "Mozilla/", "Mozilla/abc",
		"a/b/1", "Mozilla/5.0;", "x/1.0=abc", "Mozilla/" + strings.Repeat("1", 25), "",
	} {
		if isUserAgentProduct(s) {
			t.Errorf("isUserAgentProduct(%q) = true, want false", s)
		}
	}
}
