package scanner

import (
	"strings"
	"testing"
)

// Fake tokens in the exact issuer formats, assembled at runtime so no
// matchable literal sits in the source (see signatures_test.go).
var (
	gcpDumpKey  = "AI" + "zaSyD" + "x7Kq2Lp9Vt4Ny8Rb3Hc6Jw1Fs5Gd0Mzq"
	telegramBot = "8411610395:" + "AA" + "Hq3kZ9vX2mT7pL4wR8nB1cF6yD5sJ0gKe"
)

// TestEscapedCRLFSeparatesTokens: a literal "\r\n" in a request dump is a line
// break, not part of the neighbouring tokens. Glued to them it put a header
// name and its secret in one token, and the two backslashes made isPath treat
// the key as a Windows path, so it was never scored (seen in
// Mozra-the-great/wazuh-ai-analyzer#41).
func TestEscapedCRLFSeparatesTokens(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		gcpDumpKey + `\r\n`,
		`x-goog-api-key: ` + gcpDumpKey + `\r\n`,
		`Host: a\r\nx-goog-api-key: ` + gcpDumpKey + `\r\n`,
		`'POST /v1 HTTP/1.1\r\nx-goog-api-key: ` + gcpDumpKey + `\r\n'`,
	} {
		out := ScanAndRedact(in)
		if strings.Contains(out, gcpDumpKey) {
			t.Errorf("key passed through: %q", out)
		}
		if strings.Count(out, `\r\n`) != strings.Count(in, `\r\n`) {
			t.Errorf("line breaks changed: %q -> %q", in, out)
		}
	}

	// Windows paths keep their whitelist: none of them holds "\r\n".
	for _, in := range []string{
		`C:\Users\admin\AppData\Local\Temp\report.txt`,
		`app\modules\net\client.py`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("path changed: %q -> %q", in, out)
		}
	}
}

// TestBytesLiteralDumpIsScanned: urllib3 and http.client log the request they
// send as a Python bytes literal. The b prefix hid the quotes, and the colon
// pair splitter cut the dump at its first header, so nothing after it was
// scored.
func TestBytesLiteralDumpIsScanned(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	in := `send: b'POST /v1beta/models/gemini-pro:generateContent HTTP/1.1\r\n` +
		`Host: generativelanguage.googleapis.com\r\nx-goog-api-key: ` + gcpDumpKey + `\r\n'`
	out := ScanAndRedact(in)
	if strings.Contains(out, gcpDumpKey) {
		t.Errorf("key in bytes dump passed through: %q", out)
	}
	if !strings.HasPrefix(out, `send: b'POST /v1beta/models/gemini-pro:generateContent HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\n`) ||
		!strings.HasSuffix(out, `\r\n'`) {
		t.Errorf("dump framing changed: %q", out)
	}

	// JSON inside a bytes literal keeps its quotes and brace; before, the
	// value swallowed the closing "} and the line lost them.
	json := `send: b'{"password": "hunter2x"}'`
	if out := ScanAndRedact(json); strings.Contains(out, "hunter2x") ||
		!strings.HasSuffix(out, `"}'`) || strings.Count(out, `"`) != strings.Count(json, `"`) {
		t.Errorf("json in bytes literal: %q", out)
	}

	// A dump with nothing secret in it comes back byte for byte.
	clean := `send: b'GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n'`
	if out := ScanAndRedact(clean); out != clean {
		t.Errorf("clean dump changed: %q -> %q", clean, out)
	}
}

// TestTelegramBotTokenInURLPath: the Bot API puts the token in every URL path
// (/bot<id>:<token>/sendMessage). URL paths were written out unscanned, and the
// token's colon made the pair splitter cut it in two, so it passed in full URLs
// and lost the rest of the path in bare ones (seen in
// emanuelturtula/trading-bot#50).
func TestTelegramBotTokenInURLPath(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	secret := telegramBot[strings.IndexByte(telegramBot, ':')+1:]
	for _, tc := range []struct{ in, keep string }{
		{"url=https://api.telegram.org/bot" + telegramBot + "/sendMessage", "url=https://api.telegram.org/bot[HIDDEN:telegram-bot-token:"},
		{"https://api.telegram.org/bot" + telegramBot + "/sendMessage?chat_id=1", "https://api.telegram.org/bot[HIDDEN:telegram-bot-token:"},
		{"NetworkError: url: /bot" + telegramBot + "/sendMessage", "NetworkError: url: /bot[HIDDEN:telegram-bot-token:"},
		{`"GET /bot` + telegramBot + `/getUpdates HTTP/1.1" 200 5`, `"GET /bot[HIDDEN:telegram-bot-token:`},
		{"token " + telegramBot, "token [HIDDEN:telegram-bot-token:"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, secret) {
			t.Errorf("token passed through: %q", out)
		}
		if !strings.HasPrefix(out, tc.keep) {
			t.Errorf("want prefix %q, got %q", tc.keep, out)
		}
		// The rest of the path survives.
		for _, tail := range []string{"/sendMessage", "/getUpdates HTTP/1.1\" 200 5", "?chat_id=1"} {
			if strings.Contains(tc.in, tail) && !strings.Contains(out, tail) {
				t.Errorf("lost %q: %q", tail, out)
			}
		}
	}

	// Paths without a signature are still written verbatim: ids, slugs and
	// hashes in real paths are not scored by entropy.
	for _, in := range []string{
		"https://api.telegram.org/bot/getMe",
		"https://example.com/users/e38d64ed-76d1-4d06-987e-d777e1cf61cc/orders",
		"https://cdn.example.com/static/app.3f9a1c8e2b7d4f60a1c9.js",
		"https://example.com/12345:notatoken/x",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("path changed: %q -> %q", in, out)
		}
	}
}
