package scanner

import (
	"strings"
	"testing"
)

// TestLoggerNameIsNotAKey: in Python's default log format LEVEL:logger:message,
// a logger named auth, security, passport or app.token is a name, not the key
// of the message's first word. "INFO:auth:User logged in" came back as
// "INFO:auth:[HIDDEN:...] logged in" and "DEBUG:app.auth:Checking session"
// lost "Checking" (tracker 2026-10-05, first written in the description of
// PR #263). The message is read as it would be on its own.
func TestLoggerNameIsNotAKey(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"INFO:auth:User logged in",
		"DEBUG:app.auth:Checking session",
		"INFO:myapp.security:Rotating keys",
		"WARNING:passport:Strategy failed",
		"ERROR:auth.token:Expired for user 42",
		"INFO:api.keys:Loaded 3 providers",
		"INFO:django.contrib.auth:user logged in",
		"INFO:auth:user=bob action=login",
		"INFO:secrets:",
		"INFO:auth:Winter7413 logged in",
		"TRACE:oauth2.session:Refreshing token cache",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", in, out)
		}
	}

	// With the prefix glued on, a message is redacted exactly as it is on
	// its own, for loggers whose name holds a sensitive word too.
	for _, msg := range []string{
		"User logged in",
		"Password: Wintermonkey73",
		"password=Wintermonkey73",
		"password hunter2 rejected",
		"token: Wintermonkey73",
		"Authorization: Bearer abcdefghijklmnopqrstuvwx",
		"lena@example.com: login failed",
		"GET /a?token=Ywq3SUV3eVpQgBTwK_w2VV HTTP/1.1",
		"12:30:00 started",
		"Status: ok",
	} {
		for _, prefix := range []string{"INFO:auth:", "DEBUG:app.auth:", "ERROR:auth.token:", "INFO:root:"} {
			want := prefix + ScanAndRedact(msg)
			if got := ScanAndRedact(prefix + msg); got != want {
				t.Errorf("glued prefix changed the result:\n  in: %s\n got: %s\nwant: %s", prefix+msg, got, want)
			}
		}
	}

	// A key the message starts with still forces its value, and a bare
	// sensitive word after the prefix forces the token after it, as it does
	// in prose (the sibling task of 2026-10-05: "DEBUG:root:password hunter2"
	// came back unchanged).
	for _, tc := range []struct{ in, secret string }{
		{"INFO:auth:Password: Wintermonkey73", "Wintermonkey73"},
		{"DEBUG:app.auth:token: Wintermonkey73", "Wintermonkey73"},
		{"INFO:root:password=Wintermonkey73", "Wintermonkey73"},
		{"DEBUG:root:password hunter2", "hunter2"},
		{"INFO:auth:password hunter2 rejected", "hunter2"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.secret) || !strings.Contains(out, "[HIDDEN") {
			t.Errorf("value after the prefix not hidden: %q -> %q", tc.in, out)
		}
		if !strings.HasPrefix(out, tc.in[:strings.Index(tc.in, ":")+1]) {
			t.Errorf("prefix changed: %q -> %q", tc.in, out)
		}
	}
	if out := ScanAndRedact("INFO:auth:password hunter2 rejected"); !strings.HasSuffix(out, "] rejected") {
		t.Errorf("word after the value lost: %q", out)
	}
}

func TestPythonLogPrefixEnd(t *testing.T) {
	for _, tc := range []struct {
		in  string
		end int
	}{
		{"INFO:auth:User", 10},
		{"DEBUG:app.auth:Checking", 15},
		{"WARNING:passport:x", 17},
		{"ERROR:huawei_lte_api.Connection:Password:", 32},
		{"INFO:uvicorn-access:GET", 20},
		{"INFO:root:", 10},
		{"INFO:auth:a:b", 10},
		{"info:auth:User", 0},
		{"INFO:auth", 0},
		{"INFO::x", 0},
		{"INFO:9auth:x", 0},
		{"INFO:au th:x", 0},
		{"root:Password:", 0},
		{"10:15:32:Password:", 0},
		{"Status:ok", 0},
		{"INFORMATION:auth:x", 0},
		{"", 0},
	} {
		if got := pythonLogPrefixEnd(tc.in); got != tc.end {
			t.Errorf("pythonLogPrefixEnd(%q) = %d, want %d", tc.in, got, tc.end)
		}
	}
}
