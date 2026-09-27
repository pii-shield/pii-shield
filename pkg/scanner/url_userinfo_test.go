package scanner

import (
	"strings"
	"testing"
)

// TestURLUserinfoPasswordRedacted: the password in scheme://user:password@host
// was written out verbatim, since the text before a URL's query is only checked
// for signatures. A '/' in the password made it worse for any fix that stops
// the authority at the first '/'.
func TestURLUserinfoPasswordRedacted(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	// Assembled at runtime so no matchable literal sits in the source.
	ghToken := "ghp_" + strings.Repeat("a", 36)

	for _, tc := range []struct{ in, pw, want string }{
		{"postgresql://ldr:Xk9pQ2/mZ7wLr4@db:5432/ldr", "Xk9pQ2/mZ7wLr4", "postgresql://ldr:[HIDDEN:key:"},
		{"DATABASE_URL=postgresql://ldr:Xk9pQ2/mZ7wLr4@db:5432/ldr", "Xk9pQ2/mZ7wLr4", "DATABASE_URL=postgresql://ldr:[HIDDEN:key:"},
		{"connecting to postgres://app:hunter2@localhost/app", "hunter2", "connecting to postgres://app:[HIDDEN:key:3920d5]@localhost/app"},
		{"redis://:s3cr3tPassw0rd@cache:6379/0", "s3cr3tPassw0rd", "redis://:[HIDDEN:key:"},
		{"mongodb+srv://admin:P%40ss%2Fw0rd@cluster0.abcde.mongodb.net/test?retryWrites=true", "P%40ss%2Fw0rd", "mongodb+srv://admin:[HIDDEN:key:"},
		{`{"dsn":"mysql://root:ab?cd#ef@db/app"}`, "ab?cd#ef", `{"dsn":"mysql://root:[HIDDEN:key:`},
		{"amqp://svc:p@ss@rabbit:5672/", "p@ss", "amqp://svc:[HIDDEN:key:"},
		{"https://user:" + ghToken + "@github.com/org/repo.git", ghToken, "https://user:[HIDDEN:github-token:"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.pw) {
			t.Errorf("password passed through: %q", out)
		}
		if !strings.HasPrefix(out, tc.want) {
			t.Errorf("want prefix %q, got %q", tc.want, out)
		}
		// Everything after the password comes back as it was.
		if at := strings.LastIndex(tc.in, tc.pw) + len(tc.pw); !strings.HasSuffix(out, tc.in[at:]) {
			t.Errorf("rest of the URL changed: %q -> %q", tc.in, out)
		}
	}

	// An '@' or ':' in a path or a query is not userinfo, a user alone has no
	// password, and a port followed by a path is not a password.
	for _, in := range []string{
		"https://medium.com/@alice/my-post-123",
		"https://unpkg.com/react@18.2.0/umd/react.production.min.js",
		"https://host:8080/users/@alice",
		"https://example.com/login?next=/a:b@c",
		"ssh://git@github.com:22/org/repo.git",
		"https://user@example.com/path",
		"postgres://app:@db/app",
		"postgres://localhost:5432/app",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed: %q -> %q", in, out)
		}
	}

	// A second pass leaves every marker alone, the userinfo one and, in a
	// quoted URL, the query one (which was hashed again on every pass).
	for _, in := range []string{
		"postgres://app:hunter2@localhost/app",
		"x postgres://app:hunter2@localhost/app?password=hunter2 y",
		`"postgres://app:hunter2@localhost/app?password=hunter2&a=1"`,
		`{"dsn":"postgres://app:Xk9pQ2/mZ7wLr4@db/app","u":"https://x.example/cb?token=hunter2xyz"}`,
	} {
		once := ScanAndRedact(in)
		if twice := ScanAndRedact(once); twice != once {
			t.Errorf("not idempotent: %q -> %q", once, twice)
		}
	}
}

func TestURLPasswordBounds(t *testing.T) {
	for in, want := range map[string]string{
		"postgresql://ldr:a/b@db/x":       "a/b",
		"redis://:pw@h":                   "pw",
		"x://u:p@ss@h/y@z":                "p@ss",
		"x://u:p@h?x=a@b":                 "p",
		"http://example.com:80@evil.com/": "80",
		"https://h:8080/u/@a":             "",
		"https://h/a:b@c":                 "",
		"https://u@h":                     "",
		"u:p@h":                           "",
		"x://u:@h":                        "",
	} {
		got := ""
		if s, e, ok := urlPassword(in); ok {
			got = in[s:e]
		}
		if got != want {
			t.Errorf("urlPassword(%q) = %q, want %q", in, got, want)
		}
	}
}
