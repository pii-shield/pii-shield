package server

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pii-shield/pii-shield/rules/internal/store"
)

// capture keeps the mails the server sends.
type capture struct {
	mu    sync.Mutex
	mails []string // "to|subject|body"
}

func (c *capture) Send(_ context.Context, to, subject, body string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mails = append(c.mails, to+"|"+subject+"|"+body)
	return nil
}

var linkRe = regexp.MustCompile(`https?://\S+/auth/verify\?token=([0-9a-f]+)`)

func (c *capture) lastLink(t *testing.T) (string, string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.mails) == 0 {
		t.Fatal("no mail was sent")
	}
	m := linkRe.FindStringSubmatch(c.mails[len(c.mails)-1])
	if m == nil {
		t.Fatalf("no link in the mail: %s", c.mails[len(c.mails)-1])
	}
	return m[0], m[1]
}

// browser is a client with a cookie jar that behaves like the panel:
// X-Requested-With on every call and the server's origin.
type browser struct {
	t      *testing.T
	client *http.Client
	origin string
}

func newBrowser(t *testing.T, origin string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, origin: origin, client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) do(method, path, body string, headers map[string]string) (int, http.Header, string) {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.origin+path, strings.NewReader(body))
	req.Header.Set("X-Requested-With", "fetch")
	req.Header.Set("Origin", b.origin)
	if body != "" && !strings.HasPrefix(body, "token=") {
		req.Header.Set("Content-Type", "application/json")
	} else if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var sb strings.Builder
	buf := make([]byte, 64<<10)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, resp.Header, sb.String()
}

// signIn walks the magic link: request, open the link (GET spends
// nothing), post the form, and returns the browser signed in.
func signIn(t *testing.T, ts interface{ URLString() string }, mails *capture, email string) *browser {
	t.Helper()
	b := newBrowser(t, ts.URLString())
	if code, _, body := b.do("POST", "/auth/login", `{"email": "`+email+`"}`, nil); code != 200 || !strings.Contains(body, "on its way") {
		t.Fatalf("login: %d %s", code, body)
	}
	link, token := mails.lastLink(t)
	u, _ := url.Parse(link)
	if code, hdr, body := b.do("GET", u.RequestURI(), "", nil); code != 200 || !strings.Contains(body, `name="token"`) || !strings.Contains(hdr.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("verify page: %d %s", code, body)
	}
	code, hdr, _ := b.do("POST", "/auth/verify", "token="+token, nil)
	if code != 303 || hdr.Get("Location") != "/" {
		t.Fatalf("verify post: %d %s", code, hdr.Get("Location"))
	}
	cookie := hdr.Get("Set-Cookie")
	if !strings.Contains(cookie, SessionCookie+"=") || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Strict") {
		t.Fatalf("cookie: %s", cookie)
	}
	return b
}

type tsURL struct{ url string }

func (u tsURL) URLString() string { return u.url }

func TestMagicLinkSignInSignupAndOrgScope(t *testing.T) {
	mails := &capture{}
	ts := newTestServer(t, Config{AdminToken: admin, PolicyRate: 1000, Mailer: mails, BaseURL: "https://rules.example.test", Signup: true, InsecureCookies: true})
	u := tsURL{ts.URL}

	// Anonymous: the API is closed, the panel page is served.
	anon := newBrowser(t, ts.URL)
	if code, _, _ := anon.do("GET", "/api/me", "", nil); code != 401 {
		t.Errorf("anonymous /api/me: %d", code)
	}
	if code, hdr, body := anon.do("GET", "/", "", nil); code != 200 || !strings.Contains(body, "PII-Shield rules") || !strings.Contains(hdr.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Errorf("panel page: %d", code)
	}
	if code, hdr, _ := anon.do("GET", "/app.js", "", nil); code != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/javascript") {
		t.Errorf("app.js: %d %s", code, hdr.Get("Content-Type"))
	}

	anna := signIn(t, u, mails, "Anna@Example.com")
	code, _, body := anna.do("GET", "/api/me", "", nil)
	if code != 200 || !strings.Contains(body, `"mode": "session"`) || !strings.Contains(body, `"email": "anna@example.com"`) || !strings.Contains(body, `"slug": "anna"`) {
		t.Fatalf("me: %d %s", code, body)
	}
	// The link is spent.
	_, token := mails.lastLink(t)
	if code, hdr, _ := anna.do("POST", "/auth/verify", "token="+token, nil); code != 303 || !strings.Contains(hdr.Get("Location"), "error=link") {
		t.Errorf("spent link: %d %s", code, hdr.Get("Location"))
	}

	// Her organization: sets, versions with her as the author, members.
	if code, _, body = anna.do("GET", "/api/orgs", "", nil); code != 200 || strings.Count(body, `"slug"`) != 1 {
		t.Errorf("orgs for a session: %d %s", code, body)
	}
	if code, _, _ = anna.do("POST", "/api/orgs", `{"slug": "another"}`, nil); code != 403 {
		t.Errorf("create org from a session: %d", code)
	}
	if code, _, body = anna.do("POST", "/api/orgs/anna/sets", `{"slug": "payments"}`, nil); code != 201 {
		t.Fatalf("create set: %d %s", code, body)
	}
	code, _, body = anna.do("POST", "/api/orgs/anna/sets/payments/versions", `{"content": {"sensitive_keys": ["geheim"]}, "author": "someone else"}`, nil)
	if code != 201 || !strings.Contains(body, `"author": "anna@example.com"`) {
		t.Errorf("version author must be the account: %d %s", code, body)
	}
	if code, _, body = anna.do("POST", "/api/orgs/anna/sets/payments/publish", `{"revision": 1}`, nil); code != 200 {
		t.Errorf("publish: %d %s", code, body)
	}

	// Another organization exists, made by the admin; she cannot see it.
	if code, _, _, raw := do(t, ts, call{method: "POST", path: "/api/orgs", token: admin, body: `{"slug": "acme"}`}); code != 201 {
		t.Fatalf("admin creates org: %d %s", code, raw)
	}
	for _, p := range []string{"/api/orgs/acme/sets", "/api/orgs/acme/members"} {
		if code, _, _ = anna.do("GET", p, "", nil); code != 404 {
			t.Errorf("GET %s from another org's session: %d, want 404", p, code)
		}
	}
	if code, _, _ = anna.do("POST", "/api/orgs/acme/sets", `{"slug": "x"}`, nil); code != 404 {
		t.Errorf("POST into another org: %d", code)
	}
	// The admin still sees everything.
	if code, _, body, _ := do(t, ts, call{method: "GET", path: "/api/orgs", token: admin}); code != 200 || !strings.Contains(fmtAny(body["orgs"]), "anna") || !strings.Contains(fmtAny(body["orgs"]), "acme") {
		t.Errorf("admin orgs: %d %v", code, body)
	}

	// Invite: bob gets a link and lands in anna's organization; an address
	// with an account elsewhere is refused.
	code, _, body = anna.do("POST", "/api/orgs/anna/members", `{"email": "bob@example.com"}`, nil)
	if code != 201 || !strings.Contains(body, `"mailed": true`) || !strings.Contains(body, `"invitedBy": "anna@example.com"`) {
		t.Fatalf("invite: %d %s", code, body)
	}
	if code, _, _ = anna.do("POST", "/api/orgs/anna/members", `{"email": "nope"}`, nil); code != 400 {
		t.Errorf("invite a bad address: %d", code)
	}
	bob := newBrowser(t, ts.URL)
	_, token = mails.lastLink(t)
	if code, _, _ := bob.do("POST", "/auth/verify", "token="+token, nil); code != 303 {
		t.Errorf("bob verify: %d", code)
	}
	if code, _, body = bob.do("GET", "/api/me", "", nil); code != 200 || !strings.Contains(body, `"slug": "anna"`) {
		t.Errorf("bob me: %d %s", code, body)
	}
	if code, _, body, _ := do(t, ts, call{method: "POST", path: "/api/orgs/acme/members", token: admin, body: `{"email": "bob@example.com"}`}); code != 409 {
		t.Errorf("invite an address with an account: %d %v", code, body)
	}
	if code, _, body = anna.do("GET", "/api/orgs/anna/members", "", nil); code != 200 || strings.Count(body, `"email"`) != 2 {
		t.Errorf("members: %d %s", code, body)
	}

	// Sign out: the cookie is gone and the session is dead.
	if code, hdr, _ := anna.do("POST", "/auth/logout", "", nil); code != 204 || !strings.Contains(hdr.Get("Set-Cookie"), "Max-Age=0") {
		t.Errorf("logout: %d %s", code, hdr.Get("Set-Cookie"))
	}
	if code, _, _ = anna.do("GET", "/api/me", "", nil); code != 401 {
		t.Errorf("after logout: %d", code)
	}
}

func TestSessionRequestsNeedTheHeaderAndTheOrigin(t *testing.T) {
	mails := &capture{}
	ts := newTestServer(t, Config{PolicyRate: 1000, Mailer: mails, BaseURL: "https://rules.example.test", Signup: true, InsecureCookies: true})
	anna := signIn(t, tsURL{ts.URL}, mails, "anna@example.com")
	setBody := `{"slug": "s"}`
	cases := map[string]map[string]string{
		"no X-Requested-With": {"X-Requested-With": ""},
		"foreign Origin":      {"Origin": "https://evil.example"},
		"foreign Referer":     {"Origin": "", "Referer": "https://evil.example/page"},
		"no Origin at all":    {"Origin": "", "Referer": ""},
	}
	for name, hdr := range cases {
		if code, _, body := anna.do("POST", "/api/orgs/anna/sets", setBody, hdr); code != 403 {
			t.Errorf("%s: %d %s, want 403", name, code, body)
		}
	}
	// Reads need no proof; a Referer of this host is enough for a write;
	// so is a null Origin with a good Referer.
	if code, _, _ := anna.do("GET", "/api/orgs/anna/sets", "", map[string]string{"X-Requested-With": "", "Origin": ""}); code != 200 {
		t.Errorf("GET without the header: %d", code)
	}
	if code, _, _ := anna.do("POST", "/api/orgs/anna/sets", setBody, map[string]string{"Origin": "", "Referer": ts.URL + "/"}); code != 201 {
		t.Errorf("POST with a Referer of this host: %d", code)
	}
	// The login form too: a cross-site form post cannot spend a link.
	if code, _, _ := anna.do("POST", "/auth/verify", "token=abc", map[string]string{"Origin": "https://evil.example"}); code != 403 {
		t.Errorf("verify from another origin: %d", code)
	}
	if code, _, _ := anna.do("POST", "/auth/login", `{"email": "x@y.z"}`, map[string]string{"X-Requested-With": ""}); code != 403 {
		t.Errorf("login without the header: %d", code)
	}
}

func TestSignupClosedAndBadLinks(t *testing.T) {
	mails := &capture{}
	ts := newTestServer(t, Config{AdminToken: admin, PolicyRate: 1000, Mailer: mails, BaseURL: "https://rules.example.test", Signup: false, InsecureCookies: true})
	b := newBrowser(t, ts.URL)
	// An unknown address gets the same answer and no mail.
	if code, _, body := b.do("POST", "/auth/login", `{"email": "nobody@example.com"}`, nil); code != 200 || !strings.Contains(body, "on its way") {
		t.Errorf("login unknown: %d %s", code, body)
	}
	if len(mails.mails) != 0 {
		t.Errorf("mail sent for an unknown address with sign-up closed: %v", mails.mails)
	}
	if code, _, _ := b.do("POST", "/auth/login", `{"email": "nope"}`, nil); code != 400 {
		t.Errorf("login bad address: %d", code)
	}
	// An invited address can sign in.
	if code, _, _, raw := do(t, ts, call{method: "POST", path: "/api/orgs", token: admin, body: `{"slug": "acme"}`}); code != 201 {
		t.Fatalf("org: %d %s", code, raw)
	}
	if code, _, _, raw := do(t, ts, call{method: "POST", path: "/api/orgs/acme/members", token: admin, body: `{"email": "anna@example.com"}`}); code != 201 {
		t.Fatalf("invite: %d %s", code, raw)
	}
	mails.mails = nil
	anna := signIn(t, tsURL{ts.URL}, mails, "anna@example.com")
	if code, _, body := anna.do("GET", "/api/me", "", nil); code != 200 || !strings.Contains(body, `"slug": "acme"`) {
		t.Errorf("invited me: %d %s", code, body)
	}
	// Links: unknown, missing, and a link for an address without an
	// account while sign-up is closed.
	if code, hdr, _ := b.do("POST", "/auth/verify", "token=0123", nil); code != 303 || !strings.Contains(hdr.Get("Location"), "error=link") {
		t.Errorf("unknown link: %d %s", code, hdr.Get("Location"))
	}
	if code, _, _ := b.do("POST", "/auth/verify", "token=", nil); code != 400 {
		t.Errorf("empty token: %d", code)
	}
	if code, _, body := b.do("GET", "/auth/verify", "", nil); code != 200 || !strings.Contains(body, "Sign in") {
		t.Errorf("verify page without a token: %d %s", code, body)
	}
	// Invite with signup closed, then the mail link for an address whose
	// account was never created: use the store directly.
	srv := ts.Config.Handler.(*Server)
	v, err := srv.store.CreateLogin(context.Background(), "ghost@example.com", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if code, hdr, _ := b.do("POST", "/auth/verify", "token="+v, nil); code != 303 || !strings.Contains(hdr.Get("Location"), "error=no-account") {
		t.Errorf("link without an account: %d %s", code, hdr.Get("Location"))
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	mails := &capture{}
	ts := newTestServer(t, Config{AdminToken: admin, PolicyRate: 1000, Mailer: mails, BaseURL: "https://rules.example.test", Signup: true, InsecureCookies: true})
	b := newBrowser(t, ts.URL)
	// Three links per address, then 429; the per-IP limit is five, so
	// use distinct addresses to reach it after the first three.
	codes := []int{}
	for i := 0; i < 4; i++ {
		code, _, _ := b.do("POST", "/auth/login", `{"email": "anna@example.com"}`, nil)
		codes = append(codes, code)
	}
	if codes[0] != 200 || codes[2] != 200 || codes[3] != 429 {
		t.Errorf("per-address: %v", codes)
	}
	code, _, _ := b.do("POST", "/auth/login", `{"email": "bob@example.com"}`, nil)
	if code != 200 {
		t.Errorf("fifth request from the IP: %d", code)
	}
	code, hdr, _ := b.do("POST", "/auth/login", `{"email": "carol@example.com"}`, nil)
	if code != 429 || hdr.Get("Retry-After") == "" {
		t.Errorf("sixth request from the IP: %d %s", code, hdr.Get("Retry-After"))
	}
	if len(mails.mails) != 4 {
		t.Errorf("mails sent: %d, want 4", len(mails.mails))
	}
	// Verify attempts are limited too.
	var last int
	for i := 0; i < 11; i++ {
		last, _, _ = b.do("POST", "/auth/verify", "token=0123", nil)
	}
	if last != 429 {
		t.Errorf("eleventh verify attempt: %d", last)
	}
}

func TestSingleTenantIsOpenAndAdminTokenStillWorks(t *testing.T) {
	open := newTestServer(t, Config{SingleTenant: true, PolicyRate: 1000})
	b := newBrowser(t, open.URL)
	if code, _, body := b.do("GET", "/api/me", "", map[string]string{"X-Requested-With": "", "Origin": ""}); code != 200 || !strings.Contains(body, `"mode": "single-tenant"`) || !strings.Contains(body, `"slug": "default"`) {
		t.Errorf("single-tenant me: %d %s", code, body)
	}
	if code, _, _ := b.do("POST", "/api/orgs/default/sets", `{"slug": "s"}`, map[string]string{"X-Requested-With": "", "Origin": ""}); code != 201 {
		t.Errorf("open write without browser headers: %d", code)
	}
	// No mailer: the sign-in is off, and says so.
	if code, _, body := b.do("POST", "/auth/login", `{"email": "a@b.c"}`, nil); code != 503 {
		t.Errorf("login without a mailer: %d %s", code, body)
	}
	// With an admin token the single-tenant server is closed to the browser.
	closed := newTestServer(t, Config{SingleTenant: true, AdminToken: admin, PolicyRate: 1000})
	if code, _, _, _ := do(t, closed, call{method: "GET", path: "/api/me"}); code != 401 {
		t.Errorf("single-tenant with admin token, anonymous: %d", code)
	}
	if code, _, body, _ := do(t, closed, call{method: "GET", path: "/api/me", token: admin}); code != 200 || body["mode"] != "admin" {
		t.Errorf("admin me: %d %v", code, body)
	}
}

func TestKeyedLimiterPrunesIdleBuckets(t *testing.T) {
	k := newKeyedLimiter(time.Millisecond, 2)
	for i := 0; i < 10001; i++ {
		k.allow(string(rune('a'+i%26)) + string(rune(i)))
	}
	k.mu.Lock()
	n := len(k.buckets)
	k.mu.Unlock()
	if n > 10001 || n < 1 {
		t.Errorf("buckets: %d", n)
	}
	time.Sleep(5 * time.Millisecond)
	k.mu.Lock()
	k.prune(time.Now())
	n = len(k.buckets)
	k.mu.Unlock()
	if n != 0 {
		t.Errorf("after prune: %d", n)
	}
}

// A sign-in link is built from the configured base URL only. A forged
// Host header must not move it to another site: the token in it is real.
func TestSignInLinkIgnoresTheRequestHost(t *testing.T) {
	mails := &capture{}
	ts := newTestServer(t, Config{PolicyRate: 1000, Mailer: mails, BaseURL: "https://rules.example.test/", Signup: true, InsecureCookies: true})
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(`{"email": "victim@example.com"}`))
	req.Host = "evil.example"
	req.Header.Set("X-Requested-With", "fetch")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login with a forged Host: %d", resp.StatusCode)
	}
	link, _ := mails.lastLink(t)
	if !strings.HasPrefix(link, "https://rules.example.test/auth/verify?token=") {
		t.Errorf("the link follows the request instead of the configured base URL: %s", link)
	}
	if strings.Contains(link, "evil.example") {
		t.Errorf("the forged Host reached the mail: %s", link)
	}
}

// A server that sends mail must know its own address.
func TestNewRefusesAMailerWithoutABaseURL(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, bad := range []string{"", "rules.example.test", "ftp://rules.example.test", "https://", "https://u:p@rules.example.test", "https://rules.example.test/?x=1", "https://rules.example.test/#a"} {
		if _, err := New(context.Background(), st, Config{Mailer: &capture{}, BaseURL: bad}); err == nil {
			t.Errorf("base URL %q with a mailer was accepted", bad)
		}
	}
	if _, err := New(context.Background(), st, Config{Mailer: &capture{}, BaseURL: "http://localhost:8080"}); err != nil {
		t.Errorf("a plain local base URL was refused: %v", err)
	}
	if _, err := New(context.Background(), st, Config{}); err != nil {
		t.Errorf("no mailer needs no base URL: %v", err)
	}
}
