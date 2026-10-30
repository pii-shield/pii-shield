package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pii-shield/pii-shield/rules/internal/store"
)

// Who may call the management API, in the order it is decided:
//
//   - the admin token (Authorization: Bearer) sees every organization;
//   - a single-tenant server without an admin token is open: it sits behind
//     a port-forward or the operator's own access control;
//   - a session cookie, set by a magic link, sees the organization of its
//     account and nothing else.
//
// A cookie is sent by the browser on its own, so a request it authorizes
// must also prove it came from the panel: a custom header no cross-site
// form can set, and an Origin (or Referer) of this host.

// SessionCookie names the session cookie.
const SessionCookie = "pii_rules_session"

// DefaultSessionTTL and DefaultLoginTTL are the lifetimes of a session and
// of a magic link.
const (
	DefaultSessionTTL = 30 * 24 * time.Hour
	DefaultLoginTTL   = 15 * time.Minute
)

// principal is who a request runs as.
type principal struct {
	admin   bool
	open    bool // single-tenant, nobody in particular
	user    *store.User
	org     *store.Org
	session string // cookie value, for logout
}

func (p *principal) email() string {
	if p.user != nil {
		return p.user.Email
	}
	return ""
}

type principalKey struct{}

func withPrincipal(r *http.Request, p *principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}

func principalOf(r *http.Request) *principal {
	p, _ := r.Context().Value(principalKey{}).(*principal)
	if p == nil {
		return &principal{}
	}
	return p
}

// requireAccess resolves the caller of a management request and refuses
// an anonymous one with 401.
func (s *Server) requireAccess(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			s.internal(w, err)
			return
		}
		if p == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="pii-shield-rules-admin"`)
			s.fail(w, http.StatusUnauthorized, "sign in, or send the admin token")
			return
		}
		if p.user != nil && !safeMethod(r.Method) {
			if msg := s.csrfProblem(r); msg != "" {
				s.fail(w, http.StatusForbidden, msg)
				return
			}
		}
		next(w, withPrincipal(r, p))
	}
}

// authenticate returns the caller, or nil for an anonymous request.
func (s *Server) authenticate(r *http.Request) (*principal, error) {
	if value, ok := bearer(r); ok && s.cfg.AdminToken != "" {
		if subtle.ConstantTimeCompare([]byte(value), []byte(s.cfg.AdminToken)) == 1 {
			return &principal{admin: true}, nil
		}
		return nil, nil
	}
	if s.cfg.SingleTenant && s.cfg.AdminToken == "" {
		return &principal{open: true}, nil
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	sess, err := s.store.GetSession(r.Context(), c.Value)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &principal{user: sess.User, org: sess.Org, session: c.Value}, nil
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// csrfProblem checks that a state-changing request from a browser came
// from the panel on this host: the X-Requested-With header, which no
// cross-site form can set, and an Origin or Referer of this host.
func (s *Server) csrfProblem(r *http.Request) string {
	if r.Header.Get("X-Requested-With") == "" {
		return "missing X-Requested-With header"
	}
	return s.originProblem(r)
}

// originProblem reports an Origin or Referer that is not this host.
func (s *Server) originProblem(r *http.Request) string {
	source := r.Header.Get("Origin")
	if source == "" || source == "null" {
		source = r.Header.Get("Referer")
	}
	if source == "" {
		return "missing Origin header"
	}
	u, err := url.Parse(source)
	if err != nil || u.Host == "" {
		return "unreadable Origin header"
	}
	if !strings.EqualFold(u.Host, r.Host) && !strings.EqualFold(u.Host, s.baseHost()) {
		return "cross-site request refused"
	}
	return ""
}

func (s *Server) baseHost() string {
	if s.cfg.BaseURL == "" {
		return ""
	}
	u, err := url.Parse(s.cfg.BaseURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// baseURL is the public address of this server for the links in mail.
// It is the configured one and nothing else: building it from the
// request's Host header would let anyone who can reach the server have a
// real sign-in token mailed to a victim inside a link to their own site
// (New refuses a Mailer without a BaseURL, so this is never empty when a
// link is sent).
func (s *Server) baseURL() string {
	return strings.TrimRight(s.cfg.BaseURL, "/")
}

// checkBaseURL accepts an absolute http or https address with a host and
// nothing after the path.
func checkBaseURL(raw string) error {
	if raw == "" {
		return errors.New("a base URL (RULES_BASE_URL) is required to send sign-in links: they are never built from the request's Host header")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("base URL %q: want http:// or https:// with a host, no user, query or fragment", raw)
	}
	return nil
}

// clientIP is the address the login limits are keyed by: the first
// X-Forwarded-For entry behind a trusted proxy, else the peer.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				xff = xff[:i]
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- login ----

type loginRequest struct {
	Email string `json:"email"`
}

const loginMessage = "if the address can sign in, a link is on its way; it works once and for a quarter of an hour"

// login sends a magic link. The answer is the same whether or not the
// address has an account, so the panel discloses no addresses; the mail
// is only skipped when the address has no account and sign-up is closed.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if msg := s.csrfProblem(r); msg != "" {
		s.fail(w, http.StatusForbidden, msg)
		return
	}
	if s.cfg.Mailer == nil {
		s.fail(w, http.StatusServiceUnavailable, "sign-in is not available on this server: no mail is configured")
		return
	}
	if !s.loginByIP.allow(s.clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		s.fail(w, http.StatusTooManyRequests, "too many sign-in requests from this address; try again in a minute")
		return
	}
	var req loginRequest
	if !s.decode(w, r, &req) {
		return
	}
	email, err := store.NormalizeEmail(req.Email)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "not an e-mail address")
		return
	}
	if !s.loginByEmail.allow(email) {
		w.Header().Set("Retry-After", "600")
		s.fail(w, http.StatusTooManyRequests, "a link was sent to this address recently; look for it, or try again in ten minutes")
		return
	}
	_, err = s.store.GetUserByEmail(r.Context(), email)
	switch {
	case errors.Is(err, store.ErrNotFound) && !s.cfg.Signup:
		s.log.Info("sign-in for an unknown address with sign-up closed", "email", email)
		s.json(w, http.StatusOK, map[string]any{"sent": true, "message": loginMessage})
		return
	case err != nil && !errors.Is(err, store.ErrNotFound):
		s.internal(w, err)
		return
	}
	if err := s.sendLink(r, email, "Sign in to the PII-Shield rule server",
		"Open this link to sign in; it works once and for a quarter of an hour:\n\n%s\n\nIf you did not ask for it, ignore this mail."); err != nil {
		s.log.Error("send the sign-in mail", "email", email, "err", err)
		s.fail(w, http.StatusBadGateway, "the mail could not be sent; try again later")
		return
	}
	s.json(w, http.StatusOK, map[string]any{"sent": true, "message": loginMessage})
}

// sendLink creates a magic link for the address and mails it with the
// body template, which has one %s for the link.
func (s *Server) sendLink(r *http.Request, email, subject, bodyFormat string) error {
	if s.cfg.Mailer == nil {
		return errors.New("no mailer configured")
	}
	value, err := s.store.CreateLogin(r.Context(), email, s.cfg.LoginTTL)
	if err != nil {
		return err
	}
	link := s.baseURL() + "/auth/verify?token=" + url.QueryEscape(value)
	return s.cfg.Mailer.Send(r.Context(), email, subject, fmt.Sprintf(bodyFormat, link))
}

// verify is the form on the magic-link page: the link itself is a GET
// that only shows a button, so a mail scanner that opens the link does
// not spend it. The POST spends it and sets the session cookie.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	if msg := s.originProblem(r); msg != "" {
		s.fail(w, http.StatusForbidden, msg)
		return
	}
	if !s.verifyByIP.allow(s.clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		s.fail(w, http.StatusTooManyRequests, "too many attempts from this address")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, http.StatusBadRequest, "unreadable form")
		return
	}
	value := r.PostForm.Get("token")
	if value == "" {
		s.fail(w, http.StatusBadRequest, "the link carries no token")
		return
	}
	email, err := s.store.ConsumeLogin(r.Context(), value)
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrExpired):
		http.Redirect(w, r, "/#/login?error=link", http.StatusSeeOther)
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	user, err := s.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		if !s.cfg.Signup {
			s.log.Info("magic link for an address without an account, sign-up closed", "email", email)
			http.Redirect(w, r, "/#/login?error=no-account", http.StatusSeeOther)
			return
		}
		var org *store.Org
		user, org, err = s.store.Signup(r.Context(), email)
		if err != nil {
			s.internal(w, err)
			return
		}
		s.log.Info("organization created by sign-up", "org", org.Slug, "email", email)
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	session, err := s.store.CreateSession(r.Context(), user.ID, s.cfg.SessionTTL)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.setSessionCookie(w, session, s.cfg.SessionTTL)
	s.log.Info("signed in", "email", email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, value string, ttl time.Duration) {
	maxAge := int(ttl / time.Second)
	if ttl < 0 {
		maxAge = -1 // Max-Age=0: the browser drops the cookie
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !s.cfg.InsecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

// logout ends the session of the cookie.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if p.session != "" {
		if err := s.store.DeleteSession(r.Context(), p.session); err != nil {
			s.internal(w, err)
			return
		}
	}
	s.setSessionCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

// me tells the panel who it runs as.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	resp := map[string]any{"signup": s.cfg.Signup}
	switch {
	case p.admin:
		resp["mode"] = "admin"
	case p.open:
		resp["mode"] = "single-tenant"
		if org, err := s.store.GetOrg(r.Context(), DefaultOrg); err == nil {
			resp["org"] = org
		}
	default:
		resp["mode"] = "session"
		resp["email"] = p.user.Email
		resp["org"] = p.org
	}
	s.json(w, http.StatusOK, resp)
}

// ---- members ----

type memberRequest struct {
	Email string `json:"email"`
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	org, ok := s.org(w, r)
	if !ok {
		return
	}
	users, err := s.store.ListUsers(r.Context(), org.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{"members": users})
}

// invite adds an account to the organization and mails it a sign-in link.
// An address with an account elsewhere is refused: one organization per
// account.
func (s *Server) invite(w http.ResponseWriter, r *http.Request) {
	org, ok := s.org(w, r)
	if !ok {
		return
	}
	var req memberRequest
	if !s.decode(w, r, &req) {
		return
	}
	user, err := s.store.CreateUser(r.Context(), org.ID, req.Email, principalOf(r).email())
	if errors.Is(err, store.ErrInvalidEmail) {
		s.fail(w, http.StatusBadRequest, "not an e-mail address")
		return
	}
	if errors.Is(err, store.ErrExists) {
		s.fail(w, http.StatusConflict, "this address already has an account")
		return
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	mailed := true
	if err := s.sendLink(r, user.Email, "You were invited to the PII-Shield rule server",
		"You were added to the organization "+org.Name+". Open this link to sign in; it works once and for a quarter of an hour:\n\n%s"); err != nil {
		s.log.Error("send the invitation mail", "email", user.Email, "err", err)
		mailed = false
	}
	s.log.Info("member invited", "org", org.Slug, "email", user.Email, "by", principalOf(r).email())
	s.json(w, http.StatusCreated, map[string]any{"member": user, "mailed": mailed})
}

// authorOf is the author recorded on a version or a publication: the
// signed-in account, or whatever the admin or the open caller says.
func authorOf(r *http.Request, claimed string) string {
	if e := principalOf(r).email(); e != "" {
		return e
	}
	return claimed
}
