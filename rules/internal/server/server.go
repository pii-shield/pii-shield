// Package server is the rule server's HTTP surface: the public policy.json
// a cluster pulls with a read-only token, the management API that creates
// organizations, rule sets, versions and tokens, the panel that drives it
// and the magic-link sign-in behind the panel. The management API takes
// the admin token, a panel session, or nothing on a --single-tenant server
// that runs behind a port-forward or the operator's own proxy (auth.go).
package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/pii-shield/pii-shield/rules/internal/mail"
	"github.com/pii-shield/pii-shield/rules/internal/panel"
	"github.com/pii-shield/pii-shield/rules/internal/policy"
	"github.com/pii-shield/pii-shield/rules/internal/signing"
	"github.com/pii-shield/pii-shield/rules/internal/store"
)

// Config configures a Server.
type Config struct {
	// AdminToken protects the management API. Empty with SingleTenant means
	// no check; empty without it refuses every management request.
	AdminToken string
	// SingleTenant serves one organization, "default", without a login.
	SingleTenant bool
	// PolicyRate bounds policy.json pulls per token, per second; the burst
	// is ten. Zero means 1/s, which is sixty clusters polling every minute.
	PolicyRate float64
	Logger     *slog.Logger

	// BaseURL is the public address of the server (scheme and host), for
	// the links in mail and as a second accepted Origin. It is required
	// when a Mailer is set: the links are never built from the request's
	// Host header, which a client chooses, so a forged Host cannot send a
	// real sign-in token to another site.
	BaseURL string
	// Mailer sends the magic links; nil disables the sign-in.
	Mailer mail.Mailer
	// Signup lets an address without an account create an organization by
	// signing in; off, only invited addresses can sign in.
	Signup bool
	// TrustProxy reads the client address from X-Forwarded-For, for a
	// server behind a reverse proxy (the rate limits key on it).
	TrustProxy bool
	// InsecureCookies drops the Secure flag of the session cookie, for a
	// server reached over plain http on localhost.
	InsecureCookies bool
	// SessionTTL and LoginTTL are the lifetimes of a session and of a
	// magic link; zero means the defaults.
	SessionTTL time.Duration
	LoginTTL   time.Duration
}

// DefaultOrg is the organization of a single-tenant server.
const DefaultOrg = "default"

// maxBody bounds a management request body: a rule set plus its envelope.
const maxBody = policy.MaxBytes + 4096

// Server serves the rule server's HTTP surface.
type Server struct {
	cfg   Config
	store *store.Store
	mux   *http.ServeMux
	log   *slog.Logger

	limMu    sync.Mutex
	limiters map[int64]*rate.Limiter

	loginByIP    *keyedLimiter
	loginByEmail *keyedLimiter
	verifyByIP   *keyedLimiter
}

// New builds a Server over the store. In single-tenant mode the default
// organization is created if missing.
func New(ctx context.Context, st *store.Store, cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.PolicyRate <= 0 {
		cfg.PolicyRate = 1
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = DefaultSessionTTL
	}
	if cfg.LoginTTL <= 0 {
		cfg.LoginTTL = DefaultLoginTTL
	}
	if cfg.Mailer != nil {
		if err := checkBaseURL(cfg.BaseURL); err != nil {
			return nil, err
		}
	}
	if cfg.SingleTenant {
		if _, err := st.CreateOrg(ctx, DefaultOrg, "Default"); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, fmt.Errorf("create the default organization: %w", err)
		}
	}
	s := &Server{cfg: cfg, store: st, mux: http.NewServeMux(), log: cfg.Logger, limiters: map[int64]*rate.Limiter{},
		// Five sign-in requests a minute per address, three links per
		// e-mail address in ten minutes, ten link attempts a minute.
		loginByIP:    newKeyedLimiter(12*time.Second, 5),
		loginByEmail: newKeyedLimiter(200*time.Second, 3),
		verifyByIP:   newKeyedLimiter(6*time.Second, 10),
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	s.mux.HandleFunc("GET /v1/{org}/{set}/policy.json", s.servePolicy)
	s.mux.HandleFunc("GET /v1/{org}/{set}/policy.json.sig", s.serveSignature)
	s.mux.HandleFunc("POST /v1/{org}/{set}/report", s.receiveReport)

	s.mux.Handle("GET /{$}", panel.Handler())
	s.mux.Handle("GET /app.js", panel.Handler())
	s.mux.Handle("GET /style.css", panel.Handler())
	s.mux.Handle("GET /auth/verify", panel.Handler())
	s.mux.HandleFunc("POST /auth/login", s.login)
	s.mux.HandleFunc("POST /auth/verify", s.verify)

	admin := s.requireAccess
	s.mux.HandleFunc("POST /auth/logout", admin(s.logout))
	s.mux.HandleFunc("GET /api/me", admin(s.me))
	s.mux.HandleFunc("GET /api/orgs/{org}/members", admin(s.listMembers))
	s.mux.HandleFunc("POST /api/orgs/{org}/members", admin(s.invite))
	s.mux.HandleFunc("GET /api/orgs", admin(s.listOrgs))
	s.mux.HandleFunc("POST /api/orgs", admin(s.createOrg))
	s.mux.HandleFunc("GET /api/orgs/{org}/sets", admin(s.listSets))
	s.mux.HandleFunc("POST /api/orgs/{org}/sets", admin(s.createSet))
	s.mux.HandleFunc("GET /api/orgs/{org}/sets/{set}", admin(s.getSet))
	s.mux.HandleFunc("GET /api/orgs/{org}/sets/{set}/versions", admin(s.listVersions))
	s.mux.HandleFunc("POST /api/orgs/{org}/sets/{set}/versions", admin(s.createVersion))
	s.mux.HandleFunc("GET /api/orgs/{org}/sets/{set}/versions/{rev}", admin(s.getVersion))
	s.mux.HandleFunc("POST /api/orgs/{org}/sets/{set}/validate", admin(s.validate))
	s.mux.HandleFunc("POST /api/orgs/{org}/sets/{set}/preview", admin(s.preview))
	s.mux.HandleFunc("POST /api/orgs/{org}/sets/{set}/publish", admin(s.publish))
	s.mux.HandleFunc("GET /api/orgs/{org}/sets/{set}/publish/statement", admin(s.statement))
	s.mux.HandleFunc("GET /api/orgs/{org}/audit", admin(s.listAudit))
	s.mux.HandleFunc("GET /api/orgs/{org}/signing-keys", admin(s.listSigningKeys))
	s.mux.HandleFunc("POST /api/orgs/{org}/signing-keys", admin(s.addSigningKey))
	s.mux.HandleFunc("DELETE /api/orgs/{org}/signing-keys/{id}", admin(s.revokeSigningKey))
	s.mux.HandleFunc("GET /api/orgs/{org}/sets/{set}/publications", admin(s.publications))
	s.mux.HandleFunc("GET /api/orgs/{org}/sets/{set}/tokens", admin(s.listTokens))
	s.mux.HandleFunc("GET /api/orgs/{org}/sets/{set}/clusters", admin(s.listClusters))
	s.mux.HandleFunc("POST /api/orgs/{org}/sets/{set}/tokens", admin(s.createToken))
	s.mux.HandleFunc("DELETE /api/orgs/{org}/sets/{set}/tokens/{id}", admin(s.revokeToken))
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

// ---- public: policy.json ----

// servePolicy answers the pull of part 3 of #36: a bearer token names the
// set, the published version is the body, ETag is its hash, 304 on a
// matching If-None-Match.
func (s *Server) servePolicy(w http.ResponseWriter, r *http.Request) {
	acc, ok := s.pullAccess(w, r)
	if !ok {
		return
	}
	s.touch(r, acc)
	v, err := s.store.Published(r.Context(), acc.Set.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotPublished) {
			s.fail(w, http.StatusNotFound, "the rule set has no published version")
			return
		}
		s.internal(w, err)
		return
	}
	w.Header().Set("ETag", v.ETag)
	w.Header().Set("X-Policy-Revision", strconv.FormatInt(v.Revision, 10))
	if etagMatches(r.Header.Get("If-None-Match"), v.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(v.Content)))
	_, _ = w.Write(v.Content)
}

// pullAccess checks the pull token of a pull and that it belongs to the
// set of the path.
func (s *Server) pullAccess(w http.ResponseWriter, r *http.Request) (*store.Access, bool) {
	return s.tokenAccess(w, r, store.KindPull)
}

// tokenAccess checks a bearer token of the kind and that it belongs to the
// set of the path. Any token problem is 401 without detail; a token used
// against another set's path is 404, so a token discloses nothing about
// sets it does not own; a token of the other kind is 403.
func (s *Server) tokenAccess(w http.ResponseWriter, r *http.Request, kind string) (*store.Access, bool) {
	w.Header().Set("Cache-Control", "no-cache")
	value, ok := bearer(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pii-shield-rules"`)
		s.fail(w, http.StatusUnauthorized, "missing or malformed Authorization: Bearer <token>")
		return nil, false
	}
	acc, err := s.store.Authenticate(r.Context(), value)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrTokenRevoked) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="pii-shield-rules", error="invalid_token"`)
			s.fail(w, http.StatusUnauthorized, "invalid token")
			return nil, false
		}
		s.internal(w, err)
		return nil, false
	}
	if !s.limiter(acc.Token.ID).Allow() {
		w.Header().Set("Retry-After", "1")
		s.fail(w, http.StatusTooManyRequests, "too many pulls with this token")
		return nil, false
	}
	if acc.Org.Slug != r.PathValue("org") || acc.Set.Slug != r.PathValue("set") {
		s.fail(w, http.StatusNotFound, "no such rule set for this token")
		return nil, false
	}
	if acc.Token.Kind != kind {
		if kind == store.KindPull {
			s.fail(w, http.StatusForbidden, "this token sends stats reports; it cannot read rules")
		} else {
			s.fail(w, http.StatusForbidden, "this token reads rules; it cannot send reports")
		}
		return nil, false
	}
	return acc, true
}

// touch records the pull on the token: when and from where it was last
// used, which the Tokens tab shows. A failure only costs that record.
func (s *Server) touch(r *http.Request, acc *store.Access) {
	if err := s.store.TouchToken(r.Context(), acc.Token.ID, s.clientIP(r)); err != nil {
		s.log.Error("record the token's last use", "token", acc.Token.Prefix, "err", err)
	}
}

func (s *Server) limiter(tokenID int64) *rate.Limiter {
	s.limMu.Lock()
	defer s.limMu.Unlock()
	l, ok := s.limiters[tokenID]
	if !ok {
		l = rate.NewLimiter(rate.Limit(s.cfg.PolicyRate), 10)
		s.limiters[tokenID] = l
	}
	return l
}

// etagMatches implements If-None-Match for strong tags: "*", or any member
// of the comma-separated list, with a weak prefix ignored.
func etagMatches(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag {
			return true
		}
	}
	return false
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	v := strings.TrimSpace(h[7:])
	return v, v != ""
}

// ---- management API ----

type orgRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// listOrgs lists every organization for the admin, and the caller's own
// for a session.
func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	if p := principalOf(r); p.org != nil {
		s.json(w, http.StatusOK, map[string]any{"orgs": []store.Org{*p.org}})
		return
	}
	orgs, err := s.store.ListOrgs(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{"orgs": orgs})
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	if principalOf(r).user != nil {
		s.fail(w, http.StatusForbidden, "an account has one organization; the admin token creates others")
		return
	}
	var req orgRequest
	if !s.decode(w, r, &req) {
		return
	}
	org, err := s.store.CreateOrg(r.Context(), req.Slug, req.Name)
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "", org.ID, actOrgCreate, org.Slug, map[string]any{"name": org.Name})
	s.json(w, http.StatusCreated, org)
}

// org resolves the organization of the path. A session sees its own
// organization only; any other is not found, so a slug discloses nothing.
func (s *Server) org(w http.ResponseWriter, r *http.Request) (*store.Org, bool) {
	org, err := s.store.GetOrg(r.Context(), r.PathValue("org"))
	if err != nil {
		s.storeError(w, err)
		return nil, false
	}
	if p := principalOf(r); p.org != nil && p.org.ID != org.ID {
		s.fail(w, http.StatusNotFound, "not found")
		return nil, false
	}
	return org, true
}

func (s *Server) set(w http.ResponseWriter, r *http.Request) (*store.RuleSet, bool) {
	org, ok := s.org(w, r)
	if !ok {
		return nil, false
	}
	set, err := s.store.GetSet(r.Context(), org.ID, r.PathValue("set"))
	if err != nil {
		s.storeError(w, err)
		return nil, false
	}
	return set, true
}

func (s *Server) listSets(w http.ResponseWriter, r *http.Request) {
	org, ok := s.org(w, r)
	if !ok {
		return
	}
	sets, err := s.store.ListSets(r.Context(), org.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{"sets": sets})
}

func (s *Server) createSet(w http.ResponseWriter, r *http.Request) {
	org, ok := s.org(w, r)
	if !ok {
		return
	}
	var req orgRequest
	if !s.decode(w, r, &req) {
		return
	}
	set, err := s.store.CreateSet(r.Context(), org.ID, req.Slug, req.Name)
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.audit(r, "", org.ID, actSetCreate, set.Slug, nil)
	s.json(w, http.StatusCreated, set)
}

func (s *Server) getSet(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	versions, err := s.store.ListVersions(r.Context(), set.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	tokens, err := s.store.ListTokens(r.Context(), set.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{"set": set, "versions": versions, "tokens": tokens,
		"policyPath": "/v1/" + r.PathValue("org") + "/" + set.Slug + "/policy.json"})
}

func (s *Server) listVersions(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	versions, err := s.store.ListVersions(r.Context(), set.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{"versions": versions})
}

type versionRequest struct {
	Content json.RawMessage `json:"content"`
	Author  string          `json:"author"`
	Comment string          `json:"comment"`
}

// createVersion appends a version. The content is the rule set in the SDK
// init_config format; it is canonicalized and validated with the scanner's
// parser, so what the server refuses is exactly what a sidecar would
// refuse, and a 422 names the first problem.
func (s *Server) createVersion(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	var req versionRequest
	if !s.decode(w, r, &req) {
		return
	}
	if len(req.Content) == 0 {
		s.fail(w, http.StatusBadRequest, `"content" is required: the rule set as a JSON object`)
		return
	}
	v, err := s.store.CreateVersion(r.Context(), set.ID, authorOf(r, req.Author), req.Comment, func(rev int64) ([]byte, string, error) {
		doc, err := policy.Canonical(req.Content, rev)
		if err != nil {
			return nil, "", &validationError{err}
		}
		return doc.Content, doc.ETag, nil
	})
	if err != nil {
		var ve *validationError
		if errors.As(err, &ve) {
			s.fail(w, http.StatusUnprocessableEntity, "rule set rejected: "+ve.Error())
			return
		}
		s.storeError(w, err)
		return
	}
	s.audit(r, "", set.OrgID, actVersionCreate, set.Slug, map[string]any{"revision": v.Revision, "etag": v.ETag, "comment": v.Comment})
	s.json(w, http.StatusCreated, v)
}

type validationError struct{ error }

func (s *Server) getVersion(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	rev, err := strconv.ParseInt(r.PathValue("rev"), 10, 64)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "revision must be a number")
		return
	}
	v, err := s.store.GetVersion(r.Context(), set.ID, rev)
	if err != nil {
		s.storeError(w, err)
		return
	}
	// The file as a cluster receives it, as JSON inside the envelope: a
	// []byte would be base64 and useless to the panel.
	s.json(w, http.StatusOK, map[string]any{"version": v, "content": json.RawMessage(v.Content)})
}

type publishRequest struct {
	Revision int64  `json:"revision"`
	Author   string `json:"author"`
	// Publication, KeyID and Signature sign the publication: the number
	// from GET .../publish/statement, the id of a key registered with the
	// organization, and the base64 Ed25519 signature of the statement text.
	Publication int64  `json:"publication"`
	KeyID       string `json:"keyId"`
	Signature   string `json:"signature"`
}

// publish serves a revision. Once the organization has a signing key, a
// publication must be signed with one of its active keys: the server checks
// the signature against the statement it builds itself from the stored
// file, so it stores only signatures that a cluster will accept.
func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	var req publishRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.Revision <= 0 {
		s.fail(w, http.StatusBadRequest, `"revision" is required`)
		return
	}
	signed := req.Signature != "" || req.KeyID != ""
	if signed && (req.Signature == "" || req.KeyID == "" || req.Publication <= 0) {
		s.fail(w, http.StatusBadRequest, `a signed publish needs "publication", "keyId" and "signature" together`)
		return
	}
	var key ed25519.PublicKey
	if signed {
		k, err := s.store.ActiveSigningKey(r.Context(), set.OrgID, req.KeyID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				s.audit(r, "", set.OrgID, actPublishRefused, set.Slug, map[string]any{"revision": req.Revision, "keyId": req.KeyID, "reason": "no such active key"})
				s.fail(w, http.StatusUnprocessableEntity, "no active signing key "+req.KeyID+" in this organization")
				return
			}
			s.internal(w, err)
			return
		}
		if key, err = signing.ParsePublicKey(k.PublicKey); err != nil {
			s.internal(w, err)
			return
		}
	} else {
		has, err := s.store.HasSigningKeys(r.Context(), set.OrgID)
		if err != nil {
			s.internal(w, err)
			return
		}
		if has {
			s.audit(r, "", set.OrgID, actPublishRefused, set.Slug, map[string]any{"revision": req.Revision, "reason": "unsigned"})
			s.fail(w, http.StatusUnprocessableEntity, "this organization signs its publications: sign the statement from GET "+r.URL.Path+"/statement?revision=N and send publication, keyId and signature")
			return
		}
	}
	author := authorOf(r, req.Author)
	setPath := r.PathValue("org") + "/" + set.Slug
	pub, err := s.store.Publish(r.Context(), set.ID, store.PublishRequest{
		Revision: req.Revision, Author: author, Seq: req.Publication, KeyID: req.KeyID, Signature: req.Signature,
		Check: func(seq int64, v *store.Version) error {
			if !signed {
				return nil
			}
			return signing.Verify(key, signing.For(setPath, seq, v.Revision, v.Content), req.Signature)
		},
	})
	if err != nil {
		switch {
		case errors.Is(err, signing.ErrBadSignature):
			s.audit(r, "", set.OrgID, actPublishRefused, set.Slug, map[string]any{"revision": req.Revision, "keyId": req.KeyID, "reason": "bad signature"})
			s.fail(w, http.StatusUnprocessableEntity, "the signature does not verify with key "+req.KeyID+" for this statement")
		case errors.Is(err, store.ErrStale):
			s.fail(w, http.StatusConflict, err.Error())
		default:
			s.storeError(w, err)
		}
		return
	}
	s.log.Info("published", "org", r.PathValue("org"), "set", set.Slug, "revision", req.Revision, "publication", pub.Seq, "author", author, "key", req.KeyID)
	detail := map[string]any{"revision": pub.Revision, "publication": pub.Seq}
	if pub.KeyID != "" {
		detail["keyId"] = pub.KeyID
	}
	s.audit(r, "", set.OrgID, actPublish, set.Slug, detail)
	set, _ = s.store.GetSetByID(r.Context(), set.ID)
	s.json(w, http.StatusOK, set)
}

// statement answers what a publisher signs to publish a revision now: the
// statement with the next publication number, and its exact text.
func (s *Server) statement(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	rev, err := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
	if err != nil || rev <= 0 {
		s.fail(w, http.StatusBadRequest, "revision must be a positive number")
		return
	}
	v, err := s.store.GetVersion(r.Context(), set.ID, rev)
	if err != nil {
		s.storeError(w, err)
		return
	}
	seq, err := s.store.NextPublication(r.Context(), set.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	st := signing.For(r.PathValue("org")+"/"+set.Slug, seq, v.Revision, v.Content)
	s.json(w, http.StatusOK, map[string]any{"statement": st, "text": st.Text()})
}

func (s *Server) publications(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	hist, err := s.store.Publications(r.Context(), set.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{"publications": hist})
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	tokens, err := s.store.ListTokens(r.Context(), set.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{"tokens": tokens})
}

type tokenRequest struct {
	Name string `json:"name"`
	// Kind is "pull" (the default) or "report".
	Kind string `json:"kind"`
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	var req tokenRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.Name == "" {
		s.fail(w, http.StatusBadRequest, `"name" is required: which cluster or team holds the token`)
		return
	}
	tok, value, err := s.store.CreateToken(r.Context(), set.ID, req.Name, req.Kind)
	if errors.Is(err, store.ErrInvalidKind) {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	s.log.Info("token issued", "org", r.PathValue("org"), "set", set.Slug, "token", tok.Prefix, "name", req.Name)
	s.audit(r, "", set.OrgID, actTokenCreate, set.Slug, map[string]any{"name": tok.Name, "prefix": tok.Prefix, "kind": tok.Kind})
	note := "the value is shown once; put it whole, as 'Bearer " + store.TokenPrefix + "…', into the Secret named by remoteConfig.headerSecretRef"
	if tok.Kind == store.KindReport {
		note = "the value is shown once; put it whole, as 'Bearer " + store.ReportTokenPrefix + "…', into the Secret named by stats.headerSecretRef; it can only send reports"
	}
	s.json(w, http.StatusCreated, map[string]any{"token": tok, "value": value, "note": note})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "token id must be a number")
		return
	}
	if err := s.store.RevokeToken(r.Context(), set.ID, id); err != nil {
		s.storeError(w, err)
		return
	}
	s.log.Info("token revoked", "org", r.PathValue("org"), "set", set.Slug, "id", id)
	s.audit(r, "", set.OrgID, actTokenRevoke, set.Slug, map[string]any{"tokenId": id})
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers ----

func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return s.decodeLimit(w, r, v, maxBody)
}

func (s *Server) decodeLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			s.fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body larger than %d bytes", limit))
			return false
		}
		s.fail(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return false
	}
	return true
}

func (s *Server) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, status int, msg string) {
	s.json(w, status, map[string]string{"error": msg})
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "err", err)
	s.fail(w, http.StatusInternalServerError, "internal error")
}

func (s *Server) storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrExists):
		s.fail(w, http.StatusConflict, "already exists")
	case errors.Is(err, store.ErrInvalidSlug):
		s.fail(w, http.StatusBadRequest, err.Error())
	default:
		s.internal(w, err)
	}
}

// ListenAndServe runs the server on addr until ctx is done, then drains
// for up to five seconds.
func ListenAndServe(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
