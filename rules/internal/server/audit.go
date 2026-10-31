package server

import (
	"net/http"
	"strconv"

	"github.com/pii-shield/pii-shield/rules/internal/store"
)

// Audit actions. They name what changed, never a secret: a token's value,
// a session or a magic link never reaches the log, only a token's prefix.
const (
	actOrgCreate      = "org.create"
	actOrgSignup      = "org.signup"
	actSignIn         = "signin"
	actSignOut        = "signout"
	actMemberInvite   = "member.invite"
	actSetCreate      = "set.create"
	actVersionCreate  = "version.create"
	actPublish        = "publish"
	actPublishRefused = "publish.refused"
	actTokenCreate    = "token.create"
	actTokenRevoke    = "token.revoke"
	actKeyAdd         = "key.add"
	actKeyRevoke      = "key.revoke"
)

// actorOf names who a request runs as in the audit log.
func actorOf(r *http.Request) string {
	return principalOf(r).actor()
}

// actor names the principal in the audit and access logs.
func (p *principal) actor() string {
	switch {
	case p.user != nil:
		return p.user.Email
	case p.admin:
		return "admin token"
	case p.open:
		return "single-tenant, no sign-in"
	}
	return ""
}

// audit appends an event to the organization's log. actor empty means the
// caller of the request. A failure to record is logged and does not undo
// the change, which has already been made.
func (s *Server) audit(r *http.Request, actor string, orgID int64, action, target string, detail map[string]any) {
	if actor == "" {
		actor = actorOf(r)
	}
	err := s.store.Record(r.Context(), store.Event{OrgID: orgID, Actor: actor, Action: action, Target: target, Detail: detail, IP: s.clientIP(r)})
	if err != nil {
		s.log.Error("audit event not recorded", "action", action, "org", orgID, "err", err)
	}
}

// maxAuditPage bounds one page of the audit log.
const maxAuditPage = 500

// listAudit answers GET /api/orgs/{org}/audit: the organization's events,
// newest first, a page of ?limit= (default 100, at most 500) below the id
// ?before=; the answer's "next" is the before of the following page.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	org, ok := s.org(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			s.fail(w, http.StatusBadRequest, "limit must be a positive number")
			return
		}
		limit = min(n, maxAuditPage)
	}
	var before int64
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			s.fail(w, http.StatusBadRequest, "before must be a positive event id")
			return
		}
		before = n
	}
	events, err := s.store.Events(r.Context(), org.ID, before, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := map[string]any{"events": events}
	if len(events) == limit {
		out["next"] = events[len(events)-1].ID
	}
	s.json(w, http.StatusOK, out)
}
