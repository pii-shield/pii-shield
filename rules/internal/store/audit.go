package store

import (
	"context"
	"encoding/json"
	"time"
)

// Event is one entry of an organization's audit log: who did what to which
// object, when and from where. The log is append-only; triggers refuse an
// UPDATE or a DELETE, so it holds against bugs too. Pulls of policy.json
// are not events (a cluster pulls every few minutes); a token keeps the time
// and address of its last use instead.
type Event struct {
	ID     int64          `json:"id"`
	OrgID  int64          `json:"orgId"`
	At     time.Time      `json:"at"`
	Actor  string         `json:"actor"`
	Action string         `json:"action"`
	Target string         `json:"target,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`
	IP     string         `json:"ip,omitempty"`
}

const auditSchema = `
CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY,
	org_id INTEGER NOT NULL REFERENCES orgs(id),
	at TEXT NOT NULL,
	actor TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '',
	ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_events_org ON audit_events(org_id, id);
CREATE TRIGGER IF NOT EXISTS audit_events_are_immutable
	BEFORE UPDATE ON audit_events
	BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_are_kept
	BEFORE DELETE ON audit_events
	BEGIN SELECT RAISE(ABORT, 'audit events are kept'); END;
`

// Record appends an event.
func (s *Store) Record(ctx context.Context, e Event) error {
	detail := ""
	if len(e.Detail) > 0 {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return err
		}
		detail = string(b)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events (org_id, at, actor, action, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.OrgID, now(), e.Actor, e.Action, e.Target, detail, e.IP)
	return err
}

// Events returns up to limit of the organization's events, newest first,
// with ids below before (zero: from the newest).
func (s *Store) Events(ctx context.Context, orgID, before int64, limit int) ([]Event, error) {
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, org_id, at, actor, action, target, detail, ip FROM audit_events WHERE org_id = ? AND id < ? ORDER BY id DESC LIMIT ?`, orgID, before, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Event{}
	for rows.Next() {
		var e Event
		var at, detail string
		if err := rows.Scan(&e.ID, &e.OrgID, &at, &e.Actor, &e.Action, &e.Target, &detail, &e.IP); err != nil {
			return nil, err
		}
		e.At = parseTime(at)
		if detail != "" {
			_ = json.Unmarshal([]byte(detail), &e.Detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// tokenTouchEvery bounds how often a pull writes the token's last use.
const tokenTouchEvery = time.Minute

// TouchToken records a pull with the token: the time and the client
// address, at most once a minute per token, so a busy cluster does not turn
// every pull into a write.
func (s *Store) TouchToken(ctx context.Context, tokenID int64, ip string) error {
	// A fixed-width layout, so the comparison in SQL is a string comparison.
	const layout = "2006-01-02T15:04:05.000000000Z"
	t := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`,
		t.Format(layout), ip, tokenID, t.Add(-tokenTouchEvery).Format(layout))
	return err
}
