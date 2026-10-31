package store

import (
	"context"
	"encoding/json"
	"time"
)

// Report is one stats report a cluster's operator sent for a set: counters
// only, over the window From to To (the schema the operator writes is
// pii-shield-stats-v1, operator/internal/stats).
type Report struct {
	ID            int64            `json:"id"`
	SetID         int64            `json:"setId"`
	TokenID       int64            `json:"tokenId"`
	Cluster       string           `json:"cluster,omitempty"`
	Policy        string           `json:"policy"`
	ReceivedAt    time.Time        `json:"receivedAt"`
	From          time.Time        `json:"from"`
	To            time.Time        `json:"to"`
	Mode          string           `json:"mode"`
	PodsReporting int              `json:"podsReporting"`
	PodsTotal     int              `json:"podsTotal"`
	Revisions     map[string]int   `json:"revisions"`
	RemoteRev     string           `json:"remoteRevision,omitempty"`
	RemotePub     int64            `json:"remotePublication,omitempty"`
	RemoteSigner  string           `json:"remoteSignedBy,omitempty"`
	Lines         int64            `json:"lines"`
	Errors        int64            `json:"errors"`
	Redactions    map[string]int64 `json:"redactions"`
	AuditFindings map[string]int64 `json:"auditFindings,omitempty"`
}

// ReportRetention is how long reports are kept; older ones are dropped
// when a new one arrives for the set.
const ReportRetention = 90 * 24 * time.Hour

const reportsSchema = `
CREATE TABLE IF NOT EXISTS reports (
	id INTEGER PRIMARY KEY,
	set_id INTEGER NOT NULL REFERENCES rule_sets(id),
	token_id INTEGER NOT NULL REFERENCES tokens(id),
	cluster TEXT NOT NULL DEFAULT '',
	policy TEXT NOT NULL,
	received_at TEXT NOT NULL,
	window_from TEXT NOT NULL,
	window_to TEXT NOT NULL,
	mode TEXT NOT NULL,
	pods_reporting INTEGER NOT NULL,
	pods_total INTEGER NOT NULL,
	revisions TEXT NOT NULL,
	remote_revision TEXT NOT NULL DEFAULT '',
	remote_publication INTEGER NOT NULL DEFAULT 0,
	remote_signed_by TEXT NOT NULL DEFAULT '',
	lines INTEGER NOT NULL,
	errors INTEGER NOT NULL,
	redactions TEXT NOT NULL,
	audit_findings TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS reports_set ON reports(set_id, received_at);
`

// AddReport stores a report and drops the set's reports older than
// ReportRetention.
func (s *Store) AddReport(ctx context.Context, r Report) error {
	revs, _ := json.Marshal(r.Revisions)
	reds, _ := json.Marshal(r.Redactions)
	finds := ""
	if len(r.AuditFindings) > 0 {
		b, _ := json.Marshal(r.AuditFindings)
		finds = string(b)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO reports (set_id, token_id, cluster, policy, received_at, window_from, window_to, mode,
		pods_reporting, pods_total, revisions, remote_revision, remote_publication, remote_signed_by, lines, errors, redactions, audit_findings)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.SetID, r.TokenID, r.Cluster, r.Policy, now(), r.From.UTC().Format(time.RFC3339Nano), r.To.UTC().Format(time.RFC3339Nano), r.Mode,
		r.PodsReporting, r.PodsTotal, string(revs), r.RemoteRev, r.RemotePub, r.RemoteSigner, r.Lines, r.Errors, string(reds), finds); err != nil {
		return err
	}
	cutoff := time.Now().Add(-ReportRetention).UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `DELETE FROM reports WHERE set_id = ? AND received_at < ?`, r.SetID, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// ClusterSummary is what the panel shows per cluster: the latest report,
// and the sums of the reports received since a moment.
type ClusterSummary struct {
	TokenID       int64            `json:"tokenId"`
	TokenName     string           `json:"tokenName"`
	Cluster       string           `json:"cluster,omitempty"`
	Policy        string           `json:"policy"`
	Latest        Report           `json:"latest"`
	Reports       int              `json:"reports"`
	Lines         int64            `json:"lines"`
	Errors        int64            `json:"errors"`
	Redactions    map[string]int64 `json:"redactions"`
	AuditFindings map[string]int64 `json:"auditFindings,omitempty"`
}

// Clusters summarizes the set's reports received since the moment, one
// entry per token, cluster name and policy, newest report first.
func (s *Store) Clusters(ctx context.Context, setID int64, since time.Time) ([]ClusterSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, r.set_id, r.token_id, r.cluster, r.policy, r.received_at, r.window_from, r.window_to, r.mode,
		r.pods_reporting, r.pods_total, r.revisions, r.remote_revision, r.remote_publication, r.remote_signed_by, r.lines, r.errors, r.redactions, r.audit_findings, t.name
		FROM reports r JOIN tokens t ON t.id = r.token_id
		WHERE r.set_id = ? AND r.received_at >= ? ORDER BY r.id DESC`, setID, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	type key struct {
		token           int64
		cluster, policy string
	}
	index := map[key]int{}
	out := []ClusterSummary{}
	for rows.Next() {
		var r Report
		var received, from, to, revs, reds, finds, tokenName string
		if err := rows.Scan(&r.ID, &r.SetID, &r.TokenID, &r.Cluster, &r.Policy, &received, &from, &to, &r.Mode,
			&r.PodsReporting, &r.PodsTotal, &revs, &r.RemoteRev, &r.RemotePub, &r.RemoteSigner, &r.Lines, &r.Errors, &reds, &finds, &tokenName); err != nil {
			return nil, err
		}
		r.ReceivedAt, r.From, r.To = parseTime(received), parseTime(from), parseTime(to)
		_ = json.Unmarshal([]byte(revs), &r.Revisions)
		_ = json.Unmarshal([]byte(reds), &r.Redactions)
		if finds != "" {
			_ = json.Unmarshal([]byte(finds), &r.AuditFindings)
		}
		k := key{r.TokenID, r.Cluster, r.Policy}
		i, ok := index[k]
		if !ok {
			i = len(out)
			index[k] = i
			out = append(out, ClusterSummary{TokenID: r.TokenID, TokenName: tokenName, Cluster: r.Cluster, Policy: r.Policy, Latest: r,
				Redactions: map[string]int64{}})
		}
		c := &out[i]
		c.Reports++
		c.Lines += r.Lines
		c.Errors += r.Errors
		for t, n := range r.Redactions {
			c.Redactions[t] += n
		}
		for t, n := range r.AuditFindings {
			if c.AuditFindings == nil {
				c.AuditFindings = map[string]int64{}
			}
			c.AuditFindings[t] += n
		}
	}
	return out, rows.Err()
}
