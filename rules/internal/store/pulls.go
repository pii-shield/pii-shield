package store

import (
	"context"
	"time"
)

// Pull counts: how often each token fetched its set's policy.json, per UTC
// day, split into new files (200) and unchanged ones (304). A cluster
// pulls every few minutes, so a row per pull would swamp the activity log;
// one counter row per token and day says the same in little space. Rows
// older than PullRetention are dropped when a token starts a new day.

// PullRetention is how long daily pull counts are kept.
const PullRetention = 90 * 24 * time.Hour

const pullsSchema = `
CREATE TABLE IF NOT EXISTS pull_counts (
	token_id INTEGER NOT NULL REFERENCES tokens(id),
	day TEXT NOT NULL,
	pulls INTEGER NOT NULL DEFAULT 0,
	not_modified INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (token_id, day)
);
`

const dayLayout = "2006-01-02"

// CountPull adds one pull by the token today; notModified marks a 304.
func (s *Store) CountPull(ctx context.Context, tokenID int64, notModified bool) error {
	nm := 0
	if notModified {
		nm = 1
	}
	day := time.Now().UTC().Format(dayLayout)
	res, err := s.db.ExecContext(ctx, `UPDATE pull_counts SET pulls = pulls + 1, not_modified = not_modified + ? WHERE token_id = ? AND day = ?`, nm, tokenID, day)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	// The first pull of the day: a new row, and the old days go.
	_, err = s.db.ExecContext(ctx, `INSERT INTO pull_counts (token_id, day, pulls, not_modified) VALUES (?, ?, 1, ?)
		ON CONFLICT (token_id, day) DO UPDATE SET pulls = pull_counts.pulls + 1, not_modified = pull_counts.not_modified + excluded.not_modified`, tokenID, day, nm)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM pull_counts WHERE token_id = ? AND day < ?`, tokenID, time.Now().Add(-PullRetention).UTC().Format(dayLayout))
	return err
}

// PullDay is one token's pulls on one day.
type PullDay struct {
	TokenID     int64  `json:"tokenId"`
	Day         string `json:"day"`
	Pulls       int64  `json:"pulls"`
	NotModified int64  `json:"notModified"`
}

// Pulls returns the set's daily pull counts per token for the last days
// (today included), newest day first.
func (s *Store) Pulls(ctx context.Context, setID int64, days int) ([]PullDay, error) {
	since := time.Now().UTC().AddDate(0, 0, -(days - 1)).Format(dayLayout)
	rows, err := s.db.QueryContext(ctx, `SELECT p.token_id, p.day, p.pulls, p.not_modified FROM pull_counts p JOIN tokens t ON t.id = p.token_id
		WHERE t.set_id = ? AND p.day >= ? ORDER BY p.day DESC, p.token_id`, setID, since)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []PullDay{}
	for rows.Next() {
		var p PullDay
		if err := rows.Scan(&p.TokenID, &p.Day, &p.Pulls, &p.NotModified); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
