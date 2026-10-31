package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SigningKey is the public half of a publisher's key, registered with the
// organization. The private half never reaches the server.
type SigningKey struct {
	ID        int64      `json:"id"`
	OrgID     int64      `json:"orgId"`
	KeyID     string     `json:"keyId"`
	Name      string     `json:"name"`
	PublicKey string     `json:"publicKey"`
	CreatedBy string     `json:"createdBy,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}

const signingSchema = `
CREATE TABLE IF NOT EXISTS signing_keys (
	id INTEGER PRIMARY KEY,
	org_id INTEGER NOT NULL REFERENCES orgs(id),
	key_id TEXT NOT NULL,
	name TEXT NOT NULL,
	public_key TEXT NOT NULL,
	created_by TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	revoked_at TEXT,
	UNIQUE(org_id, key_id)
);
`

const signingKeyColumns = `id, org_id, key_id, name, public_key, created_by, created_at, revoked_at`

func scanSigningKey(row scanner) (*SigningKey, error) {
	var k SigningKey
	var created string
	var revoked sql.NullString
	if err := row.Scan(&k.ID, &k.OrgID, &k.KeyID, &k.Name, &k.PublicKey, &k.CreatedBy, &created, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	k.CreatedAt = parseTime(created)
	if revoked.Valid {
		at := parseTime(revoked.String)
		k.RevokedAt = &at
	}
	return &k, nil
}

// AddSigningKey registers a public key with the organization. keyID and
// publicKey come from the signing package; the same key twice is ErrExists.
func (s *Store) AddSigningKey(ctx context.Context, orgID int64, keyID, name, publicKey, createdBy string) (*SigningKey, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO signing_keys (org_id, key_id, name, public_key, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
		orgID, keyID, name, publicKey, createdBy, now()).Scan(&id)
	if isUnique(err) {
		return nil, ErrExists
	}
	if err != nil {
		return nil, err
	}
	return scanSigningKey(s.db.QueryRowContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys WHERE id = ?`, id))
}

// ListSigningKeys returns the organization's keys, revoked ones included.
func (s *Store) ListSigningKeys(ctx context.Context, orgID int64) ([]SigningKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys WHERE org_id = ? ORDER BY id`, orgID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// ActiveSigningKey returns the organization's key with the id if it is not
// revoked, or ErrNotFound.
func (s *Store) ActiveSigningKey(ctx context.Context, orgID int64, keyID string) (*SigningKey, error) {
	return scanSigningKey(s.db.QueryRowContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys WHERE org_id = ? AND key_id = ? AND revoked_at IS NULL`, orgID, keyID))
}

// HasSigningKeys reports whether the organization has an active key. Once
// it has, the server refuses an unsigned publication.
func (s *Store) HasSigningKeys(ctx context.Context, orgID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM signing_keys WHERE org_id = ? AND revoked_at IS NULL`, orgID).Scan(&n)
	return n > 0, err
}

// RevokeSigningKey revokes the organization's key; publications it signed
// keep their signatures, and clusters decide whether they still trust it.
func (s *Store) RevokeSigningKey(ctx context.Context, orgID, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE signing_keys SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND org_id = ?`, now(), id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
