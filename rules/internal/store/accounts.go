package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// Accounts: a user belongs to one organization and signs in with a magic
// link sent to the e-mail address; the link and the session that follows
// are random values stored hashed, like the read-only tokens.

// ErrInvalidEmail is returned for an address that cannot receive mail.
var ErrInvalidEmail = errors.New("not an e-mail address")

// ErrExpired is returned for a magic link or a session past its time or
// already used.
var ErrExpired = errors.New("expired or already used")

// User is a panel account: one e-mail address in one organization.
type User struct {
	ID        int64      `json:"id"`
	OrgID     int64      `json:"orgId"`
	Email     string     `json:"email"`
	InvitedBy string     `json:"invitedBy,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	LastLogin *time.Time `json:"lastLogin,omitempty"`
}

// Session is a signed-in browser.
type Session struct {
	ID        int64
	User      *User
	Org       *Org
	ExpiresAt time.Time
}

const accountsSchema = `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	org_id INTEGER NOT NULL REFERENCES orgs(id),
	email TEXT NOT NULL UNIQUE,
	invited_by TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	last_login TEXT
);
CREATE TABLE IF NOT EXISTS logins (
	id INTEGER PRIMARY KEY,
	email TEXT NOT NULL,
	hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id),
	hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);
`

// NormalizeEmail lowercases and trims an address and refuses one that is
// not a bare address (no display name, one @).
func NormalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || len(email) > 254 {
		return "", ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || addr.Name != "" || !strings.Contains(email, "@") {
		return "", ErrInvalidEmail
	}
	return email, nil
}

// CreateUser adds an account to an organization. An address with an
// account anywhere is ErrExists: one organization per account.
func (s *Store) CreateUser(ctx context.Context, orgID int64, email, invitedBy string) (*User, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	if _, err := s.GetOrgByID(ctx, orgID); err != nil {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (org_id, email, invited_by, created_at) VALUES (?, ?, ?, ?)`, orgID, email, invitedBy, now())
	if isUnique(err) {
		return nil, ErrExists
	}
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetUserByID(ctx, id)
}

// Signup creates an organization for a new address and its first account,
// in one transaction. The organization's slug is derived from the address
// and made unique with a random suffix when taken.
func (s *Store) Signup(ctx context.Context, email string) (*User, *Org, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, nil, err
	}
	base := slugFromEmail(email)
	for attempt := 0; attempt < 5; attempt++ {
		slug := base
		if attempt > 0 {
			var b [2]byte
			if _, err := rand.Read(b[:]); err != nil {
				return nil, nil, err
			}
			slug = base[:min(len(base), 58)] + "-" + hex.EncodeToString(b[:])
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, nil, err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO orgs (slug, name, created_at) VALUES (?, ?, ?)`, slug, email, now())
		if isUnique(err) {
			_ = tx.Rollback()
			continue
		}
		if err != nil {
			_ = tx.Rollback()
			return nil, nil, err
		}
		orgID, _ := res.LastInsertId()
		res, err = tx.ExecContext(ctx, `INSERT INTO users (org_id, email, created_at) VALUES (?, ?, ?)`, orgID, email, now())
		if isUnique(err) {
			_ = tx.Rollback()
			return nil, nil, ErrExists
		}
		if err != nil {
			_ = tx.Rollback()
			return nil, nil, err
		}
		userID, _ := res.LastInsertId()
		if err := tx.Commit(); err != nil {
			return nil, nil, err
		}
		u, err := s.GetUserByID(ctx, userID)
		if err != nil {
			return nil, nil, err
		}
		org, err := s.GetOrgByID(ctx, orgID)
		return u, org, err
	}
	return nil, nil, fmt.Errorf("could not find a free slug for %s", base)
}

// slugFromEmail turns the local part of an address into a slug: lowercase
// letters, digits and dashes, starting with one of the first two.
func slugFromEmail(email string) string {
	local := email[:strings.IndexByte(email, '@')]
	var b strings.Builder
	for _, r := range local {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	slug := strings.TrimRight(b.String(), "-")
	if len(slug) > 40 {
		slug = strings.TrimRight(slug[:40], "-")
	}
	if slug == "" {
		slug = "org"
	}
	return slug
}

const userColumns = `id, org_id, email, invited_by, created_at, last_login`

func scanUser(row scanner) (*User, error) {
	var u User
	var created string
	var last *string
	if err := row.Scan(&u.ID, &u.OrgID, &u.Email, &u.InvitedBy, &created, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.CreatedAt = parseTime(created)
	if last != nil {
		t := parseTime(*last)
		u.LastLogin = &t
	}
	return &u, nil
}

// GetUserByID returns one account.
func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// GetUserByEmail returns the account of an address, normalized first.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE email = ?`, email))
}

// ListUsers returns the accounts of an organization, oldest first.
func (s *Store) ListUsers(ctx context.Context, orgID int64) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users WHERE org_id = ? ORDER BY id`, orgID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// randomValue returns a fresh secret: 32 random bytes as hex.
func randomValue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// CreateLogin records a magic link for the address and returns its value,
// which goes into the mail and is never stored in clear. The address need
// not have an account yet: whether it may sign up is decided when the
// link is used.
func (s *Store) CreateLogin(ctx context.Context, email string, ttl time.Duration) (string, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	value, err := randomValue()
	if err != nil {
		return "", err
	}
	t := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO logins (email, hash, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		email, HashToken(value), t.Format(time.RFC3339Nano), t.Add(ttl).Format(time.RFC3339Nano))
	return value, err
}

// ConsumeLogin uses a magic link once and returns its address. A link
// that is unknown is ErrNotFound; one used or past its time is ErrExpired.
func (s *Store) ConsumeLogin(ctx context.Context, value string) (string, error) {
	nowS := now()
	res, err := s.db.ExecContext(ctx, `UPDATE logins SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ?`, nowS, HashToken(value), nowS)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		var email string
		err := s.db.QueryRowContext(ctx, `SELECT email FROM logins WHERE hash = ?`, HashToken(value)).Scan(&email)
		return email, err
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logins WHERE hash = ?`, HashToken(value)).Scan(&exists); err != nil {
		return "", err
	}
	if exists == 0 {
		return "", ErrNotFound
	}
	return "", ErrExpired
}

// CreateSession signs a user in and returns the session value for the
// cookie. Expired sessions and links are swept on the way.
func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration) (string, error) {
	value, err := randomValue()
	if err != nil {
		return "", err
	}
	t := time.Now().UTC()
	nowS := t.Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (user_id, hash, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		userID, HashToken(value), nowS, t.Add(ttl).Format(time.RFC3339Nano)); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET last_login = ? WHERE id = ?`, nowS, userID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, nowS); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM logins WHERE expires_at <= ?`, nowS); err != nil {
		return "", err
	}
	return value, tx.Commit()
}

// GetSession resolves a cookie value to the signed-in user and their
// organization; an unknown or expired session is ErrNotFound.
func (s *Store) GetSession(ctx context.Context, value string) (*Session, error) {
	var sess Session
	var userID int64
	var expires string
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, expires_at FROM sessions WHERE hash = ? AND expires_at > ?`, HashToken(value), now()).
		Scan(&sess.ID, &userID, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	sess.ExpiresAt = parseTime(expires)
	if sess.User, err = s.GetUserByID(ctx, userID); err != nil {
		return nil, err
	}
	if sess.Org, err = s.GetOrgByID(ctx, sess.User.OrgID); err != nil {
		return nil, err
	}
	return &sess, nil
}

// DeleteSession signs a session out; an unknown value is not an error.
func (s *Store) DeleteSession(ctx context.Context, value string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE hash = ?`, HashToken(value))
	return err
}
