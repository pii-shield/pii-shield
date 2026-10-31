// Package store keeps the rule server's data in one SQLite file: an
// organization owns rule sets, a rule set owns immutable versions and
// read-only tokens, and points at the version it publishes. Rolling back is
// publishing an older version, never editing one; a trigger refuses any
// UPDATE on a version, so the invariant holds against bugs too.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite" // database/sql driver, pure Go
)

// Errors callers can test for.
var (
	ErrNotFound     = errors.New("not found")
	ErrExists       = errors.New("already exists")
	ErrInvalidSlug  = errors.New("slug must be 1-63 characters of a-z, 0-9 and '-', starting with a letter or digit")
	ErrNotPublished = errors.New("no published version")
	ErrTokenRevoked = errors.New("token revoked")
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// CheckSlug reports whether s can name an organization or a rule set.
func CheckSlug(s string) error {
	if !slugRe.MatchString(s) {
		return ErrInvalidSlug
	}
	return nil
}

// Org is an organization: the tenant that owns rule sets.
type Org struct {
	ID        int64     `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// RuleSet is a named set of rules with a history of versions.
type RuleSet struct {
	ID                int64     `json:"id"`
	OrgID             int64     `json:"orgId"`
	Slug              string    `json:"slug"`
	Name              string    `json:"name"`
	PublishedRevision int64     `json:"publishedRevision,omitempty"`
	LatestRevision    int64     `json:"latestRevision,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
}

// Version is one immutable revision of a rule set: the canonical file as a
// cluster receives it, its ETag, and who made it and why.
type Version struct {
	ID        int64     `json:"id"`
	SetID     int64     `json:"setId"`
	Revision  int64     `json:"revision"`
	Content   []byte    `json:"-"`
	ETag      string    `json:"etag"`
	Author    string    `json:"author,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// Token is a credential for one rule set: a pull token reads its
// policy.json, a report token sends its stats reports (Kind). The value is
// shown once at creation; only its hash is stored.
type Token struct {
	ID        int64      `json:"id"`
	SetID     int64      `json:"setId"`
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"createdAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	// LastUsedAt and LastUsedIP are the last pull with the token, recorded
	// at most once a minute.
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	LastUsedIP string     `json:"lastUsedIp,omitempty"`
}

// Publication is one entry of a set's publish history. Seq numbers the
// publications of a set from 1 and is the number a signature covers; KeyID
// and Signature are empty for an unsigned publication.
type Publication struct {
	Seq         int64     `json:"publication"`
	Revision    int64     `json:"revision"`
	Author      string    `json:"author,omitempty"`
	KeyID       string    `json:"keyId,omitempty"`
	Signature   string    `json:"signature,omitempty"`
	PublishedAt time.Time `json:"publishedAt"`
}

// Store is the SQLite-backed store.
type Store struct {
	db *sql.DB
}

// Open opens or creates the database at path and applies the schema.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite serializes writers anyway, and one connection
	// means a transaction never waits on the pool for a second one.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema + accountsSchema + signingSchema + auditSchema + reportsSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS orgs (
	id INTEGER PRIMARY KEY,
	slug TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_sets (
	id INTEGER PRIMARY KEY,
	org_id INTEGER NOT NULL REFERENCES orgs(id),
	slug TEXT NOT NULL,
	name TEXT NOT NULL,
	published_version_id INTEGER REFERENCES versions(id),
	created_at TEXT NOT NULL,
	UNIQUE(org_id, slug)
);
CREATE TABLE IF NOT EXISTS versions (
	id INTEGER PRIMARY KEY,
	set_id INTEGER NOT NULL REFERENCES rule_sets(id),
	revision INTEGER NOT NULL,
	content BLOB NOT NULL,
	etag TEXT NOT NULL,
	author TEXT NOT NULL DEFAULT '',
	comment TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	UNIQUE(set_id, revision)
);
CREATE TRIGGER IF NOT EXISTS versions_are_immutable
	BEFORE UPDATE ON versions
	BEGIN SELECT RAISE(ABORT, 'versions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS versions_are_kept
	BEFORE DELETE ON versions
	BEGIN SELECT RAISE(ABORT, 'versions are kept'); END;
CREATE TABLE IF NOT EXISTS tokens (
	id INTEGER PRIMARY KEY,
	set_id INTEGER NOT NULL REFERENCES rule_sets(id),
	name TEXT NOT NULL,
	kind TEXT NOT NULL DEFAULT 'pull',
	prefix TEXT NOT NULL,
	hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	revoked_at TEXT,
	last_used_at TEXT,
	last_used_ip TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS publications (
	id INTEGER PRIMARY KEY,
	set_id INTEGER NOT NULL REFERENCES rule_sets(id),
	seq INTEGER NOT NULL,
	version_id INTEGER NOT NULL REFERENCES versions(id),
	author TEXT NOT NULL DEFAULT '',
	key_id TEXT NOT NULL DEFAULT '',
	signature TEXT NOT NULL DEFAULT '',
	published_at TEXT NOT NULL,
	UNIQUE(set_id, seq)
);
`

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateOrg creates an organization.
func (s *Store) CreateOrg(ctx context.Context, slug, name string) (*Org, error) {
	if err := CheckSlug(slug); err != nil {
		return nil, err
	}
	if name == "" {
		name = slug
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO orgs (slug, name, created_at) VALUES (?, ?, ?)`, slug, name, now())
	if isUnique(err) {
		return nil, ErrExists
	}
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetOrgByID(ctx, id)
}

// GetOrg returns the organization with the slug.
func (s *Store) GetOrg(ctx context.Context, slug string) (*Org, error) {
	return s.scanOrg(s.db.QueryRowContext(ctx, `SELECT id, slug, name, created_at FROM orgs WHERE slug = ?`, slug))
}

// GetOrgByID returns the organization with the id.
func (s *Store) GetOrgByID(ctx context.Context, id int64) (*Org, error) {
	return s.scanOrg(s.db.QueryRowContext(ctx, `SELECT id, slug, name, created_at FROM orgs WHERE id = ?`, id))
}

// ListOrgs returns every organization.
func (s *Store) ListOrgs(ctx context.Context) ([]Org, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, slug, name, created_at FROM orgs ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Org
	for rows.Next() {
		var o Org
		var created string
		if err := rows.Scan(&o.ID, &o.Slug, &o.Name, &created); err != nil {
			return nil, err
		}
		o.CreatedAt = parseTime(created)
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) scanOrg(row *sql.Row) (*Org, error) {
	var o Org
	var created string
	if err := row.Scan(&o.ID, &o.Slug, &o.Name, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	o.CreatedAt = parseTime(created)
	return &o, nil
}

// CreateSet creates a rule set in the organization.
func (s *Store) CreateSet(ctx context.Context, orgID int64, slug, name string) (*RuleSet, error) {
	if err := CheckSlug(slug); err != nil {
		return nil, err
	}
	if name == "" {
		name = slug
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO rule_sets (org_id, slug, name, created_at) VALUES (?, ?, ?, ?)`, orgID, slug, name, now())
	if isUnique(err) {
		return nil, ErrExists
	}
	if err != nil {
		return nil, err
	}
	return s.GetSet(ctx, orgID, slug)
}

const setColumns = `rs.id, rs.org_id, rs.slug, rs.name,
	COALESCE((SELECT v.revision FROM versions v WHERE v.id = rs.published_version_id), 0),
	COALESCE((SELECT MAX(v.revision) FROM versions v WHERE v.set_id = rs.id), 0),
	rs.created_at`

// GetSet returns the rule set with the slug in the organization.
func (s *Store) GetSet(ctx context.Context, orgID int64, slug string) (*RuleSet, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+setColumns+` FROM rule_sets rs WHERE rs.org_id = ? AND rs.slug = ?`, orgID, slug)
	return scanSet(row)
}

// GetSetByID returns the rule set with the id.
func (s *Store) GetSetByID(ctx context.Context, id int64) (*RuleSet, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+setColumns+` FROM rule_sets rs WHERE rs.id = ?`, id)
	return scanSet(row)
}

type scanner interface{ Scan(dest ...any) error }

func scanSet(row scanner) (*RuleSet, error) {
	var rs RuleSet
	var created string
	if err := row.Scan(&rs.ID, &rs.OrgID, &rs.Slug, &rs.Name, &rs.PublishedRevision, &rs.LatestRevision, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rs.CreatedAt = parseTime(created)
	return &rs, nil
}

// ListSets returns the organization's rule sets.
func (s *Store) ListSets(ctx context.Context, orgID int64) ([]RuleSet, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+setColumns+` FROM rule_sets rs WHERE rs.org_id = ? ORDER BY rs.slug`, orgID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []RuleSet
	for rows.Next() {
		rs, err := scanSet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rs)
	}
	return out, rows.Err()
}

// CreateVersion appends a version to the set. canonical builds the file for
// the revision the version gets, which is the next number in the set; the
// store calls it inside the transaction so two concurrent appends cannot
// produce the same revision.
func (s *Store) CreateVersion(ctx context.Context, setID int64, author, comment string, canonical func(revision int64) (content []byte, etag string, err error)) (*Version, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM rule_sets WHERE id = ?`, setID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrNotFound
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) + 1 FROM versions WHERE set_id = ?`, setID).Scan(&revision); err != nil {
		return nil, err
	}
	content, etag, err := canonical(revision)
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO versions (set_id, revision, content, etag, author, comment, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		setID, revision, content, etag, author, comment, now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getVersion(ctx, `v.id = ?`, id)
}

const versionColumns = `v.id, v.set_id, v.revision, v.content, v.etag, v.author, v.comment, v.created_at`

func (s *Store) getVersion(ctx context.Context, where string, args ...any) (*Version, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+versionColumns+` FROM versions v WHERE `+where, args...)
	return scanVersion(row)
}

func scanVersion(row scanner) (*Version, error) {
	var v Version
	var created string
	if err := row.Scan(&v.ID, &v.SetID, &v.Revision, &v.Content, &v.ETag, &v.Author, &v.Comment, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	v.CreatedAt = parseTime(created)
	return &v, nil
}

// GetVersion returns the revision of the set.
func (s *Store) GetVersion(ctx context.Context, setID, revision int64) (*Version, error) {
	return s.getVersion(ctx, `v.set_id = ? AND v.revision = ?`, setID, revision)
}

// ListVersions returns the set's versions, newest first, without content.
func (s *Store) ListVersions(ctx context.Context, setID int64) ([]Version, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT v.id, v.set_id, v.revision, v.etag, v.author, v.comment, v.created_at FROM versions v WHERE v.set_id = ? ORDER BY v.revision DESC`, setID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Version
	for rows.Next() {
		var v Version
		var created string
		if err := rows.Scan(&v.ID, &v.SetID, &v.Revision, &v.ETag, &v.Author, &v.Comment, &created); err != nil {
			return nil, err
		}
		v.CreatedAt = parseTime(created)
		out = append(out, v)
	}
	return out, rows.Err()
}

// PublishRequest is one publication: the revision to serve and, for a
// signed one, the publication number the signature covers and the
// signature. Check runs inside the transaction with the number the
// publication gets and the version it serves, so a signature is checked
// against exactly what is stored and two concurrent publishes cannot both
// claim the same number.
type PublishRequest struct {
	Revision int64
	Author   string
	// Seq, when not zero, must be the number this publication gets;
	// otherwise the publish fails with ErrStale.
	Seq       int64
	KeyID     string
	Signature string
	Check     func(seq int64, v *Version) error
}

// ErrStale means the set was published by someone else since the caller
// read the next publication number; the caller signs again.
var ErrStale = errors.New("the set was published meanwhile; sign the new statement")

// Publish makes the revision the one the set serves. Publishing an older
// revision is the rollback; it is a new publication with a higher number.
func (s *Store) Publish(ctx context.Context, setID int64, req PublishRequest) (*Publication, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	v, err := scanVersion(tx.QueryRowContext(ctx, `SELECT `+versionColumns+` FROM versions v WHERE v.set_id = ? AND v.revision = ?`, setID, req.Revision))
	if err != nil {
		return nil, err
	}
	var seq int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) + 1 FROM publications WHERE set_id = ?`, setID).Scan(&seq); err != nil {
		return nil, err
	}
	if req.Seq != 0 && req.Seq != seq {
		return nil, ErrStale
	}
	if req.Check != nil {
		if err := req.Check(seq, v); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE rule_sets SET published_version_id = ? WHERE id = ?`, v.ID, setID); err != nil {
		return nil, err
	}
	at := now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO publications (set_id, seq, version_id, author, key_id, signature, published_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		setID, seq, v.ID, req.Author, req.KeyID, req.Signature, at); err != nil {
		if isUnique(err) {
			return nil, ErrStale
		}
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Publication{Seq: seq, Revision: v.Revision, Author: req.Author, KeyID: req.KeyID, Signature: req.Signature, PublishedAt: parseTime(at)}, nil
}

// NextPublication returns the number the set's next publication gets.
func (s *Store) NextPublication(ctx context.Context, setID int64) (int64, error) {
	var seq int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) + 1 FROM publications WHERE set_id = ?`, setID).Scan(&seq)
	return seq, err
}

// LatestPublication returns the set's newest publication, the one it
// serves, or ErrNotPublished.
func (s *Store) LatestPublication(ctx context.Context, setID int64) (*Publication, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+publicationColumns+` FROM publications p JOIN versions v ON v.id = p.version_id WHERE p.set_id = ? ORDER BY p.seq DESC LIMIT 1`, setID)
	p, err := scanPublication(row)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotPublished
	}
	return p, err
}

const publicationColumns = `p.seq, v.revision, p.author, p.key_id, p.signature, p.published_at`

func scanPublication(row scanner) (*Publication, error) {
	var p Publication
	var at string
	if err := row.Scan(&p.Seq, &p.Revision, &p.Author, &p.KeyID, &p.Signature, &at); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.PublishedAt = parseTime(at)
	return &p, nil
}

// Published returns the set's published version, or ErrNotPublished.
func (s *Store) Published(ctx context.Context, setID int64) (*Version, error) {
	v, err := s.getVersion(ctx, `v.id = (SELECT published_version_id FROM rule_sets WHERE id = ?)`, setID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotPublished
	}
	return v, err
}

// Publications returns the set's publish history, newest first.
func (s *Store) Publications(ctx context.Context, setID int64) ([]Publication, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+publicationColumns+` FROM publications p JOIN versions v ON v.id = p.version_id WHERE p.set_id = ? ORDER BY p.seq DESC`, setID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Publication
	for rows.Next() {
		p, err := scanPublication(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// Token kinds. A pull token reads the set's policy.json and its signature;
// a report token only sends stats reports for the set. Neither can do the
// other's job, so the credential a cluster keeps for reports can never read
// rules, and the one that reads rules can never write.
const (
	KindPull   = "pull"
	KindReport = "report"
)

// TokenPrefix starts every pull token value and ReportTokenPrefix every
// report token value, so a leaked one is recognizable and its kind visible.
const (
	TokenPrefix       = "psr_"
	ReportTokenPrefix = "pss_"
)

// ErrInvalidKind is returned for a token kind other than pull or report.
var ErrInvalidKind = errors.New(`kind must be "pull" or "report"`)

// CreateToken issues a token of the kind for the set and returns its
// value, which is never stored or shown again.
func (s *Store) CreateToken(ctx context.Context, setID int64, name, kind string) (*Token, string, error) {
	prefixOf := map[string]string{KindPull: TokenPrefix, KindReport: ReportTokenPrefix}
	if kind == "" {
		kind = KindPull
	}
	tp, ok := prefixOf[kind]
	if !ok {
		return nil, "", ErrInvalidKind
	}
	if _, err := s.GetSetByID(ctx, setID); err != nil {
		return nil, "", err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	value := tp + hex.EncodeToString(raw)
	prefix := value[:len(tp)+8]
	res, err := s.db.ExecContext(ctx, `INSERT INTO tokens (set_id, name, kind, prefix, hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		setID, name, kind, prefix, HashToken(value), now())
	if err != nil {
		return nil, "", err
	}
	id, _ := res.LastInsertId()
	t, err := s.getToken(ctx, id)
	return t, value, err
}

// HashToken returns the stored form of a token value.
func HashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

const tokenColumns = `id, set_id, name, kind, prefix, created_at, revoked_at, last_used_at, last_used_ip`

func scanToken(row scanner) (*Token, error) {
	var t Token
	var created string
	var revoked, used sql.NullString
	if err := row.Scan(&t.ID, &t.SetID, &t.Name, &t.Kind, &t.Prefix, &created, &revoked, &used, &t.LastUsedIP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt = parseTime(created)
	if revoked.Valid {
		at := parseTime(revoked.String)
		t.RevokedAt = &at
	}
	if used.Valid {
		at := parseTime(used.String)
		t.LastUsedAt = &at
	}
	return &t, nil
}

func (s *Store) getToken(ctx context.Context, id int64) (*Token, error) {
	return scanToken(s.db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE id = ?`, id))
}

// ListTokens returns the set's tokens, revoked ones included.
func (s *Store) ListTokens(ctx context.Context, setID int64) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE set_id = ? ORDER BY id`, setID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// RevokeToken revokes the token of the set; revoking twice is not an error.
func (s *Store) RevokeToken(ctx context.Context, setID, tokenID int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND set_id = ?`, now(), tokenID, setID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Access is what a token grants: the set it belongs to and its organization.
type Access struct {
	Token *Token
	Set   *RuleSet
	Org   *Org
}

// Authenticate resolves a token value. A revoked token is ErrTokenRevoked,
// an unknown one ErrNotFound; the caller answers both with 401.
func (s *Store) Authenticate(ctx context.Context, value string) (*Access, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE hash = ?`, HashToken(value))
	t, err := scanToken(row)
	if err != nil {
		return nil, err
	}
	if t.RevokedAt != nil {
		return nil, ErrTokenRevoked
	}
	set, err := s.GetSetByID(ctx, t.SetID)
	if err != nil {
		return nil, err
	}
	org, err := s.GetOrgByID(ctx, set.OrgID)
	if err != nil {
		return nil, err
	}
	return &Access{Token: t, Set: set, Org: org}, nil
}
