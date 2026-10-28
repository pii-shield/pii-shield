package store

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func canon(body string) func(int64) ([]byte, string, error) {
	return func(rev int64) ([]byte, string, error) {
		c := strings.Replace(body, "REV", strconv.FormatInt(rev, 10), 1)
		return []byte(c), `"etag-` + c + `"`, nil
	}
}

func TestOrgsAndSets(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	org, err := s.CreateOrg(ctx, "acme", "ACME")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrg(ctx, "acme", "again"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate org: %v", err)
	}
	for _, bad := range []string{"", "Acme", "-a", "a b", strings.Repeat("a", 64)} {
		if _, err := s.CreateOrg(ctx, bad, ""); !errors.Is(err, ErrInvalidSlug) {
			t.Errorf("slug %q: %v", bad, err)
		}
	}
	set, err := s.CreateSet(ctx, org.ID, "payments", "")
	if err != nil {
		t.Fatal(err)
	}
	if set.Name != "payments" || set.PublishedRevision != 0 || set.LatestRevision != 0 {
		t.Errorf("new set = %+v", set)
	}
	if _, err := s.CreateSet(ctx, org.ID, "payments", ""); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate set: %v", err)
	}
	other, _ := s.CreateOrg(ctx, "other", "")
	if _, err := s.CreateSet(ctx, other.ID, "payments", ""); err != nil {
		t.Errorf("the same slug in another org must work: %v", err)
	}
	sets, _ := s.ListSets(ctx, org.ID)
	if len(sets) != 1 || sets[0].Slug != "payments" {
		t.Errorf("ListSets = %+v", sets)
	}
	if _, err := s.GetSet(ctx, org.ID, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing set: %v", err)
	}
}

func TestVersionsAreImmutableAndPublishRollsBack(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	org, _ := s.CreateOrg(ctx, "acme", "")
	set, _ := s.CreateSet(ctx, org.ID, "payments", "")

	if _, err := s.Published(ctx, set.ID); !errors.Is(err, ErrNotPublished) {
		t.Errorf("a new set has nothing published: %v", err)
	}
	v1, err := s.CreateVersion(ctx, set.ID, "alice", "first", canon(`{"revision":"REV","a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.CreateVersion(ctx, set.ID, "bob", "second", canon(`{"revision":"REV","a":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if v1.Revision != 1 || v2.Revision != 2 || string(v2.Content) != `{"revision":"2","a":2}` {
		t.Errorf("revisions = %d, %d, content %s", v1.Revision, v2.Revision, v2.Content)
	}
	if _, err := s.CreateVersion(ctx, 999, "", "", canon(`{}`)); !errors.Is(err, ErrNotFound) {
		t.Errorf("version for a missing set: %v", err)
	}
	if _, err := s.CreateVersion(ctx, set.ID, "", "", func(int64) ([]byte, string, error) { return nil, "", errors.New("bad") }); err == nil || err.Error() != "bad" {
		t.Errorf("a rejected file must not create a version: %v", err)
	}
	if got, _ := s.GetSetByID(ctx, set.ID); got.LatestRevision != 2 {
		t.Errorf("latest revision = %d after a rejected file", got.LatestRevision)
	}

	// Immutable: the trigger refuses an UPDATE even from raw SQL.
	if _, err := s.db.ExecContext(ctx, `UPDATE versions SET content = 'x' WHERE id = ?`, v1.ID); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Errorf("UPDATE on a version must be refused by the trigger, got %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM versions WHERE id = ?`, v1.ID); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Errorf("DELETE on a version must be refused by the trigger, got %v", err)
	}

	if err := s.Publish(ctx, set.ID, 2, "alice"); err != nil {
		t.Fatal(err)
	}
	pub, _ := s.Published(ctx, set.ID)
	if pub.Revision != 2 {
		t.Errorf("published = %d", pub.Revision)
	}
	if err := s.Publish(ctx, set.ID, 3, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("publishing a missing revision: %v", err)
	}
	// Rollback is publishing the older revision.
	if err := s.Publish(ctx, set.ID, 1, "bob"); err != nil {
		t.Fatal(err)
	}
	pub, _ = s.Published(ctx, set.ID)
	got, _ := s.GetSetByID(ctx, set.ID)
	if pub.Revision != 1 || got.PublishedRevision != 1 || got.LatestRevision != 2 {
		t.Errorf("after rollback: published %d, set %+v", pub.Revision, got)
	}
	hist, _ := s.Publications(ctx, set.ID)
	if len(hist) != 2 || hist[0].Revision != 1 || hist[0].Author != "bob" || hist[1].Revision != 2 {
		t.Errorf("publish history = %+v", hist)
	}
	list, _ := s.ListVersions(ctx, set.ID)
	if len(list) != 2 || list[0].Revision != 2 || list[0].Content != nil || list[1].Author != "alice" {
		t.Errorf("ListVersions = %+v", list)
	}
	if v, _ := s.GetVersion(ctx, set.ID, 1); string(v.Content) != `{"revision":"1","a":1}` || v.Comment != "first" {
		t.Errorf("GetVersion(1) = %+v", v)
	}
}

func TestTokens(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	org, _ := s.CreateOrg(ctx, "acme", "")
	set, _ := s.CreateSet(ctx, org.ID, "payments", "")

	tok, value, err := s.CreateToken(ctx, set.ID, "prod cluster")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, TokenPrefix) || len(value) != len(TokenPrefix)+48 || tok.Prefix != value[:12] {
		t.Errorf("token value %q, prefix %q", value, tok.Prefix)
	}
	if _, _, err := s.CreateToken(ctx, 999, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("token for a missing set: %v", err)
	}
	var stored string
	_ = s.db.QueryRowContext(ctx, `SELECT hash FROM tokens WHERE id = ?`, tok.ID).Scan(&stored)
	if stored == value || stored != HashToken(value) {
		t.Error("only the hash of the token may be stored")
	}

	acc, err := s.Authenticate(ctx, value)
	if err != nil || acc.Set.ID != set.ID || acc.Org.Slug != "acme" || acc.Token.ID != tok.ID {
		t.Fatalf("Authenticate = %+v, %v", acc, err)
	}
	if _, err := s.Authenticate(ctx, "psr_nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token: %v", err)
	}
	if err := s.RevokeToken(ctx, set.ID, tok.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(ctx, set.ID, tok.ID); err != nil {
		t.Errorf("revoking twice must be a no-op: %v", err)
	}
	if err := s.RevokeToken(ctx, set.ID+1, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking through another set: %v", err)
	}
	if _, err := s.Authenticate(ctx, value); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("revoked token: %v", err)
	}
	list, _ := s.ListTokens(ctx, set.ID)
	if len(list) != 1 || list[0].RevokedAt == nil || list[0].Name != "prod cluster" {
		t.Errorf("ListTokens = %+v", list)
	}
}

func TestOpenTwiceKeepsData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rules.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	org, _ := s.CreateOrg(ctx, "acme", "")
	_ = s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if got, err := s.GetOrg(ctx, "acme"); err != nil || got.ID != org.ID {
		t.Errorf("data lost across Open: %+v, %v", got, err)
	}
}
