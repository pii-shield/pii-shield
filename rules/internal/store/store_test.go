package store

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

	if p, err := s.Publish(ctx, set.ID, PublishRequest{Revision: 2, Author: "alice"}); err != nil || p.Seq != 1 {
		t.Fatalf("first publish: %+v %v", p, err)
	}
	pub, _ := s.Published(ctx, set.ID)
	if pub.Revision != 2 {
		t.Errorf("published = %d", pub.Revision)
	}
	if _, err := s.Publish(ctx, set.ID, PublishRequest{Revision: 3}); !errors.Is(err, ErrNotFound) {
		t.Errorf("publishing a missing revision: %v", err)
	}
	// Rollback is publishing the older revision.
	if _, err := s.Publish(ctx, set.ID, PublishRequest{Revision: 1, Author: "bob"}); err != nil {
		t.Fatal(err)
	}
	pub, _ = s.Published(ctx, set.ID)
	got, _ := s.GetSetByID(ctx, set.ID)
	if pub.Revision != 1 || got.PublishedRevision != 1 || got.LatestRevision != 2 {
		t.Errorf("after rollback: published %d, set %+v", pub.Revision, got)
	}
	hist, _ := s.Publications(ctx, set.ID)
	if len(hist) != 2 || hist[0].Revision != 1 || hist[0].Author != "bob" || hist[0].Seq != 2 || hist[1].Revision != 2 || hist[1].Seq != 1 {
		t.Errorf("publish history = %+v", hist)
	}
	// A publication that names a number other than the next one is stale,
	// and a failed check leaves nothing behind.
	if _, err := s.Publish(ctx, set.ID, PublishRequest{Revision: 2, Seq: 2}); !errors.Is(err, ErrStale) {
		t.Errorf("stale publication number: %v", err)
	}
	refuse := errors.New("refused")
	if _, err := s.Publish(ctx, set.ID, PublishRequest{Revision: 2, Seq: 3, Check: func(seq int64, v *Version) error {
		if seq != 3 || v.Revision != 2 {
			t.Errorf("check got seq %d, revision %d", seq, v.Revision)
		}
		return refuse
	}}); !errors.Is(err, refuse) {
		t.Errorf("failed check: %v", err)
	}
	if latest, _ := s.LatestPublication(ctx, set.ID); latest.Seq != 2 || latest.Revision != 1 {
		t.Errorf("after a refused publish: %+v", latest)
	}
	if next, _ := s.NextPublication(ctx, set.ID); next != 3 {
		t.Errorf("NextPublication = %d", next)
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

	tok, value, err := s.CreateToken(ctx, set.ID, "prod cluster", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, TokenPrefix) || len(value) != len(TokenPrefix)+48 || tok.Prefix != value[:12] {
		t.Errorf("token value %q, prefix %q", value, tok.Prefix)
	}
	if _, _, err := s.CreateToken(ctx, 999, "x", KindPull); !errors.Is(err, ErrNotFound) {
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

func TestSigningKeys(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	org, _ := s.CreateOrg(ctx, "acme", "")
	other, _ := s.CreateOrg(ctx, "other", "")
	if has, _ := s.HasSigningKeys(ctx, org.ID); has {
		t.Fatal("a new organization has no keys")
	}
	k, err := s.AddSigningKey(ctx, org.ID, "0011223344556677", "alice laptop", "ed25519:AAAA", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSigningKey(ctx, org.ID, "0011223344556677", "again", "ed25519:AAAA", ""); !errors.Is(err, ErrExists) {
		t.Errorf("the same key twice: %v", err)
	}
	if has, _ := s.HasSigningKeys(ctx, org.ID); !has {
		t.Error("HasSigningKeys after adding one")
	}
	if _, err := s.ActiveSigningKey(ctx, other.ID, k.KeyID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another organization's key: %v", err)
	}
	if err := s.RevokeSigningKey(ctx, other.ID, k.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking through another organization: %v", err)
	}
	if err := s.RevokeSigningKey(ctx, org.ID, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveSigningKey(ctx, org.ID, k.KeyID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a revoked key is not active: %v", err)
	}
	if has, _ := s.HasSigningKeys(ctx, org.ID); has {
		t.Error("only a revoked key left")
	}
	keys, _ := s.ListSigningKeys(ctx, org.ID)
	if len(keys) != 1 || keys[0].RevokedAt == nil || keys[0].CreatedBy != "alice@acme.test" {
		t.Errorf("ListSigningKeys = %+v", keys)
	}
}

func TestAuditLog(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	org, _ := s.CreateOrg(ctx, "acme", "")
	other, _ := s.CreateOrg(ctx, "other", "")
	for i := range 5 {
		if err := s.Record(ctx, Event{OrgID: org.ID, Actor: "alice@acme.test", Action: "publish", Target: "payments", Detail: map[string]any{"revision": i + 1}, IP: "10.0.0.1"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Record(ctx, Event{OrgID: other.ID, Actor: "eve@other.test", Action: "set.create"})

	page, _ := s.Events(ctx, org.ID, 0, 3)
	if len(page) != 3 || page[0].Detail["revision"] != float64(5) || page[0].Actor != "alice@acme.test" || page[0].IP != "10.0.0.1" {
		t.Fatalf("first page = %+v", page)
	}
	rest, _ := s.Events(ctx, org.ID, page[2].ID, 3)
	if len(rest) != 2 || rest[1].Detail["revision"] != float64(1) {
		t.Errorf("second page = %+v", rest)
	}
	if mine, _ := s.Events(ctx, other.ID, 0, 10); len(mine) != 1 || mine[0].Actor != "eve@other.test" {
		t.Errorf("another organization's log = %+v", mine)
	}
	// Append-only even for raw SQL.
	if _, err := s.db.ExecContext(ctx, `UPDATE audit_events SET actor = 'x'`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Errorf("UPDATE on the audit log: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_events`); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Errorf("DELETE on the audit log: %v", err)
	}
}

func TestTouchToken(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	org, _ := s.CreateOrg(ctx, "acme", "")
	set, _ := s.CreateSet(ctx, org.ID, "payments", "")
	tok, _, _ := s.CreateToken(ctx, set.ID, "prod", KindPull)
	if tok.LastUsedAt != nil {
		t.Fatal("a new token was never used")
	}
	if err := s.TouchToken(ctx, tok.ID, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	first, _ := s.getToken(ctx, tok.ID)
	if first.LastUsedAt == nil || first.LastUsedIP != "10.0.0.1" {
		t.Fatalf("after a pull: %+v", first)
	}
	// Within the minute a second pull writes nothing.
	_ = s.TouchToken(ctx, tok.ID, "10.0.0.2")
	if again, _ := s.getToken(ctx, tok.ID); again.LastUsedIP != "10.0.0.1" || !again.LastUsedAt.Equal(*first.LastUsedAt) {
		t.Errorf("a pull within the minute rewrote the record: %+v", again)
	}
	// An older record is replaced.
	_, _ = s.db.ExecContext(ctx, `UPDATE tokens SET last_used_at = '2000-01-01T00:00:00.000000000Z' WHERE id = ?`, tok.ID)
	_ = s.TouchToken(ctx, tok.ID, "10.0.0.3")
	if later, _ := s.getToken(ctx, tok.ID); later.LastUsedIP != "10.0.0.3" {
		t.Errorf("an old record must be replaced: %+v", later)
	}
}

func TestReportsRetentionAndClusters(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	org, _ := s.CreateOrg(ctx, "acme", "")
	set, _ := s.CreateSet(ctx, org.ID, "payments", "")
	tok, _, _ := s.CreateToken(ctx, set.ID, "stats", KindReport)
	if tok.Kind != KindReport || !strings.HasPrefix(tok.Prefix, ReportTokenPrefix) {
		t.Fatalf("report token %+v", tok)
	}
	if _, _, err := s.CreateToken(ctx, set.ID, "x", "write"); !errors.Is(err, ErrInvalidKind) {
		t.Errorf("unknown kind: %v", err)
	}
	add := func(cluster string, lines int64) {
		t.Helper()
		if err := s.AddReport(ctx, Report{SetID: set.ID, TokenID: tok.ID, Cluster: cluster, Policy: "apps/p", From: time.Now().Add(-time.Minute), To: time.Now(),
			Mode: "redact", Revisions: map[string]int{"1": 1}, Lines: lines, Redactions: map[string]int64{"entropy": lines / 10}}); err != nil {
			t.Fatal(err)
		}
	}
	add("a", 10)
	// A report older than the retention is dropped by the next insert.
	_, _ = s.db.ExecContext(ctx, `UPDATE reports SET received_at = '2000-01-01T00:00:00Z'`)
	add("a", 20)
	add("b", 30)
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reports`).Scan(&n)
	if n != 2 {
		t.Errorf("reports kept = %d, want 2", n)
	}
	cs, err := s.Clusters(ctx, set.ID, time.Now().Add(-time.Hour))
	if err != nil || len(cs) != 2 || cs[0].Cluster != "b" || cs[1].Lines != 20 || cs[1].Redactions["entropy"] != 2 || cs[0].TokenName != "stats" {
		t.Errorf("Clusters = %+v %v", cs, err)
	}
}
