package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNormalizeEmailAndSlug(t *testing.T) {
	for in, want := range map[string]string{"  Anna.Lee@Example.COM ": "anna.lee@example.com", "x@y.z": "x@y.z"} {
		if got, err := NormalizeEmail(in); err != nil || got != want {
			t.Errorf("NormalizeEmail(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "anna", "Anna <anna@example.com>", "a@b@c", "anna@", "@example.com", "a b@example.com"} {
		if _, err := NormalizeEmail(bad); !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("NormalizeEmail(%q): %v, want ErrInvalidEmail", bad, err)
		}
	}
	for in, want := range map[string]string{"anna.lee@x": "anna-lee", "_-9x__@x": "9x", "@x": "org", "---@x": "org",
		"abcdefghijklmnopqrstuvwxyz0123456789abcdefghij-xyz@x": "abcdefghijklmnopqrstuvwxyz0123456789abcd"} {
		if got := slugFromEmail(in); got != want || CheckSlug(got) != nil {
			t.Errorf("slugFromEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignupInviteAndOneOrgPerAccount(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	u, org, err := s.Signup(ctx, "Anna@Example.com")
	if err != nil || u.Email != "anna@example.com" || org.Slug != "anna" || org.Name != "anna@example.com" || u.OrgID != org.ID {
		t.Fatalf("signup: %+v %+v %v", u, org, err)
	}
	// The same local part at another domain gets a suffixed slug.
	_, org2, err := s.Signup(ctx, "anna@other.example")
	if err != nil || org2.Slug == org.Slug || len(org2.Slug) != len("anna-")+4 {
		t.Errorf("second signup: %+v %v", org2, err)
	}
	if _, _, err := s.Signup(ctx, "anna@example.com"); !errors.Is(err, ErrExists) {
		t.Errorf("signup twice: %v", err)
	}
	if _, err := s.CreateUser(ctx, org.ID, "anna@other.example", "anna@example.com"); !errors.Is(err, ErrExists) {
		t.Errorf("invite an address with an account elsewhere: %v", err)
	}
	if _, err := s.CreateUser(ctx, org.ID, "nope", "anna@example.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("invite a bad address: %v", err)
	}
	if _, err := s.CreateUser(ctx, 999, "bob@example.com", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("invite into a missing org: %v", err)
	}
	bob, err := s.CreateUser(ctx, org.ID, "Bob@example.com", "anna@example.com")
	if err != nil || bob.Email != "bob@example.com" || bob.InvitedBy != "anna@example.com" {
		t.Fatalf("invite: %+v %v", bob, err)
	}
	users, err := s.ListUsers(ctx, org.ID)
	if err != nil || len(users) != 2 || users[0].Email != "anna@example.com" || users[1].Email != "bob@example.com" {
		t.Errorf("list users: %+v %v", users, err)
	}
	if got, err := s.GetUserByEmail(ctx, " BOB@example.com"); err != nil || got.ID != bob.ID {
		t.Errorf("get by email: %+v %v", got, err)
	}
	if _, err := s.GetUserByEmail(ctx, "carol@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown email: %v", err)
	}
}

func TestMagicLinkIsUsedOnceAndExpires(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	v, err := s.CreateLogin(ctx, "anna@example.com", time.Minute)
	if err != nil || len(v) != 64 {
		t.Fatalf("create login: %q %v", v, err)
	}
	if email, err := s.ConsumeLogin(ctx, v); err != nil || email != "anna@example.com" {
		t.Fatalf("consume: %q %v", email, err)
	}
	if _, err := s.ConsumeLogin(ctx, v); !errors.Is(err, ErrExpired) {
		t.Errorf("consume twice: %v", err)
	}
	if _, err := s.ConsumeLogin(ctx, "0000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown link: %v", err)
	}
	old, _ := s.CreateLogin(ctx, "anna@example.com", -time.Second)
	if _, err := s.ConsumeLogin(ctx, old); !errors.Is(err, ErrExpired) {
		t.Errorf("expired link: %v", err)
	}
	if _, err := s.CreateLogin(ctx, "not-an-address", time.Minute); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("bad address: %v", err)
	}
}

func TestSessions(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	u, org, err := s.Signup(ctx, "anna@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.LastLogin != nil {
		t.Errorf("last login before any: %v", u.LastLogin)
	}
	v, err := s.CreateSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.GetSession(ctx, v)
	if err != nil || sess.User.ID != u.ID || sess.Org.ID != org.ID || sess.User.LastLogin == nil || time.Until(sess.ExpiresAt) < 50*time.Minute {
		t.Fatalf("get session: %+v %v", sess, err)
	}
	if _, err := s.GetSession(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown session: %v", err)
	}
	expired, _ := s.CreateSession(ctx, u.ID, -time.Second)
	if _, err := s.GetSession(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session: %v", err)
	}
	if err := s.DeleteSession(ctx, v); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, v); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted session: %v", err)
	}
	if err := s.DeleteSession(ctx, v); err != nil {
		t.Errorf("delete twice: %v", err)
	}
	// A new session sweeps expired rows.
	_, _ = s.CreateSession(ctx, u.ID, time.Hour)
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil || n != 1 {
		t.Errorf("sessions after sweep: %d %v", n, err)
	}
}

// The address goes into the To: header of the sign-in mail, so anything
// that could add a header or a second recipient must be refused here,
// before the mail package's own one-line rule.
func TestNormalizeEmailRefusesHeaderInjection(t *testing.T) {
	for _, bad := range []string{
		"anna@example.com\r\nBcc: eve@example.com",
		"anna@example.com\nX-Injected: 1",
		"anna@example.com\r\n\r\nbody",
		"\"anna\r\nBcc: eve@example.com\"@example.com",
		"Anna <anna@example.com>",
		"<anna@example.com>",
		"anna@example.com, eve@example.com",
		"anna@example.com>\r\nBcc: <eve@example.com",
	} {
		if got, err := NormalizeEmail(bad); err == nil {
			t.Errorf("NormalizeEmail(%q) = %q, want an error", bad, got)
		}
	}
}
