package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEmailAddressHiddenByShape: an address was scored by entropy alone, so
// one with a word-like local part passed while a dotted one was hidden. The
// shape decides now, in the positions loggers put an address.
func TestEmailAddressHiddenByShape(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, c := range []struct{ in, addr string }{
		{"marcosantos@corp.example", "marcosantos@corp.example"},
		{"lena_santos@example.com", "lena_santos@example.com"},
		{"lenasantos14@example.com", "lenasantos14@example.com"},
		{"user marcosantos@corp.example logged in", "marcosantos@corp.example"},
		{"email=lena_santos@example.com", "lena_santos@example.com"},
		{"Password reset email send to: marcosantos@corp.example", "marcosantos@corp.example"},
		{`{"email":"lena_santos@example.com","ok":true}`, "lena_santos@example.com"},
		{`{"msg":"contact marcosantos@corp.example"}`, "marcosantos@corp.example"},
		{"From: lena_santos@example.com", "lena_santos@example.com"},
		{"To: <lena_santos@example.com>", "lena_santos@example.com"},
		{"mailto:lena_santos@example.com", "lena_santos@example.com"},
		{"a@b.co", "a@b.co"},
		{"sent to marcosantos@corp.example.", "marcosantos@corp.example"},
		{"cc marcosantos@corp.example, done", "marcosantos@corp.example"},
		{"GET /reset?email=marcosantos@corp.example HTTP/1.1", "marcosantos@corp.example"},
	} {
		out := ScanAndRedact(c.in)
		if strings.Contains(out, c.addr) || !strings.Contains(out, "[HIDDEN") {
			t.Errorf("address leaked:\n in: %s\nout: %s", c.in, out)
		}
		if strings.HasPrefix(c.in, "{") && !json.Valid([]byte(out)) {
			t.Errorf("output is not valid JSON:\n in: %s\nout: %s", c.in, out)
		}
	}

	// Sentence punctuation after the address stays outside the marker.
	if out := ScanAndRedact("sent to marcosantos@corp.example."); !strings.HasSuffix(out, "].") {
		t.Errorf("trailing period lost: %q", out)
	}
	if out := ScanAndRedact("cc marcosantos@corp.example, done"); !strings.Contains(out, "], done") {
		t.Errorf("trailing comma lost: %q", out)
	}

	// Entity labels name the type.
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)
	if out := ScanAndRedact("user lena_santos@example.com"); !strings.Contains(out, "[HIDDEN:email:") {
		t.Errorf("expected an email label: %q", out)
	}
}

// TestNotAnEmailAddress: shapes with an '@' that are not addresses keep their
// text: package versions, decorators, scoped packages, handles.
func TestNotAnEmailAddress(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	// react@18.2.0, @types/node and @pytest.fixture are hidden by entropy
	// on main already, before this rule; they are not in this list because
	// this change does not touch them either way.
	for _, in := range []string{
		"follow @handle for updates",
		"pkg@v1",
		"user@localhost",
		"git@github.com:org/repo.git",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed:\n in: %s\nout: %s", in, out)
		}
	}
}

func TestIsEmailAddress(t *testing.T) {
	for _, s := range []string{"a@b.co", "lena_santos@example.com", "x+tag@sub.example.co.uk", "ubuntu@ip-10-0-0-1.ec2.internal", "MARCO@CORP.EXAMPLE"} {
		if !isEmailAddress(s) {
			t.Errorf("expected an address: %q", s)
		}
	}
	for _, s := range []string{"", "@b.co", "a@", "a@b", "a@b.c", "a@b.c0m", "a@@b.co", ".a@b.co", "a.@b.co", "a@-b.co", "a@b-.co", "a@b..co", "react@18.2.0", "a b@c.de", "a@b.co:22"} {
		if isEmailAddress(s) {
			t.Errorf("not an address: %q", s)
		}
	}
}

// TestEmailAddressBeforeColonHidden: an address directly followed by a colon
// is the key half of a colon pair, which is written out unscored, so the
// shape rule never saw it: "reset key for user 'lena@example.com': 543963"
// kept the address, in quotes or without, while the same address with no
// colon after it was hidden. The marker is the one the bare address gets,
// and the quotes and the colon stay.
func TestEmailAddressBeforeColonHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	const addr = "sven.fischer40@example.com"
	marker := ScanAndRedact(addr)
	if !isRedacted(marker) {
		t.Fatalf("bare address not hidden: %q", marker)
	}

	for _, c := range []struct{ in, want string }{
		{"Password reset key for user '" + addr + "': 543963", "Password reset key for user '" + marker + "': 543963"},
		{`reset for user "` + addr + `": done`, `reset for user "` + marker + `": done`},
		{"user " + addr + ": 543963", "user " + marker + ": 543963"},
		{addr + ": login failed", marker + ": login failed"},
		{"INFO:root:" + addr + ": login failed", "INFO:root:" + marker + ": login failed"},
		{`{"` + addr + `": {"role": "admin"}}`, `{"` + marker + `": {"role": "admin"}}`},
		{`{"` + addr + `":{"role":"admin"}}`, `{"` + marker + `":{"role":"admin"}}`},
		{"{'" + addr + "': 3}", "{'" + marker + "': 3}"},
	} {
		out := ScanAndRedact(c.in)
		if out != c.want {
			t.Errorf("address before a colon:\n  in: %s\n got: %s\nwant: %s", c.in, out, c.want)
		}
		if strings.HasPrefix(c.in, `{"`) && !json.Valid([]byte(out)) {
			t.Errorf("output is not valid JSON:\n in: %s\nout: %s", c.in, out)
		}
		if again := ScanAndRedact(out); again != out {
			t.Errorf("second scan changed the line:\n 1st: %s\n 2nd: %s", out, again)
		}
	}
}

// TestColonAfterAtSignKept: with a value after the colon the token is an scp
// target or a host with a port, and a name with an '@' that is not an address
// stays a plain key.
func TestColonAfterAtSignKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"git clone git@github.com:org/repo.git",
		"scp build.tar deploy@build-01.example.com:/srv/releases/",
		"user@localhost: ok",
		"pkg@v1: installed",
		"@handle: hello",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed:\n in: %s\nout: %s", in, out)
		}
	}
}
