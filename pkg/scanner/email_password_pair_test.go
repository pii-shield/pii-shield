package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEmailPasswordPairHidden: <e-mail>:<password> is a credential pair, and
// both halves are hidden. "login lena@example.com:hunter2 failed" and
// creds=lena@example.com:Winter7413# came back unchanged, address and password
// both (tracker 2026-10-05): #264 left the shape alone because an scp target
// looks the same, and the value is what tells them apart now.
func TestEmailPasswordPairHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, tc := range []struct{ in, password string }{
		{"login lena@example.com:hunter2 failed", "hunter2"},
		{"creds=lena@example.com:Winter7413#", "Winter7413#"},
		{"lena@example.com:hunter2", "hunter2"},
		{"lena@example.com:x", ":x"},
		{"[42] lena@example.com:tr0ub4dor&3", "tr0ub4dor&3"},
		{`"creds": "lena@example.com:hunter2"`, "hunter2"},
		{`{"creds":"lena@example.com:hunter2"}`, "hunter2"},
		{"lena@example.com:Winter.2024", "Winter.2024"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, "lena@example.com") || strings.Contains(out, tc.password) {
			t.Errorf("pair passed through: %q -> %q", tc.in, out)
		}
		if !strings.Contains(out, "[HIDDEN:email:") || !strings.Contains(out, "]:[HIDDEN:key:") {
			t.Errorf("want address and password as two markers: %q -> %q", tc.in, out)
		}
		if json.Valid([]byte(tc.in)) && !json.Valid([]byte(out)) {
			t.Errorf("JSON broken: %q -> %q", tc.in, out)
		}
	}
	if out := ScanAndRedact("login lena@example.com:hunter2 failed"); !strings.HasPrefix(out, "login [HIDDEN:email:") || !strings.HasSuffix(out, "] failed") {
		t.Errorf("words around the pair changed: %q", out)
	}
}

// TestSCPTargetIsNotAPassword pins what stays: an scp or git address with a
// path or a port after the colon, an address with nothing after the colon
// (handled by #264), and a JSON object keyed by address.
func TestSCPTargetIsNotAPassword(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"git@github.com:org/repo.git",
		"git clone git@github.com:org/repo.git",
		"scp lena@example.com:/var/log/app.log .",
		"lena@example.com:~/notes.txt",
		"lena@example.com:notes.txt",
		"rsync -a lena@example.com:backups/daily/ .",
		"lena@example.com:8080",
		"connecting to lena@example.com:22",
		`{"lena@example.com":"Winter7413#"}`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", in, out)
		}
	}
	// With nothing after the colon the address is still hidden by its shape
	// and the colon stays (#264).
	if out := ScanAndRedact("user lena@example.com: login failed"); !strings.HasPrefix(out, "user [HIDDEN:") || !strings.HasSuffix(out, "]: login failed") {
		t.Errorf("empty-value form changed: %q", out)
	}
	for v, want := range map[string]bool{
		"": true, "/var/log/app.log": true, "~/notes.txt": true, "org/repo.git": true, "repo.git": true,
		"notes.txt": true, "8080": true, "22": true,
		"hunter2": false, "Winter7413#": false, "x": false, "tr0ub4dor&3": false, "Winter.2024": false, "8080a": false,
	} {
		if got := isSCPTarget(v); got != want {
			t.Errorf("isSCPTarget(%q) = %v, want %v", v, got, want)
		}
	}
}
