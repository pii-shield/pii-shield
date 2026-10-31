package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/pii-shield/pii-shield/v2/pkg/metrics"
	"github.com/pii-shield/pii-shield/v2/pkg/scanner"
)

// restoreScannerConfig puts the package-level scanner config back the way
// package init left it, so a reloader test does not leak its rules into the
// tests that follow.
func restoreScannerConfig(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { scanner.UpdateConfig(scanner.ApplyEnvOverrides(scanner.DefaultConfig())) })
}

func writePolicy(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// bump makes the file look changed to a stat-based check even when the
// write lands within the same mtime tick.
func bump(t *testing.T, path string, d time.Duration) {
	t.Helper()
	if err := os.Chtimes(path, time.Now().Add(d), time.Now().Add(d)); err != nil {
		t.Fatal(err)
	}
}

const secretLine = "zzz=hunter2 keeper=hunter2"

func TestPolicyReloader_LoadsAndReloads(t *testing.T) {
	restoreScannerConfig(t)
	t.Setenv("PII_SALT", "0123456789abcdef0123456789abcdef")
	t.Setenv("PII_SENSITIVE_KEYS", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	writePolicy(t, path, `{"revision": "1", "sensitive_keys": ["zzz"]}`)
	r := newPolicyReloader(path, false)
	if !r.check() {
		t.Fatal("first check must load the file")
	}
	if r.revision != "1" {
		t.Errorf("revision = %q, want 1", r.revision)
	}
	out := scanner.ScanAndRedact(secretLine)
	if strings.Contains(out, "zzz=hunter2") || !strings.Contains(out, "keeper=hunter2") {
		t.Errorf("rules from the file not in force: %q", out)
	}
	if r.check() {
		t.Error("an unchanged file must not reload")
	}

	writePolicy(t, path, `{"revision": "2", "sensitive_keys": ["keeper"]}`)
	bump(t, path, 2*time.Second)
	if !r.check() {
		t.Fatal("a changed file must reload")
	}
	out = scanner.ScanAndRedact(secretLine)
	if !strings.Contains(out, "zzz=hunter2") || strings.Contains(out, "keeper=hunter2") {
		t.Errorf("new rules not in force after reload: %q", out)
	}
}

func TestPolicyReloader_RejectedFileKeepsPrevious(t *testing.T) {
	restoreScannerConfig(t)
	t.Setenv("PII_SALT", "0123456789abcdef0123456789abcdef")
	t.Setenv("PII_SENSITIVE_KEYS", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	writePolicy(t, path, `{"revision": "1", "sensitive_keys": ["zzz"]}`)
	r := newPolicyReloader(path, false)
	r.check()

	writePolicy(t, path, `{"revision": "2", "sensitive_keys": ["keeper"], "custom_regexes": [{"pattern": "["}]}`)
	bump(t, path, 2*time.Second)
	if r.check() {
		t.Fatal("an invalid file must not be applied")
	}
	if r.check() {
		t.Error("a rejected file must not be re-parsed while unchanged")
	}
	out := scanner.ScanAndRedact(secretLine)
	if strings.Contains(out, "zzz=hunter2") || !strings.Contains(out, "keeper=hunter2") {
		t.Errorf("previous rules must stay in force after a rejected file: %q", out)
	}
	if r.revision != "1" {
		t.Errorf("revision = %q, want the previous 1", r.revision)
	}
}

func TestPolicyReloader_CountsLoadsAndRejections(t *testing.T) {
	restoreScannerConfig(t)
	t.Setenv("PII_SALT", "0123456789abcdef0123456789abcdef")
	t.Setenv("PII_SENSITIVE_KEYS", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	loadsBefore := testutil.ToFloat64(metrics.ConfigReloadsTotal)
	errorsBefore := testutil.ToFloat64(metrics.ConfigReloadErrorsTotal)

	writePolicy(t, path, `{"revision": "1", "sensitive_keys": ["zzz"]}`)
	r := newPolicyReloader(path, true)
	if !r.check() {
		t.Fatal("first check must load the file")
	}
	if n := testutil.ToFloat64(metrics.ConfigReloadsTotal) - loadsBefore; n != 1 {
		t.Errorf("loads counted = %v, want 1", n)
	}
	if testutil.ToFloat64(metrics.ConfigLastReloadTimestamp) == 0 {
		t.Error("the last reload timestamp must be set after a load")
	}

	writePolicy(t, path, `{"custom_regexes": [{"pattern": "["}]}`)
	bump(t, path, 2*time.Second)
	if r.check() {
		t.Fatal("an invalid file must not be applied")
	}
	if n := testutil.ToFloat64(metrics.ConfigReloadErrorsTotal) - errorsBefore; n != 1 {
		t.Errorf("rejections counted = %v, want 1", n)
	}
	if n := testutil.ToFloat64(metrics.ConfigReloadsTotal) - loadsBefore; n != 1 {
		t.Errorf("a rejected file must not count as a load, loads = %v", n)
	}
	// The revision series names the file in force: a rejected file leaves it.
	if testutil.CollectAndCount(metrics.ConfigRevisionInfo) != 1 || testutil.ToFloat64(metrics.ConfigRevisionInfo.WithLabelValues("1")) != 1 {
		t.Errorf("revision info after a rejection: %d series", testutil.CollectAndCount(metrics.ConfigRevisionInfo))
	}
	writePolicy(t, path, `{"revision": "2", "sensitive_keys": ["zzz"]}`)
	bump(t, path, 4*time.Second)
	if !r.check() {
		t.Fatal("revision 2 must load")
	}
	if testutil.CollectAndCount(metrics.ConfigRevisionInfo) != 1 || testutil.ToFloat64(metrics.ConfigRevisionInfo.WithLabelValues("2")) != 1 {
		t.Errorf("revision info must carry only revision 2: %d series", testutil.CollectAndCount(metrics.ConfigRevisionInfo))
	}
}

func TestPolicyReloader_EnvWinsAndSaltStays(t *testing.T) {
	restoreScannerConfig(t)
	t.Setenv("PII_SALT", "")
	t.Setenv("PII_SENSITIVE_KEYS", "keeper")
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	r := newPolicyReloader(path, false)
	if len(r.salt) != 32 {
		t.Fatalf("expected a random salt at start, got %d bytes", len(r.salt))
	}
	if r.check() {
		t.Fatal("a missing file must not count as a load")
	}
	before := scanner.ScanAndRedact(secretLine)

	writePolicy(t, path, `{"sensitive_keys": ["zzz"]}`)
	if !r.check() {
		t.Fatal("the file must load once it appears")
	}
	after := scanner.ScanAndRedact(secretLine)
	// PII_SENSITIVE_KEYS replaces the file's list, so the file changes
	// nothing here and the tags stay the same: same rules, same salt.
	if after != before {
		t.Errorf("env must win over the file and the salt must stay:\n before %q\n after  %q", before, after)
	}
	if strings.Contains(after, "keeper=hunter2") || !strings.Contains(after, "zzz=hunter2") {
		t.Errorf("expected the env list in force: %q", after)
	}
}

func TestPolicyReloader_ConfigMapSymlinkSwap(t *testing.T) {
	restoreScannerConfig(t)
	t.Setenv("PII_SALT", "0123456789abcdef0123456789abcdef")
	t.Setenv("PII_SENSITIVE_KEYS", "")
	// The kubelet lays a ConfigMap out as <dir>/..data -> ..data_<ts>/ and
	// <dir>/policy.json -> ..data/policy.json, and updates it by writing a
	// new ..data_<ts> directory and swapping the ..data symlink.
	dir := t.TempDir()
	mkVersion := func(name, body string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		writePolicy(t, filepath.Join(dir, name, "policy.json"), body)
	}
	mkVersion("..data_1", `{"revision": "1", "sensitive_keys": ["zzz"]}`)
	if err := os.Symlink("..data_1", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.Symlink(filepath.Join("..data", "policy.json"), path); err != nil {
		t.Fatal(err)
	}

	r := newPolicyReloader(path, false)
	if !r.check() || r.revision != "1" {
		t.Fatalf("first version not loaded: revision %q", r.revision)
	}

	mkVersion("..data_2", `{"revision": "2", "sensitive_keys": ["keeper"]}`)
	bump(t, filepath.Join(dir, "..data_2", "policy.json"), 2*time.Second)
	tmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink("..data_2", tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if !r.check() || r.revision != "2" {
		t.Fatalf("swapped version not loaded: revision %q", r.revision)
	}
	out := scanner.ScanAndRedact(secretLine)
	if strings.Contains(out, "keeper=hunter2") {
		t.Errorf("rules of the swapped version not in force: %q", out)
	}
}

func TestPolicyReloader_RunStops(t *testing.T) {
	restoreScannerConfig(t)
	t.Setenv("PII_SALT", "0123456789abcdef0123456789abcdef")
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	r := newPolicyReloader(path, false)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		r.run(10*time.Millisecond, stop)
		close(done)
	}()
	// The goroutine owns r while it runs, so the test watches the scanner's
	// output for the new rules instead of reading r.revision.
	writePolicy(t, path, `{"revision": "live", "sensitive_keys": ["zzz"]}`)
	deadline := time.Now().Add(2 * time.Second)
	for strings.Contains(scanner.ScanAndRedact(secretLine), "zzz=hunter2") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("run did not stop")
	}
	if r.revision != "live" {
		t.Errorf("periodic check did not load the file, revision %q", r.revision)
	}
}

func TestParseReloadInterval(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"", defaultPolicyReloadInterval, false},
		{" 30 ", 30 * time.Second, false},
		{"0", 0, false},
		{"-1", 0, true},
		{"ten", 0, true},
		{"1.5", 0, true},
	}
	for _, c := range cases {
		got, err := parseReloadInterval(c.in)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("parseReloadInterval(%q) = %v, %v; want %v, err=%v", c.in, got, err, c.want, c.err)
		}
	}
}

func TestStartPolicyReloader(t *testing.T) {
	restoreScannerConfig(t)
	t.Setenv("PII_SALT", "0123456789abcdef0123456789abcdef")
	t.Setenv("PII_CONFIG_FILE", "")
	if startPolicyReloader(false) != nil {
		t.Error("unset PII_CONFIG_FILE must start nothing")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, `{"revision": "boot", "sensitive_keys": ["zzz"]}`)
	t.Setenv("PII_CONFIG_FILE", path)
	t.Setenv("PII_CONFIG_RELOAD_SECONDS", "junk")
	r := startPolicyReloader(false)
	if r == nil {
		t.Fatal("PII_CONFIG_FILE set: expected a reloader")
	}
	close(r.stop)
	if r.revision != "boot" {
		t.Fatalf("initial load did not happen: revision %q", r.revision)
	}
}
