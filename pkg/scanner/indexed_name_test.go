package scanner

import (
	"strings"
	"testing"
)

// TestIndexedThreadNamesKept: a camelCase name with an index (SyncWorker_3)
// was scored as one run, 3.622 against the 3.6 threshold, so the thread name
// in the Home Assistant log prefix was hidden on every line from a worker
// thread, while the bare name and MainThread were not. The name is scored
// word by word, as it is when it stands alone.
func TestIndexedThreadNamesKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, name := range []string{
		"SyncWorker_3",
		"SyncWorker_0",
		"SyncWorker_12",
		"SyncWorker-3",
		"TaskRunner_10",
		"MainThread",
		"WorkerThread_7",
		"ThreadPoolExecutor-0_0",
	} {
		in := "2026-10-04 10:00:00.123 DEBUG (" + name + ") [huawei_lte_api.Connection] Connecting in authenticated mode"
		if out := ScanAndRedact(in); out != in {
			t.Errorf("thread name hidden:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestRandomRunWithIndexStillHidden: the rule reads a name word by word only
// when it is made of words. A random run in front of an index keeps its
// whole-token score, and a User-Agent component with '/' is not an indexed
// name at all.
func TestRandomRunWithIndexStillHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tok := range []string{
		"XkQpZm_3",
		"QwJxVbKz_12",
		"KdjfQwpoZmxn_7",
		"VbNmQwErTy_1",
		"GhTyUjKl-44",
		"Zx9Kq_3",
		"aB3dE_7",
		"MobileSafari/604.1",
	} {
		in := "worker " + tok + " started"
		if out := ScanAndRedact(in); out == in {
			t.Errorf("token no longer hidden: %s", in)
		}
	}
}

func TestIsIndexedName(t *testing.T) {
	for _, s := range []string{"SyncWorker_3", "SyncWorker-3", "TaskRunner_10", "ThreadPoolExecutor-0_0", "pool-1"} {
		if !isIndexedName(s) {
			t.Errorf("expected an indexed name: %q", s)
		}
	}
	for _, s := range []string{"SyncWorker", "pool-1-thread-2", "sync_worker_3", "MobileSafari/604.1", "app.v2", "SyncWorker_3a", "SyncWorker_", ""} {
		if isIndexedName(s) {
			t.Errorf("not an indexed name: %q", s)
		}
	}
}

// TestThreadNameAfterLevelKept: a context word (WARNING, ERROR) lowers the
// threshold for the token after it, and in a log prefix that token is the
// thread name in brackets. Sync in SyncWorker scores 2.5 against the lowered
// 2.3, so the name was hidden on every WARNING and ERROR line even without
// an index. A name that reads as words, in brackets right after the context
// word, keeps its normal score.
func TestThreadNameAfterLevelKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"2026-10-04 10:00:00.123 WARNING (SyncWorker_3) [homeassistant.loader] Trying to connect",
		"2026-10-04 10:00:00.123 ERROR (SyncWorker_3) [homeassistant.components.sensor] Setup failed",
		"2026-10-04 10:00:00.123 WARNING (SyncWorker) [homeassistant.loader] Trying to connect",
		"2026-10-04 10:00:00.123 WARNING (SocketListener) [app.net] started",
		"2026-10-04 10:00:00.123 ERROR (ImportExecutor_0) [homeassistant.loader] Trying to connect",
		"2026-10-04 10:00:00.123 ERROR [KafkaConsumer-2] c.e.demo.OrderService - commit failed",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("thread name hidden after a level word:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestContextRuleKeptForRandomTokens: the lowered threshold still applies to
// a token that does not read as words, in brackets or not, and to any token
// outside brackets. The bracketed ones pass on an INFO line and are hidden
// after the context word.
func TestContextRuleKeptForRandomTokens(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, c := range []struct{ line, tok string }{
		{"ERROR (%s) failed", "k3j9x2ab"},
		{"ERROR (%s) failed", "qzxvkj"},
		{"ERROR [%s] failed", "a1b2c3"},
		{"invalid %s received", "qzxvkj"},
		{"ERROR %s stopped", "KafkaConsumer"},
	} {
		in := strings.Replace(c.line, "%s", c.tok, 1)
		if out := ScanAndRedact(in); strings.Contains(out, c.tok) {
			t.Errorf("token after a context word no longer hidden:\n in: %s\nout: %s", in, out)
		}
		if !strings.HasPrefix(c.line, "ERROR (") && !strings.HasPrefix(c.line, "ERROR [") {
			continue
		}
		plain := strings.Replace(in, "ERROR", "INFO", 1)
		if out := ScanAndRedact(plain); out != plain {
			t.Errorf("control is hidden without the context word, pick another:\n in: %s\nout: %s", plain, out)
		}
	}
}
