package scanner

import (
	"testing"
)

// TestTwoLetterThreadNameKept: a thread or worker name whose first word is
// two letters (DbWorker_0, IoWorker_3, OkHttpClient_2) was hidden in every
// log prefix it appeared in: with an index the name failed the part-shape
// test, where one lowercase letter alone between capitals counts as a random
// run, while the same name without the index read as camelCase words. #265
// left it out because letting any lone lowercase letter through for indexed
// names kept 253 more of 5 000 random mixed-case tokens; the rule here keeps
// 9 more (see isTwoLetterPrefixedName).
func TestTwoLetterThreadNameKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, name := range []string{
		"DbWorker_0", "IoWorker_3", "OkHttpClient_2", "UiThread_1", "GcTask_2", "VmThread_0",
		"FxApplicationThread_0", "JsExecutor_5", "TxScheduler_3", "IoEventLoop_7", "DbWorker-12",
	} {
		for _, line := range []string{
			"2026-10-05 12:00:00.123 INFO  [main] (" + name + ") started",
			"2026-10-05 12:00:00.123 ERROR (" + name + ") [app.db] commit failed",
			"INFO [" + name + "] c.e.demo.OrderService - order placed",
			"thread=" + name + " msg=started",
			"worker " + name + " started",
		} {
			if out := ScanAndRedact(line); out != line {
				t.Errorf("thread name hidden:\n in: %s\nout: %s", line, out)
			}
		}
	}
}

// TestRandomRunWithTwoLetterStartStillHidden: the relaxation is for one
// two-letter word in front of real words. A second two-letter word, a
// lowercase start, a word that does not read as English, or no index at all
// keep the whole-token score, so the random runs #265 measured stay hidden.
// The cost, measured on 5 000 random mixed-case tokens with an index: main
// keeps 254 of them by their score, this rule keeps 9 more (RrDxfErq_0 is
// one). A name whose word has letter pairs the table does not know (DbPool,
// OkHttpPool: oo and ol score -7) stays hidden as on main.
func TestRandomRunWithTwoLetterStartStillHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, tok := range []string{
		"XkQpZm_3", "DaSoQzg_6", "StHaXmv_13", "OsPctd_13", "crOgLew_6", "SsaxFn_1",
		"QwJxVbKz_12", "KdjfQwpoZmxn_7", "AcEtZsxlMb_0", "SrAsQtAdt_11",
	} {
		in := "worker " + tok + " started"
		if out := ScanAndRedact(in); out == in {
			t.Errorf("random run no longer hidden: %s", in)
		}
	}
}

func TestIsTwoLetterPrefixedName(t *testing.T) {
	st := cfgState()
	for _, s := range []string{"DbWorker", "IoWorker", "OkHttpClient", "UiThread", "GcTask", "FxApplicationThread", "IoEventLoop"} {
		if !st.isTwoLetterPrefixedName(s) {
			t.Errorf("isTwoLetterPrefixedName(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"XkQpZm", "DaSoQzg", "OsPctd", "crOgLew", "SsaxFn", "Worker", "DBWorker", "Db", "DbW", "DbWo",
		"HttpWorker", "SyncWorker", "Db1Worker", "DbWorker_0", "DbSecretKey", "",
	} {
		if st.isTwoLetterPrefixedName(s) {
			t.Errorf("isTwoLetterPrefixedName(%q) = true, want false", s)
		}
	}
}
