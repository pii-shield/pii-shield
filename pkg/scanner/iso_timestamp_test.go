package scanner

import (
	"strings"
	"testing"
)

// TestISOTimestampWithFractionKept: an ISO 8601 date-time with a fraction of a
// second and a zone was cut at its colons by the pair splitters, and the tail
// (31.478Z) scored as a secret on its own, so the seconds were replaced by a
// marker. The whole token is now written as it is, in every position a
// logger puts it.
func TestISOTimestampWithFractionKept(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	for _, in := range []string{
		"2026-09-27T14:15:31.478Z",
		"2026-09-27T14:15:31.478123Z",
		"2026-09-27T14:15:31,478Z",
		"2026-09-27T14:15:31.478+02:00",
		"2026-09-27T14:15:31.478-0700",
		"2026-09-27T14:15:31.478+02",
		"2026-09-27T14:15:31.478",
		"2026-09-27t14:15:31.478z",
		`{"time":"2026-09-27T14:15:31.478Z","level":"info","msg":"request served"}`,
		`{"@timestamp": "2026-09-27T14:15:31.478Z", "message": "ok"}`,
		"ts=2026-09-27T14:15:31.478Z level=info msg=ok",
		`time="2026-09-27T14:15:31.478Z" level=info`,
		"2026-09-27T14:15:31.478Z INFO server started",
		"[2026-09-27T14:15:31.478Z] started",
		"at 2026-09-27T14:15:31.478Z user bob logged in",
		"'2026-09-27T14:15:31.478Z'",
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("timestamp changed:\n in: %s\nout: %s", in, out)
		}
	}
}

// TestISOTimestampPrefixStillScored: the pass-through is for a complete
// timestamp only. A secret glued to one, and a timestamp under a sensitive
// key, are handled as before.
func TestISOTimestampPrefixStillScored(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	secret := "AbC9xY2kQ8pLmN0rZq7"
	for _, in := range []string{
		"2026-09-27T14:15:31.478Z:" + secret,
		"2026-09-27T14:15:31.478Z" + secret,
		"2026-09-27T14:15:31.478Z=" + secret,
	} {
		out := ScanAndRedact(in)
		if strings.Contains(out, secret) || !strings.Contains(out, "[HIDDEN") {
			t.Errorf("secret next to a timestamp leaked:\n in: %s\nout: %s", in, out)
		}
	}

	in := "password=2026-09-27T14:15:31.478Z"
	out := ScanAndRedact(in)
	if out != "password=[HIDDEN:58f349]" {
		t.Errorf("value under a sensitive key must stay hidden whole: %q -> %q", in, out)
	}
}

func TestIsISO8601Timestamp(t *testing.T) {
	yes := []string{
		"2026-09-27T14:15:31",
		"2026-09-27T14:15:31Z",
		"2026-09-27T14:15:31.4Z",
		"2026-09-27T14:15:31.478Z",
		"2026-09-27T14:15:31.478123456Z",
		"2026-09-27T14:15:31,478",
		"2026-09-27T14:15:31.478+02:00",
		"2026-09-27T14:15:31.478-0700",
		"2026-09-27T14:15:31+02",
		"2026-09-27t14:15:31.478z",
	}
	no := []string{
		"",
		"2026-09-27",
		"2026-09-27T14:15",
		"2026-09-27 14:15:31.478",
		"2026-09-27T14:15:31.",
		"2026-09-27T14:15:31.4781234567Z",
		"2026-09-27T14:15:31.478ZZ",
		"2026-09-27T14:15:31.478Zsecret",
		"2026-09-27T14:15:31.478+2",
		"2026-09-27T14:15:31.478+02:0",
		"2026-09-27T14:15:31.478+ab:cd",
		"2026-09-27T14:15:31.478Z:AbC9xY2kQ8pLmN0rZq7",
		"20260927T141531.478Z",
		"x026-09-27T14:15:31.478Z",
	}
	for _, s := range yes {
		if !isISO8601Timestamp(s) {
			t.Errorf("expected a timestamp: %q", s)
		}
	}
	for _, s := range no {
		if isISO8601Timestamp(s) {
			t.Errorf("not a complete timestamp: %q", s)
		}
	}
}
