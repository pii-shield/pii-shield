package scanner

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// TestDateOfBirthUnderKeyHidden: a calendar date under a key that names a
// date of birth is hidden with the dob label, and a patient MRN under a key
// that names it with the id-number label. The first three lines are the
// shapes a FastAPI service printed at INFO (leak-radar repo-risks
// 2026-10-19, HealthRex/CDSS), where every one passed in 30 of 30 runs.
func TestDateOfBirthUnderKeyHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, tc := range []struct{ in, value, label string }{
		{`2026-10-19 11:23:11,255 - __main__ - INFO - Searching by MRN: 1136893801`, "1136893801", "id-number"},
		{`2026-10-19 19:24:56,754 - __main__ - INFO - Patient data: gender=0, DOB=1986-12-01`, "1986-12-01", "dob"},
		{`mrn=6177519760`, "6177519760", "id-number"},
		{`patient_mrn: 1136893801`, "1136893801", "id-number"},
		{`{"medical_record_number": "1136893801"}`, "1136893801", "id-number"},
		{`medicalRecordNumber=1136893801`, "1136893801", "id-number"},
		{`date_of_birth=1987-07-11`, "1987-07-11", "dob"},
		{`birthDate=1987-07-11`, "1987-07-11", "dob"},
		{`dateOfBirth=11/07/1987`, "11/07/1987", "dob"},
		{`dob=11.07.1987`, "11.07.1987", "dob"},
		{`dob=12-01-1986`, "12-01-1986", "dob"},
		{`birthday: 7/11/1987`, "7/11/1987", "dob"},
		{`patient_dob="1987-07-11"`, "1987-07-11", "dob"},
		{`{"dob": "1987-07-11T00:00:00Z"}`, "1987-07-11", "dob"},
		{`{"birth_date":"1987/07/11"}`, "1987/07/11", "dob"},
		{`DOB=1987-07-11 12:00:00 next`, "1987-07-11", "dob"},
		{`GET /patients?mrn=6177519760&dob=1987-07-11 HTTP/1.1`, "6177519760", "id-number"},
		{`GET /patients?mrn=6177519760&dob=1987-07-11 HTTP/1.1`, "1987-07-11", "dob"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.value) {
			t.Errorf("value passed through: %q", out)
		}
		if !strings.Contains(out, "[HIDDEN:"+tc.label+":") {
			t.Errorf("no %s label: %q -> %q", tc.label, tc.in, out)
		}
		if json.Valid([]byte(tc.in)) && !json.Valid([]byte(out)) {
			t.Errorf("JSON broken: %q -> %q", tc.in, out)
		}
		if strings.Count(out, `"`) != strings.Count(tc.in, `"`) {
			t.Errorf("quotes changed: %q -> %q", tc.in, out)
		}
	}

	// The log prefix in front of the line is a timestamp, not a date of
	// birth, and is written as it is.
	if out := ScanAndRedact(`2026-10-19 19:24:56,754 - __main__ - INFO - Patient data: gender=0, DOB=1986-12-01`); !strings.HasPrefix(out, "2026-10-19 19:24:56,754 - __main__ - INFO - Patient data: gender=0, DOB=[HIDDEN:dob:") {
		t.Errorf("prefix changed: %q", out)
	}
	// The words after the value are not part of it.
	if out := ScanAndRedact(`DOB=1987-07-11 12:00:00 next`); !strings.HasSuffix(out, "] next") {
		t.Errorf("value ran into the next word: %q", out)
	}
}

// TestDateOfBirthAtRangeEdges: the first and last year, month and day the
// detector accepts, both orders of day and month, and every time form it
// extends over. The whole value, time and zone included, becomes one marker
// and the words around it stay. Mutation testing found that a one-character
// change to any of these bounds (1900, 2099, month 1 and 12, day 31) or to
// the time parser left the value in plaintext with every test still passing.
func TestDateOfBirthAtRangeEdges(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, tc := range []struct{ in, value string }{
		{`patient dob=1900-01-01 admitted`, "1900-01-01"},
		{`patient dob=2099-12-31 admitted`, "2099-12-31"},
		{`patient dob=31/12/1986 admitted`, "31/12/1986"},
		{`patient dob=12/31/1986 admitted`, "12/31/1986"},
		{`GET /api/patient?dob=31.12.1986&ward=4`, "31.12.1986"},
		{`patient dob=1986-12-01T10:30 admitted`, "1986-12-01T10:30"},
		{`patient dob=1986-12-01 10:30 admitted`, "1986-12-01 10:30"},
		{`patient dob=1986-12-01T10:30:00.123+0200 admitted`, "1986-12-01T10:30:00.123+0200"},
		{`patient dob=1986-12-01 10:30:00+02:00 admitted`, "1986-12-01 10:30:00+02:00"},
	} {
		i := strings.Index(tc.in, tc.value)
		want := regexp.MustCompile("^" + regexp.QuoteMeta(tc.in[:i]) + `\[HIDDEN:dob:[0-9a-f]+\]` + regexp.QuoteMeta(tc.in[i+len(tc.value):]) + "$")
		if out := ScanAndRedact(tc.in); !want.MatchString(out) {
			t.Errorf("ScanAndRedact(%q) = %q, want %q hidden whole as one dob marker", tc.in, out, tc.value)
		}
	}
}

// TestOtherDatesAreNotDatesOfBirth pins what the detector must not touch:
// dates under other keys, timestamps with no key, a key that only starts
// with a birth word, a number that is not a date, and a bare patient number
// in prose with no key that names it.
func TestOtherDatesAreNotDatesOfBirth(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, in := range []string{
		`created_at=1986-12-01`,
		`expires=2026-12-01`,
		`start_date=2026-01-01 end_date=2026-12-31`,
		`date=2026-10-19`,
		`ts=2026-09-27T14:15:31.478Z level=info`,
		`2026-10-19 11:23:11,255 - __main__ - INFO - started`,
		`birth_date_format=YYYY-MM-DD`,
		`dob_verified=1`,
		`dob=unknown`,
		`dob=19870711`,
		`dob=1987-13-01`,
		`dob=32/07/1987`,
		`dob=11/07/87`,
		`dob=1800-07-11`,
		`mrn_count=5`,
		`mrn=12345`,
		`record_number=123456`,
		`medical_record_type=2`,
		`2026-10-19 01:30:55,373 - __main__ - INFO - Fetching patient: 6177519760`,
		`GET /a?date=1987-07-11 HTTP/1.1`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("ScanAndRedact(%q) = %q, want unchanged", in, out)
		}
	}
}

func TestIsDOBKey(t *testing.T) {
	for _, k := range []string{
		"dob", "DOB", "patient_dob", "patientDob", "birth_date", "birthDate", "birthdate", "BirthDate",
		"date_of_birth", "dateOfBirth", "DateOfBirth", "birthday", "user.dob", "born",
	} {
		if !isDOBKey(k) {
			t.Errorf("isDOBKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{
		"date", "created_at", "start_date", "birth_date_format", "dob_verified", "birth", "of_birth",
		"birth_place", "dobs", "id",
	} {
		if isDOBKey(k) {
			t.Errorf("isDOBKey(%q) = true, want false", k)
		}
	}
	for _, k := range []string{"mrn", "MRN", "patient_mrn", "medical_record_number", "medicalRecordNumber", "medical_record_no"} {
		if !isIDKey(k) {
			t.Errorf("isIDKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"mrn_count", "record_number", "medical_record_type", "medical_record"} {
		if isIDKey(k) {
			t.Errorf("isIDKey(%q) = true, want false", k)
		}
	}
}

func TestMatchKeyedDate(t *testing.T) {
	for _, tc := range []struct {
		in  string
		end int
	}{
		{"1987-07-11", 10},
		{"1987/07/11", 10},
		{"1987.07.11", 10},
		{"1987-07-11T00:00:00Z", 20},
		{"1987-07-11T00:00:00.000+02:00", 29},
		{"1987-07-11 12:00:00 next", 19},
		{"1987-07-11T", 10},
		{"11/07/1987", 10},
		{"7/11/1987", 9},
		{"1.12.1986", 9},
		{"12-01-1986", 10},
		{"11/07/1987 x", 10},
		{"11/07/87", 0},
		{"1987-13-01", 0},
		{"1987-07-32", 0},
		{"32/13/1987", 0},
		{"1800-07-11", 0},
		{"2100-07-11", 0},
		{"19870711", 0},
		{"11/07-1987", 0},
		{"1987", 0},
	} {
		if got := matchKeyedDate(tc.in, 0); got != tc.end {
			t.Errorf("matchKeyedDate(%q) = %d, want %d", tc.in, got, tc.end)
		}
	}
}
