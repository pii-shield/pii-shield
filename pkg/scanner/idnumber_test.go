package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestIDNumberUnderKeyHidden: digits under a key that names an identity
// document are hidden with the id-number label. The first two lines are the
// form-payload shapes from BFPSoftware/bfpforyou2#49, where a nine-digit
// national id passed in 20 of 20 runs.
func TestIDNumberUnderKeyHidden(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, tc := range []struct{ in, number string }{
		{`Record:{"idNumber": "141638835", "city": "Haifa"}`, "141638835"},
		{`{ idNumber: '141638835', childIdNumber: '212345678' }`, "141638835"},
		{`{ idNumber: '141638835', childIdNumber: '212345678' }`, "212345678"},
		{`id_number=141638835 status=new`, "141638835"},
		{`IDNumber=141638835`, "141638835"},
		{`nationalId=141638835`, "141638835"},
		{`national_id: 141638835`, "141638835"},
		{`ssn: 078-05-1120`, "078-05-1120"},
		{`"ssn":"078051120"`, "078051120"},
		{`social_security_number=078-05-1120`, "078-05-1120"},
		{`cpf=123.456.789-09 ok`, "123.456.789-09"},
		{`{"aadhaar": "1234 5678 9012"}`, "1234 5678 9012"},
		{`tax_id=12-3456789`, "12-3456789"},
		{`teudat_zehut: 141638835`, "141638835"},
		{`GET /verify?national_id=141638835&step=2 HTTP/1.1`, "141638835"},
	} {
		out := ScanAndRedact(tc.in)
		if strings.Contains(out, tc.number) {
			t.Errorf("number passed through: %q", out)
		}
		if !strings.Contains(out, "[HIDDEN:id-number:") {
			t.Errorf("no id-number label: %q -> %q", tc.in, out)
		}
		if json.Valid([]byte(tc.in)) && !json.Valid([]byte(out)) {
			t.Errorf("JSON broken: %q -> %q", tc.in, out)
		}
		if strings.Count(out, `"`) != strings.Count(tc.in, `"`) || strings.Count(out, `'`) != strings.Count(tc.in, `'`) {
			t.Errorf("quotes changed: %q -> %q", tc.in, out)
		}
	}

	// The words after a logfmt value are not part of it.
	if out := ScanAndRedact(`id_number=141638835 42 items`); !strings.HasSuffix(out, "] 42 items") {
		t.Errorf("value ran into the next word: %q", out)
	}
}

// TestRecordIDsAreNotIDNumbers pins what the detector must not touch: record
// ids, keys that only start with a document word, and digit runs outside the
// 6-15 range.
func TestRecordIDsAreNotIDNumbers(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	cfg.EntityTypeLabels = true
	UpdateConfig(cfg)

	for _, in := range []string{
		`user_id=141638835`,
		`order_id=141638835`,
		`id=141638835`,
		`"id": 141638835`,
		`request_id=141638835`,
		`session_id: 99887766`,
		`order_id_number=141638835`,
		`transactionIdNo=141638835`,
		`ssn_verified=1`,
		`id_number_type=2`,
		`tax_id_valid=true`,
		`idNumber=12345`,
		`idNumber=1234567890123456`,
		`the id number 141638835 was checked`,
	} {
		if out := ScanAndRedact(in); out != in {
			t.Errorf("changed: %q -> %q", in, out)
		}
	}

	// Sixteen digits under an id key are not an id; a card there is a card.
	if out := ScanAndRedact(`"idNumber": "4539148803436467"`); !strings.Contains(out, "[HIDDEN:card:") {
		t.Errorf("card under an id key: %q", out)
	}
	// A number that is both keeps the id label.
	if out := ScanAndRedact(`ssn=4539148803430`); strings.Contains(out, "[HIDDEN:card:") || !strings.Contains(out, "[HIDDEN:") {
		t.Errorf("label for a number that also passes Luhn: %q", out)
	}
}

func TestIDKeys(t *testing.T) {
	for key, want := range map[string]bool{
		"idNumber": true, "id_number": true, "ID_NO": true, "IDNumber": true, "id-nr": true,
		"childIdNumber": true, "applicant_id_number": true, "customer_id_number": true,
		"national_id": true, "nationalId": true, "nationalID": true, "national_id_number": true,
		"tax_id": true, "taxId": true, "citizenId": true, "identity_number": true,
		"ssn": true, "SSN": true, "user.ssn": true, "ssn_number": true,
		"passport": true, "passport_number": true, "passportNo": true,
		"cpf": true, "dni": true, "aadhaar": true, "teudat_zehut": true,
		"social_security_number": true, "socialSecurity": true,
		"id": false, "user_id": false, "order_id": false, "userId": false, "identity": false,
		"order_id_number": false, "transactionIdNo": false, "tracking_id_number": false,
		"ssn_verified": false, "passport_country": false, "id_number_type": false,
		"tax_id_valid": false, "number": false, "security": false, "national": false, "": false,
	} {
		if got := isIDKey(key); got != want {
			t.Errorf("isIDKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestIDNumberSafeRegexAndStrategy(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	cfg := campaignConfig()
	if err := cfg.ApplySafeRegexes([]CustomRegexConfig{{Name: "test-id", Pattern: `^000000018$`}}); err != nil {
		t.Fatal(err)
	}
	UpdateConfig(cfg)
	var strategies []string
	RedactionCallback = func(strategy string) { strategies = append(strategies, strategy) }
	defer func() { RedactionCallback = nil }()

	if out := ScanAndRedact(`idNumber=000000018`); out != `idNumber=000000018` {
		t.Errorf("safe rule ignored: %q", out)
	}
	if out := ScanAndRedact(`idNumber=141638835`); strings.Contains(out, "141638835") {
		t.Errorf("number passed through: %q", out)
	}
	if len(strategies) != 1 || strategies[0] != "signature" {
		t.Errorf("strategies = %v, want [signature]", strategies)
	}
}
