package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fake numbers only: 555 area codes, the +49 170 range with a made-up
// subscriber part, UK 020 7946 0xxx (Ofcom's drama range) and 07700 900xxx.

// phoneShapes are lines whose number must be hidden with the phone label,
// whatever its entropy: digits alone score far under the threshold, so on
// main every one of them came back unchanged.
var phoneShapes = []struct {
	name, line, number string
}{
	{"E.164 compact", "call +4917412345678 now", "+4917412345678"},
	{"international spaced", "call +49 170 1234567 now", "+49 170 1234567"},
	{"international dashed", "contact_no=+49-170-1234567", "+49-170-1234567"},
	{"international dotted", "x +44.20.7946.0958 x", "+44.20.7946.0958"},
	{"international uk groups", "x +44 20 7946 0958 x", "+44 20 7946 0958"},
	{"international with area code", "tel +1 (555) 234-5678 ok", "+1 (555) 234-5678"},
	{"international trunk zero", "tel +49 (0) 170 1234567 ok", "+49 (0) 170 1234567"},
	{"nanp parens", "us (555) 234-5678 end", "(555) 234-5678"},
	{"nanp parens no space", "us (555)234-5678 end", "(555)234-5678"},
	{"nanp parens spaces", "us (555) 234 5678 end", "(555) 234 5678"},
	{"nanp dashed", "us 555-234-5678 end", "555-234-5678"},
	{"nanp dotted", "us 555.234.5678 end", "555.234.5678"},
	{"json wa_id", `{"wa_id": "4917412345678", "type": "text"}`, "4917412345678"},
	{"compact json phone", `{"phone":"4917412345678"}`, "4917412345678"},
	{"logfmt grouped", "phone=0170 1234567 user=bob", "0170 1234567"},
	{"url parameter", "GET /api?mobile=07700900123&x=1", "07700900123"},
	{"url parameter plus", "GET /api?phone=+4917412345678&x=1", "+4917412345678"},
	{"url parameter nanp", "GET /api?tel=555-234-5678&x=1", "555-234-5678"},
	{"quoted request line", `"GET /track?code=9710300118&emailOrMobile=09163074015 HTTP/1.1" 200 17 "https://x.example/track?code=9710300118" "Mozilla/5.0 (Linux; Android 4.2.2) Safari/537.36"`, "09163074015"},
	{"json url value", `{"url": "https://x.example/verify?mobile=07700900123&code=1"}`, "07700900123"},
	{"yaml quoted", `customer_phone: "020 7946 0958"`, "020 7946 0958"},
	{"camel key", `phoneNumber="+1 555 234 5678"`, "+1 555 234 5678"},
	{"contact number", "contactNo: 07700900123", "07700900123"},
	{"msisdn", "msisdn=447700900123", "447700900123"},
	{"telephone spaced colon", "telephone : 555-234-5678", "555-234-5678"},
	{"keyed parens", "tel=(555) 234-5678", "(555) 234-5678"},
	{"line end", "called +4917412345678", "+4917412345678"},
	{"before comma", "called +4917412345678, twice", "+4917412345678"},
	{"single quotes", "phone='+4917412345678'", "+4917412345678"},
}

func TestPhoneShapesHidden(t *testing.T) {
	withEntityLabels(t, nil)
	for _, tc := range phoneShapes {
		out := ScanAndRedact(tc.line)
		if strings.Contains(out, tc.number) {
			t.Errorf("%s: number still visible: %q -> %q", tc.name, tc.line, out)
		}
		if !strings.Contains(out, "[HIDDEN:phone:") {
			t.Errorf("%s: no phone marker: %q -> %q", tc.name, tc.line, out)
		}
		want := strings.Replace(tc.line, tc.number, "", 1)
		got := out
		if i := strings.Index(got, "[HIDDEN:phone:"); i >= 0 {
			j := strings.IndexByte(got[i:], ']')
			got = got[:i] + got[i+j+1:]
		}
		if got != want {
			t.Errorf("%s: framing changed: %q -> %q", tc.name, tc.line, out)
		}
		// Inside a URL the number is left to maskURLParameters (see
		// TestPhoneInsideURLKeepsTheRestOfTheURL); everywhere else the
		// carve is exactly the number.
		if strings.Contains(tc.line, "?") {
			continue
		}
		if r := FindPhoneSequences(tc.line); len(r) != 1 || tc.line[r[0].Start:r[0].End] != tc.number {
			t.Errorf("%s: FindPhoneSequences = %v, want exactly %q", tc.name, r, tc.number)
		}
	}
}

// phoneLookalikes are digit runs that are not phones and must not get the
// phone label: no '+', no NANP punctuation, no phone key, or glued to a
// larger token. Some are hidden by other rules (the card, an entropy
// token); the assertion is only about the label.
var phoneLookalikes = []string{
	"ts=1700000000123 id=1234567890",
	"at 2026-09-30T10:00:00+03:00 and +0300 and +0000",
	"delta=+1234567.89 sum=+12345 pct=+100",
	"ip 192.168.1.1 ver 1.2.34 uuid 123e4567-e89b-12d3-a456-426614174000",
	"abc+1234567890def b64 dGVzdA+12345678",
	"phone_verified=1700000000 phone_number_id=695017579123456 telemetry=123456789",
	"phoneCountryCode=49 phone_id=12345678",
	"ssn 123-45-6789 date 2026-09-30 range 100-200-3000 build 2026.0930.1234",
	"card 4539 1488 0343 6467",
	"x=+1 2 3 z=+12 w=+1234567",
	"(123) 456-7890 exchange-and-area-start-with-1 555-123-4567",
	"order 12345678901 count: 1234567 total=4917412345678",
	"from: 4917412345678 to: 4917412345678",
	"user@+4917412345678 path/+4917412345678 50%+4917412345678",
	"+4917412345678x +4917412345678_ +49174123456789012",
	"+49 170 1234567.5 +49 170 12345678901234",
	"version=+1.2.3 range=+1-2",
}

func TestPhoneLookalikesKeepLabel(t *testing.T) {
	withEntityLabels(t, nil)
	for _, line := range phoneLookalikes {
		if r := FindPhoneSequences(line); len(r) != 0 {
			var got []string
			for _, x := range r {
				got = append(got, line[x.Start:x.End])
			}
			t.Errorf("phone found in %q: %v", line, got)
		}
		if out := ScanAndRedact(line); strings.Contains(out, "[HIDDEN:phone:") {
			t.Errorf("phone label in %q -> %q", line, out)
		}
	}
}

// A phone in a URL is hidden by the parameter loop, not carved out of the
// line: carved, the rest of a quoted request line stopped being read as a URL
// and its later parameters lost their scoring. The address parameter here is
// hidden by entropy on main and must stay hidden, and the User-Agent must
// come back as it went in.
func TestPhoneInsideURLKeepsTheRestOfTheURL(t *testing.T) {
	withEntityLabels(t, nil)
	const addr = "%D8%B9%D8%A8%D8%A7%D8%B3+%D8%A2%D8%A8%D8%A7%D8%AF+%D8%AE%DB%8C%D8%A7%D8%A8%D8%A7%D9%86"
	line := `"GET /basket/storeShippingAddress?city=450&telephone=09122654130&addressLine=` + addr + ` HTTP/1.1" 302 0 "https://x.example/checkout?currentStep=2" "Mozilla/5.0 (Linux; Android 6.0.1) AppleWebKit/537.36"`
	out := ScanAndRedact(line)
	if !strings.Contains(out, "telephone=[HIDDEN:phone:") {
		t.Errorf("phone parameter not hidden: %q", out)
	}
	if strings.Contains(out, addr) {
		t.Errorf("address parameter after the phone no longer hidden: %q", out)
	}
	if !strings.HasSuffix(out, ` HTTP/1.1" 302 0 "https://x.example/checkout?currentStep=2" "Mozilla/5.0 (Linux; Android 6.0.1) AppleWebKit/537.36"`) {
		t.Errorf("tail of the line changed: %q", out)
	}
	if r := FindPhoneSequences(line); len(r) != 0 {
		t.Errorf("a number inside a URL must not be carved: %v", r)
	}
}

func TestPhoneKeys(t *testing.T) {
	yes := []string{"phone", "Phone", "PHONE", "phone_number", "phoneNumber", "PhoneNumber", "phone-number", "phone.number",
		"customer_phone", "customer.mobile", "mobileNumber", "mobile_no", "tel", "telephone", "telephoneNumber",
		"msisdn", "cell", "cellphone", "cell_phone", "fax", "fax_number", "whatsapp", "wa_id", "waId",
		"contact_number", "contactNo", "contact_num", "emergency_phone", "billing.phone_nr"}
	no := []string{"", "from", "to", "id", "contact", "contact_id", "phone_verified", "phone_number_id",
		"phoneCountryCode", "telemetry", "telemetry_count", "cellar", "faxed_at", "wa", "number", "phone_hash",
		"mobile_verified_at", "phonebook_size", strings.Repeat("phone_", 12)}
	for _, k := range yes {
		if !isPhoneKey(k) {
			t.Errorf("isPhoneKey(%q) = false, want true", k)
		}
	}
	for _, k := range no {
		if isPhoneKey(k) {
			t.Errorf("isPhoneKey(%q) = true, want false", k)
		}
	}
}

// A phone carved out of a JSON line leaves the document valid, and quotes are
// never added or lost.
func TestPhoneKeepsStructure(t *testing.T) {
	withEntityLabels(t, nil)
	lines := []string{
		`{"contacts":[{"profile":{"name":"Jonas"},"wa_id":"4917412345678"}],"messages":[{"from":"4917412345678","text":{"body":"hi"}}]}`,
		`{"phone": "+49 170 1234567", "token": "AbC9xY2kQ8pLmN0rZq7"}`,
		`{"phone":"(555) 234-5678","next":"ok"}`,
	}
	for _, line := range lines {
		out := ScanAndRedact(line)
		if !json.Valid([]byte(out)) {
			t.Errorf("not valid JSON after redaction: %q -> %q", line, out)
		}
		if strings.Count(out, `"`) != strings.Count(line, `"`) {
			t.Errorf("quote count changed: %q -> %q", line, out)
		}
		if !strings.Contains(out, "[HIDDEN:phone:") {
			t.Errorf("no phone marker: %q -> %q", line, out)
		}
	}
	// The secret after the phone is still scored on its own.
	if out := ScanAndRedact(lines[1]); strings.Contains(out, "AbC9xY2kQ8pLmN0rZq7") {
		t.Errorf("token after the phone leaked: %q", out)
	}
}

// A '+' at the start of a line is a diff marker (#192) and is emitted as
// framing, so a phone written first on a line loses its '+' and is not a
// phone; that is the price of keeping patches valid, recorded here so the
// gap is not mistaken for a detector bug.
func TestPhoneAtLineStartIsDiffMarker(t *testing.T) {
	withEntityLabels(t, nil)
	if out := ScanAndRedact("+4917412345678 called"); out != "+4917412345678 called" {
		t.Errorf("unexpected change: %q", out)
	}
	if out := ScanAndRedact("x +4917412345678 called"); !strings.Contains(out, "[HIDDEN:phone:") {
		t.Errorf("phone after a word must be hidden: %q", out)
	}
}

// Two numbers on one line, and a phone next to a card: each carved on its own,
// the card keeps its label where the two overlap.
func TestPhoneAndCardCarves(t *testing.T) {
	withEntityLabels(t, nil)
	out := ScanAndRedact("a +4917412345678 b (555) 234-5678 c")
	if strings.Count(out, "[HIDDEN:phone:") != 2 {
		t.Errorf("want two phone markers: %q", out)
	}
	out = ScanAndRedact("card=4539148803436467 phone=4917412345678")
	if !strings.Contains(out, "[HIDDEN:card:") || !strings.Contains(out, "[HIDDEN:phone:") {
		t.Errorf("want a card and a phone marker: %q", out)
	}
	// A number that is a phone by its '+' or its key and a card by Luhn and
	// issuer prefix is a phone: +4966570857316 is a German mobile that
	// happens to check out as a 13-digit Visa, one in ten does.
	for _, line := range []string{"phone=378282246310005", "call +4966570857316 now", `{"wa_id": "4966570857316"}`} {
		out = ScanAndRedact(line)
		if !strings.Contains(out, "[HIDDEN:phone:") || strings.Contains(out, "[HIDDEN:card:") {
			t.Errorf("phone label expected: %q -> %q", line, out)
		}
	}
	// Without a '+', punctuation or a phone key the same digits are a card.
	if out = ScanAndRedact("id 4966570857316"); !strings.Contains(out, "[HIDDEN:card:") {
		t.Errorf("card label expected on bare Luhn-valid digits: %q", out)
	}
}

// PII_SAFE_REGEX_LIST applies to phones as it does to cards, for a deployment
// whose own numbers have a phone shape.
func TestPhoneSafeRegex(t *testing.T) {
	withEntityLabels(t, func(cfg *Config) {
		if err := cfg.ApplySafeRegexes([]CustomRegexConfig{{Pattern: `^\+49 170 1234567$`}}); err != nil {
			t.Fatal(err)
		}
	})
	if out := ScanAndRedact("call +49 170 1234567 now"); out != "call +49 170 1234567 now" {
		t.Errorf("safe regex ignored for a phone: %q", out)
	}
	if out := ScanAndRedact("call +49 170 1234568 now"); !strings.Contains(out, "[HIDDEN:phone:") {
		t.Errorf("a phone outside the safe rule must still be hidden: %q", out)
	}
}

func TestPhoneStrategyIsSignature(t *testing.T) {
	withEntityLabels(t, nil)
	var got []string
	RedactionCallback = func(strategy string) { got = append(got, strategy) }
	defer func() { RedactionCallback = nil }()
	ScanAndRedact("call +4917412345678 now")
	if len(got) != 1 || got[0] != "signature" {
		t.Errorf("strategy = %v, want [signature]", got)
	}
}
