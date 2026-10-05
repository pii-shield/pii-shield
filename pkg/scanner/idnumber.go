package scanner

// An identity document number - a national id, a social security number, a
// passport or tax number - is digits only, like a phone, so entropy never
// reaches the threshold: "idNumber": "141638835" passed in 20 of 20 runs of a
// form-payload shape from leak-radar (complaints 2026-10-04,
// BFPSoftware/bfpforyou2#49). A checksum cannot find it either: every country
// has its own, and one bare nine-digit number in ten passes a mod-10 check
// (the card detector found 374 "cards" in 300 000 access-log lines and all of
// them were timestamps before it asked for an issuer prefix).
//
// So the number is known by its key, the way a phone under a phone key is: 6
// to 15 digits, compact or in groups, as the value of a key that names an
// identity document. Digits under any other key (user_id, order_id, id) stay.

const (
	minIDDigits = 6  // the shortest national numbers in use
	maxIDDigits = 15 // above this a digit run is a card or an account number
)

// idDocumentWords are the last word of a key that holds an identity number,
// once a trailing "number", "no", "num" or "nr" is dropped (passport_number,
// ssnNo). The run-together forms cover keys with no word boundary to split
// on (IDNumber, nationalid).
var idDocumentWords = map[string]bool{
	"ssn": true, "passport": true, "cpf": true, "dni": true, "nin": true, "tin": true,
	"aadhaar": true, "zehut": true, "teudatzehut": true,
	"idnumber": true, "nationalid": true, "taxid": true, "socialsecurity": true,
	"passportnumber": true, "identitynumber": true,
}

// idOwnerWords are the words that make "id" an identity document rather than
// a record id: national_id, tax_id, citizenId.
var idOwnerWords = map[string]bool{
	"national": true, "tax": true, "taxpayer": true, "citizen": true, "identity": true,
	"government": true, "gov": true, "state": true,
}

// idRecordWords are the words that make "id number" a record number, not a
// person's: order_id_number, transactionIdNo.
var idRecordWords = map[string]bool{
	"order": true, "transaction": true, "tracking": true, "invoice": true, "request": true,
	"session": true, "ticket": true, "message": true, "product": true, "item": true,
	"batch": true, "job": true, "trace": true, "device": true, "payment": true,
}

// isIDKey reports whether key names an identity document number. The key is
// split into words like a phone key and judged by its last words: a document
// word (ssn, passport_number, cpf), "id" after a word that says whose id it is
// (national_id, taxId), "id number" (idNumber, id_no, childIdNumber), identity
// number, social security (number). A record id - id, user_id, order_id,
// order_id_number - is not one, and neither is a key that only starts with
// such words (ssn_verified, passport_country, id_number_type).
func isIDKey(key string) bool {
	var words [maxKeyWords]string
	n := splitKeyWords(key, &words)
	return n > 0 && isIDKeyWords(words[:n])
}

func isIDKeyWords(parts []string) bool {
	np := len(parts)
	stripped := false
	if isNumberSuffix(parts[np-1]) && np >= 2 {
		np--
		stripped = true
	}
	last := parts[np-1]
	prev := ""
	if np >= 2 {
		prev = parts[np-2]
	}
	switch last {
	case "id":
		return idOwnerWords[prev] || (stripped && !idRecordWords[prev])
	case "identity":
		return stripped
	case "security":
		return prev == "social"
	}
	return idDocumentWords[last]
}

// matchKeyedIDNumber matches 6-15 digits at line[i:], compact or in groups
// separated by one '-' or '.' (078-05-1120, 123.456.789-09), and by one space
// when the value is quoted ("1234 5678 9012"). The caller has checked that
// the run is the value of an identity key. It returns the end index or 0.
func matchKeyedIDNumber(line string, i int) int {
	quoted := i > 0 && (line[i-1] == '"' || line[i-1] == '\'')
	n := len(line)
	j := i
	digits := 0
	for j < n {
		c := line[j]
		switch {
		case isASCIIDigit(c):
			digits++
		case (c == '-' || c == '.' || (c == ' ' && quoted)) && j+1 < n && isASCIIDigit(line[j+1]) && isASCIIDigit(line[j-1]):
		default:
			if digits < minIDDigits || digits > maxIDDigits {
				return 0
			}
			return j
		}
		j++
	}
	if digits < minIDDigits || digits > maxIDDigits {
		return 0
	}
	return j
}

// isIDNumberValue reports whether val, a whole URL parameter value, is 6 to
// 15 digits with optional '-' or '.' groups. The caller checks the key.
func isIDNumberValue(val string) bool {
	if val == "" || !isASCIIDigit(val[0]) {
		return false
	}
	return matchKeyedIDNumber(val, 0) == len(val)
}
