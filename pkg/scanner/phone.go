package scanner

import "strings"

// FindPhoneSequences returns the byte ranges of telephone numbers in line,
// found by shape, in the order they appear. Three shapes are recognised:
//
//   - international: a '+', a country code and 8 to 15 digits in all, either
//     compact (+4917412345678) or in groups of 1 to 4 digits separated by one
//     space, '-' or '.', with an optional parenthesised group after the
//     country code (+49 170 1234567, +1 (555) 123-4567, +44.20.7946.0958);
//   - North American: ten digits as 3-3-4 with a parenthesised area code
//     ((555) 123-4567, (555)123-4567) or with one uniform separator
//     (555-123-4567, 555.123.4567), area code and exchange starting at 2-9;
//   - keyed: 7 to 15 digits, grouped or not, written as the value of a key
//     that names a phone (phone, phone_number, mobile, tel, msisdn, wa_id,
//     ...) after ':' or '=', with or without quotes ("wa_id": "4917412345678",
//     phone=0170 1234567, ?mobile=07700900123).
//
// A bare digit run with no '+', no NANP punctuation and no phone key is not a
// phone: a 13-digit millisecond timestamp, an order id and a phone written
// compact without its '+' look the same, and the card detector already
// showed what a checksum alone does to timestamps.
//
// Numbers are scored by entropy otherwise, and a phone is exactly the kind of
// value entropy cannot see: digits only, one character class, low Shannon.
// The same phone came back unchanged in 40 of 40 runs of the WhatsApp
// webhook shape from leak-radar (repo-risks 2026-09-30, btw-so/btw).
func FindPhoneSequences(line string) []Range {
	var ranges []Range
	for _, sn := range findShapedNumbers(line) {
		if !sn.id {
			ranges = append(ranges, sn.Range)
		}
	}
	return ranges
}

// shapedNumber is a digit run hidden by its shape or its key: a telephone
// number, or an identity document number when id is set (see idnumber.go).
type shapedNumber struct {
	Range
	id bool
}

// findShapedNumbers returns the telephone numbers (see FindPhoneSequences)
// and the identity numbers under a key (see matchKeyedIDNumber) of a line, in
// the order they appear. One pass finds both: each is digits that entropy
// cannot see, and a second walk over every line cost about 3% of throughput
// when the phone detector was added.
func findShapedNumbers(line string) []shapedNumber {
	if !strings.ContainsAny(line, "0123456789") {
		return nil
	}
	var ranges []shapedNumber
	n := len(line)
	for i := 0; i < n; {
		c := line[i]
		if c != '+' && c != '(' && !isASCIIDigit(c) {
			i++
			continue
		}
		// Glued to a word, a number or a token character on the left, the
		// candidate is the tail of something else: abc+1234567890 in base64,
		// 2026-123-4567 in a date-like id, user@+4917....
		if i > 0 && phoneGlue(line[i-1]) {
			i = skipPhoneRun(line, i)
			continue
		}
		end, id := 0, false
		switch c {
		case '+':
			end = matchInternationalPhone(line, i)
		case '(':
			end = matchNANPPhone(line, i)
		default:
			end = matchNANPPhone(line, i)
			if end == 0 {
				end, id = matchKeyedNumber(line, i)
			}
		}
		if end > 0 && !phoneGluedAfter(line, end) && !insideURL(line, i) {
			ranges = append(ranges, shapedNumber{Range: Range{Start: i, End: end}, id: id})
			i = end
			continue
		}
		i = skipPhoneRun(line, i)
	}
	return ranges
}

// insideURL reports whether the candidate at line[i:] sits in the query of a
// URL: the token it belongs to has a '?' or a "://" before it. A number there
// is not carved out of the line but left to maskURLParameters, which sees the
// whole URL: cut at the number, the rest of a quoted request line was no
// longer read as a URL and its other parameters were not scored.
func insideURL(line string, i int) bool {
	for j := i - 1; j >= 0; j-- {
		switch line[j] {
		case ' ', '\t', '"', '\'':
			return false
		case '?':
			return true
		case ':':
			if strings.HasPrefix(line[j:], "://") {
				return true
			}
		}
	}
	return false
}

// isPhoneValue reports whether val, a whole URL parameter value, is a phone:
// international or North American by shape, or, under a phone key, 7 to 15
// digits with optional '-' or '.' groups.
func isPhoneValue(val string, keyed bool) bool {
	if val == "" || !isASCIIDigit(val[len(val)-1]) {
		return false
	}
	switch val[0] {
	case '+':
		return matchInternationalPhone(val, 0) == len(val)
	case '(':
		return matchNANPPhone(val, 0) == len(val)
	}
	if !isASCIIDigit(val[0]) {
		return false
	}
	if matchNANPPhone(val, 0) == len(val) {
		return true
	}
	if !keyed {
		return false
	}
	digits := 0
	for i := 0; i < len(val); i++ {
		switch {
		case isASCIIDigit(val[i]):
			digits++
		case (val[i] == '-' || val[i] == '.') && i > 0 && isASCIIDigit(val[i-1]):
		default:
			return false
		}
	}
	return digits >= minKeyedDigits && digits <= maxPhoneDigits
}

// phoneGlue reports whether a byte before a candidate makes it part of a
// larger token rather than a number of its own.
func phoneGlue(c byte) bool {
	return isASCIILetter(c) || isASCIIDigit(c) || c == '+' || c == '-' || c == '.' || c == '/' || c == '@' || c == '_' || c == '%'
}

// phoneGluedAfter reports whether the byte after a match continues it: a
// letter, a digit, '_', '@', '/', '%', or a '-' or '.' that leads into more
// digits (+1234567.89 is a signed decimal, not a phone).
func phoneGluedAfter(line string, end int) bool {
	if end >= len(line) {
		return false
	}
	c := line[end]
	if isASCIILetter(c) || isASCIIDigit(c) || c == '_' || c == '@' || c == '/' || c == '%' || c == '+' {
		return true
	}
	return (c == '-' || c == '.') && end+1 < len(line) && isASCIIDigit(line[end+1])
}

// skipPhoneRun moves past the digits, or the single '+' or '(', at i so a
// rejected candidate is not retried from its second digit.
func skipPhoneRun(line string, i int) int {
	if !isASCIIDigit(line[i]) {
		return i + 1
	}
	for i < len(line) && isASCIIDigit(line[i]) {
		i++
	}
	return i
}

const (
	minPhoneDigits    = 8  // the shortest full international numbers
	maxPhoneDigits    = 15 // E.164
	minKeyedDigits    = 7  // a national number under a phone key
	maxPhoneGroup     = 8  // digits in one group (a German subscriber number is seven)
	maxAreaCodeDigits = 4  // digits in a parenthesised group
	maxPhoneGroups    = 6  // groups after the country code
)

// matchInternationalPhone matches '+', a 1-3 digit country code and the
// national number at line[i:], and returns the end index or 0.
func matchInternationalPhone(line string, i int) int {
	n := len(line)
	j := i + 1
	cc := 0
	for j < n && isASCIIDigit(line[j]) && cc < 3 {
		j++
		cc++
	}
	if cc == 0 {
		return 0
	}
	digits := cc
	if j < n && isASCIIDigit(line[j]) {
		// A compact number: the country code and the rest are one run.
		for j < n && isASCIIDigit(line[j]) {
			j++
			digits++
		}
		if digits < minPhoneDigits || digits > maxPhoneDigits {
			return 0
		}
		return j
	}
	// Grouped: one separator, then groups of 1-4 digits, the first of which
	// may sit in parentheses.
	end, more := matchPhoneGroups(line, j, digits, true)
	if end == 0 || more < minPhoneDigits || more > maxPhoneDigits {
		return 0
	}
	return end
}

// matchPhoneGroups consumes separator-led digit groups from line[j:] and
// returns the end of the last group and the digit total including have. With
// parens, the first group may be parenthesised (an area code); the space that
// usually follows it is not a separator, so "+1 (555) 234-5678" reads as one
// number. The other separators must all be the same character, and a single
// '.' is a decimal point, so '.' counts only when it is used at least twice.
// The match never ends in a separator.
func matchPhoneGroups(line string, j, have int, parens bool) (int, int) {
	n := len(line)
	end, digits := 0, have
	sep := byte(0)
	dots := 0
	afterArea := false // the group after "(555) " needs no separator of its own
	for g := 0; g < maxPhoneGroups; g++ {
		k := j
		if k < n && (line[k] == ' ' || line[k] == '-' || line[k] == '.') {
			if sep == 0 {
				sep = line[k]
			} else if line[k] != sep {
				break
			}
			if line[k] == '.' {
				dots++
			}
			k++
		} else if g > 0 && !afterArea {
			break
		}
		afterArea = false
		if parens && g == 0 && k < n && line[k] == '(' {
			k++
			d := 0
			for k < n && isASCIIDigit(line[k]) && d < maxAreaCodeDigits {
				k++
				d++
			}
			if d == 0 || k >= n || line[k] != ')' {
				break
			}
			k++
			digits += d
			end, j = k, k
			sep = 0
			if k < n && line[k] == ' ' && k+1 < n && isASCIIDigit(line[k+1]) {
				j = k + 1
				afterArea = true
			}
			continue
		}
		d := 0
		for k < n && isASCIIDigit(line[k]) && d < maxPhoneGroup {
			k++
			d++
		}
		if d == 0 || (k < n && isASCIIDigit(line[k])) {
			break // no group, or a group longer than allowed
		}
		digits += d
		end, j = k, k
	}
	if end == 0 || dots == 1 {
		return 0, 0
	}
	return end, digits
}

// matchNANPPhone matches a ten-digit North American number at line[i:],
// written (NNN) NNN-NNNN, (NNN)NNN-NNNN, (NNN) NNN NNNN, NNN-NNN-NNNN or
// NNN.NNN.NNNN, and returns the end index or 0. The area code and the
// exchange start with 2-9, as the numbering plan requires.
func matchNANPPhone(line string, i int) int {
	n := len(line)
	j := i
	paren := false
	if j < n && line[j] == '(' {
		paren = true
		j++
	}
	if !nanpGroup(line, j, 3) {
		return 0
	}
	j += 3
	sep := byte(0)
	if paren {
		if j >= n || line[j] != ')' {
			return 0
		}
		j++
		if j < n && line[j] == ' ' {
			j++
		}
	} else {
		if j >= n || (line[j] != '-' && line[j] != '.') {
			return 0
		}
		sep = line[j]
		j++
	}
	if !nanpGroup(line, j, 3) {
		return 0
	}
	j += 3
	if j >= n {
		return 0
	}
	switch {
	case paren && (line[j] == '-' || line[j] == ' ' || line[j] == '.'):
	case !paren && line[j] == sep:
	default:
		return 0
	}
	j++
	if !digitGroup(line, j, 4) || (j+4 < n && isASCIIDigit(line[j+4])) {
		return 0
	}
	return j + 4
}

// nanpGroup reports whether line[j:j+k] is k digits whose first is 2-9.
func nanpGroup(line string, j, k int) bool {
	return digitGroup(line, j, k) && line[j] >= '2'
}

// digitGroup reports whether line[j:j+k] is exactly k ASCII digits.
func digitGroup(line string, j, k int) bool {
	if j+k > len(line) {
		return false
	}
	for m := 0; m < k; m++ {
		if !isASCIIDigit(line[j+m]) {
			return false
		}
	}
	return true
}

// matchKeyedNumber matches the digits at line[i:] as the value of a key that
// names a phone or an identity document: <key><sep><value> where <sep> is ':'
// or '=' with optional spaces and quotes around it. It returns the end index,
// or 0, and whether the key names an identity document.
func matchKeyedNumber(line string, i int) (end int, id bool) {
	key := phoneKeyBefore(line, i)
	if key == "" {
		return 0, false
	}
	var words [maxKeyWords]string
	n := splitKeyWords(key, &words)
	switch {
	case n == 0:
		return 0, false
	case isPhoneKeyWords(words[:n]):
		return matchKeyedPhone(line, i), false
	case isIDKeyWords(words[:n]):
		return matchKeyedIDNumber(line, i), true
	}
	return 0, false
}

// matchKeyedPhone matches 7-15 digits at line[i:], compact or in groups
// separated by one space, '-' or '.', with an optional parenthesised first
// group. The caller has checked that the run is the value of a phone key. It
// returns the end index or 0.
func matchKeyedPhone(line string, i int) int {
	n := len(line)
	j := i
	digits := 0
	for j < n && isASCIIDigit(line[j]) && digits < maxPhoneGroup {
		j++
		digits++
	}
	if j < n && isASCIIDigit(line[j]) {
		for j < n && isASCIIDigit(line[j]) {
			j++
			digits++
		}
		if digits < minKeyedDigits || digits > maxPhoneDigits {
			return 0
		}
		return j
	}
	end, more := matchPhoneGroups(line, j, digits, false)
	if end == 0 {
		end, more = j, digits
	}
	if more < minKeyedDigits || more > maxPhoneDigits {
		return 0
	}
	return end
}

// phoneKeyBefore returns the key that introduces the value at line[i:], or
// "" when the bytes before i are not <key> [quote] [spaces] ':'|'=' [spaces]
// [quote]. A '(' directly before the digits is accepted as the start of a
// parenthesised group.
func phoneKeyBefore(line string, i int) string {
	j := i - 1
	if j >= 0 && line[j] == '(' {
		j--
	}
	if j >= 0 && (line[j] == '"' || line[j] == '\'') {
		j--
	}
	for j >= 0 && line[j] == ' ' {
		j--
	}
	if j < 0 || (line[j] != ':' && line[j] != '=') {
		return ""
	}
	j--
	for j >= 0 && line[j] == ' ' {
		j--
	}
	if j >= 0 && (line[j] == '"' || line[j] == '\'') {
		j--
	}
	end := j + 1
	for j >= 0 && (isASCIILetter(line[j]) || isASCIIDigit(line[j]) || line[j] == '_' || line[j] == '-' || line[j] == '.') {
		j--
	}
	return line[j+1 : end]
}

// phoneKeyWords are the last word of a key that holds a telephone number, once
// a trailing "number", "no", "num" or "nr" is dropped (phone_number,
// mobileNumber, contact_no). A key whose last word is something else
// (phone_verified, phone_number_id, phoneCountryCode) is not a phone value.
var phoneKeyWords = map[string]bool{
	"phone": true, "telephone": true, "tel": true, "mobile": true, "msisdn": true,
	"cell": true, "cellphone": true, "fax": true, "whatsapp": true, "phonenumber": true,
	"mobilephone": true,
}

// isPhoneKey reports whether key names a telephone number. The key is split
// into words on '_', '-', '.' and camelCase boundaries and judged by its last
// word; "wa_id" (the WhatsApp Cloud API sender id, a phone) is a special case,
// and "contact" counts only as contact_number / contactNo.
func isPhoneKey(key string) bool {
	var words [maxKeyWords]string
	n := splitKeyWords(key, &words)
	return n > 0 && isPhoneKeyWords(words[:n])
}

// maxKeyWords is the most words a key may have to be judged by its last ones.
const maxKeyWords = 8

// splitKeyWords splits a key into lowercase words on '_', '-', '.' and
// camelCase boundaries, writes them into parts and returns how many there
// are. It returns 0 for an empty key, one longer than 64 bytes or one with
// more than maxKeyWords words. The caller owns the array, so a key on the
// hot path costs no allocation.
func splitKeyWords(key string, parts *[maxKeyWords]string) int {
	if len(key) > 64 {
		return 0
	}
	np := 0
	start := 0
	for i := 0; i <= len(key); i++ {
		boundary := i == len(key) || key[i] == '_' || key[i] == '-' || key[i] == '.' ||
			(i > start && key[i] >= 'A' && key[i] <= 'Z' && key[i-1] >= 'a' && key[i-1] <= 'z')
		if !boundary {
			continue
		}
		if i > start {
			if np == len(parts) {
				return 0
			}
			parts[np] = strings.ToLower(key[start:i])
			np++
		}
		if i < len(key) && (key[i] == '_' || key[i] == '-' || key[i] == '.') {
			start = i + 1
		} else {
			start = i
		}
	}
	return np
}

// isNumberSuffix reports whether w is a word that only says "number" at the
// end of a key (phone_number, passportNo, id_nr).
func isNumberSuffix(w string) bool {
	return w == "number" || w == "no" || w == "num" || w == "nr"
}

func isPhoneKeyWords(parts []string) bool {
	np := len(parts)
	last := parts[np-1]
	if last == "id" && np >= 2 && parts[np-2] == "wa" {
		return true
	}
	stripped := false
	if isNumberSuffix(last) && np >= 2 {
		last = parts[np-2]
		stripped = true
	}
	if last == "contact" {
		return stripped
	}
	return phoneKeyWords[last]
}
