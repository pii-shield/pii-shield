package scanner

import (
	"strings"
	"unicode"
)

// A session id or a cookie value is a credential: whoever holds it is logged
// in. When it is all digits it never reaches the entropy threshold, and
// neither "cookie" nor "session" is a sensitive key, because a cookie
// header also carries consent flags and preferences and a session key also
// carries counts. So `DEBUG: Cookie: 8092026976377529079` (the dogtagpki
// install token, leak-radar repo-risks 2026-10-07) passed in 60 of 60 runs
// while `token=8092026976377529079` was hidden.
//
// The id is known by its key and its length, the way an identity number is:
// a run of 10 or more digits, alone, as the value of a key whose last word
// names a session or a cookie. A shorter number (session: 3, cookie_count:
// 12) and digits under any other key stay.

const minSessionDigits = 10 // shorter runs are counts, ports and small ids

// sessionKeyWords are the last word of a key that holds a session id, as
// splitKeyWords lowercases it (Cookie, JSESSIONID, PHPSESSID, sid).
var sessionKeyWords = map[string]bool{
	"cookie": true, "session": true, "sessionid": true, "sid": true,
	"jsessionid": true, "phpsessid": true, "sessid": true,
}

// isSessionKey reports whether key names a session id or a cookie value.
func isSessionKey(key string) bool {
	// Every session key ends in e (cookie), n (session) or d (sid,
	// session_id): reject the rest before splitKeyWords lowercases them
	// ("[12/Oct/2026" in every access log line would allocate).
	k := strings.TrimRight(key, "_-.")
	if k == "" {
		return false
	}
	switch k[len(k)-1] | 0x20 {
	case 'e', 'n', 'd':
	default:
		return false
	}
	var words [maxKeyWords]string
	n := splitKeyWords(key, &words)
	return n > 0 && isSessionKeyWords(words[:n])
}

// isSessionKeyWords judges a key by its last word, or by "session id"
// (session_id, sessionId). A key that only starts with such a word
// (session_count, cookie_consent) is not one.
func isSessionKeyWords(parts []string) bool {
	np := len(parts)
	last := parts[np-1]
	if last == "id" && np >= 2 {
		return parts[np-2] == "session"
	}
	return sessionKeyWords[last]
}

// matchSessionNumber matches a run of minSessionDigits or more digits at
// line[i:]. The caller has checked that the run is the value of a session
// key. It returns the end index or 0.
func matchSessionNumber(line string, i int) int {
	j := i
	for j < len(line) && isASCIIDigit(line[j]) {
		j++
	}
	if j-i < minSessionDigits {
		return 0
	}
	return j
}

// isSessionTokenValue reports whether val, the value of a session or cookie
// key in a name=value pair, has the shape of a session token: long enough
// for a secret, a letter in it, and a digit or a symbol. "Cookie: sid=abc123"
// passed because the pair was scored like any other and a short token stays
// under the entropy threshold, while the key says what it is. A word
// (session=default, cookie=accepted), a count or a date (session=3,
// session=2026-10-30) has no letter or no digit and stays; a run of digits
// is matched by its own rule (see matchSessionNumber). A ';' or ',' after
// the value separates the next cookie and is not part of it. A value that
// holds a space, a ';' or another pair is a cookie list ("Cookie":
// "session=<v>; theme=dark"), whose pairs are judged one by one.
func (st *configState) isSessionTokenValue(val string) bool {
	val = strings.TrimRight(val, ";,")
	if len(val) < st.config.MinSecretLength || !looksLikeSecretWord(val) ||
		strings.ContainsAny(val, " ;") || strings.IndexByte(strings.TrimRight(val, "="), '=') >= 0 {
		return false
	}
	return strings.IndexFunc(val, unicode.IsLetter) >= 0
}

// isSessionNumberValue reports whether val, a whole URL parameter value, is a
// run of minSessionDigits or more digits. The caller checks the key.
func isSessionNumberValue(val string) bool {
	return val != "" && isASCIIDigit(val[0]) && matchSessionNumber(val, 0) == len(val)
}
