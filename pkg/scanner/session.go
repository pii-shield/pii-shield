package scanner

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

// isSessionNumberValue reports whether val, a whole URL parameter value, is a
// run of minSessionDigits or more digits. The caller checks the key.
func isSessionNumberValue(val string) bool {
	return val != "" && isASCIIDigit(val[0]) && matchSessionNumber(val, 0) == len(val)
}
