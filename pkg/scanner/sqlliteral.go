package scanner

import "strings"

// jsonDocumentEnd returns the index after the bracket that closes the JSON
// object or array opening at s[i] ('{' or '['), honouring double-quoted
// strings and backslash escapes inside them, or -1 when it does not close.
func jsonDocumentEnd(s string, i int) int {
	depth := 0
	inStr := false
	for j := i; j < len(s); j++ {
		c := s[j]
		if inStr {
			switch c {
			case '\\':
				j++
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return -1
}

// escapedOrBacktickWrap reports whether token is a value wrapped in a pair of
// backslash-escaped quotes (\'x\' or \"x\") or in backticks (`x`), with
// no other such wrapper inside, and returns the length of the opening and
// closing framing.
func escapedOrBacktickWrap(token string) (pre, post int, ok bool) {
	n := len(token)
	if n >= 5 && token[0] == '\\' && (token[1] == '\'' || token[1] == '"') &&
		token[n-2] == '\\' && token[n-1] == token[1] && !strings.Contains(token[2:n-2], token[:2]) {
		return 2, 2, true
	}
	if n >= 3 && token[0] == '`' && token[n-1] == '`' && strings.IndexByte(token[1:n-1], '`') < 0 {
		return 1, 1, true
	}
	return 0, 0, false
}
