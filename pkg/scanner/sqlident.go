package scanner

// isIdentifierName reports whether s is a database identifier made of words,
// the way an index, a constraint or a qualified column is named:
// users.email, order_items.email, order_items.PRIMARY, idx_user_email,
// uq_users_email. Parts are split on '.' and '_' only, each is ASCII letters
// with at most a trailing run of digits, two or more letters long, one of
// them three or more, and the letter pairs average above
// compoundMinBigramAvg, as for isWordCompound. Unlike isWordCompound, parts
// of equal length are allowed: order_items.email is a table and a column,
// not a generated code such as abcd-efgh-ijkl, which is dash-separated. A
// name that holds a sensitive word (api_key, auth_token) is not one.
func (st *configState) isIdentifierName(s string) bool {
	if st.config.DisableBigramCheck || len(s) < 3 || len(s) > 64 {
		return false
	}
	nParts, hasWord := 0, false
	sum, pairs := 0.0, 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' && s[i] != '_' {
			continue
		}
		p := s[start:i]
		start = i + 1
		if p == "" {
			return false
		}
		letters := 0
		for letters < len(p) && isASCIILetter(p[letters]) {
			letters++
		}
		for j := letters; j < len(p); j++ {
			if !isASCIIDigit(p[j]) {
				return false
			}
		}
		if letters < 2 {
			return false
		}
		if letters >= 3 {
			hasWord = true
		}
		for j := 1; j < letters; j++ {
			sum += st.letterBigram(p[j-1], p[j])
			pairs++
		}
		nParts++
	}
	if nParts < 2 || !hasWord || (pairs > 2 && sum/float64(pairs) <= compoundMinBigramAvg) {
		return false
	}
	return !st.namesSecret(s)
}
