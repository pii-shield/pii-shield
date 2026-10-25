package scanner

// keyMatcher answers "does this ASCII key contain any of the sensitive-key
// entries, ignoring case" in one pass over the key. isSensitiveKey used to
// lowercase every bare token and run strings.Contains once per entry; on the
// access log that loop was 19-20% of scan time (AG-2026-10-24-02). The
// matcher is an Aho-Corasick automaton over the ASCII entries, compiled to a
// full transition table once per config snapshot, so a key costs one table
// step per byte whatever the number of entries.
//
// It reproduces strings.Contains(strings.ToLower(key), entry) for an ASCII
// key exactly: A-Z are folded while walking, an entry with an upper-case
// letter can never be inside a lowercased key and is left out, and an empty
// entry is inside every key.
type keyMatcher struct {
	// class maps a folded byte to its column in next; 0 is every byte that
	// appears in no entry, and it always leads back towards the root.
	class [256]uint8
	// next is the transition table, nclass columns per state, state 0 the
	// root.
	next   []int32
	nclass int
	// hit marks the states where an entry ends, directly or through a
	// suffix link.
	hit []bool
	// always is set by an empty entry, which strings.Contains finds in any
	// key.
	always bool
}

// newKeyMatcher builds the matcher for the ASCII entries of keys. Entries
// with a non-ASCII byte or an upper-case letter are skipped (see keyMatcher).
func newKeyMatcher(keys []string) *keyMatcher {
	m := &keyMatcher{}
	var pats []string
	for _, k := range keys {
		if hasNonASCII(k) || hasASCIIUpper(k) {
			continue
		}
		if k == "" {
			m.always = true
			continue
		}
		pats = append(pats, k)
	}

	n := 1
	for _, p := range pats {
		for i := 0; i < len(p); i++ {
			if m.class[p[i]] == 0 {
				m.class[p[i]] = uint8(n)
				n++
			}
		}
	}
	m.nclass = n

	// Trie, with -1 for a missing edge.
	trie := [][]int32{newRow(n)}
	hit := []bool{false}
	for _, p := range pats {
		s := int32(0)
		for i := 0; i < len(p); i++ {
			c := m.class[p[i]]
			if trie[s][c] < 0 {
				trie = append(trie, newRow(n))
				hit = append(hit, false)
				trie[s][c] = int32(len(trie) - 1)
			}
			s = trie[s][c]
		}
		hit[s] = true
	}

	// Breadth-first: fill missing edges from the suffix link and inherit its
	// hit flag, which turns the trie into a DFA.
	fail := make([]int32, len(trie))
	queue := make([]int32, 0, len(trie))
	for c := 0; c < n; c++ {
		if t := trie[0][c]; t < 0 {
			trie[0][c] = 0
		} else {
			fail[t] = 0
			queue = append(queue, t)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		hit[s] = hit[s] || hit[fail[s]]
		for c := 0; c < n; c++ {
			if t := trie[s][c]; t < 0 {
				trie[s][c] = trie[fail[s]][c]
			} else {
				fail[t] = trie[fail[s]][c]
				queue = append(queue, t)
			}
		}
	}

	m.next = make([]int32, 0, len(trie)*n)
	for _, row := range trie {
		m.next = append(m.next, row...)
	}
	m.hit = hit
	return m
}

func newRow(n int) []int32 {
	row := make([]int32, n)
	for i := range row {
		row[i] = -1
	}
	return row
}

// containsAny reports whether the ASCII key contains an entry, ignoring the
// case of A-Z. The caller makes sure the key is ASCII.
func (m *keyMatcher) containsAny(key string) bool {
	if m.always {
		return true
	}
	s := int32(0)
	n := int32(m.nclass)
	for i := 0; i < len(key); i++ {
		b := key[i]
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		s = m.next[s*n+int32(m.class[b])]
		if m.hit[s] {
			return true
		}
	}
	return false
}

func hasASCIIUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// containsFoldPW reports whether an ASCII key contains "pw" in any case, the
// same answer as strings.Contains(strings.ToLower(key), "pw") without the
// lowercased copy.
func containsFoldPW(key string) bool {
	for i := 0; i+1 < len(key); i++ {
		if key[i]|0x20 == 'p' && key[i+1]|0x20 == 'w' {
			return true
		}
	}
	return false
}
