package scanner

import (
	"strings"
	"unicode/utf8"
)

// keyMatcher answers "does this key contain any of the sensitive-key
// entries, ignoring case" in one pass over the key. isSensitiveKey used to
// lowercase every bare token and run strings.Contains once per entry; on the
// access log that loop was 19-20% of scan time (AG-2026-10-24-02). The
// matcher is an Aho-Corasick automaton over the entries' bytes, compiled to
// a full transition table once per config snapshot, so a key costs one table
// step per byte whatever the number of entries.
//
// It reproduces "strings.Contains(strings.ToLower(key), entry) for some
// entry" exactly. An ASCII key is walked as it is, A-Z folded on the way,
// since ToLower changes nothing else in it. A key with a non-ASCII byte is
// lowercased first, because Unicode lowering can change byte lengths and
// even make ASCII (the Kelvin sign becomes k), and the lowered bytes are
// walked. An entry with an upper-case letter can never be inside a lowered
// key and is left out; an empty entry is inside every key.
type keyMatcher struct {
	// class maps a byte to its column in next; 0 is every byte that appears
	// in no entry, and it always leads back towards the root.
	class [256]uint8
	// next holds the transition table as row offsets: a state is the offset
	// of its row, the root is 0, and next[state+class[b]] is the state after
	// byte b.
	next []int32
	// hit, indexed like next by row offset, marks the states where an entry
	// ends, directly or through a suffix link.
	hit []bool
	// always is set by an empty entry, which strings.Contains finds in any
	// key.
	always bool
}

// newKeyMatcher builds the matcher for keys. Entries with an upper-case
// ASCII letter are skipped (see keyMatcher).
func newKeyMatcher(keys []string) *keyMatcher {
	m := &keyMatcher{}
	var pats []string
	for _, k := range keys {
		if hasASCIIUpper(k) {
			continue
		}
		if k == "" {
			m.always = true
			continue
		}
		pats = append(pats, k)
	}

	n := int32(1)
	for _, p := range pats {
		for i := 0; i < len(p); i++ {
			if m.class[p[i]] == 0 {
				m.class[p[i]] = uint8(n)
				n++
			}
		}
	}

	// The trie, built in place in the flat table: a state is the offset of
	// its row of n cells, -1 is a missing edge.
	newState := func() int32 {
		s := int32(len(m.next))
		for c := int32(0); c < n; c++ {
			m.next = append(m.next, -1)
		}
		m.hit = append(m.hit, make([]bool, n)...)
		return s
	}
	newState()
	for _, p := range pats {
		s := int32(0)
		for i := 0; i < len(p); i++ {
			c := int32(m.class[p[i]])
			if m.next[s+c] < 0 {
				m.next[s+c] = newState()
			}
			s = m.next[s+c]
		}
		m.hit[s] = true
	}

	// Breadth-first: fill missing edges from the suffix link and inherit its
	// hit flag, which turns the trie into a DFA.
	fail := make(map[int32]int32, len(m.next)/int(n))
	queue := make([]int32, 0, len(m.next)/int(n))
	for c := int32(0); c < n; c++ {
		if t := m.next[c]; t < 0 {
			m.next[c] = 0
		} else {
			fail[t] = 0
			queue = append(queue, t)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		f := fail[s]
		m.hit[s] = m.hit[s] || m.hit[f]
		for c := int32(0); c < n; c++ {
			if t := m.next[s+c]; t < 0 {
				m.next[s+c] = m.next[f+c]
			} else {
				fail[t] = m.next[f+c]
				queue = append(queue, t)
			}
		}
	}
	return m
}

// find reports whether key contains an entry, ignoring case. lowered is the
// lowercased key when find had to make one (a key with a non-ASCII byte),
// so the caller can reuse it instead of lowering again; it is "" otherwise.
func (m *keyMatcher) find(key string) (found bool, lowered string) {
	if m.always {
		return true, ""
	}
	s := int32(0)
	for i := 0; i < len(key); i++ {
		b := key[i]
		if b >= utf8.RuneSelf {
			lowered = strings.ToLower(key)
			return m.walk(lowered), lowered
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		s = m.next[s+int32(m.class[b])]
		if m.hit[s] {
			return true, ""
		}
	}
	return false, ""
}

// walk reports whether the lowered key contains an entry, byte for byte.
func (m *keyMatcher) walk(lowered string) bool {
	s := int32(0)
	for i := 0; i < len(lowered); i++ {
		s = m.next[s+int32(m.class[lowered[i]])]
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

// containsFoldPW reports whether key contains "pw" in any case of the two
// ASCII letters, the same answer as strings.Contains(strings.ToLower(key),
// "pw") for an ASCII key, without the lowercased copy.
func containsFoldPW(key string) bool {
	for i := 0; i+1 < len(key); i++ {
		if key[i]|0x20 == 'p' && key[i+1]|0x20 == 'w' {
			return true
		}
	}
	return false
}
