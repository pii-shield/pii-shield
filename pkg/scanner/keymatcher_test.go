package scanner

import (
	"math/rand"
	"strings"
	"testing"
)

// referenceContains is the substring step of isSensitiveKey as it was before
// O1 (ToLower, then strings.Contains once per entry), the oracle for the
// matcher. The pub/key and entropy tail after the match is unchanged code
// and is tested through isSensitiveKey itself.
func referenceContains(keys []string, key string) bool {
	k := strings.ToLower(key)
	for _, sk := range keys {
		if strings.Contains(k, sk) {
			return true
		}
	}
	return false
}

// keyMatcherConfigs are the key lists the equivalence test runs under: the
// defaults, a custom list with an upper-case and an overlapping entry, an
// empty entry (inside every key), only non-ASCII entries, and no entries.
func keyMatcherConfigs() map[string]Config {
	withKeys := func(keys ...string) Config {
		c := DefaultConfig()
		c.SensitiveKeys = keys
		return c
	}
	patterns := DefaultConfig()
	patterns.SensitiveKeyPatterns = []string{`(^|_)name$`}
	return map[string]Config{
		"default":      DefaultConfig(),
		"patterns":     patterns,
		"custom":       withKeys("ssn", "Token", "tok", "token_id", "a.b", "x-api-key"),
		"empty-entry":  withKeys("secret", ""),
		"non-ascii":    withKeys("密码", "パスワード"),
		"no-entries":   withKeys(),
		"single-byte":  withKeys("q"),
		"nested-words": withKeys("he", "she", "his", "hers"),
	}
}

func keyMatcherCorpus(rng *rand.Rand) []string {
	keys := []string{
		"", "a", "password", "PASSWORD", "Password", "db_password", "dbPassword",
		"public_key", "PubKey", "pub_key", "api_key", "API-KEY", "x-api-key",
		"X-Api-Key", "authorization", "Authorization", "author", "keywords",
		"monkey", "turnkey", "secret", "client_secret", "CLIENT_SECRET",
		"aws_secret_access_key", "token", "csrf-token", "access_token", "tokens",
		"signature", "design", "cvv", "cvc", "pass", "passport", "bypass",
		"PW", "pw", "db_pw", "dbPwd", "smtp_pwd", "PWD", "pwd", "shipway",
		"mapwidth", "httpwrapper", "first_name", "name", "username",
		"ssn", "SSN", "token_id", "a.b", "AxB", "ab", "he", "ushers", "HIS",
		"密码", "用户密码", "パスワード", "KelvinK", "Key", "İsecret",
		"aGVsbG9fc2VjcmV0X2tleV9mb3JfdGVzdA", "SecretKeyABCDEFGHIJKLmnop1234",
		"tk_test_secretXyZ123AbcDef456Ghi", "my_secret_token_value_long_name",
		"Bearer", "basic", "q", "Q", "qq", "\x00key", "key\x7f", "ke\ty",
	}
	// Random keys over an alphabet that hits the entries often: their
	// letters in both cases, separators, digits and one non-ASCII rune.
	const alphabet = "pPaAsSwWoOrRdDkKeEyYtTnNcCvVuUhHiIgGbBlLqQ_-.0129 é"
	runes := []rune(alphabet)
	for i := 0; i < 20000; i++ {
		n := 1 + rng.Intn(24)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteRune(runes[rng.Intn(len(runes))])
		}
		keys = append(keys, b.String())
	}
	// Random printable ASCII, which also reaches bytes in no entry.
	for i := 0; i < 5000; i++ {
		n := 1 + rng.Intn(32)
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = byte(0x20 + rng.Intn(0x5f))
		}
		keys = append(keys, string(buf))
	}
	return keys
}

// TestKeyMatcherMatchesReference proves the single-pass match gives the same
// answer as the old ToLower + strings.Contains loop for every key in the
// corpus under every config, and that the lowered key it hands back is the
// one isSensitiveKey would have made.
func TestKeyMatcherMatchesReference(t *testing.T) {
	keys := keyMatcherCorpus(rand.New(rand.NewSource(1)))
	for name, cfg := range keyMatcherConfigs() {
		st := buildConfigState(cfg)
		mismatches := 0
		for _, k := range keys {
			got, lowered := st.keyMatcher.find(k)
			want := referenceContains(cfg.SensitiveKeys, k)
			if got != want || (lowered != "" && lowered != strings.ToLower(k)) {
				mismatches++
				if mismatches <= 10 {
					t.Errorf("%s: find(%q) = %v, %q; reference %v", name, k, got, lowered, want)
				}
			}
		}
		if mismatches > 10 {
			t.Errorf("%s: %d mismatches in %d keys", name, mismatches, len(keys))
		}
	}
}

// TestIsSensitiveKeyTail pins the answers of the whole function on the keys
// that reach the code after the match (pub/key reject, entropy reject,
// pw/pwd components) and on non-ASCII keys, under the default list.
func TestIsSensitiveKeyTail(t *testing.T) {
	st := buildConfigState(DefaultConfig())
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"password", true},
		{"Password", true},
		{"public_key", false},
		{"PubKey", false},
		{"x-api-key", true},
		{"author", true}, // contains auth, as before O1
		{"aGVsbG9fc2VjcmV0X2tleV9mb3JfdGVzdA", false},
		{"my_secret_token_value_long_name", true},
		{"db_pw", true},
		{"dbPwd", true},
		{"PWD", false},
		{"shipway", false},
		{"密码", true},
		{"用户密码", true},
		{"パスワード", true},
		{"Kelvin\u212a", false},
		{"\u212aey", true}, // the Kelvin sign lowers to k: key
		{"İsecret", true},
		{"", false},
	} {
		if got := st.isSensitiveKey(tc.key); got != tc.want {
			t.Errorf("isSensitiveKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

// TestKeyMatcherContainsAny checks the automaton alone against
// strings.Contains on lowercased keys, including entries that end
// inside other entries (he in she, his in hers), where a missed suffix link
// would lose a match.
func TestKeyMatcherContainsAny(t *testing.T) {
	cases := []struct {
		entries []string
		key     string
		want    bool
	}{
		{[]string{"he", "she", "his", "hers"}, "ushers", true},
		{[]string{"hers"}, "ushe", false},
		{[]string{"she", "he"}, "sHE", true},
		{[]string{"abcd", "bc"}, "abce", true},
		{[]string{"abcd", "cdx"}, "abcdx", true},
		{[]string{"aab"}, "aaab", true},
		{[]string{"Token"}, "token", false},
		{[]string{"密码"}, "用户密码", true},
		{[]string{"key"}, "\u212aey", true},
		{[]string{"kelvin"}, "\u212aelvin", true},
		{[]string{""}, "anything", true},
		{nil, "password", false},
		{[]string{"key"}, "", false},
	}
	for _, tc := range cases {
		m := newKeyMatcher(tc.entries)
		if got, _ := m.find(tc.key); got != tc.want {
			t.Errorf("entries %q, key %q: got %v, want %v", tc.entries, tc.key, got, tc.want)
		}
	}
}

func TestContainsFoldPW(t *testing.T) {
	for _, k := range []string{"", "p", "pw", "PW", "pW", "Pw", "db_pw", "dbPwd", "xpx", "w p", "spawn", "ship way", "mapwidth"} {
		want := strings.Contains(strings.ToLower(k), "pw")
		if got := containsFoldPW(k); got != want {
			t.Errorf("containsFoldPW(%q) = %v, want %v", k, got, want)
		}
	}
}

func BenchmarkIsSensitiveKey(b *testing.B) {
	st := buildConfigState(DefaultConfig())
	keys := []string{"GET", "/api/v1/users", "HTTP/1.1", "200", "Mozilla/5.0", "user_id", "password", "Authorization", "10.0.0.1", "request_time"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		st.isSensitiveKey(keys[i%len(keys)])
	}
}
