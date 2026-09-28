package scanner

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// pyBytesRepr prints b the way Python's repr() prints the inside of a bytes
// literal quoted with q.
func pyBytesRepr(b []byte, q byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\\' || c == q:
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c == '\t':
			sb.WriteString(`\t`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	return sb.String()
}

// TestBytesDictReprIsScanned: Python prints a dict of bytes as
// {b'authorization': b'Basic ...'} (asgi request.headers at DEBUG, seen in
// rexzhang/asgi-webdav). The value under a sensitive key used to reach the
// key=value splitter, which cut 'Basic <base64>=' on its padding and wrote the
// credential out unscored, and a bytes value that was hidden lost its b” .
func TestBytesDictReprIsScanned(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	basic := "d2ViZGF2Ok40I3ZzZFYzUiE=" // webdav:N4#vsdV3R!
	headers := `{b'host': b'dav.example.org', b'user-agent': b'Microsoft-WebDAV-MiniRedir/10.0.19045', ` +
		`b'authorization': b'Basic ` + basic + `', b'depth': b'1', b'content-length': b'0'}`
	out := ScanAndRedact(headers)
	if strings.Contains(out, strings.TrimRight(basic, "=")) {
		t.Errorf("Basic credential passed through: %q", out)
	}
	for _, keep := range []string{`b'host': b'dav.example.org'`, `b'depth': b'1'`, `b'content-length': b'0'}`, `b'authorization': b'[HIDDEN:`} {
		if !strings.Contains(out, keep) {
			t.Errorf("missing %q in %q", keep, out)
		}
	}

	// A bytes value is hidden like the same str value: same marker, and the
	// prefix and quotes stay, so the repr is still a bytes literal.
	for _, key := range []string{"password", "authorization", "token"} {
		str := ScanAndRedact(`{'` + key + `': 'N4#vsdV3R!x9'}`)
		byt := ScanAndRedact(`{b'` + key + `': b'N4#vsdV3R!x9'}`)
		if want := strings.Replace(strings.Replace(str, `{'`, `{b'`, 1), `': '`, `': b'`, 1); byt != want {
			t.Errorf("%s: bytes %q, want %q (str gives %q)", key, byt, want, str)
		}
	}

	// The same on the key=value path, sensitive key or not.
	for _, pair := range [][2]string{
		{`password=b'N4#vsdV3R!x9'`, `password='N4#vsdV3R!x9'`},
		{`data=b'AbC9xY2kQ8pLmN0rZq7'`, `data='AbC9xY2kQ8pLmN0rZq7'`},
	} {
		byt, str := ScanAndRedact(pair[0]), ScanAndRedact(pair[1])
		if want := strings.Replace(str, `='`, `=b'`, 1); byt != want || !strings.Contains(byt, "[HIDDEN") {
			t.Errorf("%q -> %q, want %q", pair[0], byt, want)
		}
	}

	// Text in bytes literals is left alone.
	for _, in := range []string{
		`{b'host': b'dav.example.org', b'depth': b'1'}`,
		`data=b'hello world'`,
		`b'GET / HTTP/1.1'`,
		// Non-Latin text sent as bytes is all \x escapes, but it is UTF-8.
		`recv b'` + pyBytesRepr([]byte("Пользователь вошёл в систему"), '\'') + `'`,
		`recv b'` + pyBytesRepr([]byte("שלום עולם"), '\'') + `'`,
		`recv b'` + pyBytesRepr([]byte("東京都港区"), '\'') + `'`,
	} {
		if got := ScanAndRedact(in); got != in {
			t.Errorf("changed: %q -> %q", in, got)
		}
	}
}

// TestBytesBinaryBlobIsScored: a bytes literal holding binary data - the
// Kerberos keys in a Samba/UCS LDAP modlist logged at DEBUG (seen in
// univention/univention-corporate-server) - was cut by its escapes, spaces and
// brackets into short fragments, and each passed on its own.
func TestBytesBinaryBlobIsScored(t *testing.T) {
	oldCfg := activeCfg()
	defer UpdateConfig(oldCfg)
	UpdateConfig(campaignConfig())

	r := rand.New(rand.NewSource(7))
	var keys []string
	for i := 0; i < 40; i++ {
		b := make([]byte, 48+r.Intn(40))
		r.Read(b)
		keys = append(keys, pyBytesRepr(append([]byte("0\x81\x9a\xa0\x03\x02\x01\x01\xa1"), b...), '\''))
	}
	for i := 0; i+2 < len(keys); i += 3 {
		in := `password_sync_s4_to_ucs: modlist: [('krb5Key', [b'` + keys[i] + `', b'` + keys[i+1] +
			`'], [b'` + keys[i+2] + `'])]`
		out := ScanAndRedact(in)
		for _, k := range keys[i : i+3] {
			// Any 16-character run of the key surviving is a leak.
			for j := 0; j+16 <= len(k); j += 8 {
				if strings.Contains(out, k[j:j+16]) {
					t.Fatalf("key fragment %q passed through: %q", k[j:j+16], out)
				}
			}
		}
		if strings.Count(out, "'") != strings.Count(in, "'")-countEscapedQuotes(keys[i:i+3]) {
			t.Errorf("quotes changed: %q", out)
		}
	}

	// Low-entropy binary stays: zero padding, a short TLS record header.
	for _, in := range []string{
		`buf=b'` + pyBytesRepr(make([]byte, 32), '\'') + `'`,
		`hdr=b'` + pyBytesRepr([]byte{0x16, 3, 1, 0, 0xa5, 1, 0, 0, 0xa1, 3, 3}, '\'') + `'`,
	} {
		if got := ScanAndRedact(in); got != in {
			t.Errorf("low-entropy binary changed: %q -> %q", in, got)
		}
	}
}

func countEscapedQuotes(ss []string) int {
	n := 0
	for _, s := range ss {
		n += strings.Count(s, `\'`)
	}
	return n
}

func TestIsEscapedBinary(t *testing.T) {
	for in, want := range map[string]bool{
		`\xfd\xfc\x07!\x82eO\x9a`:                          true,
		`\x87\xf3\xc6`:                                     false, // too few escapes
		`\\x87\\xf3\\xc6\\x9a\\xfd`:                        false, // escaped backslashes, not bytes
		`\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82`: false, // UTF-8 text
		`caf\xc3\xa9 na\xc3\xafve`:                         false,
		`hello world`:                                      false,
	} {
		if got := isEscapedBinary(in); got != want {
			t.Errorf("isEscapedBinary(%q) = %v, want %v", in, got, want)
		}
	}
}
