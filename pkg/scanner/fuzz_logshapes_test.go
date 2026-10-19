package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// logShapeKeys are the key names the log-shape fuzzer puts in front of a
// value: sensitive ones, whose value must always be hidden, and ordinary ones.
var logShapeKeys = []struct {
	name      string
	sensitive bool
}{
	{"password", true},
	{"token", true},
	{"api_key", true},
	{"client_secret", true},
	{"db_password", true},
	{"user", false},
	{"id", false},
	{"path", false},
	{"status", false},
}

// logShapeValue keeps the characters a value in a log line is made of and
// drops quotes, backslashes, separators and anything outside ASCII, so the
// fuzzer varies the value and not the syntax around it.
func logShapeValue(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-+/~", r) {
			b.WriteRune(r)
			if b.Len() == max {
				break
			}
		}
	}
	return b.String()
}

// logShapeWords keeps letters, digits and single spaces for free message text.
func logShapeWords(s string) string {
	var b strings.Builder
	space := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			space = false
		case r == ' ' && !space:
			b.WriteByte(' ')
			space = true
		}
		if b.Len() >= 48 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// logShape builds one line of a common log format around key and value. It
// also returns the text right before the value and the byte that ends it, so
// the check can find what the scanner wrote in the value's place, and
// whether the line is JSON.
func logShape(shape uint8, key, value, words string) (line, before string, end byte, isJSON bool) {
	switch shape % 8 {
	case 0: // logfmt
		before = key + "="
		return `time=2026-10-17T10:00:00Z level=info msg="` + words + `" ` + before + value + " user=bob", before, ' ', false
	case 1: // JSON log
		before = `"` + key + `":"`
		return `{"level":"info","msg":"` + words + `",` + before + value + `","user":"bob"}`, before, '"', true
	case 2: // key: value after a timestamp and level
		before = " " + key + ": "
		return "2026-10-17 10:00:00,123 INFO " + words + before + value, before, 0, false
	case 3: // query string in an access log line
		before = "?" + key + "="
		return `10.0.0.1 - - [17/Oct/2026:10:00:00 +0000] "GET /api/items` + before + value + `&page=2 HTTP/1.1" 200 512`, before, '&', false
	case 4: // Python logging default format (a logger name holding a
		// sensitive word, app.auth, still forces the next word: a known open bug)
		before = " " + key + "="
		return "INFO:app.worker:" + words + before + value, before, 0, false
	case 5: // JSON with spaces after the separators
		before = `"` + key + `": "`
		return `{"msg": "` + words + `", ` + before + value + `"}`, before, '"', true
	case 6: // escaped JSON inside a JSON string
		before = `\"` + key + `\": \"`
		return `{"data": "{` + before + value + `\", \"user\": \"bob\"}"}`, before, '\\', true
	default: // pair inside a quoted message
		before = " " + key + "="
		return `level=warn msg="` + words + before + value + `" retry=1`, before, '"', false
	}
}

// onlyMarkers reports whether s is one or more markers and nothing else, but
// for one closing punctuation mark: the scanner keeps a trailing '.' or ','
// out of the value as sentence punctuation (api_key: [HIDDEN:x].).
func onlyMarkers(s string) bool {
	rest := markerRe.ReplaceAllString(s, "")
	return s != rest && (rest == "" || len(rest) == 1 && strings.Contains(".,;:!?", rest) && strings.HasSuffix(s, rest))
}

// FuzzLogShapes stresses the line parser with the formats real logs use, and
// checks what must hold on them: a second scan changes nothing, a JSON line
// stays valid JSON, a scan keeps the number of lines, and a value under a
// sensitive key is replaced by markers and nothing else.
func FuzzLogShapes(f *testing.F) {
	f.Add(uint8(0), uint8(0), "hunter2xyz", "login ok")
	f.Add(uint8(1), uint8(1), "Zx9aQ2Lm8Pq4Rs7Tv1Kq", "user logged in")
	f.Add(uint8(2), uint8(5), "bob", "request done")
	f.Add(uint8(3), uint8(2), "sk-proj-abcdefghijklmnop1234", "")
	f.Add(uint8(4), uint8(3), "aSJDR1jaJlTrANqyWZvI", "fetch")
	f.Add(uint8(5), uint8(6), "12345", "item")
	f.Add(uint8(6), uint8(0), "hunter2xyz", "")
	f.Add(uint8(7), uint8(7), "/var/log/app.log", "rotated file")

	f.Fuzz(func(t *testing.T, shape, keyIdx uint8, rawValue, rawWords string) {
		useDefaultConfig(t)
		k := logShapeKeys[int(keyIdx)%len(logShapeKeys)]
		value := logShapeValue(rawValue, 64)
		if value == "" {
			return
		}
		line, before, end, isJSON := logShape(shape, k.name, value, logShapeWords(rawWords))

		once := ScanAndRedact(line)
		if twice := ScanAndRedact(once); twice != once {
			t.Errorf("second scan changed the line\n in:    %q\n once:  %q\n twice: %q", line, once, twice)
		}
		if isJSON && json.Valid([]byte(line)) && !json.Valid([]byte(once)) {
			t.Errorf("JSON line became invalid\n in:  %q\n out: %q", line, once)
		}
		// A value shorter than MinSecretLength after a bare sensitive word
		// (token: A) is left alone by design, so prose such as "password: no"
		// stays readable; the check starts at that length.
		if k.sensitive && len(value) >= DefaultMinSecretLength {
			// Whatever stands where the value was must be markers only.
			i := strings.LastIndex(once, before)
			if i < 0 {
				t.Fatalf("key %q lost\n in:  %q\n out: %q", k.name, line, once)
			}
			got := once[i+len(before):]
			if end != 0 {
				if j := strings.IndexByte(got, end); j >= 0 {
					got = got[:j]
				}
			}
			if !onlyMarkers(got) {
				t.Errorf("value under %q not fully hidden: %q\n in:  %q\n out: %q", k.name, got, line, once)
			}
		}
		text := line + "\n" + line + "\n"
		if out := ScanAndRedactText(text); strings.Count(out, "\n") != 2 {
			t.Errorf("line count changed\n in:  %q\n out: %q", text, out)
		}
	})
}
