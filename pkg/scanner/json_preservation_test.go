package scanner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// A JSON log line goes to a collector that parses it. Valid JSON out is the
// least the scanner owes it; these tests ask for more: the same keys at every
// level, the same type for every value (a hidden number becomes a marker in
// quotes, nothing else changes type), and every value either untouched or
// replaced by a marker. A line that still parses but lost a key, turned a
// number into a string or gained a field breaks dashboards and alerts just as
// surely as a line that does not parse.

// jsonShapeDiff compares a JSON line with its redacted form and returns what
// changed besides string values becoming markers. hidden counts the markers.
func jsonShapeDiff(in, out string) (problems []string, hidden int) {
	decode := func(s string) (any, error) {
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if dec.More() {
			return nil, fmt.Errorf("trailing data after the value")
		}
		return v, nil
	}
	a, err := decode(in)
	if err != nil {
		return []string{"input is not JSON: " + err.Error()}, 0
	}
	b, err := decode(out)
	if err != nil {
		return []string{"output is not JSON: " + err.Error()}, 0
	}
	var walk func(path string, x, y any)
	walk = func(path string, x, y any) {
		switch xv := x.(type) {
		case map[string]any:
			yv, ok := y.(map[string]any)
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: object became %T", path, y))
				return
			}
			keys := make([]string, 0, len(xv))
			for k := range xv {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if _, ok := yv[k]; !ok {
					problems = append(problems, fmt.Sprintf("%s: key %q is gone", path, k))
					continue
				}
				walk(path+"."+k, xv[k], yv[k])
			}
			for k := range yv {
				if _, ok := xv[k]; !ok {
					problems = append(problems, fmt.Sprintf("%s: key %q appeared", path, k))
				}
			}
		case []any:
			yv, ok := y.([]any)
			if !ok || len(yv) != len(xv) {
				problems = append(problems, fmt.Sprintf("%s: array of %d became %v", path, len(xv), y))
				return
			}
			for i := range xv {
				walk(fmt.Sprintf("%s[%d]", path, i), xv[i], yv[i])
			}
		case string:
			yv, ok := y.(string)
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: string became %T", path, y))
				return
			}
			if yv != xv {
				if !strings.Contains(yv, "[HIDDEN:") {
					problems = append(problems, fmt.Sprintf("%s: string changed without a marker: %q -> %q", path, xv, yv))
				}
				hidden++
			}
		default: // json.Number, bool, nil
			if fmt.Sprintf("%T %v", x, x) == fmt.Sprintf("%T %v", y, y) {
				return
			}
			// A number that is itself the secret ("pin": 482913) cannot be
			// hidden and stay a number: it becomes a marker in quotes, the
			// one type change that is allowed.
			if yv, ok := y.(string); ok && strings.HasPrefix(yv, "[HIDDEN:") && strings.HasSuffix(yv, "]") {
				hidden++
				return
			}
			problems = append(problems, fmt.Sprintf("%s: %T %v became %T %v", path, x, x, y, y))
		}
	}
	walk("$", a, b)
	return problems, hidden
}

func TestJSONShapePreserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Salt = []byte("json-shape-test-salt-0123456789a")
	sc := NewScanner(cfg)

	for _, tc := range []struct {
		why, line  string
		wantHidden int
	}{
		{"compact", `{"level":"info","ts":1698765432,"msg":"login ok","user_id":12345,"api_key":"Zq7Lm2Xv9Rt4Kc8Wp3Nb6Yh1Df5Gs0Ja"}`, 1},
		{"spaced", `{"level": "info", "ts": 1698765432.25, "msg": "login ok", "password": "Wintermonkey73"}`, 1},
		{"nested objects", `{"request":{"id":"r-1","headers":{"Authorization":"Bearer abc123def456ghi789jkl","Accept":"*/*"}},"status":200}`, 1},
		{"array of objects", `{"events":[{"name":"a","token":"abc123def456ghi789"},{"name":"b","token":"zyx987wvu654tsr321"}],"count":2}`, 2},
		{"array of strings under a sensitive key", `{"tokens":["abc123def456ghi789","zyx987wvu654tsr321"],"n":2}`, 2},
		{"booleans, null, negative and exponent numbers", `{"ok":true,"retry":false,"error":null,"delta":-12,"ratio":1.5e-3,"secret":"Wintermonkey73"}`, 1},
		{"empty object, array and string", `{"meta":{},"tags":[],"note":"","token":"abc123def456ghi789"}`, 1},
		{"escaped quotes inside a value", `{"msg":"she said \"hello\" twice","password":"Winter\"monkey73"}`, 1},
		{"escaped backslash at the end of a value", `{"path":"C:\\logs\\","password":"Wintermonkey73"}`, 1},
		{"unicode escapes and non-Latin text", `{"msg":"\u041e\u0448\u0438\u0431\u043a\u0430 доступа","user":"лена","password":"Wintermonkey73"}`, 1},
		{"a key that holds a colon and an equals sign", `{"a:b=c":"plain","x=y":1,"password":"Wintermonkey73"}`, 1},
		{"JSON inside a string", `{"data":"{\"nested_key\": \"nested_secret_value_123\"}","n":1}`, 1},
		{"a URL with a token in a value", `{"url":"https://api.example.com/v1/items?token=abc123def456ghi789&page=2","status":200}`, 1},
		{"key=value text in a value", `{"msg":"retry user=lena password=Wintermonkey73 attempt=3","n":3}`, 1},
		{"a number under a sensitive key", `{"attempts":482913,"password":12345678,"ok":true}`, 1},
		{"deep nesting", `{"a":{"b":{"c":{"d":{"e":{"password":"Wintermonkey73","n":1}}}}}}`, 1},
		{"nothing to hide", `{"level":"debug","msg":"cache warm","items":42,"took_ms":3.5,"tags":["a","b"]}`, 0},
		{"a top-level array", `[{"password":"Wintermonkey73"},{"n":1}]`, 1},
		{"whitespace between tokens", `{ "a" : 1 , "password" : "Wintermonkey73" , "b" : [ 1 , 2 ] }`, 1},
	} {
		out := sc.ScanAndRedact(tc.line)
		problems, hidden := jsonShapeDiff(tc.line, out)
		for _, p := range problems {
			t.Errorf("%s: %s\n in:  %s\n out: %s", tc.why, p, tc.line, out)
		}
		if hidden != tc.wantHidden {
			t.Errorf("%s: %d values hidden, want %d\n in:  %s\n out: %s", tc.why, hidden, tc.wantHidden, tc.line, out)
		}
	}
}

// TestSmokeCorpusJSONShapePreserved runs the same check over every JSON line
// of the frozen smoke corpus, so the 1000-line corpus guards JSON shape in
// plain `go test`, without Docker.
func TestSmokeCorpusJSONShapePreserved(t *testing.T) {
	f, err := os.Open("../../scripts/testdata/smoke-corpus.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	cfg := DefaultConfig()
	cfg.Salt = []byte("json-shape-test-salt-0123456789a")
	sc := NewScanner(cfg)

	lines, hiddenTotal := 0, 0
	r := bufio.NewScanner(f)
	r.Buffer(make([]byte, 1<<20), 1<<24)
	for r.Scan() {
		line := r.Text()
		if !strings.HasPrefix(line, "{") || !json.Valid(bytes.TrimSpace([]byte(line))) {
			continue
		}
		lines++
		out := sc.ScanAndRedact(line)
		problems, hidden := jsonShapeDiff(line, out)
		hiddenTotal += hidden
		for _, p := range problems {
			t.Errorf("%s\n in:  %s\n out: %s", p, line, out)
		}
	}
	if err := r.Err(); err != nil {
		t.Fatal(err)
	}
	if lines < 100 || hiddenTotal == 0 {
		t.Errorf("only %d JSON lines and %d hidden values in the corpus: the check is not looking at what it should", lines, hiddenTotal)
	}
	t.Logf("%d JSON lines keep their shape, %d values hidden", lines, hiddenTotal)
}

// The benchmark lines are generated, so check them once: each is valid JSON,
// each keeps its shape through the scanner, and the mix really carries
// secrets. A generator that drifts into invalid JSON would leave the
// benchmark measuring the scanner's handling of broken lines.
func TestJSONBenchmarkLinesAreValidAndPreserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Salt = []byte("json-bench-test-salt-0123456789a")
	sc := NewScanner(cfg)
	hiddenLines := 0
	for _, line := range jsonLogLines(512) {
		out := sc.ScanAndRedact(line)
		problems, hidden := jsonShapeDiff(line, out)
		for _, p := range problems {
			t.Errorf("%s\n in:  %s\n out: %s", p, line, out)
		}
		if hidden > 0 {
			hiddenLines++
		}
	}
	if hiddenLines < 100 {
		t.Errorf("only %d of 512 lines had something hidden; the mix should carry a secret in about a third", hiddenLines)
	}
}

// The checker itself: each way a line can change shape is reported, and a
// value that became a marker is not.
func TestJSONShapeDiffReportsEveryKindOfChange(t *testing.T) {
	const in = `{"a":1,"b":"text","c":[1,2],"d":{"e":true},"password":"Wintermonkey73","pin":4829}`
	for _, tc := range []struct {
		why, out string
		problems bool
		hidden   int
	}{
		{"unchanged", in, false, 0},
		{"a string and a number hidden", `{"a":1,"b":"text","c":[1,2],"d":{"e":true},"password":"[HIDDEN:abc123]","pin":"[HIDDEN:def456]"}`, false, 2},
		{"a marker inside a longer string", `{"a":1,"b":"te [HIDDEN:abc123] xt","c":[1,2],"d":{"e":true},"password":"Wintermonkey73","pin":4829}`, false, 1},
		{"not JSON", `{"a":1,"b":"text"`, true, 0},
		{"a key gone", `{"a":1,"c":[1,2],"d":{"e":true},"password":"Wintermonkey73","pin":4829}`, true, 0},
		{"a key added", `{"a":1,"b":"text","c":[1,2],"d":{"e":true},"password":"Wintermonkey73","pin":4829,"x":1}`, true, 0},
		{"a key renamed", `{"a":1,"B":"text","c":[1,2],"d":{"e":true},"password":"Wintermonkey73","pin":4829}`, true, 0},
		{"a number changed", `{"a":2,"b":"text","c":[1,2],"d":{"e":true},"password":"Wintermonkey73","pin":4829}`, true, 0},
		{"a number turned into a plain string", `{"a":"1","b":"text","c":[1,2],"d":{"e":true},"password":"Wintermonkey73","pin":4829}`, true, 0},
		{"a number with a marker glued to text", `{"a":"x[HIDDEN:abc123]","b":"text","c":[1,2],"d":{"e":true},"password":"Wintermonkey73","pin":4829}`, true, 0},
		{"a string changed without a marker", `{"a":1,"b":"texT","c":[1,2],"d":{"e":true},"password":"Wintermonkey73","pin":4829}`, true, 1},
		{"an array shortened", `{"a":1,"b":"text","c":[1],"d":{"e":true},"password":"Wintermonkey73","pin":4829}`, true, 0},
		{"a nested boolean flipped", `{"a":1,"b":"text","c":[1,2],"d":{"e":false},"password":"Wintermonkey73","pin":4829}`, true, 0},
		{"an object flattened to a string", `{"a":1,"b":"text","c":[1,2],"d":"[HIDDEN:abc123]","password":"Wintermonkey73","pin":4829}`, true, 0},
		{"two values on the line", in + ` {}`, true, 0},
	} {
		problems, hidden := jsonShapeDiff(in, tc.out)
		if (len(problems) > 0) != tc.problems || hidden != tc.hidden {
			t.Errorf("%s: problems %v, hidden %d; want problems=%v, hidden=%d", tc.why, problems, hidden, tc.problems, tc.hidden)
		}
	}
}
