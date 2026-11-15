package scanner

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// jsonLogLines builds n structured log lines in the shapes services write:
// a flat application record, a request record with nested headers, a
// Kubernetes-style record with a labels object, and an audit record with an
// array. About a third carry a secret (a token, a password, an Authorization
// header, a URL with a key). Every value comes from a fixed seed: the same
// lines on every run and every ref.
//
// BenchmarkScanAndRedact and BenchmarkThroughput scan one JSON line over and
// over, so they measure that line. This one measures JSON as a format.
//
// scripts/bench-gate.sh copies this file into the ref it compares against,
// so it must only use what the scanner has exported since v2.2.0
// (ScanAndRedact).
func jsonLogLines(n int) []string {
	rng := rand.New(rand.NewSource(20261113))
	pick := func(xs []string) string { return xs[rng.Intn(len(xs))] }
	rnd := func(chars string, k int) string {
		b := make([]byte, k)
		for i := range b {
			b[i] = chars[rng.Intn(len(chars))]
		}
		return string(b)
	}
	hex := func(k int) string { return rnd("0123456789abcdef", k) }
	alnum := func(k int) string {
		return rnd("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k)
	}
	uuid := func() string { return hex(8) + "-" + hex(4) + "-4" + hex(3) + "-a" + hex(3) + "-" + hex(12) }
	ts := func() string {
		return fmt.Sprintf("2026-11-%02dT%02d:%02d:%02d.%03dZ", rng.Intn(28)+1, rng.Intn(24), rng.Intn(60), rng.Intn(60), rng.Intn(1000))
	}
	levels := []string{"debug", "info", "info", "info", "warn", "error"}
	services := []string{"checkout", "catalog", "auth-gateway", "billing-worker", "search-api"}
	msgs := []string{
		"request completed", "cache miss, loading from the database", "user login successful",
		"retrying upstream call", "payment authorised", "connection pool exhausted",
		"scheduled job finished", "validation failed for field email",
	}
	methods := []string{"GET", "GET", "POST", "PUT", "DELETE"}
	paths := []string{"/api/v1/orders", "/api/v1/users/me", "/healthz", "/api/v2/search", "/oauth/token"}

	lines := make([]string, n)
	for i := range lines {
		var sb strings.Builder
		switch rng.Intn(4) {
		case 0: // flat application record
			fmt.Fprintf(&sb, `{"ts":"%s","level":"%s","service":"%s","msg":"%s","request_id":"%s","user_id":%d,"duration_ms":%d.%d`,
				ts(), pick(levels), pick(services), pick(msgs), uuid(), rng.Intn(1000000), rng.Intn(900), rng.Intn(10))
			if rng.Intn(3) == 0 {
				fmt.Fprintf(&sb, `,"session_token":"%s"`, alnum(40))
			}
			sb.WriteString("}")
		case 1: // request record with nested headers
			fmt.Fprintf(&sb, `{"ts":"%s","level":"info","msg":"http request","http":{"method":"%s","path":"%s","status":%d,"bytes":%d},"headers":{"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36","Accept":"application/json","X-Request-Id":"%s"`,
				ts(), pick(methods), pick(paths), []int{200, 200, 201, 204, 400, 401, 500}[rng.Intn(7)], rng.Intn(60000), hex(32))
			if rng.Intn(3) == 0 {
				fmt.Fprintf(&sb, `,"Authorization":"Bearer %s"`, alnum(48))
			}
			sb.WriteString("}}")
		case 2: // Kubernetes-style record
			fmt.Fprintf(&sb, `{"time":"%s","stream":"stdout","kubernetes":{"namespace":"%s","pod":"%s-%s-%s","container":"app","labels":{"app.kubernetes.io/name":"%s","pod-template-hash":"%s"}},"log":"%s","trace_id":"%s"`,
				ts(), pick([]string{"prod", "staging", "payments"}), pick(services), hex(10), rnd("bcdfghjklmnpqrstvwxz2456789", 5),
				pick(services), hex(10), pick(msgs), hex(32))
			if rng.Intn(3) == 0 {
				fmt.Fprintf(&sb, `,"url":"https://api.example.com%s?api_key=%s&page=%d"`, pick(paths), alnum(32), rng.Intn(50))
			}
			sb.WriteString("}")
		default: // audit record with an array
			fmt.Fprintf(&sb, `{"@timestamp":"%s","event":{"action":"%s","outcome":"%s"},"actor":{"id":%d,"email":"user%d@example.com","roles":["viewer","%s"]},"changes":[{"field":"plan","from":"free","to":"team"},{"field":"seats","from":%d,"to":%d}]`,
				ts(), pick([]string{"user.update", "token.create", "login", "export"}), pick([]string{"success", "failure"}),
				rng.Intn(100000), rng.Intn(100000), pick([]string{"editor", "admin", "billing"}), rng.Intn(10), rng.Intn(50)+10)
			if rng.Intn(3) == 0 {
				fmt.Fprintf(&sb, `,"password":"%s"`, alnum(14))
			}
			sb.WriteString("}")
		}
		lines[i] = sb.String()
	}
	return lines
}

// BenchmarkJSONLines measures one JSON log line per op over 512 different
// lines, so the scanner cannot win by seeing the same tokens every time.
func BenchmarkJSONLines(b *testing.B) {
	lines := jsonLogLines(512)
	total := 0
	for _, l := range lines {
		total += len(l)
	}
	b.SetBytes(int64(total / len(lines)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result = ScanAndRedact(lines[i%len(lines)])
	}
}
