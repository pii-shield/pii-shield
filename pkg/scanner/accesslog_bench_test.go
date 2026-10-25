package scanner

import (
	"fmt"
	"math/rand"
	"testing"
)

// accessLogLines builds n lines in the shape of an nginx combined access log
// with request time and upstream, the shape where the CLI lost the most
// throughput between v2.2.0 and v2.2.8 (38k -> 29k lines/s on one core,
// against 73k -> 61k on short text lines; AG-2026-10-24-01). The real log
// cannot go into this repository, so every value here is made up from a
// fixed seed: the same lines on every run and every ref.
//
// scripts/bench-gate.sh copies this file into the ref it compares against,
// so it must only use what the scanner has exported since v2.2.0
// (ScanAndRedact).
func accessLogLines(n int) []string {
	rng := rand.New(rand.NewSource(20261025))
	pick := func(xs []string) string { return xs[rng.Intn(len(xs))] }
	hex := func(k int) string {
		const digits = "0123456789abcdef"
		b := make([]byte, k)
		for i := range b {
			b[i] = digits[rng.Intn(16)]
		}
		return string(b)
	}
	alnum := func(k int) string {
		const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, k)
		for i := range b {
			b[i] = chars[rng.Intn(len(chars))]
		}
		return string(b)
	}
	methods := []string{"GET", "GET", "GET", "POST", "PUT", "DELETE", "HEAD"}
	paths := []string{
		"/", "/health", "/favicon.ico", "/static/js/app.%s.js", "/static/css/main.%s.css",
		"/api/v1/users/%d", "/api/v1/orders/%d/items", "/api/v2/search?q=winter+boots&page=%d",
		"/products/%d/reviews?sort=newest", "/login", "/account/settings", "/wp-login.php",
		"/api/v1/session?token=%s", "/download?file=report-%d.pdf&api_key=%s",
		"/reset-password?email=user%d@example.com&code=%s", "/oauth/callback?code=%s&state=%s",
	}
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"curl/8.4.0", "python-requests/2.31.0", "Go-http-client/1.1", "-",
	}
	referers := []string{"-", "-", "https://www.example.com/", "https://shop.example.com/products?ref=nav", "https://www.google.com/"}
	statuses := []int{200, 200, 200, 204, 301, 304, 404, 500}
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

	lines := make([]string, n)
	for i := range lines {
		path := pick(paths)
		switch path {
		case "/static/js/app.%s.js", "/static/css/main.%s.css":
			path = fmt.Sprintf(path, hex(8))
		case "/api/v1/session?token=%s":
			path = fmt.Sprintf(path, alnum(32))
		case "/download?file=report-%d.pdf&api_key=%s":
			path = fmt.Sprintf(path, rng.Intn(9999), alnum(40))
		case "/reset-password?email=user%d@example.com&code=%s":
			path = fmt.Sprintf(path, rng.Intn(9999), alnum(12))
		case "/oauth/callback?code=%s&state=%s":
			path = fmt.Sprintf(path, alnum(24), hex(16))
		case "/api/v1/users/%d", "/api/v1/orders/%d/items", "/api/v2/search?q=winter+boots&page=%d", "/products/%d/reviews?sort=newest":
			path = fmt.Sprintf(path, rng.Intn(100000))
		}
		lines[i] = fmt.Sprintf(`%d.%d.%d.%d - - [%02d/%s/2026:%02d:%02d:%02d +0000] "%s %s HTTP/1.1" %d %d "%s" "%s" rt=%d.%03d uct="0.%03d" upstream=10.0.%d.%d:8080 req_id=%s`,
			rng.Intn(223)+1, rng.Intn(256), rng.Intn(256), rng.Intn(256),
			rng.Intn(28)+1, pick(months), rng.Intn(24), rng.Intn(60), rng.Intn(60),
			pick(methods), path, statuses[rng.Intn(len(statuses))], rng.Intn(50000),
			pick(referers), pick(agents),
			rng.Intn(3), rng.Intn(1000), rng.Intn(1000), rng.Intn(256), rng.Intn(256), hex(16))
	}
	return lines
}

// BenchmarkAccessLog measures one access-log line per op over 512 different
// lines, so the scanner cannot win by seeing the same tokens every time.
func BenchmarkAccessLog(b *testing.B) {
	lines := accessLogLines(512)
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
