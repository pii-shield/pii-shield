package scanner

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// F6 (length-dependent entropy threshold) is judged on a frozen, labelled
// token corpus instead of on sample output. testdata/f6-corpus.tsv holds one
// token per line as label<TAB>class<TAB>token, where label is secret, safe or
// ambiguous. testdata/f6-corpus.expected pins how the current scanner treats
// every class and length bucket, so any change to detection shows up here as
// a count that moved, not as a line that "looks right".
//
// Regenerate the corpus (needs /usr/share/dict/words) and the expected counts:
//
//	go test ./pkg/scanner/ -run TestEntropyThresholdCorpus -update-f6-corpus
//
// Re-pin only the expected counts after an intended detection change:
//
//	go test ./pkg/scanner/ -run TestEntropyThresholdCorpus -update-f6-expected
//
// Print rates per class and length bucket:
//
//	F6_REPORT=1 go test ./pkg/scanner/ -run TestEntropyThresholdCorpus -v
var (
	updateF6Corpus   = flag.Bool("update-f6-corpus", false, "regenerate testdata/f6-corpus.tsv and its expected counts")
	updateF6Expected = flag.Bool("update-f6-expected", false, "re-pin testdata/f6-corpus.expected from the current scanner")
)

const (
	f6CorpusPath   = "testdata/f6-corpus.tsv"
	f6ExpectedPath = "testdata/f6-corpus.expected"
	f6DictPath     = "/usr/share/dict/words"
	f6SmokeMeta    = "../../scripts/testdata/smoke-corpus.tsv"
	f6SmokeLines   = "../../scripts/testdata/smoke-corpus.txt"
)

type f6Token struct {
	label, class, token string
}

// f6Buckets are rune-length buckets; the edges follow MinSecretLength (6) and
// the lengths where short secrets and long identifiers are expected to meet.
var f6Buckets = []struct {
	name     string
	min, max int
}{
	{"01-05", 1, 5},
	{"06-08", 6, 8},
	{"09-12", 9, 12},
	{"13-16", 13, 16},
	{"17-24", 17, 24},
	{"25-40", 25, 40},
	{"41+", 41, 1 << 30},
}

func f6Bucket(tok string) string {
	n := utf8.RuneCountInString(tok)
	for _, b := range f6Buckets {
		if n >= b.min && n <= b.max {
			return b.name
		}
	}
	return "?"
}

// f6Outcome reports whether the token is hidden in the two places F6 cares
// about: alone in keyless prose, and as the key half of key=value (B7's hole,
// where the key side is written out unscored today).
func f6Outcome(s *Scanner, tok string) (keyless, asKey bool) {
	out := s.ScanAndRedact("event " + tok + " done")
	fields := strings.Fields(out)
	keyless = len(fields) < 2 || fields[1] != tok
	out = s.ScanAndRedact(tok + "=x")
	asKey = !strings.HasPrefix(out, tok+"=")
	return keyless, asKey
}

func TestEntropyThresholdCorpus(t *testing.T) {
	if *updateF6Corpus {
		corpus, err := buildF6Corpus()
		if err != nil {
			t.Fatalf("build corpus: %v", err)
		}
		if err := writeF6Corpus(corpus); err != nil {
			t.Fatalf("write corpus: %v", err)
		}
	}

	corpus, err := readF6Corpus()
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}

	s := NewScanner(campaignConfig())
	type cell struct{ n, keyless, asKey int }
	cells := map[string]*cell{}
	for _, c := range corpus {
		key := c.label + "\t" + c.class + "\t" + f6Bucket(c.token)
		if cells[key] == nil {
			cells[key] = &cell{}
		}
		k, a := f6Outcome(s, c.token)
		cells[key].n++
		if k {
			cells[key].keyless++
		}
		if a {
			cells[key].asKey++
		}
	}

	keys := make([]string, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var got strings.Builder
	got.WriteString("# label\tclass\tbucket\tn\tredacted_keyless\tredacted_as_key\n")
	for _, k := range keys {
		c := cells[k]
		fmt.Fprintf(&got, "%s\t%d\t%d\t%d\n", k, c.n, c.keyless, c.asKey)
	}

	if os.Getenv("F6_REPORT") != "" {
		t.Log("\n" + f6Report(keys, func(k string) (int, int, int) {
			c := cells[k]
			return c.n, c.keyless, c.asKey
		}))
	}

	if *updateF6Corpus || *updateF6Expected {
		if err := os.WriteFile(f6ExpectedPath, []byte(got.String()), 0o644); err != nil {
			t.Fatalf("write expected: %v", err)
		}
		return
	}
	want, err := os.ReadFile(f6ExpectedPath)
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}
	if got.String() != string(want) {
		t.Errorf("F6 corpus counts changed. If the detection change is intended, re-pin with -update-f6-expected and put the diff in the PR.\n%s",
			f6Diff(string(want), got.String()))
	}
}

// f6Report prints recall for secret cells and the false-positive rate for
// safe cells, overall and per length bucket, for both contexts.
func f6Report(keys []string, get func(string) (int, int, int)) string {
	var b strings.Builder
	type agg struct{ n, k, a int }
	byLabel := map[string]*agg{}
	byLabelBucket := map[string]*agg{}
	fmt.Fprintf(&b, "%-10s %-22s %-6s %5s %8s %8s\n", "label", "class", "bucket", "n", "keyless", "as_key")
	for _, key := range keys {
		n, k, a := get(key)
		p := strings.Split(key, "\t")
		fmt.Fprintf(&b, "%-10s %-22s %-6s %5d %7.1f%% %7.1f%%\n", p[0], p[1], p[2], n, pct(k, n), pct(a, n))
		for _, m := range []struct {
			mp  map[string]*agg
			key string
		}{{byLabel, p[0]}, {byLabelBucket, p[0] + "\t" + p[2]}} {
			if m.mp[m.key] == nil {
				m.mp[m.key] = &agg{}
			}
			m.mp[m.key].n += n
			m.mp[m.key].k += k
			m.mp[m.key].a += a
		}
	}
	b.WriteString("\nby label and bucket (secret = recall, safe = false-positive rate):\n")
	lb := make([]string, 0, len(byLabelBucket))
	for k := range byLabelBucket {
		lb = append(lb, k)
	}
	sort.Strings(lb)
	for _, k := range lb {
		v := byLabelBucket[k]
		p := strings.Split(k, "\t")
		fmt.Fprintf(&b, "%-10s %-6s %5d %7.1f%% %7.1f%%\n", p[0], p[1], v.n, pct(v.k, v.n), pct(v.a, v.n))
	}
	b.WriteString("\nby label:\n")
	for _, l := range []string{"secret", "safe", "ambiguous"} {
		if v := byLabel[l]; v != nil {
			fmt.Fprintf(&b, "%-10s %5d %7.1f%% %7.1f%%\n", l, v.n, pct(v.k, v.n), pct(v.a, v.n))
		}
	}
	if s, f := byLabel["secret"], byLabel["safe"]; s != nil && f != nil {
		tp, fp := s.k, f.k
		fmt.Fprintf(&b, "keyless: TP %d FN %d FP %d TN %d precision %.1f%% recall %.1f%%\n",
			tp, s.n-tp, fp, f.n-fp, pct(tp, tp+fp), pct(tp, s.n))
		tp, fp = s.a, f.a
		fmt.Fprintf(&b, "as_key:  TP %d FN %d FP %d TN %d precision %.1f%% recall %.1f%%\n",
			tp, s.n-tp, fp, f.n-fp, pct(tp, tp+fp), pct(tp, s.n))
	}
	return b.String()
}

func pct(a, n int) float64 {
	if n == 0 {
		return 0
	}
	return 100 * float64(a) / float64(n)
}

func f6Diff(want, got string) string {
	w := map[string]bool{}
	for _, l := range strings.Split(want, "\n") {
		w[l] = true
	}
	g := map[string]bool{}
	for _, l := range strings.Split(got, "\n") {
		g[l] = true
	}
	var b strings.Builder
	for _, l := range strings.Split(want, "\n") {
		if !g[l] {
			b.WriteString("- " + l + "\n")
		}
	}
	for _, l := range strings.Split(got, "\n") {
		if !w[l] {
			b.WriteString("+ " + l + "\n")
		}
	}
	return b.String()
}

func readF6Corpus() ([]f6Token, error) {
	f, err := os.Open(f6CorpusPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []f6Token
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.SplitN(line, "\t", 3)
		if len(p) != 3 {
			return nil, fmt.Errorf("bad corpus line %q", line)
		}
		out = append(out, f6Token{p[0], p[1], p[2]})
	}
	return out, sc.Err()
}

func writeF6Corpus(corpus []f6Token) error {
	var b strings.Builder
	b.WriteString("# F6 frozen token corpus. label<TAB>class<TAB>token. Generated by f6_corpus_test.go; do not edit by hand.\n")
	for _, c := range corpus {
		fmt.Fprintf(&b, "%s\t%s\t%s\n", c.label, c.class, c.token)
	}
	if err := os.MkdirAll(filepath.Dir(f6CorpusPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(f6CorpusPath, []byte(b.String()), 0o644)
}

// buildF6Corpus assembles the corpus from fixed seeds and fixed lists, so a
// regeneration on the same machine is byte-identical. Everything is synthetic:
// random secrets from a seeded generator, the smoke corpus's own labelled
// values, dictionary words, and hand-written identifier lists. Signature
// formats (AKIA, ghp_, xox, sk_live) are left out on purpose: they are caught
// by signatures.go regardless of the threshold, and complete Slack/Stripe
// literals are rejected by GitHub push protection.
func buildF6Corpus() ([]f6Token, error) {
	var out []f6Token
	seen := map[string]bool{}
	add := func(label, class, tok string) {
		if tok == "" || strings.ContainsAny(tok, "\t\n\r ") || seen[tok] {
			return
		}
		seen[tok] = true
		out = append(out, f6Token{label, class, tok})
	}

	// Random secrets: four alphabets, twelve lengths, twenty tokens per cell.
	rng := rand.New(rand.NewPCG(6, 2026))
	alphabets := []struct{ class, chars string }{
		{"random-mixed-alnum", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
		{"random-lower-digit", "abcdefghijklmnopqrstuvwxyz0123456789"},
		{"random-hex", "0123456789abcdef"},
		{"random-base64", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"},
	}
	for _, a := range alphabets {
		for _, n := range []int{6, 8, 10, 12, 14, 16, 20, 24, 32, 40, 48, 64} {
			for i := 0; i < 20; i++ {
				buf := make([]byte, n)
				for j := range buf {
					buf[j] = a.chars[rng.IntN(len(a.chars))]
				}
				add("secret", a.class, string(buf))
			}
		}
	}

	for _, p := range f6Passwords {
		add("secret", "human-password", p)
	}

	// The smoke corpus's labelled values: SECRET values are keyed there,
	// KNOWN_GAP values are the keyless ones the scanner is allowed to miss.
	meta, err := os.ReadFile(f6SmokeMeta)
	if err != nil {
		return nil, err
	}
	lines, err := os.ReadFile(f6SmokeLines)
	if err != nil {
		return nil, err
	}
	var smokeSafe []string
	metaRows := strings.Split(strings.TrimRight(string(meta), "\n"), "\n")
	logRows := strings.Split(strings.TrimRight(string(lines), "\n"), "\n")
	for i, row := range metaRows {
		p := strings.SplitN(row, "\t", 2)
		switch p[0] {
		case "SECRET":
			add("secret", "smoke-secret", p[1])
		case "KNOWN_GAP":
			add("secret", "smoke-keyless-secret", p[1])
		case "SAFE":
			if i < len(logRows) {
				smokeSafe = append(smokeSafe, logRows[i])
			}
		}
	}

	// Dictionary words: lowercase only, 25 per length from 4 to 16, picked
	// with a seeded generator so the sample is stable.
	dict, err := os.ReadFile(f6DictPath)
	if err != nil {
		return nil, err
	}
	byLen := map[int][]string{}
	for _, w := range strings.Split(string(dict), "\n") {
		if w == "" || strings.ToLower(w) != w {
			continue
		}
		byLen[len(w)] = append(byLen[len(w)], w)
	}
	wrng := rand.New(rand.NewPCG(6, 4))
	for n := 4; n <= 16; n++ {
		words := byLen[n]
		for i := 0; i < 25 && len(words) > 0; i++ {
			add("safe", "dictionary-word", words[wrng.IntN(len(words))])
		}
	}

	for _, k := range f6LogFields {
		add("safe", "log-field-snake", k)
		add("safe", "log-field-camel", snakeToCamel(k))
	}
	for _, id := range f6PascalIdentifiers {
		add("safe", "identifier-pascal", id)
	}
	for _, noun := range f6EventNouns {
		for _, verb := range f6EventVerbs {
			if wrng.IntN(4) == 0 {
				add("safe", "event-name-dotted", noun+"."+verb)
			}
		}
	}
	for _, w := range f6Cyrillic {
		add("safe", "cyrillic-word", w)
	}
	for _, m := range f6Misc {
		add("safe", "misc-structured", m)
	}

	// Tokens of the smoke corpus's SAFE lines, added after the hand lists so
	// a field name keeps its own class. UUIDs and 40-hex hashes are skipped:
	// they are the ambiguous shapes below, and isSafe whitelists both.
	userIDs := 0
	for _, line := range smokeSafe {
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return unicode.IsSpace(r) || strings.ContainsRune(`"{}[](),:=`, r)
		}) {
			if uuidRegex.MatchString(tok) || isGitHash(tok) {
				continue
			}
			// user_<4 hex> fills most SAFE lines; twenty of them are enough
			// to measure the shape without letting it outweigh the rest.
			if strings.HasPrefix(tok, "user_") {
				if userIDs >= 20 {
					continue
				}
				userIDs++
			}
			add("safe", "smoke-safe-token", tok)
		}
	}

	// Ambiguous: shapes that are sometimes secrets and usually not. Reported
	// on their own, never folded into precision or recall.
	hex := "0123456789abcdef"
	randFrom := func(chars string, n int) string {
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = chars[rng.IntN(len(chars))]
		}
		return string(buf)
	}
	for i := 0; i < 10; i++ {
		u := randFrom(hex, 32)
		add("ambiguous", "uuid", u[0:8]+"-"+u[8:12]+"-4"+u[13:16]+"-a"+u[17:20]+"-"+u[20:32])
		add("ambiguous", "git-sha-40", randFrom(hex, 40))
		add("ambiguous", "git-sha-short", randFrom(hex, 7))
		add("ambiguous", "objectid-24", randFrom(hex, 24))
		add("ambiguous", "sha256-64", randFrom(hex, 64))
		add("ambiguous", "epoch-millis", fmt.Sprintf("17%011d", rng.Int64N(1e11)))
		add("ambiguous", "k8s-pod-name", "api-"+randFrom("bcdfghjklmnpqrstvwxz2456789", 10)+"-"+randFrom("bcdfghjklmnpqrstvwxz2456789", 5))
	}
	return out, nil
}

func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// Human-chosen passwords: low entropy by construction. This class measures
// what entropy cannot do; it is not a target to tune for.
var f6Passwords = []string{
	"hunter2", "Summer2024!", "P@ssw0rd123", "Welcome1!", "Qwerty123!", "letmein2024",
	"Passw0rd!", "Tr0ub4dor&3", "correcthorsebatterystaple", "iloveyou99", "Dragon2023$",
	"Monkey!234", "Football#7", "Sunshine88", "Admin@123", "changeme123", "S3cureP@ss",
	"MyP@ssw0rd!", "Autumn2025?", "Liverpool1892", "Winter#2026", "abc123xyz", "Password1",
	"Chelsea2019", "London2012!", "Maria1985", "Secret!42", "Company2026#", "Temp1234!",
	"Spring_2026",
}

var f6LogFields = []string{
	"request_id", "trace_id", "span_id", "context_id", "commit_sha", "user_agent",
	"http_status_code", "response_time_ms", "remote_addr", "x_forwarded_for", "content_length",
	"content_type", "tenant_id", "correlation_id", "parent_span_id", "service_name", "pod_name",
	"container_id", "node_name", "cluster_name", "log_level", "error_code", "error_message",
	"retry_count", "duration_ms", "bytes_sent", "bytes_received", "upstream_addr",
	"upstream_status", "request_method", "request_uri", "query_string", "server_name",
	"client_ip", "geo_country", "device_type", "app_version", "build_number", "deploy_id",
	"feature_flag", "experiment_id", "order_id", "customer_id", "account_id", "invoice_id",
	"payment_method", "currency_code", "amount_minor", "merchant_id", "batch_size",
	"queue_name", "topic_name", "partition_id", "offset_lag", "consumer_group", "job_name",
	"task_id", "worker_id", "attempt_number", "max_retries", "timeout_seconds", "cache_hit",
	"db_statement", "db_rows_affected", "lock_wait_ms", "gc_pause_ms", "heap_used_bytes",
	"thread_name", "logger_name", "source_file", "line_number", "function_name",
	"exception_type", "stack_trace", "http_route", "peer_service", "net_peer_name",
	"otel_scope_name", "event_type", "span_kind",
}

var f6PascalIdentifiers = []string{
	"UserAccountService", "PaymentAuthorizationHandler", "HttpClientFactory",
	"KafkaConsumerCoordinator", "OrderRepository", "RetryPolicyConfig", "TokenBucketLimiter",
	"InvoiceGenerator", "NullPointerException", "IllegalArgumentException",
	"ConnectionPoolTimeout", "SessionExpiredError", "ReconcileLoop", "PodDisruptionBudget",
	"DeploymentController", "GrpcServerInterceptor", "JsonMarshaller", "S3BucketUploader",
	"OAuth2Client", "HealthCheckProbe", "RateLimitExceeded", "TransferRejected",
	"LedgerEntryWriter", "FraudScoreEvaluator", "AccountStatementBuilder",
	"CircuitBreakerOpen", "MetricsExporter", "TraceContextPropagator", "IdempotencyKeyStore",
	"WebhookDispatcher",
}

var f6EventNouns = []string{
	"payment", "transfer", "user", "session", "order", "invoice", "account", "card",
	"refund", "login", "export", "deploy", "job", "webhook", "cache", "pod",
}

var f6EventVerbs = []string{
	"authorised", "declined", "failed", "created", "updated", "deleted", "expired", "started",
	"completed", "rejected", "retried", "timeout", "shipped", "evicted", "scheduled",
}

var f6Cyrillic = []string{
	"пользователь", "авторизован", "успешно", "конфигурация", "маршрутизация",
	"Аутентификация", "Днепропетровск", "подключение", "соединение", "ошибка", "запрос",
	"ответ", "сервер", "данных", "транзакция", "платёж", "отклонён", "превышен", "лимит",
	"обработка", "завершена", "Санкт-Петербург", "Екатеринбург", "Новосибирск",
	"администратор", "перезагрузка", "обновление", "синхронизация", "идентификатор",
	"уведомление", "подтверждение", "регистрация", "резервирование", "масштабирование",
	"балансировщик", "контейнер", "развёртывание", "журналирование", "Владивосток",
	"недоступен",
}

var f6Misc = []string{
	"v2.2.4", "1.26.5", "10.0.19045", "2026-09-24", "2026-01-30T10:00:00Z", "HTTP/1.0",
	"HTTP/1.1", "HTTP/2.0", "/var/log/pods", "/api/v1/users", "scanner.go", "values.yaml",
	"192.168.1.5", "10.244.0.17", "12345", "120.00", "nginx-deployment", "kube-system",
	"application/json", "text/plain;charset=utf-8", "api.example.com", "localhost:8080",
	"GET", "POST", "200", "404", "503", "us-east-1", "eu-west-2", "t3.medium",
	"sha256", "gzip", "Mozilla/5.0", "x86_64", "arm64", "UTF-8", "ISO-8601", "0.0.0.0:9090",
	"/healthz", "prometheus",
}
