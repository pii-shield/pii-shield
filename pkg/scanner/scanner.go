package scanner

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"log"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
)

// Config holds scanner configuration parameters.
type Config struct {
	EntropyThreshold        float64
	ConfidenceThreshold     float64 // Hybrid validation confidence
	MinSecretLength         int
	Salt                    []byte
	SensitiveKeys           []string
	DisableBigramCheck      bool     // Disable English bigram analysis for non-English logs
	BigramDefaultScore      float64  // Default score for unknown bigrams
	AdaptiveThreshold       bool     // Enable statistical adaptive threshold mode
	SensitiveKeyPatterns    []string // Regex patterns for sensitive key detection (stored as strings)
	AdaptiveBaselineSamples int      // Number of samples for adaptive baseline
	EntityTypeLabels        bool     // Emit [HIDDEN:<type>:<hash>] instead of [HIDDEN:<hash>]
	CustomRegexes           []CustomRegexRule
	SafeRegexes             []CustomRegexRule
	CombinedCustomRegex     *regexp.Regexp // Optimized "Mega-Regex" (O(1) match)
	CustomRegexNames        []string       // Names corresponding to CombinedCustomRegex submatches
}

// CustomRegexConfig is the DTO for JSON unmarshalling from environment variables.
type CustomRegexConfig struct {
	Pattern string `json:"pattern"`
	Name    string `json:"name"`
}

// CustomRegexRule holds the compiled regex and its name for runtime use.
type CustomRegexRule struct {
	Regexp *regexp.Regexp
	Name   string
}

// configState is the immutable snapshot of everything the scanner reads on the
// hot path. UpdateConfig publishes a fresh one atomically; readers load the
// pointer with cfgState(), so a config swap can never race with an in-flight
// ScanAndRedact call (a reader sees either the whole old snapshot or the whole
// new one, never a torn mix).
type configState struct {
	config         Config
	sensitiveRegex *regexp.Regexp // compiled sensitive-key patterns, may be nil
	hmacPool       *sync.Pool     // HMAC hashers keyed by config.Salt
}

// activeConfig holds the currently published *configState.
var activeConfig atomic.Pointer[configState]

// cfgState returns the currently published configuration snapshot.
func cfgState() *configState { return activeConfig.Load() }

var (
	// UUID regex to skip false positive entropy unless forced
	uuidRegex = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	logTable [256]float64

	// sepTable marks scanSegment's separator set " \t,;[]{}()<>"; all
	// separators are ASCII, so runes >= utf8.RuneSelf are never separators.
	sepTable [utf8.RuneSelf]bool

	bufferPool = sync.Pool{
		New: func() interface{} {
			return new(strings.Builder)
		},
	}

	// RedactionCallback is triggered whenever a string is redacted.
	// The strategy is guaranteed to be one of "entropy", "regex", "luhn".
	RedactionCallback func(strategy string)

	// ContextKeywords trigger lower entropy thresholds for subsequent tokens
	ContextKeywords = map[string]bool{
		"error": true, "failed": true, "exception": true, "invalid": true,
		"fatal": true, "panic": true, "warning": true, "bad": true,
		"denied": true, "unauthorized": true, "broken": true,
		"password": true, "secret": true, "token": true, "key": true, "auth": true,
	}

	// DefaultEntropyThreshold is the Shannon entropy threshold for high-entropy strings.
	// Lowered from 3.8 to 3.6 to catch shorter random alphanumeric strings.
	DefaultEntropyThreshold = 3.6

	DefaultMinSecretLength = 6
	MaxMinSecretLength     = 1024

	// maxTokenRecursionDepth bounds the mutual recursion between
	// processTokenLogic, processEqualPair/processColonPair, and
	// scanSegment/scanLine. Untrusted input like a 2MB "a=a=a=...b" chain
	// otherwise recurses once per '=' (measured: 53.5s wall, 779MB RSS for
	// one line). Past the limit the remainder is scored as one opaque token,
	// which keeps normal entropy-based redaction (fail-safe).
	maxTokenRecursionDepth = 32
)

var luhnPool *sync.Pool

func init() {
	// defaults. UpdateConfig builds every piece of derived state (sensitive key
	// regex, HMAC pool), so the CLI/env, Go API, and WASM/SDK entrypoints all go
	// through one path and stay in parity.
	UpdateConfig(loadConfig())

	// Initialize Luhn Pool (slice of ints)
	luhnPool = &sync.Pool{
		New: func() interface{} {
			// Start with capacity 32 (common for shorter lines), it will grow if needed
			s := make([]int, 0, 32)
			return &s
		},
	}

	for i := 1; i < 256; i++ {
		logTable[i] = math.Log2(float64(i))
	}

	for _, c := range []byte(" \t,;[]{}()<>") {
		sepTable[c] = true
	}
}

// isSepRune reports whether r is one of scanSegment's token separators,
// equivalent to strings.ContainsRune(" \t,;[]{}()<>", r).
func isSepRune(r rune) bool {
	return r >= 0 && r < utf8.RuneSelf && sepTable[r]
}

// parseFloat parses a float from string, returns error if invalid.
// Strict: trailing junk ("9.9junk") is an error, unlike fmt.Sscanf which
// silently stops at the first non-numeric character.
func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(s), 64)
}

// parseInt parses an int from string, returns error if invalid
func parseInt(s string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(s))
}

func envTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

// compileSensitiveKeyPatterns builds the combined case-insensitive regex used by
// isSensitiveKey. It returns (nil, nil) when there is nothing to compile, and
// never terminates the process so WASM/SDK callers can recover from bad input.
func compileSensitiveKeyPatterns(patterns []string) (*regexp.Regexp, error) {
	valid := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if cleaned := strings.TrimSpace(p); cleaned != "" {
			valid = append(valid, cleaned)
		}
	}
	if len(valid) == 0 {
		return nil, nil
	}
	re, err := regexp.Compile("(?i)(" + strings.Join(valid, "|") + ")")
	if err != nil {
		return nil, fmt.Errorf("failed to compile combined sensitive key regex: %w", err)
	}
	return re, nil
}

// compileRegexRules compiles raw pattern/name pairs into runtime rules. It
// returns an error instead of terminating, so an invalid pattern supplied by an
// SDK caller cannot kill the embedding host process.
func compileRegexRules(raw []CustomRegexConfig) ([]CustomRegexRule, error) {
	rules := make([]CustomRegexRule, 0, len(raw))
	for _, r := range raw {
		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", r.Pattern, err)
		}
		rules = append(rules, CustomRegexRule{Regexp: compiled, Name: r.Name})
	}
	return rules, nil
}

// ApplySensitiveKeyPatterns stores regex patterns for sensitive key detection.
// The combined regex itself is rebuilt by UpdateConfig, so every entrypoint
// derives it the same way.
func (c *Config) ApplySensitiveKeyPatterns(patterns []string) error {
	cleaned := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if t := strings.TrimSpace(p); t != "" {
			cleaned = append(cleaned, t)
		}
	}
	c.SensitiveKeyPatterns = cleaned
	_, err := compileSensitiveKeyPatterns(cleaned)
	return err
}

// ApplyCustomRegexes compiles custom redaction rules into c, including the
// combined "mega-regex" fast path. Returns an error for an invalid pattern.
func (c *Config) ApplyCustomRegexes(raw []CustomRegexConfig) error {
	rules, err := compileRegexRules(raw)
	if err != nil {
		return fmt.Errorf("custom regex list: %w", err)
	}
	c.CustomRegexes = rules

	if len(raw) == 0 {
		c.CombinedCustomRegex = nil
		c.CustomRegexNames = nil
		return nil
	}

	patterns := make([]string, 0, len(raw))
	names := make([]string, 0, len(raw))
	for _, r := range raw {
		// Each rule is wrapped in a capturing group to identify which matched.
		patterns = append(patterns, "("+r.Pattern+")")
		names = append(names, r.Name)
	}
	combined, err := regexp.Compile(strings.Join(patterns, "|"))
	if err != nil {
		// Fall back to the individual rules, matching prior behavior.
		log.Printf("WARNING: Failed to compile combined custom regex: %v. Fallback to individual checks.", err)
		c.CombinedCustomRegex = nil
		c.CustomRegexNames = nil
		return nil
	}
	c.CombinedCustomRegex = combined
	c.CustomRegexNames = names
	return nil
}

// ApplySafeRegexes compiles whitelist rules into c.
func (c *Config) ApplySafeRegexes(raw []CustomRegexConfig) error {
	rules, err := compileRegexRules(raw)
	if err != nil {
		return fmt.Errorf("safe regex list: %w", err)
	}
	c.SafeRegexes = rules
	return nil
}

// DefaultConfig returns the built-in defaults (no env vars, no salt). Embedders
// like the WASM SDKs build on it so a partial override won't wipe SensitiveKeys.
func DefaultConfig() Config {
	cfg := Config{
		EntropyThreshold:        DefaultEntropyThreshold, // Adjusted for bigrams
		ConfidenceThreshold:     1.0,                     // High confidence required to skip false positives
		MinSecretLength:         DefaultMinSecretLength,  // Lower minimal length as we have better context
		DisableBigramCheck:      false,                   // Enable bigram check by default
		BigramDefaultScore:      -7.0,                    // Default for unknown bigrams
		AdaptiveThreshold:       false,                   // Disabled by default (User feedback)
		AdaptiveBaselineSamples: 100,                     // Default baseline sample size
		EntityTypeLabels:        false,                   // Legacy [HIDDEN:<hash>] format by default
		SensitiveKeys: []string{
			"pass", "secret", "token", "key", "cvv", "cvc", "auth", "sign",
			"password", "passwd", "api_key", "apikey", "access_token", "client_secret",
			"aws_access_key_id", "aws_secret_access_key", "gcp_credentials", "slack_token",
		},
	}
	for i, k := range cfg.SensitiveKeys {
		cfg.SensitiveKeys[i] = strings.ToLower(strings.TrimSpace(k))
	}
	return cfg
}

func loadConfig() Config {
	cfg := DefaultConfig()

	// Load Salt - CRITICAL SECURITY: Try secure, fallback to error log (don't panic library)
	if envSalt := os.Getenv("PII_SALT"); envSalt != "" {
		if len(envSalt) < 16 {
			if envTruthy(os.Getenv("PII_REQUIRE_STRONG_SALT")) {
				panic("FATAL: PII_SALT is too short (<16 bytes) and PII_REQUIRE_STRONG_SALT is enabled")
			}
			fmt.Fprintf(os.Stderr, "WARNING: PII_SALT is too short (<16 bytes). Weak security.\n")
		}
		cfg.Salt = []byte(envSalt)
	} else {
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			// CRITICAL SECURITY: Fail closed if we cannot generate a secure salt.
			// Do not use a fallback.
			panic(fmt.Sprintf("FATAL: Failed to generate secure random salt: %v", err))
		}
		cfg.Salt = salt
	}

	// Load entropy threshold override
	if envThreshold := os.Getenv("PII_ENTROPY_THRESHOLD"); envThreshold != "" {
		if threshold, err := parseFloat(envThreshold); err == nil {
			cfg.EntropyThreshold = threshold
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: PII_ENTROPY_THRESHOLD must be a number. Using default %v.\n", cfg.EntropyThreshold)
		}
	}

	// Load confidence threshold
	if envConfThreshold := os.Getenv("PII_CONFIDENCE_THRESHOLD"); envConfThreshold != "" {
		if confThreshold, err := parseFloat(envConfThreshold); err == nil {
			cfg.ConfidenceThreshold = confThreshold
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: PII_CONFIDENCE_THRESHOLD must be a number. Using default %v.\n", cfg.ConfidenceThreshold)
		}
	}

	// Load minimum secret length override
	if envMinSecretLength := os.Getenv("PII_MIN_SECRET_LENGTH"); envMinSecretLength != "" {
		if minSecretLength, err := parseInt(envMinSecretLength); err == nil && minSecretLength > 0 && minSecretLength <= MaxMinSecretLength {
			cfg.MinSecretLength = minSecretLength
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: PII_MIN_SECRET_LENGTH must be a positive integer <= %d. Using default %d.\n", MaxMinSecretLength, cfg.MinSecretLength)
		}
	}

	// Load bigram configuration
	if envDisableBigram := os.Getenv("PII_DISABLE_BIGRAM_CHECK"); envDisableBigram == "true" || envDisableBigram == "1" {
		cfg.DisableBigramCheck = true
	}

	if envBigramScore := os.Getenv("PII_BIGRAM_DEFAULT_SCORE"); envBigramScore != "" {
		if score, err := parseFloat(envBigramScore); err == nil {
			cfg.BigramDefaultScore = score
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: PII_BIGRAM_DEFAULT_SCORE must be a number. Using default %v.\n", cfg.BigramDefaultScore)
		}
	}

	// Opt-in entity-type labels in redaction output: [HIDDEN:<type>:<hash>]
	if envTruthy(os.Getenv("PII_ENTITY_TYPE_LABELS")) {
		cfg.EntityTypeLabels = true
	}

	// Load adaptive threshold mode
	if envAdaptive := os.Getenv("PII_ADAPTIVE_THRESHOLD"); envAdaptive == "true" || envAdaptive == "1" {
		cfg.AdaptiveThreshold = true
		if envSamples := os.Getenv("PII_ADAPTIVE_SAMPLES"); envSamples != "" {
			if samples, err := parseInt(envSamples); err == nil && samples > 0 {
				cfg.AdaptiveBaselineSamples = samples
			}
		}
	}

	// Load Sensitive Keys (overrides the defaults seeded by DefaultConfig)
	if envKeys := os.Getenv("PII_SENSITIVE_KEYS"); envKeys != "" {
		cfg.SensitiveKeys = strings.Split(envKeys, ",")
		// Normalized
		for i, k := range cfg.SensitiveKeys {
			cfg.SensitiveKeys[i] = strings.ToLower(strings.TrimSpace(k))
		}
	}

	// Load Sensitive Key Patterns (regex). The combined regex is compiled by
	// UpdateConfig; a bad pattern warns rather than exits, as before.
	if envPatterns := os.Getenv("PII_SENSITIVE_KEY_PATTERNS"); envPatterns != "" {
		if err := cfg.ApplySensitiveKeyPatterns(strings.Split(envPatterns, ",")); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
		}
	}

	// Load Custom Regex List. A malformed list or entry warns and is skipped
	// instead of terminating (B6): loadConfig also runs inside library
	// embedders via package init, where log.Fatalf would kill the host
	// process before its main() ever ran. Same policy as the
	// PII_SENSITIVE_KEY_PATTERNS path above.
	if envCustomRegex := os.Getenv("PII_CUSTOM_REGEX_LIST"); envCustomRegex != "" {
		var rawRules []CustomRegexConfig
		if err := json.Unmarshal([]byte(envCustomRegex), &rawRules); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: PII_CUSTOM_REGEX_LIST ignored: invalid json format: %v\n", err)
		} else {
			rawRules = dropInvalidRegexRules("PII_CUSTOM_REGEX_LIST", rawRules)
			if err := cfg.ApplyCustomRegexes(rawRules); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: PII_CUSTOM_REGEX_LIST error: %v\n", err)
			}
		}
	}

	// Load Safe Regex List (Whitelist). Same warn-and-skip policy as above.
	if envSafeRegex := os.Getenv("PII_SAFE_REGEX_LIST"); envSafeRegex != "" {
		var rawRules []CustomRegexConfig
		if err := json.Unmarshal([]byte(envSafeRegex), &rawRules); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: PII_SAFE_REGEX_LIST ignored: invalid json format: %v\n", err)
		} else {
			rawRules = dropInvalidRegexRules("PII_SAFE_REGEX_LIST", rawRules)
			if err := cfg.ApplySafeRegexes(rawRules); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: PII_SAFE_REGEX_LIST error: %v\n", err)
			}
		}
	}

	return cfg
}

// dropInvalidRegexRules filters out entries whose pattern does not compile,
// warning once per dropped rule, so a single typo disables that rule only —
// not the whole list and not the process (B6).
func dropInvalidRegexRules(envName string, raw []CustomRegexConfig) []CustomRegexConfig {
	valid := make([]CustomRegexConfig, 0, len(raw))
	for _, r := range raw {
		if _, err := regexp.Compile(r.Pattern); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: %s: skipping invalid regex %q: %v\n", envName, r.Pattern, err)
			continue
		}
		valid = append(valid, r)
	}
	return valid
}

// buildConfigState compiles cfg into the immutable snapshot the scan engine
// reads: the derived sensitive-key regex and an HMAC pool keyed to cfg.Salt.
// Shared by UpdateConfig (publishes the snapshot globally) and NewScanner
// (keeps the snapshot private to one Scanner instance).
func buildConfigState(cfg Config) *configState {
	// Rebuild derived state from the raw config fields. Doing this here (rather
	// than only while parsing env vars) is what lets the WASM/SDK entrypoints
	// honor SensitiveKeyPatterns exactly like the CLI does.
	re, err := compileSensitiveKeyPatterns(cfg.SensitiveKeyPatterns)
	if err != nil {
		log.Printf("WARNING: %v", err)
		re = nil
	}

	// HMAC pool keyed by this config's salt. Captured in the closure so it is
	// bound to the snapshot, not to a shared mutable global.
	salt := cfg.Salt
	pool := &sync.Pool{
		New: func() interface{} {
			return hmac.New(sha256.New, salt)
		},
	}

	return &configState{
		config:         cfg,
		sensitiveRegex: re,
		hmacPool:       pool,
	}
}

// UpdateConfig updates the global configuration and resets the HMAC pool.
// This is primarily used for WASM environments where config is dynamic.
func UpdateConfig(cfg Config) {
	// Publish the whole snapshot in one atomic store. Readers on the hot path
	// (cfgState) never observe a partially-updated configuration, so
	// UpdateConfig is safe to call concurrently with ScanAndRedact.
	activeConfig.Store(buildConfigState(cfg))
}

// Scanner is an instance-based redactor built from its own immutable Config
// snapshot. Unlike the package-level ScanAndRedact/UpdateConfig pair (which
// share one process-wide configuration), a Scanner's configuration is fixed
// at construction time by NewScanner and never changes — so independently
// configured Scanners can be used concurrently without one call's config
// affecting another's, and without affecting the package-level default.
type Scanner struct {
	*configState
}

// NewScanner builds a Scanner from cfg. Callers that only want the built-in
// defaults plus a few overrides should start from DefaultConfig() rather than
// a bare Config{}, the same way UpdateConfig callers already do — an empty
// Config has no SensitiveKeys and a zero EntropyThreshold.
func NewScanner(cfg Config) *Scanner {
	return &Scanner{configState: buildConfigState(cfg)}
}

// -----------------------------------------------------------------------------
// 1. Core Entropy Logic
// -----------------------------------------------------------------------------

func CalculateComplexity(token string) float64 {
	return cfgState().calculateComplexity(token)
}

// calculateComplexity is CalculateComplexity's config-aware implementation,
// callable on any configState (the global snapshot or a Scanner's own) so a
// Scanner instance's bigram/entropy config is honored instead of silently
// falling back to the package-level default.
func (st *configState) calculateComplexity(token string) float64 {
	if len(token) == 0 {
		return 0
	}

	// 1. Shannon Entropy
	entropy := calculateShannon(token)

	// 2. Class Bonus
	bonus := calculateClassBonus(token)

	// 3. Bigram Check (English Likelihood)
	bigramScore := st.calculateBigramAdjustment(token)

	return entropy + bonus + bigramScore
}

func calculateShannon(token string) float64 {
	if len(token) == 0 {
		return 0
	}

	// Optimization: Stack allocation for ASCII-only tokens (common case)
	// Checks for ASCII and populates counts in one pass.
	// If non-ASCII found, falls back to map.
	var counts [256]int
	isASCII := true
	totalChars := 0

	// Use byte iteration for speed
	for i := 0; i < len(token); i++ {
		b := token[i]
		if b >= utf8.RuneSelf {
			isASCII = false
			break
		}
		counts[b]++
		totalChars++
	}

	if isASCII {
		entropy := 0.0
		// logTable is filled in init() by the same math.Log2 calls, so a
		// lookup is bit-identical to computing Log2 directly; indices >= 256
		// (tokens longer than 255 bytes) fall back to math.Log2.
		var logLen float64
		if totalChars < 256 {
			logLen = logTable[totalChars]
		} else {
			logLen = math.Log2(float64(totalChars))
		}
		for _, count := range counts {
			if count == 0 {
				continue
			}
			var logCount float64
			if count < 256 {
				logCount = logTable[count]
			} else {
				logCount = math.Log2(float64(count))
			}
			p := float64(count) / float64(totalChars)
			entropy -= p * (logCount - logLen)
		}
		return entropy
	}

	// Fallback: Unicode (Allocates map)
	freq := make(map[rune]int)
	totalChars = 0
	for _, r := range token {
		freq[r]++
		totalChars++
	}

	entropy := 0.0
	logLen := math.Log2(float64(totalChars))

	for _, count := range freq {
		p := float64(count) / float64(totalChars)
		entropy -= p * (math.Log2(float64(count)) - logLen)
	}
	return entropy
}

func calculateClassBonus(token string) float64 {
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSymbol := false

	for _, r := range token {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
		if unicode.IsDigit(r) {
			hasDigit = true
		}
		if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			hasSymbol = true
		}
	}

	classes := 0
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSymbol {
		classes++
	}

	if classes > 1 {
		return float64(classes-1) * 0.5
	}
	return 0.0
}

func (st *configState) calculateBigramAdjustment(token string) float64 {
	// CONDITIONAL: Can be disabled for non-English logs
	if st.config.DisableBigramCheck || len(token) <= 3 {
		return 0.0
	}

	sumProb := 0.0
	count := 0
	if isASCIIString(token) {
		// For pure-ASCII tokens strings.ToLower only maps A-Z, so an inline
		// byte lowercase produces the same bigrams without the per-token
		// allocation. Non-ASCII tokens keep the ToLower path: multibyte
		// lowercasing changes bytes and must stay byte-identical to before.
		prev := lowerASCIIByte(token[0])
		for i := 1; i < len(token); i++ {
			cur := lowerASCIIByte(token[i])
			sumProb += st.bigramProbBytes(prev, cur)
			count++
			prev = cur
		}
	} else {
		sLower := strings.ToLower(token)
		for i := 0; i < len(sLower)-1; i++ {
			bg := sLower[i : i+2]
			sumProb += st.bigramProb(bg) // Using shared bigram table from bigrams.go
			count++
		}
	}

	if count > 0 {
		avgProb := sumProb / float64(count)
		// If avgProb > -5.8, it's likely English or common text.
		// We reduce complexity score to avoid false positives.
		if avgProb > -5.8 {
			return -1.5 // Penalize score (make it "safer")
		} else if avgProb < -7.0 {
			return 0.5 // Boost score (more random)
		}
	}
	return 0.0
}

// isASCIIString reports whether s contains only single-byte (ASCII) runes.
func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// lowerASCIIByte lowercases A-Z; all other bytes pass through unchanged,
// which is exactly what strings.ToLower does to a pure-ASCII string.
func lowerASCIIByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// entityLabel returns the entity-type label to embed in the redaction marker
// when EntityTypeLabels is enabled, or "" for the legacy unlabeled format.
// The set of types is deliberately small and fixed: card, key, context, url,
// regex, entropy (named custom rules keep their own name instead).
func (st *configState) entityLabel(entityType string) string {
	if st.config.EntityTypeLabels {
		return entityType
	}
	return ""
}

func (st *configState) redactWithHMAC(sensitiveData string, name string, strategy string, sb *strings.Builder) {
	if RedactionCallback != nil {
		if strategy == "" {
			strategy = "entropy"
		}
		RedactionCallback(strategy)
	}

	pool := st.hmacPool
	mac := pool.Get().(hash.Hash)
	defer pool.Put(mac)

	mac.Reset()
	mac.Write([]byte(sensitiveData))

	// Zero-allocation hex encoding using stack buffer
	var buf [32]byte
	sum := mac.Sum(buf[:0])

	// Write [HIDDEN
	sb.WriteString("[HIDDEN")

	// Optional Name
	if name != "" {
		sb.WriteRune(':')
		sb.WriteString(name)
	}

	// Separator for hash
	sb.WriteRune(':')

	// Hex encode first 3 bytes (6 chars) directly to builder
	// We can manually hex encode to avoid string conv
	dst := make([]byte, 6)
	hex.Encode(dst, sum[:3])
	sb.Write(dst)

	sb.WriteString("]")
}

// -----------------------------------------------------------------------------
// 2. Main Scanner (Quotes & Key-Value Aware)
// -----------------------------------------------------------------------------

// ScanAndRedact redacts logLine using the package-level configuration (see
// UpdateConfig). It is a thin wrapper around the same engine a Scanner
// instance uses; construct a Scanner via NewScanner for an isolated,
// immutable configuration instead of the shared package-level one.
func ScanAndRedact(logLine string) string {
	return cfgState().ScanAndRedact(logLine)
}

// ScanAndRedact is configState's redaction engine. Scanner embeds
// *configState, so this is promoted as (*Scanner).ScanAndRedact; the
// package-level ScanAndRedact above is a thin wrapper calling it on the
// globally published snapshot.
func (st *configState) ScanAndRedact(logLine string) string {
	if len(logLine) == 0 {
		return ""
	}
	sb := bufferPool.Get().(*strings.Builder)
	sb.Reset()
	sb.Grow(len(logLine) + 100)
	defer bufferPool.Put(sb)

	st.scanLine(logLine, sb, 0)
	return sb.String()
}

// ScanAndRedactText redacts text that may span several lines, scanning each
// line on its own. ScanAndRedact is a single-line engine: '\n' is not a token
// separator, so a value at the end of a line would otherwise be scored
// together with its newline (and the first token of the next line). That
// defeats structural safe rules such as isPlainDecimal and swallows the
// newline inside the redaction marker, changing the line count (#184). Line
// endings ("\n" and "\r\n") are preserved, so the output has exactly as
// many lines as the input — the same contract the CLI gives stdin.
func ScanAndRedactText(text string) string {
	return cfgState().ScanAndRedactText(text)
}

// ScanAndRedactText is the multi-line counterpart of ScanAndRedact; Scanner
// embeds *configState, so it is promoted as (*Scanner).ScanAndRedactText.
func (st *configState) ScanAndRedactText(text string) string {
	if strings.IndexByte(text, '\n') == -1 {
		return st.ScanAndRedact(text)
	}
	var sb strings.Builder
	sb.Grow(len(text) + 100)
	for len(text) > 0 {
		line, ending := text, ""
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			line, ending, text = text[:i], "\n", text[i+1:]
		} else {
			text = ""
		}
		if strings.HasSuffix(line, "\r") {
			line, ending = line[:len(line)-1], "\r"+ending
		}
		sb.WriteString(st.ScanAndRedact(line))
		sb.WriteString(ending)
	}
	return sb.String()
}

// scanLine is the zero-allocation internal version of ScanAndRedact.
// depth tracks nesting of the recursive token machinery (see
// maxTokenRecursionDepth); top-level callers pass 0.
func (st *configState) scanLine(logLine string, sb *strings.Builder, depth int) {
	if len(logLine) == 0 {
		return
	}

	// JSON lines are handled by the tokenizer itself (quotes, braces, colon
	// pairs) — deliberately no encoding/json parse here; see compact_json_test.go.

	luhnRanges := FindLuhnSequences(logLine)

	// Hybrid Validation: Reduce false positive Luhn matches if confidence threshold is strictly elevated
	if st.config.ConfidenceThreshold > 1.2 {
		var validLuhns []Range
		lowerLine := strings.ToLower(logLine)
		hasContext := strings.Contains(lowerLine, "card") || strings.Contains(lowerLine, "cc") || strings.Contains(lowerLine, "pan") || strings.Contains(lowerLine, "visa")
		if hasContext {
			validLuhns = luhnRanges
		}
		luhnRanges = validLuhns
	}

	chunkStart := 0

	for _, lr := range luhnRanges {
		if lr.Start > chunkStart {
			safeSegment := logLine[chunkStart:lr.Start]
			st.scanSegment(safeSegment, sb, depth)
		}

		secret := logLine[lr.Start:lr.End]
		if st.isSafeRegexWhitelisted(secret) {
			sb.WriteString(secret)
		} else {
			st.redactWithHMAC(secret, st.entityLabel("card"), "luhn", sb)
		}

		chunkStart = lr.End
	}

	if chunkStart < len(logLine) {
		safeSegment := logLine[chunkStart:]
		st.scanSegment(safeSegment, sb, depth)
	}
}

// scanSegment implements a Quote-Aware Tokenizer.
// It iterates runes and respects " and ' bounds.
// scanSegment implements a Context-Aware & Quote-Aware Tokenizer.
// It handles: escaped quotes, spaces, and sensitive key tracking.
func (st *configState) scanSegment(segment string, sb *strings.Builder, depth int) {
	n := len(segment)
	start := 0
	inQuote := false
	quoteChar := rune(0)
	seenInvalid := false // Track invalid UTF-8 sequence

	state := segmentState{}

	// Manual Byte Loop for precise control and skipping
	i := 0
	for i < n {
		r, width := utf8.DecodeRuneInString(segment[i:])
		if r == utf8.RuneError {
			if width == 1 {
				seenInvalid = true
			}
			i++
			continue
		}

		if inQuote {
			if r == '\\' {
				i += width
				if i < n {
					r2, w2 := utf8.DecodeRuneInString(segment[i:])
					if r2 == utf8.RuneError && w2 == 1 {
						seenInvalid = true
					}
					i += w2
				}
				continue
			}
			if r == quoteChar {
				inQuote = false
			}
			i += width
			continue
		}

		if r == '"' || r == '\'' {
			inQuote = true
			quoteChar = r
			i += width
			continue
		}

		if isSepRune(r) {
			if i > start {
				token := segment[start:i]
				if seenInvalid {
					token = strings.ToValidUTF8(token, "\uFFFD")
				}
				st.processAndAppend(token, sb, &state, depth)
			}
			sb.WriteRune(r)
			i += width
			start = i
			seenInvalid = false
		} else {
			i += width
		}
	}

	// Final token
	if start < n {
		token := segment[start:n]
		if seenInvalid {
			token = strings.ToValidUTF8(token, "\uFFFD")
		}
		st.processAndAppend(token, sb, &state, depth)
	}
}

// processTokenLogic analyzes a token and returns (processedString, isSensitiveKey).
// forcedSensitive: if true, treat this token as a Value that MUST be protected (skips MinLength).
// contextSensitive: if true, reduce entropy threshold (Context Aware).
// isValuePos: if true, this token MUST be a value (skiye key checks).
func (st *configState) processTokenLogic(rawToken string, forcedSensitive bool, contextSensitive bool, isValuePos bool, overrideSensitivity bool, sb *strings.Builder, depth int) (isKey bool) {
	// Recursion bound: past the limit, score the remainder as one opaque
	// token instead of descending further (see maxTokenRecursionDepth).
	if depth > maxTokenRecursionDepth {
		st.processSingleToken(trimQuotes(rawToken), rawToken, forcedSensitive, contextSensitive, true, sb)
		return false
	}

	if strings.Contains(rawToken, "://") || (strings.Contains(rawToken, "?") && strings.Contains(rawToken, "=")) {
		st.maskURLParameters(rawToken, sb)
		return false
	}

	// 1. Check for Key=Value (e.g. key=value)
	isKey, handled := st.processEqualPair(rawToken, forcedSensitive, overrideSensitivity, sb, depth)
	if handled {
		return isKey
	}

	// 2. Check for Key:Value (e.g. "key": "value" or "key":value)
	isKey, handled = st.processColonPair(rawToken, overrideSensitivity, sb, depth)
	if handled {
		return isKey
	}

	// 3. Single Token parsing (Value or Key)
	trimmed := trimQuotes(rawToken)

	// CRITICAL FIX: If we know we are in a Value position (e.g. after :),
	// do NOT treat this as a key, even if it looks like one.
	if !isValuePos {
		if st.isSensitiveKey(trimmed) || overrideSensitivity {
			sb.WriteString(rawToken)
			return true
		}
	}

	// Optimization Phase 3 Regression Fix / B9: if the token is a genuinely
	// quoted string, we must "unwrap" it and scan the specific content for
	// embedded secrets (e.g. JSON fields containing long error messages or
	// nested structures) instead of scoring the whole quoted blob as one
	// token. This applies whenever we're about to fall through to "process as
	// value" below — both when something upstream already knows we're in a
	// value position, AND when there was no key at all (a bare quoted phrase
	// at the top level, e.g. "contact alice@example.com" with nothing before
	// it) — not only the isValuePos==true case. Skipped when forcedSensitive,
	// since a forced value is redacted as one whole blob regardless.
	if !forcedSensitive && len(rawToken) >= 2 {
		first := rawToken[0]
		last := rawToken[len(rawToken)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			// Write opening quote
			sb.WriteByte(first)
			// Recursive scan of the inner content
			// This handles "Error: 1.2.3.4 failed" by splitting it into tokens
			st.scanSegment(trimmed, sb, depth+1)
			// Write closing quote
			sb.WriteByte(last)
			return false
		}
	}

	// Not a key. Process as value.
	st.processSingleToken(trimmed, rawToken, forcedSensitive, contextSensitive, true, sb)
	return false
}

func trimQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	if s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

func isRedacted(content string) bool {
	return strings.HasPrefix(content, "[HIDDEN") && strings.HasSuffix(content, "]")
}

func (st *configState) processSingleToken(content, original string, forcedSensitive bool, contextSensitive bool, autoQuote bool, sb *strings.Builder) {
	// -1. Check Idempotency (Already Redacted)
	if isRedacted(content) {
		sb.WriteString(original)
		return
	}

	// 0. Safety Whitelists (Static - Fastest)
	if !forcedSensitive && isSafe(content) {
		sb.WriteString(original)
		return
	}

	// Every field read below comes from the same explicitly-passed snapshot,
	// so a single token is never scored against a mix of two configs.
	cfg := st.config

	// 1. Whitelist Check: Safe Regexes
	if len(content) >= 3 {
		for _, rule := range cfg.SafeRegexes {
			if rule.Regexp.MatchString(content) {
				sb.WriteString(original)
				return
			}
		}
	}

	// 2. Deterministic Check: Custom Regexes
	if len(content) >= 5 {
		if cfg.CombinedCustomRegex != nil {
			loc := cfg.CombinedCustomRegex.FindStringSubmatchIndex(content)
			if loc != nil {
				matchName := ""
				for i := 0; i < len(cfg.CustomRegexNames); i++ {
					idx := 2 + (i * 2)
					if idx < len(loc) && loc[idx] != -1 {
						matchName = cfg.CustomRegexNames[i]
						break
					}
				}

				quoteChar := byte(0)
				if strings.HasPrefix(original, "\"") {
					quoteChar = '"'
				} else if strings.HasPrefix(original, "'") {
					quoteChar = '\''
				} else if autoQuote {
					lower := strings.ToLower(content)
					if isDigits(content) || lower == "true" || lower == "false" || lower == "null" {
						quoteChar = '"'
					}
				}

				if quoteChar != 0 {
					sb.WriteByte(quoteChar)
				}

				// Use hashed redaction for Custom Regex
				if matchName == "" {
					matchName = st.entityLabel("regex")
				}
				st.redactWithHMAC(content, matchName, "regex", sb)

				if quoteChar != 0 {
					sb.WriteByte(quoteChar)
				}
				return
			}
		} else {
			for _, rule := range cfg.CustomRegexes {
				if rule.Regexp.MatchString(content) {
					quoteChar := byte(0)
					if strings.HasPrefix(original, "\"") {
						quoteChar = '"'
					} else if strings.HasPrefix(original, "'") {
						quoteChar = '\''
					} else if autoQuote {
						lower := strings.ToLower(content)
						if isDigits(content) || lower == "true" || lower == "false" || lower == "null" {
							quoteChar = '"'
						}
					}

					if quoteChar != 0 {
						sb.WriteByte(quoteChar)
					}

					// Use hashed redaction for Custom Regex
					ruleName := rule.Name
					if ruleName == "" {
						ruleName = st.entityLabel("regex")
					}
					st.redactWithHMAC(content, ruleName, "regex", sb)

					if quoteChar != 0 {
						sb.WriteByte(quoteChar)
					}
					return
				}
			}
		}
	}

	// 3. Heuristics Check (Length & Spaces)
	if !forcedSensitive {
		if len(content) < cfg.MinSecretLength {
			sb.WriteString(original)
			return
		}
		if strings.Contains(content, " ") {
			sb.WriteString(original)
			return
		}
	}

	// 3.5 Hybrid Validation (Confidence & Pattern Skipping)
	if !forcedSensitive {
		// Skip UUIDs if they lack specific keyword context
		if len(content) == 36 && uuidRegex.MatchString(content) {
			if !contextSensitive {
				sb.WriteString(original)
				return
			} else {
				// We have a direct context keyword for this UUID. Force redact it instead of delegating to complexity score
				forcedSensitive = true
			}
		}

		// Fast heuristic for standard Base64 payloads/blobs
		if len(content) > 64 && strings.HasSuffix(content, "=") && !strings.ContainsAny(content, "-_ \t\n") {
			if !contextSensitive {
				sb.WriteString(original)
				return
			} else {
				forcedSensitive = true
			}
		}
	}

	// 4. Complexity Score
	score := st.calculateComplexity(content)
	threshold := cfg.EntropyThreshold
	if forcedSensitive {
		threshold = 1.0
	} else if contextSensitive {
		threshold -= 1.3
	} else if cfg.AdaptiveThreshold {
		if adaptiveThreshold, ready := globalBaseline.GetThreshold(); ready {
			threshold = adaptiveThreshold
		}
	}

	// Apply Hybrid Confidence Threshold
	// High confidence threshold (e.g. 1.2) means the score must exceed baseline * 1.2
	threshold *= cfg.ConfidenceThreshold

	// If it is explicitly forced by a sensitive key context, we bypass the entropy threshold.
	if forcedSensitive || score > threshold {
		quoteChar := byte(0)
		if strings.HasPrefix(original, "\"") {
			quoteChar = '"'
		} else if strings.HasPrefix(original, "'") {
			quoteChar = '\''
		} else if autoQuote {
			lower := strings.ToLower(content)
			if isDigits(content) || lower == "true" || lower == "false" || lower == "null" {
				quoteChar = '"'
			}
		}

		if quoteChar != 0 {
			sb.WriteByte(quoteChar)
		}
		entityType := "entropy"
		if forcedSensitive {
			entityType = "key"
		} else if contextSensitive {
			entityType = "context"
		}
		st.redactWithHMAC(content, st.entityLabel(entityType), "entropy", sb)
		if quoteChar != 0 {
			sb.WriteByte(quoteChar)
		}
		return
	}

	// Token SAFE
	if !forcedSensitive && cfg.AdaptiveThreshold {
		globalBaseline.Update(score)
	}

	sb.WriteString(original)
}

func (st *configState) processEqualPair(rawToken string, forcedSensitive bool, overrideSensitivity bool, sb *strings.Builder, depth int) (isKey bool, handled bool) {
	idx := strings.IndexByte(rawToken, '=')
	if idx == -1 {
		return false, false
	}
	// Handle quoted strings: "key=value". Require a *matching* closing quote —
	// entering this branch on a leading quote alone re-wraps unbalanced input
	// and invents quote characters that were not present (B3), e.g.
	// `data="key=value` -> `data=""key=...`. Unbalanced tokens fall through to
	// the unquoted branch below.
	if len(rawToken) >= 2 && (rawToken[0] == '"' || rawToken[0] == '\'') &&
		rawToken[len(rawToken)-1] == rawToken[0] {
		quote := string(rawToken[0])
		trimmed := trimQuotes(rawToken)

		tIdx := strings.IndexByte(trimmed, '=')
		if tIdx != -1 {
			// Logic: key is trimmed[:tIdx], val is trimmed[tIdx+1:]
			key := trimmed[:tIdx]
			val := trimmed[tIdx+1:]

			keySensitive := st.isSensitiveKey(key)

			sb.WriteString(quote)
			sb.WriteString(key)
			sb.WriteRune('=')
			if keySensitive {
				st.processSingleToken(val, val, true, false, false, sb)
			} else {
				// Optimization Phase 3 Fix: "data=key=val"
				// If the value itself looks like a KV pair, recurse!
				// Only do this if it contains separators.
				if strings.Contains(val, "=") || strings.Contains(val, ":") {
					// We need to call processTokenLogic again on the value.
					// Pass false for forcedSensitive since the parent key wasn't sensitive.
					// Pass overrideSensitivity (likely false here).
					// Depth-bounded: processTokenLogic stops descending past
					// maxTokenRecursionDepth.
					st.processTokenLogic(val, false, false, false, overrideSensitivity, sb, depth+1)
				} else {
					// Recursive scan for non-sensitive keys (e.g. "data=key=val")
					st.scanLine(val, sb, depth+1)
				}
			}
			sb.WriteString(quote)

			return keySensitive && val == "", true
		}
		// Fallthrough to single token processing
	} else {
		// Unquoted Key=Value
		key := rawToken[:idx] // Up to =
		val := rawToken[idx+1:]

		keySensitive := st.isSensitiveKey(key) || overrideSensitivity

		sb.WriteString(key)
		sb.WriteRune('=')

		if containsSep := strings.Contains(val, "=") || strings.Contains(val, ":"); containsSep && !keySensitive {
			// Recursive handling for "data=key=val" where "data" is safe.
			st.processTokenLogic(val, false, false, false, overrideSensitivity, sb, depth+1)
		} else {
			st.processSingleToken(val, val, keySensitive, false, false, sb)
		}

		return keySensitive && val == "", true
	}
	return false, false
}

func (st *configState) processColonPair(rawToken string, overrideSensitivity bool, sb *strings.Builder, depth int) (isKey bool, handled bool) {
	if strings.Contains(rawToken, "://") {
		return false, false // URL-like
	}
	// Fix: Only split on colon if it's NOT inside quotes
	// e.g. "Error: msg" -> Should NOT split
	// "key": val -> Should split (colon after quote)

	idx := -1
	if strings.HasPrefix(rawToken, "\"") || strings.HasPrefix(rawToken, "'") {
		// Quoted token: Find end quote
		quote := rawToken[0]
		// Find closing quote starting from index 1
		endQ := strings.IndexByte(rawToken[1:], quote)
		if endQ != -1 {
			realEnd := endQ + 1
			// Check if colon is after the closing quote
			// e.g. "key":
			rest := rawToken[realEnd+1:]
			colIdx := strings.IndexByte(rest, ':')
			if colIdx != -1 {
				idx = realEnd + 1 + colIdx
			}
		} else {
			// Unbalanced quote: treat as a normal (unquoted) string.
			idx = strings.IndexByte(rawToken, ':')
		}
	} else {
		idx = strings.IndexByte(rawToken, ':')
	}

	if idx != -1 {
		if isImage(rawToken) {
			sb.WriteString(rawToken)
			return false, true
		}

		keyRaw := rawToken[:idx]
		val := rawToken[idx+1:]

		key := trimQuotes(keyRaw)
		keySensitive := st.isSensitiveKey(key) || overrideSensitivity

		// Recursively process val? Val might be empty if "key:"
		if val == "" {
			sb.WriteString(rawToken)
			return keySensitive, true
		}

		sb.WriteString(keyRaw) // Write original key (with quotes)
		sb.WriteRune(':')
		// Route through processTokenLogic's isValuePos handling instead of
		// calling processSingleToken directly: a quoted multi-word value (e.g.
		// compact JSON with no space after ':') must be unwrapped and
		// re-tokenized so an embedded secret is scored on its own, the same way
		// it already is when whitespace follows the colon (B9).
		st.processTokenLogic(val, keySensitive, false, true, false, sb, depth+1)

		return keySensitive, true
	}
	return false, false
}

func (st *configState) isSensitiveKey(key string) bool {
	// 1. Check substring matching (fast path for standard keys)
	// We still need ToLower for the fixed list unless we change that too,
	// but let's keep it for backward compatibility and as a "fast filter"
	// before the regex if possible? No, user said ToLower is slow.
	// But currentConfig.SensitiveKeys are lowercase.
	// Optimization: If we trust the regex is case-insensitive, we can skip ToLower
	// for the specific regex check. For the list check, we still need it.
	// However, if we move ALL keys to regex, that would be fastest.
	// For now, let's keep the hybrid approach but optimize the Regex part.

	k := strings.ToLower(key)

	// Check substring matching (backward compatible)
	for _, sk := range st.config.SensitiveKeys {
		if strings.Contains(k, sk) {
			// Fast reject for 'public_key' or 'pubkey' or 'pub_key'
			if strings.Contains(k, "pub") && strings.Contains(k, "key") {
				return false
			}

			// Safety check: High entropy strings (likely secrets) should not be treated as keys
			// even if they contain the word "secret" or "key".
			if len(key) > 15 && st.calculateComplexity(key) > st.config.EntropyThreshold {
				return false
			}
			return true
		}
	}

	// 2. Check compiled regex (single pass, case-insensitive)
	// sensitiveRegex is already (?i), so we match against original 'key'
	// to avoid relying on 'k' (result of ToLower) if we want?
	// Actually 'key' is fine.
	if st.sensitiveRegex != nil {
		if st.sensitiveRegex.MatchString(key) {
			return true
		}
	}

	return false
}

func (st *configState) maskURLParameters(url string, sb *strings.Builder) {
	parts := strings.Split(url, "?")
	if len(parts) < 2 {
		sb.WriteString(url)
		return
	}

	sb.WriteString(parts[0])
	entropyThreshold := st.config.EntropyThreshold

	// Everything after the first '?' is query text. A well-formed URL has a
	// single '?', but malformed log lines can carry several; process each
	// '?'-separated section through the parameter loop so no bytes are dropped
	// and secrets in later sections are still scanned/redacted (B2).
	for _, section := range parts[1:] {
		sb.WriteRune('?')

		params := strings.Split(section, "&")
		for i, param := range params {
			if i > 0 {
				sb.WriteRune('&')
			}

			if strings.Contains(param, "=") {
				kv := strings.SplitN(param, "=", 2)
				key := kv[0]
				val := kv[1]

				if st.isSafeRegexWhitelisted(val) {
					sb.WriteString(param)
				} else if st.isSensitiveKey(key) {
					sb.WriteString(key)
					sb.WriteRune('=')
					st.redactWithHMAC(val, st.entityLabel("key"), "entropy", sb)
				} else {
					score := st.calculateComplexity(val)
					if score > entropyThreshold {
						sb.WriteString(key)
						sb.WriteRune('=')
						st.redactWithHMAC(val, st.entityLabel("url"), "entropy", sb)
					} else {
						sb.WriteString(param)
					}
				}
			} else {
				sb.WriteString(param)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Safety Whitelists
// -----------------------------------------------------------------------------

// isSafeRegexWhitelisted reports whether content matches a user-configured
// PII_SAFE_REGEX_LIST rule. processSingleToken already checks cfg.SafeRegexes
// on the normal token pipeline; this lets the redaction paths that bypass
// that pipeline (Luhn card sequences in scanLine, URL query parameters in
// maskURLParameters) honor the same explicit whitelist instead of silently
// ignoring it (B10).
func (st *configState) isSafeRegexWhitelisted(content string) bool {
	if len(content) < 3 {
		return false
	}
	for _, rule := range st.config.SafeRegexes {
		if rule.Regexp.MatchString(content) {
			return true
		}
	}
	return false
}

func isSafe(token string) bool {
	// Note: URL check moved up to processTokenLogic to handle masking.

	// URL / Protocol (Fallback only)
	if strings.Contains(token, "://") {
		return true
	}

	// Usage of Helper Functions to reduce complexity
	// Note: isUUID is checked via Hybrid Validation, so it's not here
	if isIPv6(token) || isTimestamp(token) || isImage(token) {
		return true
	}

	if isPath(token) || isGitHash(token) || isMongoObjectID(token) {
		return true
	}

	if isSSHKey(token) || isGeneratedUsername(token) || isPlainDecimal(token) {
		return true
	}

	return false
}

func isPlainDecimal(token string) bool {
	// Plain decimal number: optional sign, digits, one dot, digits, optional
	// exponent (6742381.25, -0.5, 6.39426e-05). The dot adds a second
	// character class, so a full-precision float can cross the entropy
	// threshold on the class bonus alone; a token of this shape is a
	// measurement, not a secret. Exponent-only forms without a dot (1e10)
	// deliberately do not match.
	s := token
	if len(s) > 1 && (s[0] == '+' || s[0] == '-') {
		s = s[1:]
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(s) || s[i] != '.' {
		return false
	}
	i++
	fracStart := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == fracStart {
		return false
	}
	if i == len(s) {
		return true
	}
	if s[i] != 'e' && s[i] != 'E' {
		return false
	}
	i++
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	expStart := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i > expStart && i == len(s)
}

func isHexStr(s string) bool {
	for _, r := range s {
		if !isHex(r) {
			return false
		}
	}
	return true
}

func isTimestamp(token string) bool {
	// Unix Timestamp (10 digits, starts with 17.., 18.., 2...)
	// 1700000000 is year 2023. ~2033 is 2000000000.
	// Check if pure digits and length 10.
	if len(token) == 10 && isDigits(token) {
		// Unix Timestamp (10 digits).
		// Current time (2023-2026) starts with 17 or 18.
		// Future proofing: also accept 19, 20 (up to year 2033+)
		if strings.HasPrefix(token, "17") || strings.HasPrefix(token, "18") ||
			strings.HasPrefix(token, "19") || strings.HasPrefix(token, "20") {
			return true
		}
	}

	// ISO8601 / RFC3339
	// 2026-01-30...
	// Req: Start with 4 digits, then -, then 2 digits.
	if len(token) >= 10 {
		if isDigits(token[0:4]) && token[4] == '-' && isDigits(token[5:7]) && token[7] == '-' {
			return true
		}
	}
	return false
}

func isImage(token string) bool {
	// common docker registries or image formats
	// e.g. docker.io/..., library/..., gcr.io/...
	if strings.Contains(token, "docker.io") || strings.Contains(token, "gcr.io") || strings.Contains(token, "quay.io") {
		return true
	}
	// common image extensions? not usually in logs unless URL.
	// common structure "name:tag" where name is alpha.
	return false
}

func isIPv6(token string) bool {
	if strings.Count(token, ":") >= 2 {
		isIPv6 := true
		for _, r := range token {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') && r != ':' {
				isIPv6 = false
				break
			}
		}
		if isIPv6 {
			return true
		}
	}
	return false
}

func isPath(token string) bool {
	// Unix Paths
	if strings.HasPrefix(token, "/") || strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") {
		return true
	}

	// Windows Paths / Namespaces
	// 1. Drive letter (e.g. C:\...)
	if len(token) >= 3 && unicode.IsLetter(rune(token[0])) && token[1] == ':' && token[2] == '\\' {
		return true
	}

	// 2. UNC Path (e.g. \\Server\Share)
	if strings.HasPrefix(token, `\\`) {
		return true
	}

	// 3. Generic Windows Path or Namespace (contains at least two backslashes)
	// e.g. "app\modules\adaptivephishing" or "System\Windows\.."
	// We require at least 2 backslashes to avoid false positives with escaped chars in other contexts,
	// though the tokenizer handles those.
	if strings.Count(token, `\`) >= 2 {
		return true
	}

	return false
}

func isGitHash(token string) bool {
	return len(token) == 40 && isHexStr(token)
}

func isMongoObjectID(token string) bool {
	return len(token) == 24 && isHexStr(token)
}

func isSSHKey(token string) bool {
	// SSH Public Key (starts with ssh-rsa, ssh-ed25519)
	if strings.HasPrefix(token, "ssh-") {
		return true
	}

	// SSH Public Key Body (starts with AAAA, high entropy, base64)
	if strings.HasPrefix(token, "AAAA") && len(token) > 20 {
		// Minimal Base64 check (just charset)
		isBase64 := true
		for _, r := range token {
			if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '+' && r != '/' && r != '=' {
				isBase64 = false
				break
			}
		}
		if isBase64 {
			return true
		}
	}
	return false
}

func isGeneratedUsername(token string) bool {
	if strings.HasPrefix(token, "user_") {
		// Safe if rest is just hex/digits/alpha and reasonable length
		rest := token[5:]
		if len(rest) > 0 && len(rest) < 12 {
			isSafeUser := true
			for _, r := range rest {
				if !isHex(r) && r != '_' { // Hex + maybe underscore?
					isSafeUser = false
					break
				}
			}
			if isSafeUser {
				return true
			}
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Luhn Check (Preserved)
// -----------------------------------------------------------------------------

type Range struct {
	Start, End int
}

func FindLuhnSequences(line string) []Range {
	// Optimization: Early exit if no digits (Avoids allocating slices)
	if !strings.ContainsAny(line, "0123456789") {
		return nil
	}
	// Note: The above optimization covers ASCII digits (most common for Credit Cards).
	// If we support non-ASCII digits (e.g. Arabic-Indic), we'd need unicode check,
	// but strings.IndexFunc(line, unicode.IsDigit) is slower.
	// Given standard usage, checking ASCII digits is a massive win for 99% of logs.

	var ranges []Range
	n := len(line)
	if n < 13 {
		return ranges
	}

	// Optimization: Use sync.Pool for digitIndices to avoid allocation per line
	digitIndicesPtr := luhnPool.Get().(*[]int)
	defer luhnPool.Put(digitIndicesPtr)

	// Reset slice length to 0, keep capacity
	digitIndices := (*digitIndicesPtr)[:0]

	// Collect ASCII digits only: the validation below (validLuhnFromIndices,
	// countDistinctDigits) does byte math (line[idx]-'0'), so collecting
	// non-ASCII digits via unicode.IsDigit would feed it rune start offsets
	// of multibyte characters — garbage arithmetic on continuation bytes.
	for i := 0; i < len(line); i++ {
		if line[i] >= '0' && line[i] <= '9' {
			digitIndices = append(digitIndices, i)
		}
	}

	// Update the pointer in the pool (in case append grew the slice reallocating underlying array)
	*digitIndicesPtr = digitIndices

	numDigits := len(digitIndices)
	if numDigits < 13 {
		return ranges
	}

	for i := 0; i <= numDigits-13; i++ {
		maxLen := 19
		if i+maxLen > numDigits {
			maxLen = numDigits - i
		}

		for L := 13; L <= maxLen; L++ {
			startIdx := digitIndices[i]
			endIdx := digitIndices[i+L-1] + 1

			// Connectivity Check
			if !areDigitsConnected(line, digitIndices[i:i+L]) {
				continue
			}

			// Boundary Check
			if !isValidBoundary(line, startIdx, endIdx) {
				continue
			}

			// Guard against degenerate all-same-digit padding (e.g. "0000000000000000",
			// which is Luhn-valid by construction). Real card numbers, including common
			// test cards like Visa's 4111111111111111, can have as few as 2 distinct
			// digits, so the threshold must stay at 2, not higher.
			if countDistinctDigits(line, digitIndices[i:i+L]) < 2 {
				continue
			}

			if validLuhnFromIndices(line, digitIndices[i:i+L]) {
				ranges = append(ranges, Range{Start: startIdx, End: endIdx})
			}
		}
	}
	return mergeRanges(ranges)
}

func countDistinctDigits(line string, indices []int) int {
	seen := 0
	mask := 0
	for _, idx := range indices {
		d := int(line[idx] - '0')
		// Safety bound check
		if d >= 0 && d <= 9 {
			if (mask & (1 << d)) == 0 {
				mask |= (1 << d)
				seen++
			}
		}
	}
	return seen
}

func validLuhnFromIndices(line string, indices []int) bool {
	n := len(indices)
	sum := 0
	alternate := false
	for i := n - 1; i >= 0; i-- {
		r := line[indices[i]]
		digit := int(r - '0')
		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		alternate = !alternate
	}
	return sum%10 == 0
}

func mergeRanges(ranges []Range) []Range {
	if len(ranges) == 0 {
		return ranges
	}
	var merged []Range
	current := ranges[0]
	for i := 1; i < len(ranges); i++ {
		next := ranges[i]
		if next.Start <= current.End {
			if next.End > current.End {
				current.End = next.End
			}
		} else {
			merged = append(merged, current)
			current = next
		}
	}
	merged = append(merged, current)
	return merged
}

func areDigitsConnected(line string, indices []int) bool {
	for k := 1; k < len(indices); k++ {
		currIdx := indices[k]
		prevIdx := indices[k-1]
		diff := currIdx - prevIdx

		if diff > 2 {
			return false
		}
		if diff == 2 {
			sep := line[prevIdx+1]
			if sep != ' ' && sep != '-' {
				return false
			}
		}
	}
	return true
}

// prevRune decodes the rune ending at byte offset idx (exclusive), with an
// ASCII fast path. A single byte cast (rune(line[idx-1])) misreads multibyte
// UTF-8 neighbors: the continuation byte of a Cyrillic letter looks like a
// non-letter Latin-1 rune and lets a letter-adjacent card run pass.
func prevRune(line string, idx int) rune {
	if b := line[idx-1]; b < utf8.RuneSelf {
		return rune(b)
	}
	r, _ := utf8.DecodeLastRuneInString(line[:idx])
	return r
}

// nextRune decodes the rune starting at byte offset idx, ASCII fast path.
func nextRune(line string, idx int) rune {
	if b := line[idx]; b < utf8.RuneSelf {
		return rune(b)
	}
	r, _ := utf8.DecodeRuneInString(line[idx:])
	return r
}

func isValidBoundary(line string, startIdx, endIdx int) bool {
	// BOUNDARY CHECK: Ensure we are not inside a word or larger number
	if startIdx > 0 {
		r := prevRune(line, startIdx)
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
		// UUID/Alphanumeric check: if separator is '-', check prev char
		if r == '-' || r == '.' {
			if startIdx > 1 {
				r2 := prevRune(line, startIdx-1)
				if unicode.IsLetter(r2) {
					return false
				}
				// Decimal check: digits on both sides of a '.' mean the run
				// is the fractional part of a number (0.6378436834372556),
				// not a standalone card candidate.
				if r == '.' && unicode.IsDigit(r2) {
					return false
				}
			}
		}
	}
	if endIdx < len(line) {
		r := nextRune(line, endIdx)
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
		// UUID/Alphanumeric check: if separator is '-', check next char
		if r == '-' || r == '.' {
			if endIdx+1 < len(line) {
				r2 := nextRune(line, endIdx+1)
				if unicode.IsLetter(r2) {
					return false
				}
				// Decimal check: run followed by '.<digit>' is the integer
				// part of a number (6378436834372556.25), not a card.
				if r == '.' && unicode.IsDigit(r2) {
					return false
				}
			}
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func isDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

type segmentState struct {
	pendingKeySensitive     bool
	pendingContextSensitive bool // NEW: For "Error: secret"
	isInValuePos            bool // Tracks if we are physically after a ':' or '=' separator

	// Generic KV Support
	pendingGenericKey    bool // True if last key was "key", "name"
	nextValueIsSensitive bool // True if "key"="password", so next "value" is sensitive
}

func (st *configState) processAndAppend(token string, sb *strings.Builder, state *segmentState, depth int) {
	// 0. Pre-analysis for Generic Key State (before token is consumed/redacted)
	trimmed := strings.TrimSpace(token)
	cleanToken := trimmed
	// Strip trailing separators for analysis
	if strings.HasSuffix(cleanToken, ":") || strings.HasSuffix(cleanToken, "=") {
		cleanToken = cleanToken[:len(cleanToken)-1]
	}
	cleanToken = trimQuotes(cleanToken)
	lowerClean := strings.ToLower(cleanToken)

	// Check if this token is a "Generic Key" identifier (e.g. "key", "name")
	isGenericKeyName := lowerClean == "key" || lowerClean == "name" || lowerClean == "setting"

	// 1. Process Token
	isKey := st.processTokenLogic(token, state.pendingKeySensitive, state.pendingContextSensitive, state.isInValuePos, state.nextValueIsSensitive, sb, depth)
	// sb is updated inside processTokenLogic

	// 2. Update Context State
	if isKey {
		state.pendingKeySensitive = true // Next token (value) will be redacted
		// Reset expectation since we found the key
		state.nextValueIsSensitive = false

		if isGenericKeyName {
			state.pendingGenericKey = true
		} else {
			state.pendingGenericKey = false
		}
	} else {
		// A non-key token consumes any pending key-sensitivity. Reset it
		// unconditionally (not only in value position) so a bare sensitive
		// word in prose — e.g. "password was rejected for user bob" — does not
		// force-redact the rest of the segment (B1). processTokenLogic above
		// already read the flag, so the first token after the key is still
		// redacted (keeping "password hunter2" detection); only later tokens
		// are freed.
		state.pendingKeySensitive = false

		// If we were waiting for the value of a Generic Key...
		if state.isInValuePos && state.pendingGenericKey {
			// Check if THIS value is a sensitive key name (e.g. "password")
			// cleanToken is the raw content of the value (e.g. "password")
			if st.isSensitiveKey(cleanToken) {
				// We found {"key": "password"}. The NEXT key-value pair should be sensitive.
				state.nextValueIsSensitive = true
			}
			state.pendingGenericKey = false
		}
	}

	// Check if this token is a Context Keyword (e.g. "Error", "Failed")
	if ContextKeywords[lowerClean] {
		state.pendingContextSensitive = true
	} else {
		state.pendingContextSensitive = false
	}

	// Fix: Detect separators attached to end of token (e.g. "key":)
	// This ensures the NEXT token is treated as a value.
	hasSuffixSep := strings.HasSuffix(trimmed, ":") || strings.HasSuffix(trimmed, "=")

	if trimmed == ":" || trimmed == "=" || hasSuffixSep {
		state.isInValuePos = true
	} else if trimmed != "" {
		// Reset if it was a normal token (key or value)
		state.isInValuePos = false
	}
}
