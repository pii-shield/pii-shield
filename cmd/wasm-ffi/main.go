//go:build wasm

package main

import (
	"encoding/json"
	"strings"
	"unsafe"

	"github.com/pii-shield/pii-shield/pkg/scanner"
)

// ConfigFromSDK represents configuration passed from Python/Node.js SDKs.
// Every field the core scanner supports at scan time is accepted here; the
// regex-backed fields are compiled via the shared scanner.Apply* helpers so the
// SDKs and the CLI derive identical matching state.
type ConfigFromSDK struct {
	EntropyThreshold     float64                     `json:"entropy_threshold"`
	Salt                 string                      `json:"salt"`
	ConfidenceThreshold  float64                     `json:"confidence_score"`
	FailPolicy           string                      `json:"fail_policy"`
	MinSecretLength      int                         `json:"min_secret_length"`
	SensitiveKeys        []string                    `json:"sensitive_keys"`
	DisableBigramCheck   *bool                       `json:"disable_bigram_check"`
	AdaptiveThreshold    *bool                       `json:"adaptive_threshold"`
	EntityTypeLabels     *bool                       `json:"entity_type_labels"`
	SensitiveKeyPatterns []string                    `json:"sensitive_key_patterns"`
	CustomRegexes        []scanner.CustomRegexConfig `json:"custom_regexes"`
	SafeRegexes          []scanner.CustomRegexConfig `json:"safe_regexes"`
}

// We use a map to pin memory allocations. This prevents Go's Garbage Collector
// from reclaiming the memory before the WASM Host (Python/Node.js) reads it.
var allocations = make(map[uint32][]byte)

// allocate reserves memory for the host to write strings into.
//go:wasmexport allocate
func allocate(size uint32) uint32 {
	if size == 0 {
		return 0
	}
	buf := make([]byte, size)
	ptr := uint32(uintptr(unsafe.Pointer(&buf[0])))
	allocations[ptr] = buf
	return ptr
}

// free releases memory allocated by allocate or redact.
//go:wasmexport free
func free(ptr uint32, size uint32) {
	delete(allocations, ptr)
}

// init_config receives JSON representing the config payload.
//go:wasmexport init_config
func init_config(ptr uint32, length uint32) {
	if ptr == 0 || length == 0 {
		return
	}

	// Reconstruct the byte slice from host memory
	b := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)

	// Seed from real defaults so a partial SDK override (e.g. just a salt) keeps
	// SensitiveKeys and the entropy threshold; only provided fields are applied.
	cfg := scanner.DefaultConfig()
	cfg.Salt = []byte("pii-shield-default-salt-12345678")

	var sdkCfg ConfigFromSDK
	if err := json.Unmarshal(b, &sdkCfg); err == nil {
		if sdkCfg.EntropyThreshold > 0 {
			cfg.EntropyThreshold = sdkCfg.EntropyThreshold
		}
		if sdkCfg.Salt != "" {
			cfg.Salt = []byte(sdkCfg.Salt)
		}
		if sdkCfg.ConfidenceThreshold > 0 {
			cfg.ConfidenceThreshold = sdkCfg.ConfidenceThreshold
		}
		if sdkCfg.MinSecretLength > 0 {
			cfg.MinSecretLength = sdkCfg.MinSecretLength
		}
		if len(sdkCfg.SensitiveKeys) > 0 {
			// Normalize the same way loadConfig does for PII_SENSITIVE_KEYS so
			// SDK-provided keys match the CLI's case-insensitive matching.
			keys := make([]string, len(sdkCfg.SensitiveKeys))
			for i, k := range sdkCfg.SensitiveKeys {
				keys[i] = strings.ToLower(strings.TrimSpace(k))
			}
			cfg.SensitiveKeys = keys
		}
		if sdkCfg.DisableBigramCheck != nil {
			cfg.DisableBigramCheck = *sdkCfg.DisableBigramCheck
		}
		if sdkCfg.AdaptiveThreshold != nil {
			cfg.AdaptiveThreshold = *sdkCfg.AdaptiveThreshold
		}
		if sdkCfg.EntityTypeLabels != nil {
			cfg.EntityTypeLabels = *sdkCfg.EntityTypeLabels
		}
		// Regex-backed fields go through the shared compile helpers. Errors are
		// deliberately swallowed: unlike the CLI (which fails fast at startup),
		// an invalid pattern from an SDK caller must never terminate the host
		// Node/Python process. A rejected list simply leaves the default in place.
		if len(sdkCfg.SensitiveKeyPatterns) > 0 {
			if err := cfg.ApplySensitiveKeyPatterns(sdkCfg.SensitiveKeyPatterns); err != nil {
				cfg.SensitiveKeyPatterns = nil
			}
		}
		if len(sdkCfg.CustomRegexes) > 0 {
			_ = cfg.ApplyCustomRegexes(sdkCfg.CustomRegexes)
		}
		if len(sdkCfg.SafeRegexes) > 0 {
			_ = cfg.ApplySafeRegexes(sdkCfg.SafeRegexes)
		}
		// Fail policy is handled in the SDK wrappers (Node/Python), not in
		// scanner.Config.
	}

	scanner.UpdateConfig(cfg)
}

// redact reads a string from memory, redacts it, and returns a packed uint64 (ptr << 32 | length).
//go:wasmexport redact
func redact(ptr uint32, length uint32) uint64 {
	if ptr == 0 || length == 0 {
		return 0
	}

	// Read the string from host memory
	b := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)
	input := unsafe.String(&b[0], length)

	// Process line by line: SDK callers pass whole documents (a git diff, a
	// log batch), and the single-line engine would otherwise score the last
	// token of every line together with its newline (#184).
	redacted := scanner.ScanAndRedactText(input)
	
	outBytes := []byte(redacted)
	var ptr32 uint32
	var len32 uint32 = uint32(len(outBytes))

	if len32 > 0 {
		ptr32 = uint32(uintptr(unsafe.Pointer(&outBytes[0])))
		// Pin it!
		allocations[ptr32] = outBytes
	}

	// Pack 64-bit integer: High 32 bits = Pointer, Low 32 bits = Length
	return (uint64(ptr32) << 32) | uint64(len32)
}

// main must exist for the WebAssembly compiler to run, but is unused for library builds.
func main() {}
