# @aragossa/pii-shield-wasi

PII redaction scanner powered by the core Go engine compiled to WebAssembly (WASI). It runs **in-process** — no network hop — using hybrid heuristic and entropy-based detection.

## Installation

```bash
npm install @aragossa/pii-shield-wasi
```

## Usage

```javascript
const { PiiShield } = require('@aragossa/pii-shield-wasi');

// Initialize the scanner with optional configuration overrides
const shield = await PiiShield.create({
    entropyThreshold: 4.0,
    confidenceScore: 0.8
});

const text = "Connecting to DB with api_key: aB3$xyz890LmnopQ";
const redactedText = shield.redact(text);

console.log(redactedText);
// Output will have the high entropy token redacted
```

`redact()` accepts multi-line text. Each line is scanned independently and `\n` / `\r\n` endings are preserved, so the output has exactly as many lines as the input (the same contract the CLI gives stdin).

## Configuration

`PiiShield.create(config)` accepts these overrides. Any field left unset keeps
the core scanner default, so redaction matches the CLI for the same config.

| Option | Type | Description |
|--------|------|-------------|
| `entropyThreshold` | number | Shannon entropy cut-off for candidate tokens. |
| `confidenceScore` | number | Hybrid-validation confidence threshold. |
| `salt` | string | HMAC salt for deterministic `[HIDDEN:xxxxxx]` tokens. Set it to correlate across processes. |
| `minSecretLength` | number | Minimum candidate token length before entropy checks apply. |
| `sensitiveKeys` | string[] | Key names whose values are always redacted (case-insensitive). Replaces the defaults. |
| `disableBigramCheck` | boolean | Disable English bigram analysis (useful for non-English logs). |
| `adaptiveThreshold` | boolean | Enable the **experimental** statistical adaptive-threshold mode. |
| `entityTypeLabels` | boolean | Emit `[HIDDEN:<type>:<hash>]` markers, where `<type>` names the detector that fired (`card`, `key`, `context`, `url`, `regex`, `entropy`). Off by default; the hash is unchanged. |
| `sensitiveKeyPatterns` | string[] | Regex patterns matched against key names (equivalent to `PII_SENSITIVE_KEY_PATTERNS`). |
| `customRegexes` | `{pattern, name}[]` | Rules forcing redaction of matching tokens (equivalent to `PII_CUSTOM_REGEX_LIST`). |
| `safeRegexes` | `{pattern, name}[]` | Whitelist rules exempting matching tokens (equivalent to `PII_SAFE_REGEX_LIST`). |
| `failPolicy` | `"open"` \| `"closed"` | On an internal error, `open` returns the input unchanged; `closed` returns a drop marker. Handled in this wrapper. |

### Invalid regex handling

The CLI fails fast on an invalid pattern at startup. The SDK deliberately does
**not**: an invalid `sensitiveKeyPatterns`, `customRegexes`, or `safeRegexes`
entry is ignored and the default is kept, so a bad pattern can never terminate
your Node process. Validate patterns before passing them if you need strictness.

## Features

- **In-process**: runs the Go WASM binary inside Node.js — no network hop by construction.
- **Low-allocation hot path**: the scan loop is optimized to reduce garbage-collection overhead during large log streaming.
- **Hybrid scoring**: combines static whitelists, regex heuristics, and Shannon entropy, which helps avoid false positives on structured values like UUIDs and IPv6 addresses.
