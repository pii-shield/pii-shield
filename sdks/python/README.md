# pii-shield-wasi

PII redaction scanner powered by the core Go engine compiled to WebAssembly (WASI). It runs **in-process** — no network hop — using hybrid heuristic and entropy-based detection.

## Installation

```bash
pip install pii-shield-wasi
```

Requires Python 3.9+ and `wasmtime` 45.0.0+ (pulled in by `pip`). On macOS this
includes Apple's `/usr/bin/python3`: the SDK turns off wasmtime's Mach-port trap
handler there, which Apple-signed interpreters do not allow and which used to get
the process killed (`Killed: 9`) on the first call.

## Usage

```python
from pii_shield import PiiShield, PiiShieldConfig

# Initialize the scanner with optional configuration overrides
shield = PiiShield(PiiShieldConfig(
    entropy_threshold=4.0,
    confidence_score=0.8
))

text = "Connecting to DB with password: MySuperSecretPassword123!"
redacted_text = shield.redact(text)

print(redacted_text)
# Output might redact the high entropy secret based on context
```

`redact()` accepts multi-line text. Each line is scanned independently and `\n` / `\r\n` endings are preserved, so the output has exactly as many lines as the input (the same contract the CLI gives stdin).

## Configuration

`PiiShieldConfig` accepts these overrides. Any field left unset keeps the core
scanner default, so redaction matches the CLI for the same config.

| Option | Type | Description |
|--------|------|-------------|
| `entropy_threshold` | float | Shannon entropy cut-off for candidate tokens. |
| `confidence_score` | float | Hybrid-validation confidence threshold. |
| `salt` | str | HMAC salt for the `[HIDDEN:xxxxxx]` tags. Treat it as a secret: anyone who has it can compute the tag of a guessed value. If unset, each instance draws a random salt, so tags match only within that instance; set the same salt in every process that must produce matching tags. |
| `min_secret_length` | int | Minimum candidate token length before entropy checks apply. |
| `sensitive_keys` | list[str] | Key names whose values are always redacted (case-insensitive). Replaces the defaults. |
| `disable_bigram_check` | bool | Disable English bigram analysis (useful for non-English logs). |
| `adaptive_threshold` | bool | Enable the **experimental** statistical adaptive-threshold mode. |
| `entity_type_labels` | bool | Emit `[HIDDEN:<type>:<hash>]` markers, where `<type>` names the detector that fired: `card`, `key`, `context`, `url`, `regex`, `entropy`, or one of the issuer-format detectors `aws-key`, `gcp-key`, `github-token`, `slack-token`, `stripe-key`, `jwt`, `telegram-bot-token`, and `private-key` (a PEM private-key framing line). A named custom rule uses its own name. Off by default; the hash is unchanged. |
| `sensitive_key_patterns` | list[str] | Regex patterns matched against key names (equivalent to `PII_SENSITIVE_KEY_PATTERNS`). |
| `custom_regexes` | list[dict] | Rules forcing redaction: `[{"pattern": ..., "name": ...}]` (equivalent to `PII_CUSTOM_REGEX_LIST`). |
| `safe_regexes` | list[dict] | Whitelist rules exempting matching tokens (equivalent to `PII_SAFE_REGEX_LIST`). |
| `fail_policy` | `"open"` \| `"closed"` | On an internal error, `open` returns the input unchanged; `closed` returns a drop marker. Handled in this wrapper. |

### Invalid regex handling

A bad pattern can never terminate your Python process. An invalid
`custom_regexes` or `safe_regexes` entry is **skipped and the rest of the list is
applied**; each skipped rule is reported with a `WARNING` on stderr. (Before
version 2.2.4 one invalid entry silently dropped the *whole* list, so a single
stray bracket switched off every rule in it.) An invalid `sensitive_key_patterns`
entry disables that pattern list with a warning. The CLI behaves the same way
for its environment-variable lists. Validate patterns before rollout if you need
strictness — a skipped custom rule means its matches are no longer force-redacted.

## Features

- **In-process**: runs the Go WASM binary inside Python via Wasmtime — no network hop by construction.
- **Low-allocation hot path**: the scan loop is optimized to reduce garbage-collection overhead during large log streaming.
- **Hybrid scoring**: combines static whitelists, regex heuristics, and Shannon entropy, which helps avoid false positives on structured values like UUIDs and IPv6 addresses.
