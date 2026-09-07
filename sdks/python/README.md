# pii-shield-wasi

PII redaction scanner powered by the core Go engine compiled to WebAssembly (WASI). It runs **in-process** — no network hop — using hybrid heuristic and entropy-based detection.

## Installation

```bash
pip install pii-shield-wasi
```

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
| `salt` | str | HMAC salt for deterministic `[HIDDEN:xxxxxx]` tokens. Set it to correlate across processes. |
| `min_secret_length` | int | Minimum candidate token length before entropy checks apply. |
| `sensitive_keys` | list[str] | Key names whose values are always redacted (case-insensitive). Replaces the defaults. |
| `disable_bigram_check` | bool | Disable English bigram analysis (useful for non-English logs). |
| `adaptive_threshold` | bool | Enable the **experimental** statistical adaptive-threshold mode. |
| `entity_type_labels` | bool | Emit `[HIDDEN:<type>:<hash>]` markers, where `<type>` names the detector that fired (`card`, `key`, `context`, `url`, `regex`, `entropy`). Off by default; the hash is unchanged. |
| `sensitive_key_patterns` | list[str] | Regex patterns matched against key names (equivalent to `PII_SENSITIVE_KEY_PATTERNS`). |
| `custom_regexes` | list[dict] | Rules forcing redaction: `[{"pattern": ..., "name": ...}]` (equivalent to `PII_CUSTOM_REGEX_LIST`). |
| `safe_regexes` | list[dict] | Whitelist rules exempting matching tokens (equivalent to `PII_SAFE_REGEX_LIST`). |
| `fail_policy` | `"open"` \| `"closed"` | On an internal error, `open` returns the input unchanged; `closed` returns a drop marker. Handled in this wrapper. |

### Invalid regex handling

The CLI fails fast on an invalid pattern at startup. The SDK deliberately does
**not**: an invalid `sensitive_key_patterns`, `custom_regexes`, or `safe_regexes`
entry is ignored and the default is kept, so a bad pattern can never terminate
your Python process. Validate patterns before passing them if you need strictness.

## Features

- **In-process**: runs the Go WASM binary inside Python via Wasmtime — no network hop by construction.
- **Low-allocation hot path**: the scan loop is optimized to reduce garbage-collection overhead during large log streaming.
- **Hybrid scoring**: combines static whitelists, regex heuristics, and Shannon entropy, which helps avoid false positives on structured values like UUIDs and IPv6 addresses.
