# PII-Shield Configuration

PII-Shield is configured entirely via environment variables.

## Critical Security Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PII_SALT` | Random byte string used for HMAC hashing. **MUST be >16 chars in production.** | **No (Recommended)** | Randomly generated on startup (but ephemeral) |
| `PII_REQUIRE_STRONG_SALT` | Reject startup when `PII_SALT` is explicitly set to fewer than 16 bytes. Recommended for production and compliance deployments. | No | `false` |

> [!WARNING]
> If `PII_SALT` is not set, PII-Shield generates a random salt on startup. This means hashes will change every time the pod restarts, making it impossible to correlate logs across restarts. For production, **ALWAYS** set a persistent `PII_SALT`.

Set `PII_REQUIRE_STRONG_SALT=true` in production if you want startup to fail instead of only warning when a weak explicit salt is configured.

## Detection Tuning

| Variable | Description | Default |
|----------|-------------|---------|
| `PII_ENTROPY_THRESHOLD` | Shannon entropy threshold (3.0 - 8.0). Higher = fewer false positives, but might miss simple passwords. | `3.6` |
| `PII_CONFIDENCE_THRESHOLD` | Multiplier applied to the effective entropy threshold. Values above `1.2` also restrict credit-card (Luhn) matches to lines containing card context words (`card`, `cc`, `pan`, `visa`). | `1.0` |
| `PII_MIN_SECRET_LENGTH` | Minimum length of a string to be considered a candidate token. | `6` |
| `PII_SENSITIVE_KEYS` | Comma-separated list of keys to *always* redact values for (case-insensitive, substring match). **Replaces** the default list instead of extending it. | `pass,secret,token,key,cvv,cvc,auth,sign,password,passwd,api_key,apikey,access_token,client_secret,aws_access_key_id,aws_secret_access_key,gcp_credentials,slack_token` |
| `PII_SENSITIVE_KEY_PATTERNS` | Comma-separated list of regex patterns for key detection. | (empty) |

> **Strict numeric parsing:** an invalid value in `PII_ENTROPY_THRESHOLD`, `PII_CONFIDENCE_THRESHOLD`, or `PII_BIGRAM_DEFAULT_SCORE` — including trailing junk like `3.6junk` — is rejected with a startup `WARNING` and the default is kept. Earlier versions silently applied the numeric prefix of such values.

## Advanced Features

| Variable | Description | Default |
|----------|-------------|---------|
| `PII_ADAPTIVE_THRESHOLD` | Enable statistical learning. Scanner adjusts threshold based on traffic baseline. | `false` |
| `PII_ADAPTIVE_SAMPLES` | Number of samples to collect before activating adaptive mode. | `100` |
| `PII_DISABLE_BIGRAM_CHECK` | Disable English bigram validation. Set to `true` for non-English logs. | `false` |
| `PII_BIGRAM_DEFAULT_SCORE` | Log-probability score for unknown bigrams. | `-7.0` |
| `PII_ENTITY_TYPE_LABELS` | Emit `[HIDDEN:<type>:<hash>]` instead of `[HIDDEN:<hash>]`, where `<type>` names the detector that fired: `card` (Luhn), `key` (sensitive key), `context` (context keyword), `url` (URL parameter entropy), `regex` (unnamed custom rule), `entropy` (plain entropy). Named custom rules keep their own name as the label. The hash is unchanged, so enabling the flag does not break tag correlation. Accepts `1`/`true`/`yes`/`y`/`on`. | `false` |

## Runtime Failure Policy

| Variable | Description | Default |
|----------|-------------|---------|
| `PII_FAIL_POLICY` | Controls behavior when line processing fails. Use `open` to keep log flow alive where possible, or `closed` to emit drop markers instead of raw lines. | `open` |

See `docs/sidecar-failure-modes.md` for production failure-mode guidance.

## Observability

| Variable | Description | Default |
|----------|-------------|---------|
| `PII_METRICS_ENABLED` | Expose a Prometheus `/metrics` endpoint and a `/healthz` probe. | `false` |
| `PII_METRICS_PORT` | Port for the metrics/health server (1–65535). | `9090` |
| `PII_STATS_LOG_INTERVAL` | When set to a positive Go duration (e.g. `1h`, `30m`), log a periodic aggregated redaction summary — counts of high-entropy secrets, pattern matches, and card numbers, plus lines and bytes processed — and a final summary on shutdown. Empty or invalid disables it. Independent of `PII_METRICS_ENABLED`. | _(disabled)_ |

The stats summary is a single log line per interval, e.g.
`PII-Shield stats: 1,240 redactions (900 high-entropy secrets, 297 pattern matches, 43 card numbers) across 12,345 lines / 5.2 MB processed`.

## Value-Based Regex Redaction (Deterministic)

| Variable | Description |
|----------|-------------|
| `PII_CUSTOM_REGEX_LIST` | JSON array of regex objects to enforce redaction regardless of entropy. Supports named placeholders. |

> [!WARNING]
> **Invalid input is skipped, not fatal:** malformed JSON in `PII_CUSTOM_REGEX_LIST` or `PII_SAFE_REGEX_LIST` disables that list, and an invalid regex pattern disables that rule only — each with a startup `WARNING` on stderr, while scanning continues with the remaining rules. A skipped **custom** rule means its matches are no longer force-redacted, and a skipped **safe** rule means its matches lose their whitelist protection — so still validate patterns before rollout and watch startup logs. (Earlier versions terminated the process at startup instead, which showed up as a crash loop in a sidecar.)

### Example

```bash
export PII_CUSTOM_REGEX_LIST='[{"pattern": "^[0-9a-fA-F-]{36}$", "name": "UUID"}, {"pattern": "^TX-\\d{5}$", "name": "TX"}]'
```

> [!TIP]
> **Priority:** Custom regexes are checked **before** entropy but **after** static safety whitelists. The built-in static whitelists cover URLs, file paths, timestamps, UUIDs, git hashes and `abc1234..def5678` hash ranges, MongoDB ObjectIDs, SSH keys, plain decimal numbers, and whole `git diff` header lines (`diff --git`, `--- a/`, `+++ b/`, `rename`/`copy from|to`, `Binary files`); diff body lines are scanned normally. Use this to catch structured data like UUIDs or specific IDs that the entropy scanner might miss or consider "safe".
> **Performance:** Regex checks are skipped for tokens shorter than 5 characters.

> [!NOTE]
> **Optimized Performance:** PII-Shield uses a combined O(1) regex engine. You can define multiple custom rules (10+) with minimal performance impact.

> [!WARNING]
> **Per-Token Matching:** The regex is applied to individual tokens (words/strings separated by spaces, `=`, `:`).
> Patterns containing spaces (e.g., Credit Cards `4111 1234...`) **will not work** because the scanner splits them into multiple tokens before checking the regex.


## Safe Regex Whitelist (Bypass)

| Variable | Description |
|----------|-------------|
| `PII_SAFE_REGEX_LIST` | JSON array of regex objects to **ignore** during scanning. Matches are returned as-is. |

### Example

```bash
export PII_SAFE_REGEX_LIST='[{"pattern": "^SAFE-[0-9]{4}$", "name": "SafePrefix"}]'
```

> [!IMPORTANT]
> **Top Priority:** Whitelisted patterns are checked **first**. If a token matches a safe regex, it bypasses all other checks (Custom Regex, Entropy, etc.).


## Example (Kubernetes)

> [!NOTE]
> When the sidecar is injected by the PII-Shield operator, do not set these
> variables by hand — declare them in a `PiiPolicy` object instead. See
> [Scanner Configuration via PiiPolicy](operator/README.md#scanner-configuration-via-piipolicy)
> for the field mapping and the effective precedence rules.

Here is a production-ready configuration using `secretKeyRef` for the salt and defining regex rules.

```yaml
env:
  # 1. Determinism: Load Salt from a K8s Secret (Recommended)
  - name: PII_SALT
    valueFrom:
      secretKeyRef:
        name: pii-shield-secrets
        key: salt

  # 2. Tuning: Adjust Sensitivity
  - name: PII_ENTROPY_THRESHOLD
    value: "4.2"
  
  # 3. Whitelist: Explicitly allow safe patterns (e.g. Git SHA)
  # Note: Use single quotes '' for the value to avoid YAML escaping issues with JSON
  - name: PII_SAFE_REGEX_LIST
    value: '[{"pattern": "^[a-f0-9]{7}$", "name": "GitShortSHA"}]'

  # 4. Custom Redaction: Block specific patterns (e.g. internal IDs)
  - name: PII_CUSTOM_REGEX_LIST
    value: '[{"pattern": "^INTERNAL-[0-9]+$", "name": "InternalID"}]'
```
