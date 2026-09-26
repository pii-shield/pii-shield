# Known Limitations

PII-Shield is released and usable, but not yet fully production-hardened across all deployment modes. Production compliance deployments should account for the boundaries below.

## Kubernetes Logging

- The default file-based sidecar mode expects the application to write logs to the configured file path.
- Full transparent interception of standard Kubernetes `stdout`/`stderr` logs is not complete yet.
- Pipe mode is experimental and not recommended for production. It rewrites the target container command through `/bin/sh -c`, which can break distroless images (no shell), argument quoting, signal handling, and the app lifecycle. The webhook returns a warning when a pipe-mode policy is applied.

## Operator

- The Kubernetes operator is in stabilization. It supports policy objects and webhook injection, but advanced policy lifecycle management is still evolving.
- eBPF mode is experimental/R&D and should not be treated as production-ready interception.

## Scanner Configuration

- Set a persistent `PII_SALT` in production if deterministic hashes must remain stable across restarts.
- **Rotating `PII_SALT` breaks tag correlation, and there is no overlap mode.** The scanner holds one key and the tag carries no key id, so the same value gets a different tag before and after a rotation: joins and distinct counts across the boundary do not work. To trace a known identifier across periods, keep each retired salt with the dates it was active, run the identifier through the scanner under each one and search that period's logs for the tag it prints:

  ```bash
  echo 'iban=GB29NWBK60161331926819' | docker run -i --rm -e PII_SALT="$RETIRED_SALT" ghcr.io/pii-shield/pii-shield:2.2.4
  ```

  The tag depends only on the value and the salt, not on the key name around it, but the scanner has to redact the value in the first place: a short numeric account number is hidden only under a sensitive key, so pass the same `PII_SENSITIVE_KEYS` the deployment used. The tag is the first 3 bytes of HMAC-SHA256 (`pkg/scanner/scanner.go`), six hex characters, so in a large log a match is a candidate to confirm by time and surrounding fields, not proof. A retired salt still lets whoever holds it compute tags for its period, so keep it as a secret and destroy it when the logs of that period are deleted. Emitting old and new tags side by side during a transition is not built.
- Adaptive entropy thresholding is experimental and should be validated against representative log traffic before enabling.
- Custom regex and safe regex rules should be tested with real log samples to avoid false positives or false negatives.
- **The card detector only knows the major networks.** A digit run counts as a card when it passes Luhn and starts with a Visa, Mastercard, American Express, Discover, JCB, Diners Club or UnionPay issuer prefix at a length that issuer uses (the table is in `pkg/scanner/bin.go`). Maestro is left out on purpose — its range is wide enough to admit most numeric IDs — and store cards, fleet cards and regional schemes are not listed. Such a number may still be redacted by entropy, but it will not carry the `card` label; add a custom regex if a specific scheme matters to you.
- **A rule can never match a phrase that spans two words.** Rules are applied in `processSingleToken` (`pkg/scanner/scanner.go`) to one whitespace-separated token at a time, so a pattern like `British Asian` is never tested against anything containing a space, however it is written — the scanner has already split the line before the rule is reached. Single-word patterns (`^Asian$`) work normally. This is a boundary of the design, not a gap in the rule list: matching phrases in the core would mean carrying multi-token state through the tokenizer, and free-text semantics is reserved for the selective PII model plan. Handle multi-word categories — GDPR Article 9 special-category phrases, for instance — before the text reaches the scanner.
- **A key that looks like a field name is not scored.** In `key=value` the key half is checked only when it does not have a field-name shape (`writeKeyHalf` in `pkg/scanner/scanner.go`). A key with `_`, `-`, `.`, `:`, `&`, `;` or `%` in it, or one made only of letters with at most trailing digits (`requestId`, `HTTP`, `sha256`), is written out as is unless it matches a secret signature such as an AWS or GitHub key. Scoring every key would hide ordinary field names, since `context_id` and `request_id` sit right at the entropy threshold. So a random secret made only of letters, or one containing `_` or `-`, still passes when it is used as a key, and keys before a colon (`"key": value`) are not scored at all.

## Roadmap Boundaries

Proxy-Wasm gateway integration, a visual Control Plane, and production-grade eBPF interception are planned R&D areas rather than completed stable features.
