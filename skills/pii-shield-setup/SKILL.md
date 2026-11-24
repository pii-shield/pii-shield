---
name: pii-shield-setup
description: Set up and tune PII-Shield, the log redaction sidecar for Kubernetes (also a CLI, a Docker image, a Go library and WASM SDKs for Node and Python). Use when someone wants to install the PII-Shield operator, write or review a PiiPolicy, get the sidecar injected into a workload, choose PII_* environment variables, fix false positives or missed values, run audit mode before redacting, or check that a deployment really hides what it should.
---

# PII-Shield setup

PII-Shield reads log lines and replaces secrets and personal data with a tag such as `[HIDDEN:25d845]`. It runs in-process (CLI, sidecar, Go library, WASM); nothing is sent to a server. The docs of record are in the repository: `README.md`, `CONFIGURATION.md`, `operator/README.md`, `KNOWN_LIMITATIONS.md`. When this skill and those files disagree, the files win: read them.

Work in this order: pick the deployment, set the salt, run in audit mode, tune, turn redaction on, verify with planted values.

## 1. Pick the deployment

| Situation | Use |
|---|---|
| Kubernetes, the app can write its log to a file | Operator, `injectionMode: file` (the supported path) |
| Try it on a laptop, or sanitize a file or a pipe | CLI or the Docker image |
| A Go service that should redact before writing | Go library `github.com/pii-shield/pii-shield/v3/pkg/scanner` |
| Node or Python code that should redact in-process | `@aragossa/pii-shield-wasi` (npm), `pii-shield-wasi` (PyPI) |

Say these limits early, before the user builds on them:

- Transparent interception of plain container stdout/stderr is not done. File mode needs the app to write its log to a file.
- `injectionMode: pipe` is experimental. It wraps the container command in `/bin/sh -c`, which breaks distroless images, quoting and signal handling. Do not suggest it for production.
- `injectionMode: ebpf` only counts. It never redacts, and the API server rejects it without `auditMode: true`.
- The scanner works on single tokens. It does not find names or other PII written as free text. See `KNOWN_LIMITATIONS.md`.

## 2. Try it locally first

```bash
echo "Error: User password=MySecretPass123! failed login" | docker run -i --rm ghcr.io/pii-shield/pii-shield:3.0.0
# Error: User password=[HIDDEN:...] failed login
```

The tag changes between runs unless `PII_SALT` is set (`-e PII_SALT=...`). To build from source: `go build -o pii-shield ./cmd/cleaner`. Each line of input gives exactly one line of output.

Use `PII_ENTITY_TYPE_LABELS=true` while tuning. The marker then names the detector that fired, for example `[HIDDEN:card:...]`, `[HIDDEN:key:...]` or `[HIDDEN:entropy:...]`. The hash part stays the same.

## 3. Kubernetes with the operator

Install. The chart uses cert-manager for the webhook certificate by default (`webhook.useCertManager: true`). Without cert-manager in the cluster, set it to `false` and Helm generates a self-signed certificate:

```bash
helm repo add pii-shield https://pii-shield.github.io/pii-shield/
helm repo update
helm install pii-shield-operator pii-shield/pii-shield-operator \
  -n operator-system --create-namespace \
  --set webhook.useCertManager=false   # only when cert-manager is not installed
```

Injection needs all four of these. Check each one when "the sidecar was not injected":

1. The namespace has the label `pii-shield.io/injection=enabled`. The webhook is not called for pods in other namespaces.
   `kubectl label namespace <ns> pii-shield.io/injection=enabled`
2. The pod template has the label `pii-shield.io/inject: "true"`. A namespace label alone injects nothing.
3. A `PiiPolicy` exists in the same namespace. Its name comes from the pod annotation `pii-shield.io/policy`, or is `default` when the annotation is missing. With no policy found, the pod starts without a sidecar and the API server returns a warning. Use `webhook.strictMode=true` together with `webhook.failurePolicy=Fail` to reject such pods.
4. The pod is created after 1-3 are in place. A running pod never gets a sidecar: run `kubectl rollout restart` on the workload.

A pod with more than one container also needs the annotation `pii-shield.io/target-container: <name>`. Without it, the pod is denied.

How file mode works, so you can explain what to change in the app:

- The app writes to `logPath`. The default is `/app/logs/log.txt`.
- The webhook mounts an empty `emptyDir` over the directory of `logPath` in the app container. Anything the image had in that directory is hidden by the mount, so pick a directory used only for this log.
- The redacted lines are on the sidecar's stdout: `kubectl logs <pod> -c pii-shield-sidecar`. Point the log collector at that container.

A starting policy with a persistent salt, in audit mode:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pii-shield-salt
  namespace: payments
type: Opaque
stringData:
  salt: "<at least 32 random characters, for example from: openssl rand -hex 32>"
---
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: default
  namespace: payments
spec:
  injectionMode: file
  logPath: /var/log/app/app.log
  auditMode: true
  saltSecretKeyRef:
    name: pii-shield-salt
    key: salt
```

Never put a real salt value in a policy, in chat or in a committed file. Use `saltSecretKeyRef`, or set it once for all policies with `--set sidecar.saltSecret.name=pii-shield-salt` at install time (that Secret must exist in every namespace with injection).

PiiPolicy fields and the variables they become:

| Field | Sidecar variable | Notes |
|---|---|---|
| `failPolicy` | `PII_FAIL_POLICY` | `open` (default) or `closed` |
| `auditMode` | `PII_MODE=audit` | also turns on metrics on port 9090 and an hourly summary line |
| `saltSecretKeyRef` / `salt` | `PII_SALT` | prefer the Secret reference |
| `entropyThreshold` | `PII_ENTROPY_THRESHOLD` | default 3.6 |
| `confidenceThreshold` | `PII_CONFIDENCE_THRESHOLD` | default 1.0 |
| `minSecretLength` | `PII_MIN_SECRET_LENGTH` | default 6 |
| `sensitiveKeys` | `PII_SENSITIVE_KEYS` | replaces the built-in list |
| `sensitiveKeyPatterns` | `PII_SENSITIVE_KEY_PATTERNS` | regexes on key names |
| `customRegexList` | `PII_CUSTOM_REGEX_LIST` | `[{name, pattern}]`, always redact |
| `safeRegexList` | `PII_SAFE_REGEX_LIST` | `[{name, pattern}]`, never redact |

The rule fields (thresholds, keys, regex lists) reach running sidecars without a restart, through a ConfigMap the controller writes, in about a minute. `failPolicy`, `auditMode`, the salt, `injectionMode`, `logPath` and `resources` need a rollout. A central rule server (`spec.remoteConfig`) is described in `docs/rules-server.md`.

## 4. Audit mode before redaction

With `auditMode: true` (or `PII_MODE=audit` outside Kubernetes), every line is written out unchanged and the sidecar only counts what it would have hidden. Watch `piishield_audit_lines_total{result}` and `piishield_audit_findings_total{type}`, or the hourly `PII-Shield audit: ...` line in the sidecar log. The counters never hold the values. To find a false positive, run a sample of the app's own logs through the CLI with `PII_ENTITY_TYPE_LABELS=true`. When the numbers look right, remove `auditMode` and restart the workload.

## 5. Tuning

Test every change on real lines with the CLI before rolling it out. A rule that is too wide hides useful data. A rule that is too narrow lets values through.

A value is hidden that should stay (false positive):

- Add a safe rule for that exact shape: `PII_SAFE_REGEX_LIST='[{"pattern":"^RUN-[A-Za-z0-9]{10}$","name":"RunID"}]'`. Safe rules are checked first and win over everything else, so anchor them with `^...$` and keep them narrow.
- Only if many unrelated tokens are hit, raise `PII_ENTROPY_THRESHOLD` a little (for example 3.6 to 4.0). Then re-check what it lets through.
- For logs that are mostly not English, `PII_DISABLE_BIGRAM_CHECK=true`.

A value passes that should be hidden (false negative):

- Its key names the secret: add a key pattern, `PII_SENSITIVE_KEY_PATTERNS='(^|_)name$'`. A matching key hides its value whatever the value looks like.
- It has a fixed shape: add a custom rule, `PII_CUSTOM_REGEX_LIST='[{"pattern":"^TX-\\d{5}$","name":"TX"}]'`. The marker then carries the rule name, `[HIDDEN:TX:...]`.
- Rules match one token at a time. A pattern with a space in it never matches.

Traps:

- `PII_SENSITIVE_KEYS` replaces the default list. `PII_SENSITIVE_KEYS=pwd` stops `password=...` from being forced. Copy the default list from `CONFIGURATION.md` and add to it, or use `PII_SENSITIVE_KEY_PATTERNS` instead.
- An invalid regex or bad JSON in an environment variable is skipped with a `WARNING` on stderr, not treated as fatal. Read the startup log after every rule change. In a policy file (`PII_CONFIG_FILE`, or the ConfigMap the operator writes), one bad rule rejects the whole file and the old rules stay.
- `PII_CONFIDENCE_THRESHOLD` above 1.2 also lets long base64 blobs through and limits card matches to lines with card words.

## 6. Verify the deployment

Tests of the scanner do not prove that your installation works. Plant values you control and look for them where the logs end up:

1. From a pod you control, log a line with a test card number (for example `4111111111111111`), a made-up e-mail and a made-up account number under a key such as `password`.
2. In the log store, `grep -c` each value. Every count must be 0, and the markers must be there instead.
3. Run a few thousand real lines through the CLI with a fixed `PII_SALT` and read the diff: look for values that survived and for values hidden for no reason.
4. With `PII_METRICS_ENABLED=true`, watch `piishield_redaction_events_total` by `type`. A drop after a deploy often means a log format changed.
5. Repeat the planted-value check after every new safe rule.

Report what you checked and what is still open. Do not call a setup "done" before the planted-value check passes.

## Where to look next

- Every variable and its default: `CONFIGURATION.md`
- Policy fields, audit mode, the rule server and the stats channel: `operator/README.md`
- What is not caught by design: `KNOWN_LIMITATIONS.md`
- Fail-open versus fail-closed, CPU limits and sizing: `docs/sidecar-failure-modes.md`
- A production checklist: `docs/production-adoption-checklist.md`
