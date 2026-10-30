# PII-Shield Operator

The Kubernetes Operator for [PII-Shield](https://github.com/pii-shield/pii-shield), providing automatic Personally Identifiable Information masking for application logs in K8s clusters using Distroless Native Sidecars.

## Architecture

* **Operator Manager**: A lightweight Go controller managing `PiiPolicy` Custom Resources and a Mutating Webhook.
* **Sidecar Agent**: A highly-secure, distroless Go binary injected automatically into your Pods. It monitors application logs via `nxadm/tail` and masks PII in real time before streaming them to `stdout`.

## Getting Started

### Installation via Helm (Recommended)

The easiest way to install the operator is via our official Helm chart hosted on GitHub Pages.

1. Add the Helm repository:
   ```bash
   helm repo add pii-shield https://pii-shield.github.io/pii-shield
   helm repo update
   ```

2. Install the Operator:
   ```bash
   helm install pii-shield-operator pii-shield/pii-shield-operator -n operator-system --create-namespace
   ```
   *Note: If `cert-manager` is not installed, the Helm chart will automatically generate and inject fallback self-signed TLS certificates for the Mutating Webhook.*

### Quickstart Example

Once installed, you can protect any application by applying a `PiiPolicy` and adding a label to your Pods.

1. **Create a Policy:**
   ```yaml
   apiVersion: core.pii-shield.io/v1alpha1
   kind: PiiPolicy
   metadata:
     name: strict-policy
     namespace: default
   spec:
     injectionMode: "file"
   ```

   Supported `injectionMode` values:

   | Mode | Status | Description |
   |------|--------|-------------|
   | `file` | Controlled rollout (default) | The sidecar tails a log file on a shared `emptyDir` volume. The recommended path; gate production use with [docs/production-adoption-checklist.md](../docs/production-adoption-checklist.md). |
   | `pipe` | **Experimental** | Rewrites the target container command through `/bin/sh -c` to redirect output into a named pipe. Can break distroless images (no shell), argument quoting, signal handling, and the app lifecycle. The webhook returns a warning on injection. Not recommended for production. |
   | `ebpf` | **Experimental**, observation only | The eBPF audit agent: it shares the pod's pid namespace and counts what it would have redacted in the pod's stdout and stderr, without touching them. Requires `auditMode: true`, a kernel of 5.8 or newer with BTF, and the `BPF` and `PERFMON` capabilities on the agent container. There is no eBPF redaction. |

## Scanner Configuration via PiiPolicy

The webhook translates `PiiPolicy` fields into the `PII_*` environment
variables of the injected sidecar (see [CONFIGURATION.md](../CONFIGURATION.md)
for what each variable does). Fields you leave unset produce no environment
variable, so the scanner's built-in defaults apply.

| PiiPolicy field | Sidecar env | Format |
|-----------------|-------------|--------|
| `failPolicy` | `PII_FAIL_POLICY` | `open` (default) or `closed` |
| `auditMode` | `PII_MODE=audit` (plus the sidecar's metrics on port 9090 and an hourly summary in its log) | `true` for the dry run: see [Audit mode](#audit-mode-dry-run) |
| `confidenceThreshold` | `PII_CONFIDENCE_THRESHOLD` | float |
| `salt` | `PII_SALT` | plain text — prefer `saltSecretKeyRef` |
| `saltSecretKeyRef` | `PII_SALT` via `secretKeyRef` | Secret resolved in the pod's namespace |
| `entropyThreshold` | `PII_ENTROPY_THRESHOLD` | float |
| `minSecretLength` | `PII_MIN_SECRET_LENGTH` | integer ≥ 1 |
| `sensitiveKeys` | `PII_SENSITIVE_KEYS` | list → comma-separated |
| `sensitiveKeyPatterns` | `PII_SENSITIVE_KEY_PATTERNS` | list of regexes → comma-separated |
| `customRegexList` | `PII_CUSTOM_REGEX_LIST` | list of `{name, pattern}` → JSON |
| `safeRegexList` | `PII_SAFE_REGEX_LIST` | list of `{name, pattern}` → JSON |

### Rules without a restart

The controller also renders the rule fields of every `PiiPolicy` —
`entropyThreshold`, `confidenceThreshold`, `minSecretLength`,
`sensitiveKeys`, `sensitiveKeyPatterns`, `customRegexList`, `safeRegexList`
— into a ConfigMap named `pii-shield-policy-<policy name>` in the policy's
namespace (key `policy.json`, the same JSON the SDKs pass to `init_config`,
plus a `revision` equal to the policy's generation). The webhook mounts that
ConfigMap read-only at `/etc/pii-shield` in every injected sidecar and sets
`PII_CONFIG_FILE=/etc/pii-shield/policy.json`. The sidecar reads the file
before its first line and re-reads it when it changes (see
`PII_CONFIG_FILE` in [CONFIGURATION.md](../CONFIGURATION.md)), so an edit to
the policy reaches running pods about a minute later — the kubelet's
ConfigMap refresh — without a restart.

What stays as it was:

- The env vars in the table above are still set on the sidecar and win over
  the file. A pod admitted before the ConfigMap exists (the volume is
  mounted `optional`), or running an agent image older than the file
  support, behaves exactly as before.
- The salt never goes through the ConfigMap: it comes from `salt` or
  `saltSecretKeyRef` as a Secret reference, and the sidecar keeps the salt it
  started with across reloads. `failPolicy`, `injectionMode`, `logPath` and
  `resources` are pod settings and still need a rollout to change.
- The ConfigMap is owned by the policy and deleted with it; it is left
  untouched when a reconcile renders the same rules, so no reload happens
  for nothing.

The status of the policy names the ConfigMap and a content hash of the file
(`status.renderedPolicyConfigMap`, `status.renderedPolicyHash`) and carries a
`Rendered` condition; `RenderFailed` means the file could not be written
(the policy still works through the env vars at injection time).

### Audit mode (dry run)

Before a policy starts redacting, run it with `auditMode: true` on real
traffic: the sidecar scans every line as usual, writes it out unchanged,
byte for byte, and only counts what it would have redacted. The policy's
`Available` condition says `audit mode: logs are not modified`, and every
pod admitted under it gets an admission warning that its logs are not
redacted.

```yaml
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: default
  namespace: payments
spec:
  injectionMode: file
  auditMode: true
  saltSecretKeyRef: { name: pii-shield-salt, key: salt }
  sensitiveKeys: [password, token, geheim]
```

The numbers are the point of the mode, so the webhook turns the sidecar's
metrics on with it: `PII_METRICS_ENABLED=true` on port `9090` (a container
port named `pii-metrics`; the pod must leave that port free, otherwise the
sidecar logs that its metrics server is disabled and the audit has only the
log summary) and `PII_STATS_LOG_INTERVAL=1h`, which writes a line such as
`PII-Shield audit: 1,240 would-be redactions (…) in 310 of 12,345 lines
(2.5%) …; nothing was changed` into the sidecar's log every hour. The
counters are `piishield_audit_lines_total{result="clean"|"would_redact"}`
and `piishield_audit_findings_total{type}`; `piishield_redaction_events_total`
stays at zero in audit mode, so an alert on it does not fire on a dry run.
Scraping the port is the cluster's business: a `PodMonitor` on the
workload's pods, or the `prometheus.io` annotations. With
`metrics.prometheusRule.enabled` the chart adds two rules on those counters:
`PIIShieldAuditWouldRedact` (info: the sidecar saw lines it would redact in
the last 24 hours) and `PIIShieldAuditSeesNoLines` (warning: an audit sidecar
processed no lines for an hour, so the application is quiet or does not
write to `logPath`).

The counters hold the fact of a finding and its detector, never the value:
the audit does not record the secrets it saw. A false positive is found by
reading the application's own logs for that period. `auditMode` is a
setting of the pod, like the salt and the fail policy, so it comes through
the environment, not through the rules file: switching it off is a
`kubectl rollout restart` of the workload. It works with `injectionMode`
`file` (the sidecar reads a file the application writes and cannot block it)
and `pipe` (the sidecar still sits in the stream's path, audit or not), and
it is required with `ebpf`: that mode is the eBPF audit agent of #96, which
watches the pod's stdout and stderr from outside their path and only
observes, so the API server rejects `ebpf` without `auditMode`. The agent
is injected as a native sidecar sharing the pod's pid namespace, as root
with the `BPF`, `PERFMON` and `SYS_RESOURCE` capabilities and nothing else
(no privileged flag, no hostPath), from the image `sidecar.ebpfImage` of the
chart; it needs a kernel of 5.8 or newer with BTF (`/sys/kernel/btf/vmlinux`
on the node). It exports the same audit counters on port 9090 and writes
the same hourly summary. A startup probe on its `/healthz`, which answers
only once the program is attached, holds the application containers until
then, so the application's first lines are counted; if the program cannot
load the agent still answers (`piishield_ebpf_attached 0`), so the pod is
not held back. What it does not see: writes to files and sockets,
and more than 8 KiB of one write. `tests/deployments/operator-ebpf/run.sh`
runs it end to end in kind.

### Central rule repository (`remoteConfig`)

A policy can pull its rules from a central source instead of carrying them
all itself. The source is any HTTPS address that answers a `GET` with the
policy file in the same JSON format as `policy.json` above: a file on an
object store, an internal web server, or a rule server. Nothing about the
cluster is sent; the operator only asks for the file.

```yaml
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: default
  namespace: payments
spec:
  injectionMode: file
  saltSecretKeyRef: { name: pii-shield-salt, key: salt }
  remoteConfig:
    url: https://rules.example.internal/pii/payments/policy.json
    intervalSeconds: 300                 # default 300, minimum 30
    headerSecretRef: { name: rules-token, key: authorization }   # whole Authorization header value, e.g. "Bearer …"
    caBundleSecretRef: { name: rules-ca, key: ca.crt }          # PEM bundle instead of the system roots
    # allowInsecure: true                # http:// or an unverified certificate; labs only, the status warns
  sensitiveKeys: [password, token, geheim]   # a local field always wins over the source
```

How a pull works:

- Every `intervalSeconds` the controller sends `GET` with `If-None-Match`
  set to the ETag of the last good copy (a 10 s timeout, a 256 KiB body
  limit). A `304` costs nothing; a `200` is validated whole, the way the
  sidecar validates `PII_CONFIG_FILE`: the first invalid JSON, pattern or
  value rejects the file.
- The rule fields set in the local `PiiPolicy` are laid over the remote
  file field by field (a list replaces the whole list, the same as
  `PII_SENSITIVE_KEYS` replaces the default list); fields the policy leaves
  unset keep what the source says. The result is rendered into the
  policy's ConfigMap as before, with `revision` = `<remote revision>+<policy
  generation>`, and the sidecars reload it.
- Only rules are accepted from the source: `entropy_threshold`,
  `confidence_score`, `min_secret_length`, `sensitive_keys`,
  `sensitive_key_patterns`, `custom_regexes`, `safe_regexes`,
  `disable_bigram_check`, `adaptive_threshold`, `entity_type_labels` and
  `revision`. A `salt` or `fail_policy` in the file is ignored and named in
  the status; `injectionMode`, `logPath`, `resources` and the salt never
  come from outside.
- When the source is down, answers an error, or serves an invalid file, the
  last good copy stays in use: it is kept in the ConfigMap as `remote.json`
  together with its ETag, so it survives an operator restart, and a local
  edit of the policy still applies on top of it. The pull is retried after
  at most 60 s. Before the first successful pull the local policy alone is
  rendered, the same as without `remoteConfig`.
- `status.remote` reports the last good pull (`lastSyncTime`, `etag`,
  `revision`, `hash`); the `RemoteSynced` condition reports the latest
  attempt with a reason: `Synced`, `FetchFailed`, `TooLarge`,
  `InvalidJSON`, `InvalidRegex`, `InvalidValue`, `InsecureURL`,
  `SecretNotFound`.
- Rollback: remove `remoteConfig` from the policy; on the next reconcile
  the ConfigMap is rendered from the local policy alone and `remote.json`
  is dropped. To pin a value against the source, set it in the policy.

The Secrets named by `headerSecretRef` and `caBundleSecretRef` live in the
policy's namespace and are read straight from the API server (the manager
needs `get` on Secrets, not `list`/`watch`, and caches none). If a
NetworkPolicy restricts the operator's egress, allow the source host and
port. Operator metrics `piishield_operator_remote_sync_total{result}`,
`piishield_operator_remote_sync_last_success_timestamp_seconds` and
`piishield_operator_remote_sync_interval_seconds` are served on the
manager's metrics endpoint; the chart's `PrometheusRule` alerts when a
policy's last successful pull is older than three intervals
(`PIIShieldRemoteRulesStale`) and on any failed pull
(`PIIShieldRemoteRulesSyncErrors`). The runbook is in
[docs/operational-runbooks.md](../docs/operational-runbooks.md#central-rule-repository).

### Effective configuration precedence

From most to least specific:

1. **PiiPolicy fields** — within a policy, `saltSecretKeyRef` wins over `salt`.
2. **Operator-level defaults** — the chart value `sidecar.saltSecret.{name,key}`
   becomes `AGENT_SALT_SECRET_NAME`/`AGENT_SALT_SECRET_KEY` on the operator and
   is used when the policy configures no salt at all. The referenced Secret is
   resolved in each injected pod's namespace, so it must exist in every
   namespace where injection happens.
3. **Scanner built-in defaults** — apply to everything still unset.

Pod annotations (`pii-shield.io/policy`, `pii-shield.io/target-container`)
select which policy and container to use; they deliberately cannot override
individual scanner fields, so redaction settings stay auditable through
`PiiPolicy` objects.

### Production example: persistent salt

Without a persistent salt, hashes change on every pod restart and log
correlation breaks (see the warning in
[CONFIGURATION.md](../CONFIGURATION.md#critical-security-variables)).
Reference the salt from a Secret so it never appears in the policy object:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pii-shield-salt
  namespace: production
type: Opaque
stringData:
  salt: "replace-with-at-least-32-random-characters"
---
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: production-policy
  namespace: production
spec:
  injectionMode: file
  logPath: /var/log/app/log.txt
  failPolicy: closed
  saltSecretKeyRef:
    name: pii-shield-salt
    key: salt
  safeRegexList:
    - name: GitShortSHA
      pattern: "^[a-f0-9]{7}$"
```

To share one salt across all policies, set it once at install time and omit
salt fields from the policies:

```bash
helm upgrade --install pii-shield-operator pii-shield/pii-shield-operator \
  --namespace operator-system \
  --set sidecar.saltSecret.name=pii-shield-salt
```

2. **Label your Application Pods:**
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: my-app
   spec:
     template:
       metadata:
         labels:
           pii-shield.io/inject: "true"
         annotations:
           pii-shield.io/policy: "strict-policy"
   ```
   *Tip: You can also label an entire namespace (`pii-shield.io/inject: "true"`) to automatically protect all Pods within it.*

The Operator will automatically inject the secure Sidecar Agent into your Pod, configuring it with the correct `fsGroup` to securely access `emptyDir` log volumes.

## Development

If you want to contribute to the Operator:

> [!NOTE]
> The Kustomize and `make deploy` paths in this directory are for local development, CRD generation, and manual validation of the operator source tree. For user-facing v2.x installs, use the Helm chart.

### Prerequisites
- Go version 1.26+ (matching the repository `go.mod`)
- Docker version 17.03+
- kubectl and access to a K8s cluster (e.g. Minikube)

### Local Testing

1. Install the CRDs into the cluster:
   ```bash
   make install
   ```
2. Run the controller locally (outside the cluster):
   ```bash
   make run
   ```

### Synchronizing CRDs to the Helm Chart

If you modify the API definitions (`api/v1alpha1/piipolicy_types.go`), regenerate the manifests and automatically sync them to the Helm chart:

```bash
make sync-helm
```

## License

Distributed under the Apache 2.0 License.
