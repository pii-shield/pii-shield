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
   | `ebpf` | Experimental / R&D | Kernel-level interception prototype. Not production-ready. |

## Scanner Configuration via PiiPolicy

The webhook translates `PiiPolicy` fields into the `PII_*` environment
variables of the injected sidecar (see [CONFIGURATION.md](../CONFIGURATION.md)
for what each variable does). Fields you leave unset produce no environment
variable, so the scanner's built-in defaults apply.

| PiiPolicy field | Sidecar env | Format |
|-----------------|-------------|--------|
| `failPolicy` | `PII_FAIL_POLICY` | `open` (default) or `closed` |
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
