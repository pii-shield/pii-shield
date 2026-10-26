# PII-Shield Helm Chart

This Helm chart deploys **PII-Shield** as a scratch-compatible logging sidecar. The production path starts the container directly with `/pii-shield --watch-file ...`; it does not require `/bin/sh`, `tail`, or any other userspace tooling in the PII-Shield image.

PII-Shield leverages an advanced informational-entropy algorithm written in Go to catch new, unknown secrets and tokens that standard Regex engines miss, operating entirely without external network dependencies.

## Architecture

This chart provisions a **Sidecar Logging Pipeline**. The PII-Shield container watches a file on a shared `emptyDir` volume and writes sanitized output to `stdout`, ready for aggregation by standard Kubernetes log shippers.

By default, the chart renders the production-safe PII-Shield container only. Demo traffic generation is disabled so production installs do not start a synthetic log generator.

## Footprint And Sizing

The sidecar is a single thread with a small heap. The chart sets:

*   **Memory**: 30Mi request and limit
*   **CPU**: 100m request, 250m limit

Throughput is the CPU limit times the per-core rate (about 90k lines/s per core on text or JSON logs, 53k on an nginx access log, measured on one Apple M1 core), so 250m sustains roughly 22k lines/s, or 13k on access logs; the former 50m default capped the sidecar near 4.5k and 2.6k. Raise `resources.limits.cpu` for a busier application; above 1000m there is no gain. The sizing table is in `docs/sidecar-failure-modes.md`.

## Installation

Assuming you have added the repository:

```bash
helm repo add pii-shield https://pii-shield.github.io/pii-shield/
helm install pii-shield pii-shield/pii-shield
```

## Demo Mode

To run the built-in log generator for a live demo, enable `demo.enabled` explicitly:

```bash
helm install my-demo pii-shield/pii-shield --set demo.enabled=true
```

Once the demo pod is running, you can stream the sidecar's logs to see PII-Shield redacting data in real time:

```bash
kubectl logs -l app.kubernetes.io/name=pii-shield -c pii-shield -f
```

## Configuration

You can tune the redaction engine via `values.yaml` under `piiConfig`:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `salt` | string | `""` | Persistent HMAC salt. If empty, randomly generated on boot. Prefer `saltSecret` in production. |
| `saltSecret.name` | string | `""` | Name of an existing Secret to source `PII_SALT` from. When set, it takes precedence over `salt` and the salt is never rendered into the manifest. |
| `saltSecret.key` | string | `"salt"` | Key within `saltSecret.name` holding the salt. |
| `requireStrongSalt` | string | `"false"` | Reject explicitly configured salts shorter than 16 bytes. |
| `entropyThreshold` | string | `"3.6"` | Shannon entropy cut-off determining what is considered a "secret". |
| `minSecretLength` | string | `"6"` | Minimum string length to apply entropy checks. |
| `sensitiveKeys` | string | `""` | Key names whose `key=value` values are always redacted. Empty keeps the scanner's built-in 18-key default; setting it **replaces** that default rather than extending it. |
| `adaptiveThreshold` | string | `"false"` | Auto-tuning baselines based on standard traffic. |
| `failPolicy` | string | `"open"` | Runtime failure policy. Use `"open"` to keep log flow alive, or `"closed"` to emit drop markers on processing failure. |

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `watchFile` | string | `"/var/log/app/output.log"` | File path watched by the PII-Shield sidecar. |
| `demo.enabled` | bool | `false` | Enables the demo-only Alpine log generator (pinned tag, never `latest`). |
| `metrics.enabled` | bool | `true` | Expose the Prometheus metrics endpoint and set `PII_METRICS_*`. |
| `metrics.port` | int | `9090` | Container port for the metrics endpoint. |
| `metrics.serviceMonitor.enabled` | bool | `false` | Render a Prometheus Operator `ServiceMonitor`. |
| `metrics.prometheusRule.enabled` | bool | `false` | Render default Prometheus alert rules for PII-Shield availability, restarts, errors, latency, and missing throughput. |
| `networkPolicy.enabled` | bool | `false` | Render a `NetworkPolicy` restricting ingress to the metrics port only. |
| `networkPolicy.metricsFrom` | list | `[]` | Optional `from` peers allowed to reach the metrics port. Empty allows any source. |

## Security & Networking

The chart ships production-safe defaults suitable for a controlled production rollout:

- **Hardened security context** (on by default): the sidecar runs as non-root (UID `65532`) with a read-only root filesystem, all Linux capabilities dropped, `allowPrivilegeEscalation: false`, and the `RuntimeDefault` seccomp profile. A pod-level `fsGroup` keeps the shared `emptyDir` readable no matter which UID the application container writes as. Override via `podSecurityContext` / `securityContext` if your platform requires different IDs.
- **No plaintext secrets by default**: `PII_SALT` is only rendered as a literal if you set `piiConfig.salt`. For production, set `piiConfig.saltSecret.name` (and optionally `.key`) to source the salt from an existing Secret via `secretKeyRef`, so it never appears in the rendered manifest.

Enable a NetworkPolicy that admits traffic only to the metrics port:

```bash
helm install pii-shield pii-shield/pii-shield \
  --set networkPolicy.enabled=true
```

Restrict which peers may scrape metrics by supplying `networkPolicy.metricsFrom` (standard NetworkPolicy `from` selectors). Egress is deliberately left unrestricted so log shipping and DNS keep working.

## Operational Alerts

Prometheus Operator users can render the default alert rules:

```bash
helm install pii-shield pii-shield/pii-shield \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.prometheusRule.enabled=true
```

Tune alert labels and thresholds under `metrics.prometheusRule` before production rollout. Operational runbooks are documented in `docs/operational-runbooks.md`.
