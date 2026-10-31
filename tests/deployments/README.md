# Deployment manual test matrix

Each deployment path has its own folder with a focused `run.sh`.

Shared utilities live in `shared/`:

- `shared/replay-image`: local replay app image that bakes in the resolved `access.log` fixture. Set `PII_SHIELD_ACCESS_LOG` to the path of a local representative log file (the fixture is kept outside this repository and is not committed).
- `shared/scripts/common.sh`: common helpers for fixture checks, image loading, replay pod deployment, log collection, and assertions.

## Operator paths

| Folder | What it tests |
| --- | --- |
| `operator-helm-published` | Published `pii-shield/pii-shield-operator` chart with Helm-generated webhook certs |
| `operator-helm-local` | Local `charts/pii-shield-operator` chart |
| `operator-local-images` | Locally built operator and agent images installed through local Helm chart |
| `operator-kustomize` | Dev-only `operator/Makefile` / Kustomize deploy |
| `operator-pipe` | Existing operator install with `PiiPolicy.spec.injectionMode=pipe` |
| `operator-ebpf` | Experimental eBPF mutation/rendering only |
| `operator-rules-server` | Operator and rule server built from the tree, in a kind cluster of its own: signed remote rules reach a sidecar, a new signed publication reaches the running pod without a restart, an untrusted key is refused, stats reports reach the server |

All paths are self-contained: they recreate the local Kind cluster if it is missing, and `operator-pipe` / `operator-ebpf` install the operator themselves when it is not present. Scripts that build docker images remove them (and prune dangling layers) on exit via `cleanup_docker_images`. Before creating test pods the scripts wait for the mutating webhook to actually inject (server-side dry-run canary) — right after an install/upgrade the webhook cert can lag and pods would otherwise be created without a sidecar.

## Runtime and SDK paths

| Folder | What it tests |
| --- | --- |
| `standalone-helm-published` | Published `pii-shield/pii-shield` chart in demo mode |
| `standalone-helm-local` | Local `charts/pii-shield` chart in demo mode |
| `docker-ghcr` | Published runtime container as stdin/stdout sanitizer |
| `docker-local` | Locally built runtime container as stdin/stdout sanitizer |
| `local-binary` | Locally built `cmd/cleaner` binary as stdin/stdout sanitizer |
| `wasm-node` | Published Node WASM SDK |
| `wasm-python` | Published Python WASM SDK |

Run one folder at a time. Most scripts write sanitized logs under `/tmp/pii-shield-sanitized/<folder-name>`.

Example:

```bash
cd /Users/aragossa/dzrprj/pii-shield/algorythm
tests/deployments/operator-helm-local/run.sh
```

Helm folders also provide `chart.sh` for chart lifecycle operations:

```bash
tests/deployments/operator-helm-local/chart.sh template
tests/deployments/operator-helm-local/chart.sh lint
tests/deployments/operator-helm-local/chart.sh upgrade
tests/deployments/operator-helm-local/chart.sh history
tests/deployments/operator-helm-local/chart.sh values
tests/deployments/operator-helm-local/chart.sh manifest
tests/deployments/operator-helm-local/chart.sh rollback
tests/deployments/operator-helm-local/chart.sh uninstall
```

Chart scripts support:

- `VALUES_FILE=/path/to/values.yaml`
- `EXTRA_HELM_ARGS='--set key=value --set other=value'`
- `RELEASE=<release-name>`
- `NAMESPACE=<namespace>`
- `HELM_TIMEOUT=180s`
- `REVISION=<revision>` for rollback

## PII-Shield variable controls

Runtime scripts can read PII-Shield variables from the shell or from `PII_ENV_FILE`.
An example env file is available at `shared/pii-env.example`.

Example:

```bash
PII_ENTROPY_THRESHOLD=4.2 \
PII_MIN_SECRET_LENGTH=8 \
PII_SENSITIVE_KEYS='password,secret,token,authorization' \
tests/deployments/docker-local/run.sh
```

Env file example:

```bash
cat >/tmp/pii-shield.env <<'EOF'
PII_SALT=manual-test-salt-12345
PII_REQUIRE_STRONG_SALT=true
PII_ENTROPY_THRESHOLD=4.2
PII_MIN_SECRET_LENGTH=8
PII_FAIL_POLICY=open
PII_CUSTOM_REGEX_LIST=[{"pattern":"^TX-\\d{5}$","name":"TX"}]
EOF

PII_ENV_FILE=/tmp/pii-shield.env tests/deployments/standalone-helm-local/run.sh
```

Or:

```bash
cp tests/deployments/shared/pii-env.example /tmp/pii-shield.env
PII_ENV_FILE=/tmp/pii-shield.env tests/deployments/docker-local/run.sh
```

Supported variables for Docker/local-binary paths:

- `PII_SALT`
- `PII_REQUIRE_STRONG_SALT`
- `PII_ENTROPY_THRESHOLD`
- `PII_CONFIDENCE_THRESHOLD`
- `PII_MIN_SECRET_LENGTH`
- `PII_SENSITIVE_KEYS`
- `PII_SENSITIVE_KEY_PATTERNS`
- `PII_ADAPTIVE_THRESHOLD`
- `PII_ADAPTIVE_SAMPLES`
- `PII_ENTITY_TYPE_LABELS`
- `PII_DISABLE_BIGRAM_CHECK`
- `PII_BIGRAM_DEFAULT_SCORE`
- `PII_FAIL_POLICY`
- `PII_CUSTOM_REGEX_LIST`
- `PII_SAFE_REGEX_LIST`
- `PII_METRICS_ENABLED`
- `PII_METRICS_PORT`
- `PII_CONFIG_FILE` (CLI/container paths; the file must be reachable from the container)
- `PII_CONFIG_RELOAD_SECONDS`

Standalone Helm paths map supported chart variables to `piiConfig.*` and `metrics.*`.
Node/Python WASM SDK paths map `PII_SALT`, `PII_ENTROPY_THRESHOLD`, `PII_CONFIDENCE_THRESHOLD`, and `PII_FAIL_POLICY`.
Operator path scripts currently map only `PII_FAIL_POLICY` to `PiiPolicy.spec.failPolicy`. The operator API itself supports the full scanner configuration surface (salt, thresholds, sensitive keys, regex lists) through `PiiPolicy` fields — see [Scanner Configuration via PiiPolicy](../../operator/README.md#scanner-configuration-via-piipolicy); the test scripts just do not template those fields yet.

## Prometheus metrics

Deployment folders with a Prometheus endpoint include a `Prometheus metrics` section in their README with a copy-paste command:

- operator Helm/Kustomize folders: manager metrics through `svc/...-metrics-service` on HTTPS `8443`;
- standalone Helm folders: sidecar metrics through pod port-forward on HTTP `9090`;
- Docker/local-binary folders: runtime metrics through `PII_METRICS_ENABLED=true` and HTTP `9090`.

For `docker-ghcr`, `docker-local`, and `local-binary`, `run.sh` enables metrics by default while `access.log` is being processed. Watch live counters from a second terminal:

```bash
watch -n 2 "curl -s http://127.0.0.1:9090/metrics | grep -E 'piishield_processed_bytes_total|piishield_redaction_events_total|piishield_errors_total'"
```

Cleanup scripts exist for Kubernetes scenarios that create cluster resources.
