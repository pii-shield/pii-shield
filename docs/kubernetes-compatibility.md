# Kubernetes Compatibility Matrix

This matrix defines the Kubernetes environments that should be validated before broad production rollout.

PII-Shield currently supports controlled Kubernetes deployments where workloads can write logs to the configured file path consumed by the sidecar. Full transparent `stdout` and `stderr` interception is not a production-supported path yet.

## Version Support

| Kubernetes version | Status | Notes |
| --- | --- | --- |
| 1.28 | Supported for controlled rollout | Native sidecar behavior is available. Validate workload log path behavior. |
| 1.29 | Supported for controlled rollout | Validate Helm rendering, webhook injection, and sidecar log flow. |
| 1.30 | Supported for controlled rollout | Validate Helm rendering, webhook injection, and sidecar log flow. |
| 1.31+ | Needs validation | Expected to work, but test before broad rollout. |
| Earlier than 1.28 | Not recommended | Native sidecar assumptions may not hold. Use only after explicit local validation. |

## Cluster Matrix

| Environment | Status | Required validation |
| --- | --- | --- |
| Kind | Recommended local validation | Helm install, policy creation, sidecar injection, log redaction, rollback. |
| Minikube | Recommended local validation | Helm install, policy creation, sidecar injection, log redaction, rollback. |
| K3s | Needs validation | Lightweight runtime behavior, webhook cert handling, log path behavior. |
| EKS | Needs validation | Admission webhook behavior, IAM/security context constraints, managed node log behavior. |
| GKE | Needs validation | Admission webhook behavior, workload identity constraints, managed node log behavior. |
| AKS | Needs validation | Admission webhook behavior, managed identity constraints, managed node log behavior. |

## Container Runtime Assumptions

PII-Shield sidecar file mode assumes:

- the application writes logs to the configured shared file path;
- the PII-Shield sidecar can mount the same volume;
- the sidecar can tail and reopen the file after rotation;
- downstream collectors read sanitized sidecar output instead of the original file;
- resource limits allow the sidecar to keep up with log volume.

Runtime notes:

| Runtime | Status | Notes |
| --- | --- | --- |
| containerd | Expected | Validate in the target cluster. |
| CRI-O | Needs validation | Validate file rotation and pod restart behavior. |
| Docker shim | Not targeted | Deprecated Kubernetes runtime path. |

## Known Incompatibilities And Limits

- Applications that only emit to normal Kubernetes `stdout` and `stderr` without writing to the configured file path are not fully protected by sidecar file mode.
- Workloads with custom log rotation must be validated before rollout.
- Very high-volume workloads need throughput and backpressure validation.
- Webhook failure policy must be reviewed for compliance requirements.
- Proxy-Wasm and full transparent `stdout`/`stderr` interception are not production-supported modes yet. The eBPF audit agent watches `stdout`/`stderr` without redacting and needs Linux 5.8 or newer with BTF on `amd64` or `arm64` nodes and the `BPF`, `PERFMON` and `SYS_RESOURCE` capabilities ([ebpf-audit.md](ebpf-audit.md)).

## Compatibility Test Checklist

Run this checklist for each target Kubernetes environment.

Cluster setup:

- [ ] Record cluster name, provider, Kubernetes version, node OS, and container runtime.
- [ ] Install or confirm cert-manager if the operator uses cert-manager-managed certificates.
- [ ] Install Prometheus monitoring if ServiceMonitor or PrometheusRule validation is in scope.
- [ ] Confirm required CRDs can be installed.

Install:

- [ ] Install the operator Helm chart.
- [ ] Confirm operator pod readiness.
- [ ] Confirm webhook service endpoints exist.
- [ ] Confirm webhook certificate is valid.
- [ ] Create a test namespace with injection enabled.

Policy and injection:

- [ ] Create a `PiiPolicy` in the test namespace.
- [ ] Deploy a test workload with injection labels.
- [ ] Confirm the PII-Shield sidecar is injected.
- [ ] Confirm sidecar resource requests and limits are applied.
- [ ] Confirm opt-out behavior by removing labels or annotations.

Log flow:

- [ ] Confirm the application writes logs to the configured file path.
- [ ] Confirm PII-Shield reads from that path.
- [ ] Confirm sanitized logs appear in the sidecar output.
- [ ] Confirm downstream collectors ingest sanitized logs.
- [ ] Confirm original unsanitized logs are not collected by mistake.

Failure behavior:

- [ ] Restart the application container.
- [ ] Restart the PII-Shield sidecar.
- [ ] Restart the operator.
- [ ] Rotate the watched log file.
- [ ] Apply a bad policy and confirm expected failure behavior.
- [ ] Roll back to the previous policy.
- [ ] Roll back the Helm release.

Monitoring:

- [ ] Confirm metrics endpoint is scraped.
- [ ] Confirm Prometheus alert rules render when enabled.
- [ ] Trigger or simulate a sidecar restart alert.
- [ ] Trigger or simulate an operator availability alert.
- [ ] Confirm runbook links are available to operators.

Sign-off:

- [ ] Record any incompatibility.
- [ ] Record required chart values.
- [ ] Record rollback steps.
- [ ] Record owner and date of validation.
