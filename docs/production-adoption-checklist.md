# Production Adoption Checklist

Use this checklist before running PII-Shield in production or production-like environments. Each deployment mode has a different readiness level and rollout risk.

## Readiness States

| State | Meaning |
| --- | --- |
| Ready | Suitable for production after normal staging validation. |
| Controlled rollout | Suitable for limited production rollout with explicit monitoring and rollback. |
| Beta | Usable by early adopters, but not recommended for broad production rollout. |
| Experimental | Research or prototype path. Do not use for production compliance controls. |

## CLI And Container Mode

Status: controlled rollout.

Use this mode when logs are passed directly through the `pii-shield` binary or container and the caller controls stdin/stdout behavior.

Required configuration:

- [ ] Set a persistent `PII_SALT` when stable deterministic hashes are required.
- [ ] Set `PII_REQUIRE_STRONG_SALT=true` for compliance-sensitive environments.
- [ ] Configure `PII_SENSITIVE_KEYS` for organization-specific secret names.
- [ ] Add `PII_CUSTOM_REGEX_LIST` for domain-specific identifiers.
- [ ] Review any `PII_SAFE_REGEX_LIST` rule with representative logs before rollout.

Validation before production:

- [ ] Run unit tests and scanner benchmarks for the target release.
- [ ] Run `./scripts/test-smoke.sh` with representative log samples.
- [ ] Confirm JSON logs remain valid after redaction.
- [ ] Confirm expected secrets and PII are redacted.
- [ ] Confirm safe identifiers are not over-redacted.
- [ ] Confirm downstream log collectors accept the sanitized output.

Rollback:

- [ ] Keep the previous image tag or binary available.
- [ ] Keep the previous configuration values available.
- [ ] Roll back the container image or binary if redaction breaks application observability.
- [ ] Disable custom regex or safe-list changes independently when possible.

Monitoring:

- [ ] Track process exits.
- [ ] Track sanitizer error logs.
- [ ] Track log throughput before and after rollout.
- [ ] Sample sanitized logs for false positives and false negatives.

## Kubernetes Sidecar File Mode

Status: controlled rollout.

Use this mode when the application can write logs to the configured file path consumed by the sidecar.

Required configuration:

- [ ] Confirm the application writes logs to the expected file path.
- [ ] Set a persistent `PII_SALT`.
- [ ] Set `PII_REQUIRE_STRONG_SALT=true` for compliance-sensitive environments.
- [ ] Configure file paths and volume mounts consistently across app and sidecar containers.
- [ ] Configure resource requests and limits for the sidecar: the CPU limit is a throughput ceiling (the chart default of 250m sustains about 22k lines/s on text or JSON logs, 13k on access logs; see the sizing table in `docs/sidecar-failure-modes.md`).
- [ ] Keep adaptive thresholding disabled until validated with real traffic.

Validation before production:

- [ ] Validate the Helm-rendered deployment.
- [ ] Run a staging workload with representative logs.
- [ ] Confirm sidecar startup order does not drop required logs.
- [ ] Confirm application restarts do not leave stale file handles.
- [ ] Confirm file rotation behavior for the target workload.
- [ ] Confirm sidecar restarts do not corrupt or duplicate logs.
- [ ] Confirm sanitized logs reach the downstream collector.

Rollback:

- [ ] Keep the previous Helm values file.
- [ ] Remove injection labels or policy annotations to bypass the sidecar.
- [ ] Roll back the Helm release if sidecar behavior regresses.
- [ ] Keep the application logging path unchanged until the rollback path is tested.

Monitoring:

- [ ] Track sidecar restarts.
- [ ] Track pod readiness and container status.
- [ ] Track sanitizer error logs.
- [ ] Track downstream log volume.
- [ ] Alert on missing logs for protected workloads.

## Kubernetes Operator Mode

Status: controlled rollout.

Use this mode when the operator manages sidecar injection through `PiiPolicy` resources and pod labels.

Required configuration:

- [ ] Install the operator through the Helm chart.
- [ ] Review admission webhook failure policy for compliance requirements.
- [ ] Define `PiiPolicy` resources per namespace or workload group.
- [ ] Label only selected workloads during initial rollout.
- [ ] Store runtime secrets in Kubernetes secrets or an external secret manager.
- [ ] Configure operator and sidecar resource requests and limits.

Validation before production:

- [ ] Run `scripts/verify-helm-runtime.sh`.
- [ ] Run operator unit tests for the target release.
- [ ] Run operator integration tests where local API server binding is available.
- [ ] Validate injection on a staging namespace.
- [ ] Validate policy updates without manual pod edits.
- [ ] Validate webhook behavior when the operator is unavailable.
- [ ] Confirm opt-out or rollback behavior before broad rollout.

Rollback:

- [ ] Remove injection labels from affected workloads.
- [ ] Revert the `PiiPolicy` change if policy behavior regresses.
- [ ] Roll back the operator Helm release.
- [ ] Disable the admission webhook only as an emergency action.
- [ ] Keep cluster change records for policy and chart updates.

Monitoring:

- [ ] Track operator pod health.
- [ ] Track admission webhook errors.
- [ ] Track failed injection events.
- [ ] Track sidecar restarts in protected namespaces.
- [ ] Track policy update events.

## WASM SDK Mode

Status: beta.

Use this mode when applications embed the scanner through the Node.js or Python WASM SDKs.

Required configuration:

- [ ] Pin the SDK package version.
- [ ] Set a persistent salt through the application configuration when deterministic hashes must remain stable.
- [ ] Keep organization-specific rules in application-owned configuration.
- [ ] Keep SDK initialization failures visible to the application owner.

Validation before production:

- [ ] Add application-level tests with representative logs.
- [ ] Confirm expected redaction behavior in the application runtime.
- [ ] Benchmark request or job latency with SDK redaction enabled.
- [ ] Confirm WASM loading works in the production runtime environment.
- [ ] Confirm the application can disable or bypass SDK redaction during emergency rollback.

Rollback:

- [ ] Keep the previous SDK package version available.
- [ ] Use feature flags where possible.
- [ ] Disable SDK redaction if it breaks application behavior.
- [ ] Revert application-level rule changes independently from package updates.

Monitoring:

- [ ] Track SDK initialization failures.
- [ ] Track application error rates after rollout.
- [ ] Track latency impact.
- [ ] Sample sanitized logs for false positives and false negatives.

## Experimental Modes

The following modes are not production adoption paths yet:

- eBPF interception.
- Proxy-Wasm gateway integration.
- Hosted Control Plane UI.
- Full transparent Kubernetes `stdout` and `stderr` interception.
- Model-assisted PII detection.

Do not use these modes as production compliance controls until they move out of experimental or planned status.

## Compliance Review Questions

Security and compliance reviewers should answer these questions before production use:

- [ ] Which deployment mode is being used?
- [ ] Is the mode marked ready, controlled rollout, beta, or experimental?
- [ ] What data classes must be redacted?
- [ ] Which logs were used for validation?
- [ ] How are false positives reviewed?
- [ ] How are false negatives reviewed?
- [ ] Who owns the redaction policy?
- [ ] Where is `PII_SALT` stored?
- [ ] Is `PII_REQUIRE_STRONG_SALT=true` enabled?
- [ ] What is the rollback path?
- [ ] What monitoring proves logs are still flowing?
- [ ] What monitoring proves redaction is still active?
- [ ] Who reviews security alerts and dependency updates?
