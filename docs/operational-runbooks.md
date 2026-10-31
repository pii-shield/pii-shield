# Operational Runbooks

Use these runbooks when PII-Shield is deployed in production or controlled production rollouts.

## Alert Severity

| Severity | Expected response | Examples |
| --- | --- | --- |
| Critical | Start investigation immediately. | Sanitized logs stop flowing for protected workloads. |
| Warning | Investigate during the current on-call window. | Error rate increases, sidecar restarts, latency increases. |
| Info | Review during normal maintenance. | Low-volume workloads with no recent redactions. |

## Admission Webhook Failures

Symptoms:

- New pods are not created.
- Pods are created without PII-Shield sidecars.
- Kubernetes events mention admission webhook timeouts or errors.

Immediate checks:

- [ ] Check operator pod health.
- [ ] Check admission webhook configuration.
- [ ] Check webhook service endpoints.
- [ ] Check TLS certificate validity.
- [ ] Check recent operator logs.
- [ ] Check namespace labels and pod labels.

Commands:

```bash
kubectl get pods -n operator-system
kubectl get validatingwebhookconfiguration,mutatingwebhookconfiguration
kubectl get events --all-namespaces --sort-by=.lastTimestamp
kubectl logs -n operator-system deploy/pii-shield-operator
```

Recovery:

- [ ] Restart the operator if it is unhealthy.
- [ ] Roll back the operator Helm release if the failure started after an upgrade.
- [ ] Remove injection labels from affected workloads if pod creation must continue.
- [ ] Disable the webhook only as an emergency action and record the exception.

## Sidecar Injection Failures

Symptoms:

- Pods with injection labels do not contain the PII-Shield sidecar.
- `PiiPolicy` changes do not affect new pods.
- Protected workloads produce unsanitized logs.

Immediate checks:

- [ ] Confirm the pod has `pii-shield.io/inject: "true"`.
- [ ] Confirm the namespace has the expected labels.
- [ ] Confirm the referenced `PiiPolicy` exists.
- [ ] Confirm the operator has permissions to read the policy.
- [ ] Check pod events for webhook patches or admission errors.

Commands:

```bash
kubectl describe pod <pod> -n <namespace>
kubectl get piipolicy -A
kubectl get events -n <namespace> --sort-by=.lastTimestamp
kubectl logs -n operator-system deploy/pii-shield-operator
```

Recovery:

- [ ] Fix labels or policy references.
- [ ] Recreate pods after policy or label fixes.
- [ ] Roll back the policy if the issue started after a policy update.
- [ ] Remove injection labels if the workload must run without PII-Shield during the incident.

## High False-Positive Incidents

Symptoms:

- Logs lose important debugging values.
- Safe identifiers are redacted.
- Teams report reduced observability after rollout.

Immediate checks:

- [ ] Identify the affected workload and log pattern.
- [ ] If the rules are still being tuned, put the policy back into `auditMode` so the logs flow unchanged while you work (see Audit Mode below); the counters show whether a change helps.
- [ ] Check recent changes to `PII_ENTROPY_THRESHOLD`.
- [ ] Check recent changes to `PII_CUSTOM_REGEX_LIST`.
- [ ] Check recent changes to `PII_SAFE_REGEX_LIST`.
- [ ] Collect representative sanitized and original samples without exposing real PII.

Recovery:

- [ ] Add a narrow safe-list rule for known safe identifiers.
- [ ] Revert broad custom regex rules.
- [ ] Raise the entropy threshold only after testing representative logs.
- [ ] Roll back to previous policy or Helm values if observability is severely degraded.

Post-incident:

- [ ] Add regression fixtures for the false-positive pattern.
- [ ] Document the accepted safe-list rule and owner.
- [ ] Review whether the same pattern appears in other workloads.

## High False-Negative Incidents

Symptoms:

- Sensitive data appears in downstream logs.
- Security review finds unredacted PII or secrets.
- A new domain-specific identifier is not detected.

Immediate checks:

- [ ] Identify the data class that escaped redaction.
- [ ] Check whether the value is structured or free-form.
- [ ] Check whether a safe-list rule bypassed redaction.
- [ ] Check whether the log path bypassed PII-Shield.
- [ ] Check whether the affected workload was injected and running the expected policy.

Recovery:

- [ ] Add a custom regex rule for structured identifiers.
- [ ] Add sensitive key names for `key=value` patterns.
- [ ] Lower the entropy threshold only after testing representative logs.
- [ ] Remove or narrow unsafe safe-list rules.
- [ ] Rotate leaked credentials if secrets were exposed.

Post-incident:

- [ ] Add regression fixtures for the missed pattern.
- [ ] Review downstream retention and deletion requirements.
- [ ] Document the incident and remediation owner.

## Dependency Or Security Alert Response

Symptoms:

- Dependabot alert is opened.
- CodeQL alert is opened.
- OpenSSF Scorecard reports a vulnerability.
- `govulncheck` reports a reachable vulnerability.

Immediate checks:

- [ ] Identify affected module or package.
- [ ] Determine whether the vulnerable code is reachable.
- [ ] Check fixed version and compatibility notes.
- [ ] Check whether Dependabot already opened a PR.
- [ ] Check whether the finding affects released artifacts.

Recovery:

- [ ] Update the dependency.
- [ ] Run `go test ./...` in the root module.
- [ ] Run `cd operator && go test ./...`.
- [ ] Run `govulncheck ./...` in affected Go modules.
- [ ] Re-run Scorecard targeted checks after merge.
- [ ] Publish a security release if released artifacts are affected and the issue is material.

Response target:

- Critical reachable vulnerability: same day triage.
- High reachable vulnerability: triage within 2 business days.
- Medium reachable vulnerability: triage within 7 business days.
- Non-reachable or module-level finding: document and remediate in the next dependency update window.

## Central Rule Repository

`spec.remoteConfig` on a `PiiPolicy` makes the operator pull the rules from an HTTPS address and lay the policy's own rule fields over them (operator README, "Central rule repository"). The sidecars keep the last good rules whenever a pull fails, so a broken source degrades to "rules stop updating", never to "rules disappear".

Hosting the file:

1. Serve `policy.json` (the SDK `init_config` format plus a `revision`) from any HTTPS endpoint that answers `GET` with an `ETag` header and `304 Not Modified` for a matching `If-None-Match`: an object store bucket, an internal web server, or a rule server. Keep it under 256 KiB.
2. Put the whole `Authorization` header value (for example `Bearer <token>`) in a Secret in the policy's namespace and reference it with `headerSecretRef`; put a private CA bundle in a Secret and reference it with `caBundleSecretRef`. The operator reads both at every pull, so a change takes effect at the next interval.
3. Validate a new file before publishing it: run the agent with `PII_CONFIG_FILE=<file>` on a sample line, or push it to a staging policy first. The operator rejects an invalid file whole and reports `InvalidJSON`, `InvalidRegex` or `InvalidValue` in the `RemoteSynced` condition while the sidecars keep the previous rules.

Rotating the token:

1. Add the new token to the source so both tokens are accepted.
2. Update the Secret named by `headerSecretRef`.
3. Watch `kubectl get piipolicy <name> -o jsonpath='{.status.remote.lastSyncTime}'` move past the change, then retire the old token at the source.

When `PIIShieldRemoteRulesStale` or `PIIShieldRemoteRulesSyncErrors` fires:

1. `kubectl describe piipolicy <name>`: the `RemoteSynced` condition names the reason (`FetchFailed` with the HTTP status or the network error, `SecretNotFound`, `TooLarge`, `InsecureURL`, or a validation reason) and `status.remote` says when the last good pull was and which revision it carried.
2. Fix the source, the Secret or the file. The next pull happens within 60 s of the fix, or sooner if you edit the policy (any spec change triggers a pull).
3. Nothing needs a restart: the sidecars pick the merged file up from the ConfigMap about a minute after the operator writes it.

Rolling back to local rules: remove `remoteConfig` from the policy. The ConfigMap is rendered from the local policy alone on the next reconcile and `remote.json` is dropped. To pin one value against the source without leaving it, set that field in the policy; a local field always wins.

## Audit Mode

`auditMode: true` on a `PiiPolicy` (or `PII_MODE=audit` on a sidecar run by hand) is the dry run: the sidecar scans every line, writes it out unchanged and counts what it would have redacted. The numbers are `piishield_audit_lines_total{result="clean"|"would_redact"}` per line, `piishield_audit_findings_total{type}` per finding, the gauge `piishield_audit_mode`, and an hourly `PII-Shield audit: N would-be redactions (…) in M of L lines (x%)` line in the sidecar's log. The counters never hold the value that was found; the application's own logs for the period are the only place to see it. The eBPF audit agent (`injectionMode: ebpf`, [ebpf-audit.md](ebpf-audit.md)) exports the same counters and the same summary, so everything below applies to it too; it adds `piishield_ebpf_attached`, which is 0 when its program could not be loaded and the counts stay at zero for that reason.

When `PIIShieldAuditWouldRedact` fires, or the share of `would_redact` lines is not what you expect:

1. Read `piishield_audit_findings_total` by `type` for the pod: `entropy` is a bare high-entropy token, `regex` a custom rule, `luhn` a card number, `signature` an issuer-prefixed key (AWS, GitHub, JWT, …), a phone number by shape or an identity number by key, `key` a value under a sensitive key (or after an auth scheme, or a URL password), hidden whatever its score. A policy that only names `sensitiveKeys` shows up as `key`.
2. A share far above what the application should produce usually means ordinary values scored as secrets: request ids, hashes, model names under a sensitive key. Take a sample of the application's logs for an hour of the audit, run it through the CLI with the policy's rules as `PII_CONFIG_FILE` and `PII_ENTITY_TYPE_LABELS=true`, and read the markers. Then follow the false-positive runbook above: a narrow `safeRegexList` rule, a shorter `sensitiveKeys` list, a threshold change tested on the sample.
3. A share of zero, or `signature` at zero, on an application that handles credentials means the rules do not reach the values: a key name the defaults do not know (`sensitiveKeys`, `sensitiveKeyPatterns`), a structured identifier without a rule (`customRegexList`), or a log path the sidecar does not see. Follow the false-negative runbook.
4. Edit the policy and keep auditing: the rules file is reloaded without a restart, so the next hour's summary shows the change. Switch to redaction (`auditMode: false` and a rollout restart) only when the share and the types look right for a full week, batch jobs included.

When `PIIShieldAuditSeesNoLines` fires: the sidecar is in audit mode but processed no lines for an hour. Check that the application writes to the policy's `logPath` (`kubectl exec` into the app container and look at the file) and that it is not simply idle. An audit that sees nothing proves nothing, so do not count that time toward the dry run.

Leaving audit mode is a pod restart: the mode comes through the sidecar's environment, not through the rules file, because whether a pod redacts or only watches must not be switchable from a central rule server.

## Prometheus Alerts

The Helm chart can render a `PrometheusRule` for Prometheus Operator installations:

```yaml
metrics:
  prometheusRule:
    enabled: true
```

The default rules cover:

- target availability;
- sidecar restarts through kube-state-metrics;
- sanitizer error rate;
- sanitizer processing latency;
- missing processed-log throughput.

Tune alert thresholds and labels in `values.yaml` before production rollout.

The operator Helm chart can also render operator and webhook alert rules:

```yaml
metrics:
  prometheusRule:
    enabled: true
```

The operator rules cover:

- operator deployment availability;
- webhook service endpoint availability;
- webhook certificate expiry when cert-manager metrics are available;
- injection or admission failures when Kubernetes event metrics such as `kube_event_count` are available;
- a `PiiPolicy` with `remoteConfig` whose last successful pull is older than three intervals, and any failed pull in the last 15 minutes (operator metrics, no extra exporter needed);
- a sidecar in `auditMode` that saw lines it would redact in the last 24 hours (info), and one that processed no lines for an hour (warning); both read the sidecar's own counters, so the sidecar pods must be scraped.

These rules depend on common cluster observability components such as kube-state-metrics, cert-manager metrics, and an event metrics exporter. Disable or adjust rules that are not supported by your monitoring stack.
