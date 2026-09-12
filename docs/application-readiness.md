# PII-Shield Application Readiness

## Current Maturity

PII-Shield is an actively developed open-source security tool in a production-hardening phase. The current release line provides usable core scanner, CLI/container, Helm/operator, and WASM SDK artifacts for controlled deployments.

Production compliance use should account for the limits documented in `KNOWN_LIMITATIONS.md`, especially around Kubernetes logging modes, operator stabilization, and experimental eBPF work.

For deployment-mode adoption gates, see `docs/production-adoption-checklist.md`. For production incident handling, see `docs/operational-runbooks.md`. For cluster validation, see `docs/kubernetes-compatibility.md`. For sidecar runtime failure behavior, see `docs/sidecar-failure-modes.md`. For operator rollout and stabilization guidance, see `docs/operator-stabilization.md`. For transparent `stdout`/`stderr` planning, see `docs/stdout-stderr-interception-design.md`.

## Supported Use Cases

- Redacting sensitive values from text logs through the CLI/container path.
- Running PII-Shield as a Kubernetes sidecar for workloads that can write logs to the configured file path.
- Managing sidecar injection through the Kubernetes operator and `PiiPolicy` resources.
- Embedding the core scanner through WASM SDKs for Node.js and Python integrations.
- Tuning detection with sensitive keys, entropy thresholds, custom regex rules, and safe-list rules.

## Unsupported Or Experimental Areas

- Full transparent interception of standard Kubernetes `stdout` and `stderr` logs.
- Production-grade eBPF interception.
- Proxy-Wasm gateway integration.
- Hosted control-plane features.
- Broadly configured safe-list rules that have not been validated against representative production logs.
- Production deployments without a persistent `PII_SALT` when stable hash correlation is required.

## Installation Paths

### Local Development

Prerequisites:

- Go 1.26 or newer for normal development (the authoritative toolchain version is `go.mod`).
- Helm for chart validation.
- Docker with Buildx for container image validation.
- Minikube or Kind for local Kubernetes validation.

Common commands:

```bash
go mod verify
go test -race -coverprofile=coverage.out ./...
go build -o pii-shield ./cmd/cleaner/main.go
```

Operator tests:

```bash
cd operator
go test -v -race -coverprofile=cover.out ./...
```

### Docker

Official images are published to Docker Hub and GitHub Container Registry. The current README documents:

```bash
docker pull thelisdeep/pii-shield:2.2.3
docker pull ghcr.io/pii-shield/pii-shield:2.2.3
```

Smoke test example:

```bash
echo "Error: User password=MySecretPass123! failed login" | docker run -i --rm ghcr.io/pii-shield/pii-shield:2.2.3
```

### Kubernetes And Helm

The recommended Kubernetes path is the Helm-distributed operator:

```bash
helm repo add pii-shield https://pii-shield.github.io/pii-shield/
helm repo update
helm install pii-shield-operator pii-shield/pii-shield-operator -n operator-system --create-namespace
```

Workloads opt in through pod labels and policy annotations. Production users should validate webhook behavior, failure policy, sidecar injection, and log paths in a staging cluster before rollout.

### WASM SDKs

The WASM integration path is intended for in-process usage where applications need low-latency redaction without a sidecar or network hop. SDK consumers should include representative fixture tests in their own CI.

## Configuration Readiness

Important settings are documented in `CONFIGURATION.md`.

Production-sensitive settings:

- `PII_SALT`: set a persistent value longer than 16 characters when deterministic hashes must remain stable across restarts.
- `PII_REQUIRE_STRONG_SALT`: set to `true` in production or compliance environments to reject explicitly configured salts shorter than 16 bytes.
- `PII_ENTROPY_THRESHOLD`: tune carefully to balance false positives and false negatives.
- `PII_SENSITIVE_KEYS`: keep organization-specific key names covered.
- `PII_CUSTOM_REGEX_LIST`: use for deterministic redaction of structured IDs and domain-specific secrets.
- `PII_SAFE_REGEX_LIST`: validate carefully because broad safe-list rules can bypass redaction.
- `PII_ADAPTIVE_THRESHOLD`: treat as experimental until validated against real traffic.

## Validation

Automated validation currently includes:

- Go unit tests and race-enabled coverage runs.
- Operator unit tests.
- Scanner fuzz sanity checks.
- Scanner benchmarks and performance checks.
- Helm runtime verification.
- Multi-architecture agent image build verification.
- Node SDK and Python SDK checks after WASM compilation.

Manual or environment-dependent validation:

- `./scripts/test-smoke.sh` for mixed workload smoke testing.
- `./scripts/test-operator-integration.sh` for envtest-based controller integration.
- `operator/tests/run_e2e.sh` for Minikube/Helm end-to-end operator validation.
- Deployment-specific checks for Kubernetes log paths, webhook failure behavior, and policy selection.

## Security Readiness

Security documentation and controls:

- `SECURITY.md` defines private vulnerability reporting, supported versions, deployment guidance, and secret handling.
- `docs/threat-model.md` documents assets, actors, data flows, trust boundaries, STRIDE threats, mitigations, and residual risks.
- `.github/workflows/scorecard.yml` runs OpenSSF Scorecard and uploads SARIF results.
- `.github/workflows/codeql.yml` runs CodeQL for Go code.
- `.github/workflows/security-scan.yml` runs Go vulnerability checks, filesystem vulnerability scanning, and SBOM generation.
- `.github/dependabot.yml` tracks dependency updates across Go modules, GitHub Actions, Docker, Node SDK, and Python SDK ecosystems.

Required operator actions before production:

- Store runtime secrets in Kubernetes secrets or an external secret manager.
- Store CI/CD credentials in GitHub Actions secrets or an equivalent CI secret store.
- Review generated logs and test fixtures for real PII before publication.
- Rotate any credential immediately if it is accidentally committed.

## Operational Readiness

Logging:

- PII-Shield is designed to reduce sensitive log exposure before logs leave the workload boundary.
- Users should validate downstream logs, sidecar outputs, and failure modes in staging.

Monitoring:

- Helm charts include Prometheus-related resources for PII-Shield sidecar metrics.
- Production users should connect these metrics to their cluster monitoring stack and define alerts around webhook health, pod injection failures, and sidecar failures.
- The `pii-shield` Helm chart can render default Prometheus alert rules with `metrics.prometheusRule.enabled=true`.

Upgrade process:

- Review release notes, `KNOWN_LIMITATIONS.md`, and chart values before upgrading.
- Test policy compatibility and sidecar behavior in staging.
- Roll out namespace by namespace or workload by workload where possible.

Rollback process:

- Keep the previous chart values and image tags available.
- Roll back Helm releases if operator or injection behavior regresses.
- Remove opt-in labels or policy annotations from workloads if immediate bypass is required.

## Release And Maintenance

Release workflows publish:

- Go binaries through GoReleaser.
- Container images to GHCR and Docker Hub.
- Node and Python WASM SDK packages.
- Helm chart releases.

Release notes expectations are documented in `docs/release-notes-policy.md`. Release artifact verification is documented in `docs/release-verification.md`. Current releases include checksums, and release workflows are being hardened with GitHub artifact attestations plus container SBOM/provenance attestations.

Maintenance expectations:

- Keep CI green before release.
- Review Dependabot updates regularly.
- Update the threat model when deployment modes, CI/CD flows, permissions, or scanner behavior change.
- Keep `KNOWN_LIMITATIONS.md` aligned with the actual stability of deployment modes.
