# PII-Shield 🛡️

**Zero-code log sanitization sidecar for Kubernetes.**
Prevents data leaks (GDPR/SOC2) by redacting PII from logs *before* they leave the pod.

PII-Shield runs in-process — CLI, sidecar, or WASM. There is no hosted API and no server your data is sent to.

[![Release](https://img.shields.io/badge/release-v2.2.3-blue)](https://github.com/pii-shield/pii-shield/releases/tag/v2.2.3) ![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg) ![Docker Pulls](https://img.shields.io/docker/pulls/thelisdeep/pii-shield) [![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/pii-shield)](https://artifacthub.io/packages/search?repo=pii-shield)<br>
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12945/badge)](https://www.bestpractices.dev/projects/12945) ![Go Report Card](https://goreportcard.com/badge/github.com/pii-shield/pii-shield?v=1) ![Test Coverage](https://github.com/pii-shield/pii-shield/actions/workflows/test.yml/badge.svg) [![Sponsor](https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-ea4aaa?logo=githubsponsors)](https://pii-shield.com/go/sponsors?utm_source=github&utm_medium=readme-badge&utm_campaign=sponsors)

"Don't let PII poison your AI models." PII-Shield ensures that sensitive data never reaches your training dataset, saving you from GDPR-forced model retraining.

> [!WARNING]
> **Upgrading to v2.0.0?**
> We have moved end-user distribution to Helm-based installs and Distroless Native Sidecars. Kustomize is no longer a supported release installation path for production users, though the operator repository still keeps Kustomize scaffolding for local development and manifest generation. `/bin/sh` access inside the PII-Shield sidecar is no longer supported. Read the Migration Guide.

## Two Deployment Models

PII-Shield offers two distinct ways to integrate into your stack:

1. **Kubernetes Operator (Zero-code)**: Our flagship deployment model. A fully automated K8s Operator that injects a highly-secure Distroless Sidecar into your pods to intercept and sanitize logs on the fly.
2. **In-Process WASM (For core integrations)**: For extreme performance, the core engine can be embedded directly via WASM, providing `<1ms` latency without network hops.

## Project Status & Roadmap

PII-Shield is an actively developed open-source security tool in a production-hardening phase. The v2.x release line ships usable CLI, container, Helm/operator, and WASM SDK artifacts. Core redaction paths are ready for controlled deployments, while some Kubernetes deployment modes and supply-chain guarantees are still being stabilized.

| Component | Status |
| --- | --- |
| Core scanner | Released / controlled deployments |
| CLI sidecar | Released / controlled deployments |
| Kubernetes operator | Stabilization phase |
| WASM SDKs | Released beta |
| Proxy-Wasm gateway integration | Planned R&D |
| Control Plane UI | Planned R&D |
| eBPF interception | Experimental R&D |

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for the current production-hardening boundaries.

## Why PII-Shield?

Developers often forget to mask sensitive data. Traditional regex filters in Fluentd/Logstash are slow, hard to maintain, and consume expensive CPU on log aggregators.

**PII-Shield sits right next to your app container:**
- **Production-hardening Core Engine:** Optimized for Kubernetes sidecars with low memory allocations on hot paths and deterministic regex matching.
- **Context-Aware Entropy Analysis:** Detected high-entropy secrets even without keys (e.g. `Error: ... 44saCk9...`) by analyzing context keywords.
- **Custom Regex Rules:** Deterministic redaction for structured data (UUIDs, IDs) that overrides entropy checks for known patterns.
- **Regression & Fuzz Coverage:** Tested against stress cases including binary garbage, JSON nesting, and multilingual logs.
- **Deterministic Hashing:** Replaces secrets with unique hashes (e.g., `[HIDDEN:a1b2c]`), allowing QA to correlate errors without seeing the raw data.
- **Drop-in:** No code changes required. Works with any language (Node, Python, Java, Go).
- **Whitelist Support:** Explicitly allow safe patterns (e.g., git hashes, system IDs) using `PII_SAFE_REGEX_LIST` to prevent false positives.


## Managing PII-Shield across dozens of clusters?
We are building a hosted Control Plane with centralized rule management, Slack alerting, and redaction analytics. 
[![Join the Waitlist](https://img.shields.io/badge/Join_the_Waitlist-PII--Shield_Cloud-blue?style=for-the-badge)](https://tally.so/r/PdY7Ze)

## Integrations

PII-Shield's in-process WASM build ships inside [GuardSpine Code](https://github.com/DNYoussef/guardspine-code-action), an open-source AI code-governance GitHub Action, which vendors the binary and credits it in its `NOTICE`.

## Performance Considerations

While PII-Shield is highly optimized, deep inspection of complex logs requires careful attention to configuration.
- **Text Logs:** Extremely fast (>100k lines/s).
- **JSON Logs:** Zero-allocation parsing (no `encoding/json` overhead). The scanner manually parses JSON structures to ensure high throughput (~7MB/s) without memory spikes.
- **Recommendation:** Usage is safe for high throughput. We use recursion safeguards to prevent stack overflows on deeply nested JSON.

## Installation

### Helm Chart (Kubernetes Operator)
The official and recommended way to deploy PII-Shield in Kubernetes is via our fully-automated Operator:

```bash
helm repo add pii-shield https://pii-shield.github.io/pii-shield/
helm repo update
helm install pii-shield-operator pii-shield/pii-shield-operator -n operator-system --create-namespace
```
This deploys the PII-Shield Operator which automatically injects highly-secure, distroless sidecars into your Pods without requiring any code or Dockerfile changes.

### Docker
Get the latest lightweight image from Docker Hub or GHCR:
```bash
docker pull thelisdeep/pii-shield:2.2.3
# OR from GitHub Container Registry (Enterprise):
docker pull ghcr.io/pii-shield/pii-shield:2.2.3
```

### Build from Source

You can build the binary directly from the source code:

```bash
go build -o pii-shield ./cmd/cleaner/main.go
```

## Configuration
See [CONFIGURATION.md](CONFIGURATION.md) for a full list of environment variables, including:
- `PII_SALT`: Custom HMAC salt (Required for production).
- `PII_ADAPTIVE_THRESHOLD`: Enable dynamic entropy baselines.
- `PII_DISABLE_BIGRAM_CHECK`: Optimize for non-English logs.
- `PII_CUSTOM_REGEX_LIST`: Custom regex rules for deterministic redaction.
- `PII_SAFE_REGEX_LIST`: Whitelist regex rules to ignore (matches are returned as-is).

### Entropy Sensitivity Table (Default Threshold: 3.6)

| Entropy | Data Type | Example |
|---------|-----------|---------|
| **0.0 - 3.0** | Common words, repeats | `password`, `admin`, `111111` |
| **3.0 - 3.6** | CamelCase, partial hashes | `ProgramCampaignInstanceJob`, `8f3a11b2c` |
| **3.6 - 4.5** | Paths, UUIDs, Weak Passwords | `/opt/application/runtime`, `P@ssw0rd2026!` |
| **4.5 - 5.0** | Medium Tokens | `E8s9d_2kL1` |
| **5.0+** | High Entropy Keys | (SHA-256, API Keys) |

## Quick Start
1. Test Locally (CLI)
You can pipe any log output through PII-Shield to see it in action immediately:

```bash
# Emulate a log with a sensitive password
echo "Error: User password=MySecretPass123! failed login" | docker run -i --rm ghcr.io/pii-shield/pii-shield:2.2.3

# Output: Error: User password=[HIDDEN:8f3a11] failed login
```

2. Kubernetes (Automated Sidecar Injection)
With the PII-Shield Operator installed, protecting an application is as simple as creating a `PiiPolicy` and labeling your Pods.

**Create a Policy:**
```yaml
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: strict-policy
  namespace: default
spec:
  injectionMode: "file"
```

**Label your Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    metadata:
      labels:
        pii-shield.io/inject: "true"
      annotations:
        pii-shield.io/policy: "strict-policy"
# ...
```

The Operator will automatically inject the `pii-shield-agent` using the Native Sidecar pattern (K8s 1.28+) and securely mask all logs!

---

📋 **Free: 25-point Kubernetes Log PII Audit Checklist** — where PII leaks from pods, which log paths bypass your filters, and how to verify redaction actually works. [Get the checklist →](https://pii-shield.com/#checklist)

📦 **GDPR Compliance Pack — available now (early access)**: 40+ tested redaction rules, DPO-ready docs, audit-trail templates. [$149 →](https://pii-shield.com/gdpr-pack?utm_source=github-readme&utm_medium=readme&utm_campaign=gdpr-pack) · HIPAA/PCI [on the waitlist →](https://pii-shield.com/#waitlist)

💬 **Using PII-Shield?** [Tell us about your deployment →](https://tally.so/r/Gx4WoZ) — 2 minutes, and it shapes what gets built next.

## Verification
This project is verified with a growing testing suite intended to raise confidence before production hardening:
1. **Unit Tests**: Cover edge cases, multilingual support, and JSON integrity with >85% coverage.
2. **Fuzzing**: Native Go fuzzing ensures crash safety against invalid and random binary inputs.
3. **Smoke Testing**: `./scripts/test-smoke.sh` exercises mixed workloads and reports detection accuracy.
4. **End-to-End (E2E) Testing**: The `operator/tests/run_e2e.sh` suite performs full-stack validation using Minikube and Helm. It builds local images, provisions the Operator without cert-manager, deploys target Jobs, and verifies actual log redaction by intercepting sidecar outputs.

### Performance Benchmarks

To compare end-to-end CLI throughput between the current branch and a baseline ref:

```bash
./benchmark/run_benchmarks.sh
```

By default, the benchmark compares `HEAD` against `origin/main`, refreshes `origin/main`, generates a mixed log corpus, alternates old/new run order, and reports median, p95, min/max, and MiB/s:

```bash
BASE_REF=origin/main RUNS=9 LINES=500000 ./benchmark/run_benchmarks.sh
```

This measures the full stdin-to-stdout CLI path. For scanner-only microbenchmarks, run:

```bash
go test -bench=. -benchmem ./pkg/scanner
```

### Operator Integration Tests

The operator keeps fast unit tests separate from Kubernetes API integration tests. Regular operator tests do not start a local API server:

```bash
cd operator
go test ./...
```

To run the envtest-based controller integration suite:

```bash
./scripts/test-operator-integration.sh
```

These tests start a local Kubernetes API server and etcd through `envtest`, so they require permission to bind to `127.0.0.1`. In restricted sandboxes, run them in a local shell, Docker environment, or CI runner that allows localhost bind.

## Support

PII-Shield is open-source infrastructure for privacy-preserving logs. If this project is useful to you or your organization, you can support its development through [GitHub Sponsors](https://pii-shield.com/go/sponsors?utm_source=github&utm_medium=readme-support&utm_campaign=sponsors).

## Release Verification

Release checksum and image-digest verification guidance is documented in [docs/release-verification.md](docs/release-verification.md). Signature and provenance-backed releases are tracked as part of the supply-chain hardening roadmap.

## License
Distributed under the Apache 2.0 License. See `LICENSE` for more information.
