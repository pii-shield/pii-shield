# Contributing Guide

Welcome! Please read this short guide before you start.

## Contribution Process

1. Open an issue for bugs, feature requests, or larger design changes.
2. Fork the repository and create a branch for your change.
3. Make the change and add or update tests when behavior changes.
4. Run the relevant local tests described below.
5. Open a pull request against `main`.
6. Wait for required GitHub Actions checks to pass and address review feedback before merge.

## Contribution Requirements

Acceptable contributions should:
- Follow standard Go formatting with `gofmt`.
- Keep existing tests passing and add or update tests when behavior changes.
- Update documentation when user-facing behavior, configuration, deployment, or security guidance changes.
- Avoid committing secrets, credentials, generated binaries, or unrelated formatting-only churn.
- Keep pull requests focused on one logical change whenever practical.

## Prerequisites
You will need the following tools:
- **Go** (version 1.26+, matching `go.mod`)
- **Minikube** or **Kind**
- **Helm**

## Local Setup
Run these commands to build the project locally and check for errors:
```bash
go mod tidy
go build -o bin/operator ./operator/main.go
# Or use the build script:
./build.sh
```

## Testing
Before making a PR, please run tests to make sure you didn't break the pipeline:
```bash
# Run unit and fuzzing tests
go test ./... -v -fuzz=Fuzz

# Run stress and smoke tests against the frozen corpus (deterministic)
./scripts/test-smoke.sh

# Optional: score a freshly generated random corpus instead
./scripts/test-smoke.sh --fuzz
```

The default run scores the corpus committed under `scripts/testdata/`, so the
same code always produces the same numbers and a red run means a real change.
`--regenerate` rebuilds that corpus; review the diff and re-run the smoke test
before committing it.

For performance-sensitive changes, compare CLI throughput against the baseline branch:
```bash
BASE_REF=origin/main RUNS=7 LINES=500000 ./benchmark/run_benchmarks.sh
```

For scanner-only microbenchmarks, run:
```bash
go test -bench=. -benchmem ./pkg/scanner
```

## Review Policy
Pull requests should pass the required GitHub Actions checks before merge. Ownership for major areas of the repository is documented in `.github/CODEOWNERS`; use it to identify the right reviewer for scanner, operator, chart, SDK, workflow, and security-documentation changes.

For solo-maintainer periods, CODEOWNERS documents responsibility but should not be enforced as a required branch rule unless another reviewer is available.

## Operator Run
To debug the webhook in a local Minikube cluster:
```bash
# 1. Start cluster and use minikube docker daemon
minikube start
eval $(minikube docker-env)

# 2. Build local image
docker build -t pii-shield:local .

# 3. Install the Helm chart
helm upgrade --install pii-shield ./charts/pii-shield \
  --set image.repository=pii-shield \
  --set image.tag=local \
  --set demo.enabled=true \
  --namespace pii-shield --create-namespace
```
