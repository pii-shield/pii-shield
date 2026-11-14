# Scripts

[docs/testing.md](../docs/testing.md) is the full guide to testing; this page
is the index of what lives in this folder.

## Test runners (from fast to thorough)

| Script | What it runs | Needs |
| --- | --- | --- |
| `test-unit.sh` | Unit tests of the root module, the operator and the rule server | Go |
| `test-operator-integration.sh` | Operator integration tests against envtest (local kube-apiserver) | Go, envtest |
| `test-smoke.sh [--fuzz \| --regenerate]` | Scanner tests and benchmarks, then the container image end to end on the frozen corpus, scored for false positives and false negatives | Go, Docker, python3, jq, openssl |
| `test-deployments.sh [group\|path ...]` | Deployment test matrix (`tests/deployments/*`); groups: `local`, `published`, `cluster`, `cluster-published`, `all` | Docker; kind for cluster groups |
| `test-all.sh [deployment-group]` | Everything above, in order | All of the above |

Fixture for `test-deployments.sh`: set `PII_SHIELD_ACCESS_LOG` to a real log
(never commit or upload one), or let the script generate a synthetic fixture
via `generate-access-log-fixture.sh` — the default in CI.

## Checks CI runs that you can run too

| Script | Purpose | Needs |
| --- | --- | --- |
| `bench-gate.sh` | Scanner benchmarks at a base ref and at the working tree, compared with benchstat; the pull-request performance gate | Go |
| `check-test-docs.sh` | Every test script, deployment path and operator test target is in `docs/testing.md`, and every script the docs name exists | bash |
| `smoke-rules-server.sh <image>` | The rule server image starts, takes a rule set through its API and serves it back | Docker, curl |
| `smoke-ebpf-agent.sh <binary>` | The eBPF audit agent counts what a shell prints, on this kernel | Linux 5.8+ with BTF, root |
| `smoke-ebpf-image.sh <image>` | The same check on the binary inside a built agent image | Linux 5.8+ with BTF, root, Docker |
| `verify-agent-multiarch-build.sh` | The agent image builds for amd64 and arm64 | Docker buildx |
| `verify-helm-runtime.sh` | The standalone chart renders the container wiring the sidecar needs | Helm |

## Utilities

| Script | Purpose |
| --- | --- |
| `generate-access-log-fixture.sh [out] [lines]` | Synthetic access.log-style fixture with fake PII (safe for CI) |
| `set-version.sh` | Stamp the version from `VERSION` into every file that carries it; `--check` verifies they agree |
