# Testing

Every way to test PII-Shield on your own machine, from the fastest check to
the full deployment matrix, with what each one proves and what it needs.
`scripts/check-test-docs.sh` (run in CI) fails when a test script, a
deployment path or an operator test target is missing from this page, or when
this page names a script that no longer exists.

The repository holds four Go modules, and `go test ./...` covers only the one
it is run in:

| Module | Directory | What lives there |
| --- | --- | --- |
| scanner and CLI | repository root | `pkg/scanner`, `cmd/cleaner`, `sdks/parity` |
| operator | `operator/` | the PiiPolicy controller and the pod webhook |
| rule server | `rules/` | the server that stores and signs rule sets |
| eBPF agent | `ebpf/` | the audit agent (builds and tests on Linux only) |

## Quick reference

Times are from an M-series laptop with a warm build cache.

| Command | What it proves | Needs | Time |
| --- | --- | --- | --- |
| `scripts/test-unit.sh` | Unit tests of the root module, the operator and the rule server | Go | 20 s |
| `go test -fuzz=FuzzScanner -fuzztime=15s ./pkg/scanner` | The scanner does not crash, emit invalid UTF-8 or blow up the output on random input | Go | 20 s |
| `scripts/test-operator-integration.sh` | The controller against a real kube-apiserver: CRD schema, status, rendered ConfigMap, remote rules | Go; envtest binaries are downloaded on first run | 15 s |
| `scripts/verify-helm-runtime.sh` | The standalone chart renders the container wiring the sidecar needs | Helm | 1 s |
| `scripts/test-smoke.sh` | The container image end to end on a frozen 1000-line corpus: zero false positives, zero false negatives, valid JSON | Docker, python3, jq, openssl | 2 min |
| `scripts/test-deployments.sh local` | The CLI binary and the local Docker image on an access-log fixture | Docker | minutes |
| `scripts/test-deployments.sh cluster` | Helm, operator, pipe and eBPF paths on a kind cluster | Docker, kind, kubectl, Helm | tens of minutes |
| `scripts/test-all.sh` | Unit, operator integration, smoke and the deployment matrix, in that order | all of the above | tens of minutes |

Before a pull request, run at least `scripts/test-unit.sh` and, for a change
to `pkg/scanner`, the fuzz check and `scripts/test-smoke.sh`.

## Scanner and CLI

```bash
go test ./...                       # root module: scanner, CLI, parity golden
go test -race -coverprofile=coverage.out ./...   # what CI runs; total coverage must stay at 70% or more
go test ./pkg/scanner -run TestGolden            # golden files in pkg/scanner/testdata
```

Golden and corpus files that pin behavior, and how to refresh them after an
intended change (review the diff before committing it):

| File | Refresh with |
| --- | --- |
| `pkg/scanner/testdata/*.golden` | `go test ./pkg/scanner -run TestGolden -update` |
| `pkg/scanner/testdata/f6-corpus.expected`, `f6-corpus.verdicts` | `go test ./pkg/scanner -run TestEntropyThresholdCorpus -update-f6-expected` |
| `scripts/testdata/smoke-corpus.txt`, `.tsv` | `scripts/test-smoke.sh --regenerate` |
| `sdks/parity/cases.json` | by hand; the Go, Node and Python tests must agree on it |

### Fuzzing

```bash
go test -fuzz=FuzzScanner -fuzztime=15s ./pkg/scanner   # the CI sanity run
go test -fuzz=FuzzScanner -fuzztime=10m ./pkg/scanner   # before merging a change to the tokenizer
```

`go test -fuzz` takes one target in one package per run. When a run fails, Go
writes the input to `pkg/scanner/testdata/fuzz/FuzzScanner/`; commit that file
with the fix so it stays a regression test.

### Smoke test

```bash
scripts/test-smoke.sh               # frozen corpus: the same code always gives the same numbers
scripts/test-smoke.sh --fuzz        # a freshly generated random corpus
scripts/test-smoke.sh --regenerate  # rebuild the frozen corpus
```

The script runs the scanner unit tests and benchmarks, builds the
`pii-shield:local` image, and scores the corpus through the container. A
secret counts as caught only when its value is gone from the output and a
marker took its place; a safe line must come back byte for byte. It exits
non-zero on any false positive or false negative, on a line count that
changed, and on invalid JSON.

### Benchmarks

```bash
go test -bench=. -benchmem ./pkg/scanner                               # microbenchmarks
scripts/bench-gate.sh                                                  # this branch against origin/main, the PR gate
BASE_REF="$(cat benchmark/baseline-ref)" THRESHOLD_PCT=15 WARN_PCT=8 scripts/bench-gate.sh   # against the accepted baseline
BASE_REF=origin/main RUNS=7 LINES=500000 benchmark/run_benchmarks.sh   # end-to-end CLI throughput, old and new binaries interleaved
```

`scripts/bench-gate.sh` builds the scanner benchmarks at a base ref and at the
working tree, runs them interleaved and compares them with benchstat; it fails
only on a slowdown that is both above the threshold and statistically
significant. Use `benchmark/run_benchmarks.sh` on a quiet machine for a number
you can quote.

### Trying the CLI by hand

`MANUAL_TESTING.md` walks through the metrics endpoint and the two fail
policies with commands you can paste.

## SDKs (Node and Python)

Both SDKs run the scanner as a WebAssembly module, so build it first:

```bash
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o pii-shield-wasi.wasm cmd/wasm-ffi/main.go
(cd sdks/node && node test.js)
(cd sdks/python && python3 -m pip install wasmtime && python3 test.py)
```

Each test loads `sdks/parity/cases.json` and must produce the same bytes as
the Go test in `sdks/parity`, which is how "every entry point redacts
identically" is checked.

## Operator

Run these from `operator/`, or from the root with `make -C operator`.

```bash
go test ./...                 # unit tests, fake client, no cluster
make test-integration         # envtest: a local kube-apiserver, no kubelet
make test                     # regenerate manifests, fmt, vet, then unit and envtest together
make lint                     # golangci-lint with the operator's own config
make test-e2e                 # kind: build and load images, install the chart, check live redaction
```

`scripts/test-operator-integration.sh` is `make test-integration` with a
directory check in front. The envtest suite starts a real API server on
localhost; endpoint-security software that blocks local listeners makes it
fail with a connection error.

After changing `operator/api/`, run `make manifests generate sync-helm` and
commit the regenerated CRD and chart; never edit generated files by hand.

## Rule server

```bash
cd rules && go test ./...
RULES_TEST_POSTGRES='postgres://postgres:ci@127.0.0.1:5432/postgres?sslmode=disable' go test -count=1 ./internal/store/... ./internal/server/...
docker build -f rules/Dockerfile -t pii-shield-rules:local . && scripts/smoke-rules-server.sh pii-shield-rules:local
```

Without `RULES_TEST_POSTGRES` the store tests run on SQLite only; with it they
run again on the Postgres at that address. The smoke script starts the image,
publishes a rule set through the API and pulls it back with a token.

## eBPF audit agent

Linux only: a kernel of 5.8 or newer with BTF, and root or the BPF and PERFMON
capabilities.

```bash
cd ebpf && go test -race ./...
go build -o ../pii-shield-ebpf ./cmd/pii-shield-ebpf && sudo ../scripts/smoke-ebpf-agent.sh ../pii-shield-ebpf
sudo scripts/smoke-ebpf-image.sh <image>      # the same check on the binary inside a built image
```

## Helm charts and images

```bash
helm lint charts/pii-shield charts/pii-shield-operator
helm template charts/pii-shield-operator > /dev/null
scripts/verify-helm-runtime.sh
scripts/verify-agent-multiarch-build.sh       # builds the agent image for amd64 and arm64; needs docker buildx
scripts/set-version.sh --check                # every file that carries the version agrees with VERSION
```

## Deployment matrix

`scripts/test-deployments.sh [group|path ...]` runs the paths under
`tests/deployments/`. Each path is a folder with its own `run.sh`; pass folder
names instead of a group to run only those.

| Group | Paths | Needs |
| --- | --- | --- |
| `local` | `local-binary`, `docker-local` | Docker |
| `published` | `docker-ghcr`, `wasm-node`, `wasm-python` | Docker, Node, Python, network |
| `cluster` | `standalone-helm-local`, `operator-helm-local`, `operator-local-images`, `operator-kustomize`, `operator-pipe`, `operator-ebpf` | kind, kubectl, Helm |
| `cluster-published` | `standalone-helm-published`, `operator-helm-published` | kind, kubectl, Helm, network |
| not in a group | `operator-rules-server` | kind, kubectl, Helm; run it by name |

The matrix reads an access log as its input. Set `PII_SHIELD_ACCESS_LOG` to a
real one (never commit or upload it); without it the script generates a
synthetic log with `scripts/generate-access-log-fixture.sh`, which is what CI
does. `tests/deployments/README.md` describes each path and where its
sanitized output lands.

## What CI runs

| Check | Local equivalent |
| --- | --- |
| Version consistency | `scripts/set-version.sh --check` |
| Test documentation is current | `scripts/check-test-docs.sh` |
| Lint | `golangci-lint run` at the root, `make -C operator lint` |
| Fuzz sanity | `go test -fuzz=FuzzScanner -fuzztime=15s ./pkg/scanner` |
| Tests with the race detector and the 70% coverage floor | `go test -race -coverprofile=coverage.out ./...` |
| Operator unit and envtest suites | `cd operator && go test -race ./... && make test-integration` |
| Rule server tests, SQLite and Postgres | see Rule server above |
| eBPF agent tests and kernel smoke | see eBPF audit agent above |
| Helm lint and runtime wiring | see Helm charts and images above |
| Performance Check on pull requests | `scripts/bench-gate.sh`, twice: against the PR base and against `benchmark/baseline-ref` |
| SDK parity (Node, Python) | see SDKs above |
| Deployment matrix, nightly | `scripts/test-deployments.sh <group>` |
