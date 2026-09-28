#!/usr/bin/env bash
# bench-gate.sh - fail when the scanner got significantly slower than a base ref.
#
#   BASE_REF=origin/main scripts/bench-gate.sh
#
# Builds the pkg/scanner test binary at BASE_REF and at the working tree, runs
# the end-to-end benchmarks COUNT times with the two binaries interleaved (so
# drift on a shared runner hits both sides alike), and compares them with
# benchstat. It fails only when a benchmark is slower by more than
# THRESHOLD_PCT percent AND benchstat calls the difference significant
# (p < 0.05). Shared CI runners are noisy: a small threshold would fail on
# noise, so this catches real regressions of the size a reviewer would care
# about, not a 2% drift. For a precise number, run benchmark/run_benchmarks.sh
# (end-to-end CLI A/B) on a quiet machine.
#
# Environment:
#   BASE_REF       git ref to compare against (default origin/main)
#   COUNT          runs per side (default 10)
#   THRESHOLD_PCT  allowed slowdown in percent (default 15)
#   BENCH          benchmark regexp (default the two end-to-end benchmarks)
#   BENCHTIME      -test.benchtime per run (default 1s)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BASE_REF="${BASE_REF:-origin/main}"
COUNT="${COUNT:-10}"
THRESHOLD_PCT="${THRESHOLD_PCT:-15}"
BENCH="${BENCH:-^(BenchmarkScanAndRedact|BenchmarkThroughput)$}"
BENCHTIME="${BENCHTIME:-1s}"
# Pinned so the gate does not change under us; bump deliberately.
BENCHSTAT="${BENCHSTAT:-golang.org/x/perf/cmd/benchstat@v0.0.0-20260908200009-22c9c6c9d4da}"

work="$(mktemp -d)"
cleanup() {
    git worktree remove --force "${work}/base" >/dev/null 2>&1 || true
    rm -rf "${work}"
}
trap cleanup EXIT

base_sha="$(git rev-parse --verify "${BASE_REF}^{commit}")"
head_sha="$(git rev-parse HEAD)"
echo "base ${BASE_REF} = ${base_sha}"
echo "head            = ${head_sha}"

git worktree add --detach --quiet "${work}/base" "${base_sha}"
(cd "${work}/base" && go test -c -o "${work}/base.test" ./pkg/scanner)
go test -c -o "${work}/head.test" ./pkg/scanner

# The test binaries read testdata relative to the package directory.
run() {
    (cd "${ROOT_DIR}/pkg/scanner" && "$1" -test.run '^$' -test.bench "${BENCH}" \
        -test.benchmem -test.benchtime "${BENCHTIME}" -test.count 1) | grep -E '^Benchmark' >> "$2"
}
: > "${work}/base.txt"
: > "${work}/head.txt"
for i in $(seq 1 "${COUNT}"); do
    if (( i % 2 == 1 )); then
        run "${work}/base.test" "${work}/base.txt"
        run "${work}/head.test" "${work}/head.txt"
    else
        run "${work}/head.test" "${work}/head.txt"
        run "${work}/base.test" "${work}/base.txt"
    fi
done

(cd "${work}" && go run "${BENCHSTAT}" base=base.txt head=head.txt) | tee "${work}/benchstat.txt"

# Read the sec/op table only: a line per benchmark such as
#   ScanAndRedact-4   10.17µ ± 2%   11.90µ ± 3%  +17.01% (p=0.000 n=10)
# "~" in place of a percentage means not significant.
python3 - "${work}/benchstat.txt" "${THRESHOLD_PCT}" <<'EOF'
import re, sys
path, threshold = sys.argv[1], float(sys.argv[2])
in_secop = False
failed = []
for line in open(path):
    if "sec/op" in line:
        in_secop = True
        continue
    if in_secop and (line.strip() == "" or line.lstrip().startswith("│")):
        if line.strip() == "":
            break
        continue
    if not in_secop or line.startswith("geomean"):
        continue
    m = re.search(r"([+-]\d+(?:\.\d+)?)% \(p=(\d+(?:\.\d+)?) ", line)
    if m and float(m.group(1)) > threshold and float(m.group(2)) < 0.05:
        failed.append(line.split()[0] + " " + m.group(1) + "%")
if failed:
    print("FAIL: significant slowdown above %.0f%%: %s" % (threshold, ", ".join(failed)))
    sys.exit(1)
print("OK: no significant slowdown above %.0f%%" % threshold)
EOF
