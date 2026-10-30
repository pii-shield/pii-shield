#!/usr/bin/env bash
# bench-gate.sh - fail when the scanner got significantly slower than a base ref.
#
#   BASE_REF=origin/main scripts/bench-gate.sh
#   BASE_REF=$(cat benchmark/baseline-ref) THRESHOLD_PCT=15 WARN_PCT=8 \
#       LABEL="accepted baseline" scripts/bench-gate.sh
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
# A slowdown above WARN_PCT (and significant) but within THRESHOLD_PCT does not
# fail: it prints a warning, which on GitHub Actions becomes an annotation on
# the run and a table in the job summary, so a trend shows before it blocks.
#
# With REPORT set, every run also appends its verdict and the benchstat table
# to that markdown file, whether it passed or not. CI uploads the file and the
# bench-comment workflow posts it on the pull request.
#
# CI runs this twice on a pull request: against the PR base, which catches one
# PR that is too slow, and against the ref in benchmark/baseline-ref, which
# catches many small slowdowns that add up (v2.2.0 -> v2.2.8 lost 13-24% of
# CLI throughput over 72 scanner commits, each within the per-PR threshold).
# Accepting a slowdown on purpose means moving benchmark/baseline-ref in the
# same PR, where the reviewer sees it.
#
# The OVERLAY files are copied from the working tree into the base checkout
# before it is built, so a benchmark added after the base ref (such as
# BenchmarkAccessLog) is measured on both sides with the same code.
#
# Environment:
#   BASE_REF       git ref to compare against (default origin/main)
#   COUNT          runs per side (default 10)
#   THRESHOLD_PCT  allowed slowdown in percent (default 10)
#   WARN_PCT       slowdown in percent that warns without failing (default 5)
#   LABEL          what BASE_REF is, for the messages (default "base")
#   BENCH          benchmark regexp (default the three end-to-end benchmarks)
#   BENCHTIME      -test.benchtime per run (default 1s)
#   OVERLAY        test files copied into the base checkout, space-separated
#   REPORT         markdown file to append the verdict and table to (optional)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BASE_REF="${BASE_REF:-origin/main}"
COUNT="${COUNT:-10}"
# 10%: on the GitHub runners the first gate runs (#246) measured the same code
# within about +-1% over 10 interleaved runs; 10 leaves room for a noisy
# neighbour. Revisit with more runs.
THRESHOLD_PCT="${THRESHOLD_PCT:-10}"
WARN_PCT="${WARN_PCT:-5}"
LABEL="${LABEL:-base}"
BENCH="${BENCH:-^(BenchmarkScanAndRedact|BenchmarkThroughput|BenchmarkAccessLog)$}"
BENCHTIME="${BENCHTIME:-1s}"
OVERLAY="${OVERLAY:-pkg/scanner/accesslog_bench_test.go}"
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
echo "${LABEL} ${BASE_REF} = ${base_sha}"
echo "head            = ${head_sha}"

git worktree add --detach --quiet "${work}/base" "${base_sha}"
for f in ${OVERLAY}; do
    cp "${ROOT_DIR}/${f}" "${work}/base/${f}"
done
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
python3 - "${work}/benchstat.txt" "${THRESHOLD_PCT}" "${WARN_PCT}" "${LABEL} ${BASE_REF}" "${REPORT:-}" <<'EOF'
import os, re, sys
path, threshold, warn, where, report = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), sys.argv[4], sys.argv[5]
in_secop = False
failed, warned = [], []
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
    if not m or float(m.group(2)) >= 0.05:
        continue
    entry = line.split()[0] + " " + m.group(1) + "%"
    if float(m.group(1)) > threshold:
        failed.append(entry)
    elif float(m.group(1)) > warn:
        warned.append(entry)

# On GitHub Actions a warning or an error becomes an annotation on the run,
# and the job summary gets the verdict with the whole benchstat table.
gha = os.environ.get("GITHUB_ACTIONS") == "true"
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary and (failed or warned):
    with open(summary, "a") as out:
        out.write("### Scanner benchmarks against the %s\n\n" % where)
        if failed:
            out.write("Slower by more than %.0f%%: %s\n\n" % (threshold, ", ".join(failed)))
        if warned:
            out.write("Slower by more than %.0f%%, within %.0f%%: %s\n\n" % (warn, threshold, ", ".join(warned)))
        out.write("```\n" + open(path).read() + "```\n")
if report:
    os.makedirs(os.path.dirname(os.path.abspath(report)), exist_ok=True)
    with open(report, "a") as out:
        out.write("#### Against the %s\n\n" % where)
        if failed:
            out.write(":x: Slower by more than %.0f%%: %s\n\n" % (threshold, ", ".join(failed)))
        if warned:
            out.write(":warning: Slower by more than %.0f%%, within %.0f%%: %s\n\n" % (warn, threshold, ", ".join(warned)))
        if not failed and not warned:
            out.write(":white_check_mark: No significant slowdown above %.0f%%.\n\n" % warn)
        out.write("<details><summary>benchstat</summary>\n\n```\n" + open(path).read() + "```\n\n</details>\n\n")
if warned:
    msg = "slower than the %s by more than %.0f%% (fails above %.0f%%): %s" % (where, warn, threshold, ", ".join(warned))
    print(("::warning title=Scanner benchmarks::" if gha else "WARN: ") + msg)
if failed:
    msg = "significant slowdown above %.0f%% against the %s: %s" % (threshold, where, ", ".join(failed))
    print(("::error title=Scanner benchmarks::" if gha else "FAIL: ") + msg)
    sys.exit(1)
print("OK: no significant slowdown above %.0f%% against the %s" % (threshold, where))
EOF
