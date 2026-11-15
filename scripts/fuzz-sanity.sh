#!/bin/bash
# Runs every Go fuzz target in the repository for a short time each.
#
# `go test -fuzz` accepts one target in one package per run, so a plain
# `go test ./... -fuzz=Fuzz` stops with an error as soon as a second target
# exists. This script finds the targets and runs them one after another; a
# new FuzzXxx function is picked up without editing anything here or in CI.
#
# Usage: scripts/fuzz-sanity.sh [name-filter]
#   FUZZTIME=15s   time per target (any value `go test -fuzztime` accepts)
#   name-filter    run only the targets whose name contains this text
#
# A failing input is written to <package>/testdata/fuzz/<Target>/; commit it
# with the fix so it stays a regression test.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZTIME="${FUZZTIME:-15s}"
FILTER="${1:-}"

# One Go module per directory; a target is run from its own module.
MODULES=(. operator rules)

total=0
failed=()
for module in "${MODULES[@]}"; do
  cd "${ROOT_DIR}/${module}"
  # The root module must not descend into the modules nested in it.
  nested=(--exclude-dir=.cache)
  if [ "${module}" = "." ]; then
    nested=(--exclude-dir=operator --exclude-dir=rules)
  fi
  # "<file>:func FuzzXxx(" for every target of the module.
  while IFS= read -r hit; do
    [ -n "${hit}" ] || continue
    file="${hit%%:*}"
    name="${hit#*:func }"
    name="${name%%(*}"
    if [ -n "${FILTER}" ] && [[ "${name}" != *"${FILTER}"* ]]; then
      continue
    fi
    pkg="./$(dirname "${file}")"
    total=$((total + 1))
    echo "==> ${module}/${pkg#./} ${name} (${FUZZTIME})"
    if ! go test "${pkg}" -run '^$' -fuzz "^${name}\$" -fuzztime "${FUZZTIME}"; then
      failed+=("${module}/${pkg#./} ${name}")
    fi
  done < <(grep -rEn --include='*_test.go' '^func Fuzz[A-Za-z0-9_]*\(' . \
             --exclude-dir=.claude --exclude-dir=.git --exclude-dir=node_modules \
             "${nested[@]}" 2>/dev/null \
           | sed -E 's/^\.\/([^:]+):[0-9]+:/\1:/' | sort)
done

if [ "${total}" -eq 0 ]; then
  echo "No fuzz target matched '${FILTER}'." >&2
  exit 2
fi
if [ "${#failed[@]}" -gt 0 ]; then
  echo
  echo "Fuzz targets that failed (${#failed[@]} of ${total}):" >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
echo
echo "All ${total} fuzz targets passed."
