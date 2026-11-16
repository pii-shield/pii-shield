#!/usr/bin/env bash
# Fails when the testing documentation and the tree disagree:
#
#   - a script in scripts/ is missing from docs/testing.md or scripts/README.md;
#   - a deployment path (a folder under tests/deployments/ with a run.sh) or an
#     operator `make test*` target is missing from docs/testing.md;
#   - a document names a scripts/*.sh or benchmark/*.sh file that does not
#     exist, which is what a renamed or deleted script leaves behind.
#
# A new test script therefore cannot land without a line that says what it
# proves, and a command in the docs cannot outlive the script it runs.
#
# Usage: scripts/check-test-docs.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

GUIDE="docs/testing.md"
INDEX="scripts/README.md"
DOCS=("${GUIDE}" "${INDEX}" CONTRIBUTING.md MANUAL_TESTING.md README.md tests/deployments/README.md)

problems=0
problem() {
  echo "  - $*" >&2
  problems=$((problems + 1))
}

for f in "${GUIDE}" "${INDEX}"; do
  [ -f "${f}" ] || { echo "${f} is missing" >&2; exit 1; }
done

# 1. Every script is described in the guide and listed in the index.
for path in scripts/*.sh; do
  name="$(basename "${path}")"
  grep -qF "scripts/${name}" "${GUIDE}" || problem "${path} is not mentioned in ${GUIDE}"
  grep -qF "\`${name}" "${INDEX}" || problem "${path} is not listed in ${INDEX}"
done
for path in benchmark/*.sh; do
  grep -qF "${path}" "${GUIDE}" || problem "${path} is not mentioned in ${GUIDE}"
done

# 2. Every deployment path is in the guide.
for run in tests/deployments/*/run.sh; do
  name="$(basename "$(dirname "${run}")")"
  grep -qF "\`${name}\`" "${GUIDE}" || problem "deployment path tests/deployments/${name} is not mentioned in ${GUIDE}"
done

# 3. Every operator test target is in the guide.
while IFS= read -r target; do
  grep -qE "make (-C operator )?${target}( |\$)" "${GUIDE}" || problem "operator target 'make ${target}' is not mentioned in ${GUIDE}"
done < <(grep -oE '^test[a-z0-9-]*:' operator/Makefile | tr -d ':' | sort -u)

# 4. Every script a document names exists. Only paths from the repository
# root count: tests/deployments/shared/scripts/common.sh is not scripts/.
for doc in "${DOCS[@]}"; do
  [ -f "${doc}" ] || continue
  while IFS= read -r ref; do
    [ -f "${ref}" ] || problem "${doc} names ${ref}, which does not exist"
  done < <(grep -oE '(^|[^A-Za-z0-9_./-])(scripts|benchmark)/[A-Za-z0-9_.-]+\.sh' "${doc}" \
             | sed -E 's/^[^sb]*((scripts|benchmark)\/)/\1/' | sort -u)
done
# The index names its scripts without the folder.
while IFS= read -r name; do
  [ -f "scripts/${name}" ] || problem "${INDEX} lists ${name}, which is not in scripts/"
done < <(grep -oE '^\| `[A-Za-z0-9_.-]+\.sh' "${INDEX}" | sed -E 's/^\| `//' | sort -u)

if [ "${problems}" -gt 0 ]; then
  echo "Testing documentation is out of date: ${problems} problem(s). Fix ${GUIDE} and ${INDEX}." >&2
  exit 1
fi
echo "Testing documentation matches the tree."
