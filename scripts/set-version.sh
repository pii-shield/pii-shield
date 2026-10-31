#!/usr/bin/env bash
#
# Single source of truth for the release version lives in the repo-root VERSION
# file. This script stamps that version into every file that hard-codes it, so
# the version is edited in exactly one place.
#
#   scripts/set-version.sh           # stamp VERSION into all files
#   scripts/set-version.sh --check   # verify files match VERSION (CI guard); non-zero exit on drift
#
# When adding a new file that carries the version, add it to FILES and to the
# transform() case below. The --check job in CI will then enforce it forever.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CHECK=false
if [[ "${1:-}" == "--check" ]]; then
  CHECK=true
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "✗ VERSION file does not contain a valid semver: '${VERSION}'" >&2
  exit 1
fi

# Files that hard-code the release version, relative to repo root.
FILES=(
  charts/pii-shield/Chart.yaml
  charts/pii-shield-operator/Chart.yaml
  charts/pii-shield/values.yaml
  sdks/node/package.json
  sdks/python/pyproject.toml
  README.md
  docs/application-readiness.md
  docs/rules-server.md
  deploy/rules-server/compose.yaml
  deploy/rules-server/.env.example
  tests/deployments/docker-ghcr/README.md
)

# Emit the file with VERSION stamped in. Patterns are anchored so only the
# intended fields change (e.g. the image tag, not the unrelated `tag: latest`).
transform() {
  local file="$1"
  case "$file" in
    */charts/*/Chart.yaml)
      sed -E \
        -e "s|^version: .*|version: ${VERSION}|" \
        -e "s|^appVersion: .*|appVersion: \"${VERSION}\"|" \
        "$file" ;;
    */charts/pii-shield/values.yaml)
      # Only the 2-space-indented image tag whose value looks like a version.
      sed -E "s|^(  tag: )\"[0-9][^\"]*\"|\1\"${VERSION}\"|" "$file" ;;
    */sdks/node/package.json)
      # Top-level "version" key (2-space indent), not nested dependency versions.
      sed -E "s|^(  \"version\": )\"[^\"]*\"|\1\"${VERSION}\"|" "$file" ;;
    */sdks/python/pyproject.toml)
      # [project] version, anchored at column 0 (dependency pins are indented).
      sed -E "s|^version = \"[^\"]*\"|version = \"${VERSION}\"|" "$file" ;;
    */docs/application-readiness.md|*/tests/deployments/docker-ghcr/README.md)
      # Docker image tags in usage examples (thelisdeep/pii-shield:X.Y.Z,
      # ghcr.io/pii-shield/pii-shield:X.Y.Z).
      sed -E "s|(pii-shield):[0-9][0-9A-Za-z.-]*|\1:${VERSION}|g" "$file" ;;
    */docs/rules-server.md|*/deploy/rules-server/compose.yaml|*/deploy/rules-server/.env.example)
      # The rule server image tag: the docker run example, and the deploy
      # kit's default RULES_IMAGE.
      sed -E "s|(pii-shield-rules):[0-9][0-9A-Za-z.-]*|\1:${VERSION}|g" "$file" ;;
    */README.md)
      sed -E \
        -e "s|release-v[0-9][0-9A-Za-z.-]*-blue|release-v${VERSION}-blue|g" \
        -e "s|releases/tag/v[0-9][0-9A-Za-z.-]*|releases/tag/v${VERSION}|g" \
        -e "s|(pii-shield):[0-9][0-9A-Za-z.-]*|\1:${VERSION}|g" \
        "$file" ;;
    *)
      echo "✗ no transform rule for ${file}" >&2
      return 1 ;;
  esac
}

fail=0
for rel in "${FILES[@]}"; do
  file="$ROOT/$rel"
  if [[ ! -f "$file" ]]; then
    echo "✗ missing file: ${rel}" >&2
    fail=1
    continue
  fi
  tmp="$(mktemp)"
  transform "$file" > "$tmp"
  if "$CHECK"; then
    if ! diff -q "$file" "$tmp" >/dev/null; then
      echo "✗ ${rel} is out of sync with VERSION=${VERSION}"
      diff -u "$file" "$tmp" | sed 's/^/    /' || true
      fail=1
    fi
    rm -f "$tmp"
  else
    if diff -q "$file" "$tmp" >/dev/null; then
      rm -f "$tmp"
    else
      cat "$tmp" > "$file"
      rm -f "$tmp"
      echo "✓ updated ${rel} -> ${VERSION}"
    fi
  fi
done

if [[ "$fail" -ne 0 ]]; then
  if "$CHECK"; then
    echo "" >&2
    echo "Version drift detected. Run 'scripts/set-version.sh' and commit the result." >&2
  fi
  exit 1
fi

if "$CHECK"; then
  echo "✓ all files match VERSION=${VERSION}"
fi
