#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
fixture="$(require_access_log_fixture "${repo_root}")"
output_dir="$(ensure_output_dir wasm-python)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="${PII_PY_IMAGE:-python:3.11-slim}"
prepare_pii_env_args

# Run the Python SDK inside a Linux container, so the result does not depend on the
# host's Python build. Published SDK versions up to 2.2.4 are SIGKILLed (`Killed: 9`) on
# Apple's own /usr/bin/python3: wasmtime's Mach-port trap handler trips a kernel guard
# there (see README.md). Mounts: the fixture (read-only), the redaction script
# (read-only), and the output dir so the sanitized log lands on the host.
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required: this test runs the Python SDK inside a Linux container (host-independent SDK run). See README.md." >&2
  exit 1
fi

docker run --rm \
  ${pii_docker_env_args[@]+"${pii_docker_env_args[@]}"} \
  -v "${fixture}":/fixture:ro \
  -v "${script_dir}/redact.py":/redact.py:ro \
  -v "${output_dir}":/out \
  "${image}" \
  bash -c "pip install -q pii-shield-wasi && python /redact.py /fixture /out/access.sanitized.log"

assert_sanitized_file "${output_dir}/access.sanitized.log"
