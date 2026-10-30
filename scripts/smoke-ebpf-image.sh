#!/usr/bin/env bash
#
# Smoke test of the eBPF audit agent image: the image answers --help, and
# the binary it ships loads its program into this kernel and counts what a
# shell prints (scripts/smoke-ebpf-agent.sh). The image is distroless, so
# the binary is copied out of it and run on the host, which needs root
# (or CAP_BPF and CAP_PERFMON) and a kernel of 5.8 or newer with BTF.
#
#   scripts/smoke-ebpf-image.sh <image>
#
set -euo pipefail

image="${1:?usage: $0 <image>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

docker run --rm "$image" --help 2>&1 | grep -q -- '--exec' || {
  echo "the image does not answer --help with the agent's usage" >&2
  exit 1
}
echo "✓ image runs and prints its usage"

id="$(docker create "$image")"
docker cp "$id:/pii-shield-ebpf" "$work/pii-shield-ebpf"
docker rm "$id" >/dev/null
chmod +x "$work/pii-shield-ebpf"
echo "✓ binary copied out of the image ($(stat -c %s "$work/pii-shield-ebpf" 2>/dev/null || stat -f %z "$work/pii-shield-ebpf") bytes)"

"$here/smoke-ebpf-agent.sh" "$work/pii-shield-ebpf"
echo "eBPF audit agent image smoke: ok"
