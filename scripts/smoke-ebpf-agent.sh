#!/usr/bin/env bash
#
# Smoke test of the eBPF audit agent on a real kernel: the agent starts a
# shell that prints two lines, one with a secret, and must report one line
# it would have redacted and one clean line, both in /metrics while the
# shell is still alive and in the final summary. Needs root (or CAP_BPF,
# CAP_PERFMON), a kernel of 5.8 or newer with BTF, and is what CI runs on
# the ubuntu runner after building the agent.
#
#   scripts/smoke-ebpf-agent.sh <path to pii-shield-ebpf>
#
set -euo pipefail

agent="${1:?usage: $0 <pii-shield-ebpf binary>}"
port="${EBPF_SMOKE_PORT:-19095}"
log="$(mktemp)"
out="$(mktemp)"
cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "--- agent log" >&2
    cat "$log" >&2 || true
    echo "--- child output" >&2
    cat "$out" >&2 || true
  fi
  rm -f "$log" "$out"
}
trap cleanup EXIT

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "no /sys/kernel/btf/vmlinux: this kernel has no BTF, the agent cannot load" >&2
  exit 1
fi

run_as_root() {
  if [[ $(id -u) -eq 0 ]]; then "$@"; else sudo -E "$@"; fi
}

# stop_agent stops the agent listening on $port. The PID of the background
# job is sudo's when the script is not root, and sudo does not relay a
# signal sent from the command's own process group, which is where this
# script and its kill live, so killing that PID left the agent running
# and holding the port for the next run. Match the agent's command line
# instead ([-] keeps the pattern from matching the pkill command line of
# the sudo that runs it), then wait until the port is free.
stop_agent() {
  run_as_root pkill -TERM -f "[-]-listen 127.0.0.1:${port} " 2>/dev/null || true
  for _ in $(seq 1 40); do
    curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1 || return 0
    sleep 0.25
  done
  echo "the agent on port ${port} did not stop" >&2
  return 1
}

if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
  echo "port ${port} is already served by something (an agent left over from an earlier run?); set EBPF_SMOKE_PORT or stop it" >&2
  exit 1
fi

# The child writes one secret line, one clean line, then waits so the
# metrics can be scraped while the agent still runs.
run_as_root "$agent" --listen "127.0.0.1:${port}" --stats-interval 1h --exec \
  sh -c 'echo "login ok password=hunter2hunter2 user=anna"; echo "GET /health 200"; sleep 3' \
  >"$out" 2>"$log" &
pid=$!

metrics=""
for _ in $(seq 1 40); do
  if metrics="$(curl -fsS "http://127.0.0.1:${port}/metrics" 2>/dev/null)" \
     && grep -q 'piishield_audit_lines_total{result="would_redact"} 1' <<<"$metrics" \
     && grep -q 'piishield_audit_lines_total{result="clean"} 1' <<<"$metrics"; then
    break
  fi
  sleep 0.25
done
grep -q 'piishield_audit_lines_total{result="would_redact"} 1' <<<"$metrics"
grep -q 'piishield_audit_lines_total{result="clean"} 1' <<<"$metrics"
grep -q 'piishield_audit_mode 1' <<<"$metrics"
grep -Eq 'piishield_audit_findings_total\{type="(entropy|signature|regex|luhn)"\} [1-9]' <<<"$metrics"
if grep -Eq 'piishield_redaction_events_total\{[^}]*\} [1-9]' <<<"$metrics"; then
  echo "redaction_events_total moved in audit mode" >&2
  exit 1
fi
echo "✓ /metrics: 1 line would be redacted, 1 clean, findings by type, no redaction events"

wait "$pid"
grep -q 'password=hunter2hunter2' "$out"
echo "✓ the child's output reached stdout unchanged"
grep -q 'PII-Shield audit: .* in 1 of 2 lines (50.0%)' "$log"
echo "✓ final summary: 1 of 2 lines"

# The pod's case: no --exec, the agent watches every process of its pid
# namespace. This shell is one of them, so its own lines are counted; on a
# host namespace other processes may add to the counts, hence "at least".
: >"$log"
run_as_root "$agent" --listen "127.0.0.1:${port}" --stats-interval 1h >"$out" 2>"$log" &
pid=$!
for _ in $(seq 1 40); do
  curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1 && grep -q "watching stdout and stderr of every process" "$log" && break
  sleep 0.25
done
echo "namespace mode: password=hunter2hunter2 token=abcDEF123456"
echo "namespace mode: GET /health 200"
ok=0
for _ in $(seq 1 40); do
  metrics="$(curl -fsS "http://127.0.0.1:${port}/metrics" 2>/dev/null || true)"
  would="$(sed -n 's/^piishield_audit_lines_total{result="would_redact"} //p' <<<"$metrics")"
  clean="$(sed -n 's/^piishield_audit_lines_total{result="clean"} //p' <<<"$metrics")"
  if [[ -n "$would" && -n "$clean" ]] && (( ${would%%.*} >= 1 && ${clean%%.*} >= 1 )); then ok=1; break; fi
  sleep 0.25
done
stop_agent
wait "$pid" || true
if (( ok == 0 )); then
  echo "namespace mode: the agent did not count this shell's lines" >&2
  exit 1
fi
echo "✓ namespace mode: this shell's lines were counted (would_redact ${would}, clean ${clean})"
echo "eBPF audit agent smoke: ok"
