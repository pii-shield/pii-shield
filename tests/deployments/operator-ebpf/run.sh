#!/usr/bin/env bash
#
# The eBPF audit agent end to end in a local kind cluster (#96): a PiiPolicy
# with injectionMode ebpf and auditMode true, a pod whose app prints a
# secret every second, the agent injected as a native sidecar sharing the
# pid namespace. The check: the app's own logs are untouched, and the
# agent's /metrics (port-forwarded) counts lines it would have redacted.
#
# The agent image is built from the repository root (ebpf/Dockerfile) and
# loaded into the cluster, because the kernel of the cluster's node is the
# Docker VM's and the program must load there; EBPF_IMAGE_TAG picks a tag,
# SKIP_IMAGE_BUILD=true reuses one already loaded.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../shared/scripts" && pwd)/common.sh"
repo_root="$(deployment_repo_root)"
namespace="${NAMESPACE:-default}"
image_tag="${EBPF_IMAGE_TAG:-manual-$(date +%Y%m%d%H%M%S)}"
ebpf_image="ghcr.io/pii-shield/pii-shield-ebpf:${image_tag}"

ensure_local_cluster
ensure_operator_installed

if [[ "${SKIP_IMAGE_BUILD:-false}" != "true" ]]; then
  docker build -t "${ebpf_image}" -f "${repo_root}/ebpf/Dockerfile" "${repo_root}"
  load_image_into_current_local_cluster "${ebpf_image}"
fi

# Point the operator at the agent image. The chart value is the clean way
# (sidecar.ebpfImage.tag); a manual run sets the env var on the deployment.
kubectl set env deployment/pii-shield-operator -n operator-system "EBPF_AGENT_IMAGE=${ebpf_image}"
kubectl rollout status deployment/pii-shield-operator -n operator-system --timeout=120s

kubectl label namespace "${namespace}" pii-shield.io/injection=enabled --overwrite
kubectl apply -n "${namespace}" -f - <<'YAML'
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: ebpf-policy
spec:
  injectionMode: ebpf
  auditMode: true
  sensitiveKeys: [password, token, geheim]
  # A tight CPU limit slows the agent's start and the program load by
  # several seconds. Without the startup probe the app then writes its first
  # line before the attach and the check below fails (0 of 5 runs counted
  # it on 2026-10-30); with the probe the app waits (5 of 5).
  resources:
    limits: { cpu: 20m, memory: 128Mi }
    requests: { cpu: 20m, memory: 64Mi }
YAML

# ebpf without auditMode must not even be admitted.
if kubectl apply -n "${namespace}" -f - <<'YAML' 2>/dev/null
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: ebpf-policy-no-audit
spec:
  injectionMode: ebpf
YAML
then
  echo "FAIL: a PiiPolicy with injectionMode ebpf and no auditMode was accepted" >&2
  kubectl delete piipolicy ebpf-policy-no-audit -n "${namespace}" --ignore-not-found
  exit 1
fi
echo "OK: ebpf without auditMode is rejected by the API server"

wait_for_webhook_injection_ready "${namespace}" ebpf-policy

kubectl delete pod pii-ebpf-test -n "${namespace}" --ignore-not-found --wait
kubectl apply -n "${namespace}" -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: pii-ebpf-test
  labels:
    pii-shield.io/inject: "true"
  annotations:
    pii-shield.io/policy: ebpf-policy
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: busybox:1.36
    # The secret is the very first line and never repeats: counting it
    # proves the agent was attached before the app wrote anything.
    command: ["sh", "-c", "echo \"boot password=hunter2hunter2 user=anna\"; i=0; while [ $i -lt 90 ]; do echo \"GET /health 200 $i\"; i=$((i+1)); sleep 1; done"]
YAML

kubectl wait --for=condition=Ready pod/pii-ebpf-test -n "${namespace}" --timeout=120s

injected_image="$(kubectl get pod pii-ebpf-test -n "${namespace}" -o jsonpath='{.spec.initContainers[?(@.name=="pii-shield-sidecar")].image}')"
grep -q "pii-shield-ebpf" <<<"${injected_image}" \
  || { echo "FAIL: the eBPF agent was not injected" >&2; kubectl describe pod pii-ebpf-test -n "${namespace}"; exit 1; }
echo "OK: agent injected"

# The agent may be slow to attach under its CPU limit; give it a minute.
for _ in $(seq 1 120); do
  agent_log="$(kubectl logs pii-ebpf-test -n "${namespace}" -c pii-shield-sidecar 2>/dev/null || true)"
  grep -q "watching stdout and stderr" <<<"${agent_log}" && break
  sleep 0.5
done
agent_log="$(kubectl logs pii-ebpf-test -n "${namespace}" -c pii-shield-sidecar)"
tail -5 <<<"${agent_log}"
grep -q "watching stdout and stderr" <<<"${agent_log}" \
  || { echo "FAIL: the agent did not start watching within a minute (kernel without BTF, or capabilities missing?)" >&2; exit 1; }
sleep 2

# The app's logs must be exactly what it printed.
# Read the logs first: with pipefail, `kubectl logs | grep -q` fails when
# grep exits on the first match before kubectl has written everything.
app_log="$(kubectl logs pii-ebpf-test -n "${namespace}" -c app)"
grep -q "password=hunter2hunter2" <<<"${app_log}" \
  || { echo "FAIL: the app's own logs changed or are missing" >&2; exit 1; }
echo "OK: the app's logs are untouched"

# The agent's counters, through a port-forward (the image has no shell).
kubectl port-forward pod/pii-ebpf-test -n "${namespace}" 19097:9090 >/dev/null 2>&1 &
pf=$!
trap 'kill "${pf}" 2>/dev/null || true' EXIT
metrics=""
for _ in $(seq 1 40); do
  metrics="$(curl -fsS http://127.0.0.1:19097/metrics 2>/dev/null || true)"
  if grep -Eq 'piishield_audit_lines_total\{result="would_redact"\} [1-9]' <<<"$metrics"; then break; fi
  sleep 0.5
done
grep -E 'piishield_audit_(lines_total|mode)|piishield_ebpf_' <<<"$metrics" || true
grep -Eq 'piishield_audit_lines_total\{result="would_redact"\} 1$' <<<"$metrics" \
  || { echo "FAIL: the agent did not count the app's first line (the only secret); the startup probe should hold the app until the program is attached" >&2; exit 1; }
echo "OK: the app's first line was counted, so the app started after the attach"
grep -Eq 'piishield_audit_lines_total\{result="clean"\} [1-9]' <<<"$metrics" \
  || { echo "FAIL: the agent counted no clean line" >&2; exit 1; }
if grep -Eq 'piishield_redaction_events_total\{[^}]*\} [1-9]' <<<"$metrics"; then
  echo "FAIL: redaction_events_total moved; the agent must only observe" >&2
  exit 1
fi
echo "OK: the agent counts what it would have redacted and redacts nothing"
kill "${pf}" 2>/dev/null || true

# Fail open: the same pod as the webhook rendered it, but the agent without
# its added capabilities, so the program cannot load. The agent must not
# crash, the startup probe must pass, the app must start, and the agent
# must say it is not attached.
kubectl delete pod pii-ebpf-noload -n "${namespace}" --ignore-not-found --wait
kubectl get pod pii-ebpf-test -n "${namespace}" -o json | python3 -c '
import json, sys
p = json.load(sys.stdin)
spec = p["spec"]
spec.pop("nodeName", None)
for c in spec["initContainers"]:
    if c["name"] == "pii-shield-sidecar":
        c["securityContext"]["capabilities"] = {"drop": ["ALL"]}
for c in spec["initContainers"] + spec["containers"]:
    c["volumeMounts"] = [m for m in c.get("volumeMounts", []) if not m["name"].startswith("kube-api-access")]
spec["volumes"] = [v for v in spec.get("volumes", []) if not v["name"].startswith("kube-api-access")]
print(json.dumps({"apiVersion": "v1", "kind": "Pod",
                  "metadata": {"name": "pii-ebpf-noload", "labels": {"app": "pii-ebpf-noload"}}, "spec": spec}))
' | kubectl apply -n "${namespace}" -f -
kubectl wait --for=condition=Ready pod/pii-ebpf-noload -n "${namespace}" --timeout=90s \
  || { echo "FAIL: without capabilities the pod did not start; the agent must fail open" >&2; kubectl describe pod pii-ebpf-noload -n "${namespace}"; exit 1; }
restarts="$(kubectl get pod pii-ebpf-noload -n "${namespace}" -o jsonpath='{.status.initContainerStatuses[?(@.name=="pii-shield-sidecar")].restartCount}')"
[[ "${restarts}" == "0" ]] || { echo "FAIL: the agent restarted ${restarts} times instead of failing open" >&2; exit 1; }
noload_log="$(kubectl logs pii-ebpf-noload -n "${namespace}" -c pii-shield-sidecar)"
grep -q "eBPF program not loaded" <<<"${noload_log}" \
  || { echo "FAIL: the agent did not log why the program is not loaded" >&2; exit 1; }
kubectl port-forward pod/pii-ebpf-noload -n "${namespace}" 19098:9090 >/dev/null 2>&1 &
pf=$!
noload=""
for _ in $(seq 1 40); do
  noload="$(curl -fsS http://127.0.0.1:19098/metrics 2>/dev/null || true)"
  grep -q '^piishield_ebpf_attached' <<<"$noload" && break
  sleep 0.5
done
grep -q '^piishield_ebpf_attached 0' <<<"$noload" \
  || { echo "FAIL: the agent without capabilities does not report piishield_ebpf_attached 0" >&2; exit 1; }
kubectl delete pod pii-ebpf-noload -n "${namespace}" --wait=false
echo "OK: without capabilities the agent fails open: the pod starts, piishield_ebpf_attached 0"
echo "eBPF audit agent end to end: ok"
