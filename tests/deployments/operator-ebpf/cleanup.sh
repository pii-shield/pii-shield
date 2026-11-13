#!/usr/bin/env bash
set -euo pipefail

namespace="${NAMESPACE:-default}"
kubectl delete pod pii-ebpf-test -n "${namespace}" --ignore-not-found
kubectl delete piipolicy ebpf-policy -n "${namespace}" --ignore-not-found

# run.sh points the operator at the locally built agent image with
# `kubectl set env`, which makes kubectl the owner of that field. Left in
# place, the next path's `helm upgrade` of the same release stops with a
# server-side apply conflict on EBPF_AGENT_IMAGE. Removing the variable
# drops that ownership, and the chart sets its own value again.
if kubectl get deployment pii-shield-operator -n operator-system >/dev/null 2>&1; then
  kubectl set env deployment/pii-shield-operator -n operator-system EBPF_AGENT_IMAGE-
  kubectl rollout status deployment/pii-shield-operator -n operator-system --timeout=120s
fi
