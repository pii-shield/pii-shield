#!/usr/bin/env bash

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pii-env.sh"

deployment_repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd
}

require_access_log_fixture() {
  local repo_root="$1"
  local fixture="${PII_SHIELD_ACCESS_LOG:-${repo_root}/notes/log_example/access.log}"
  if [[ ! -s "${fixture}" ]]; then
    echo "missing fixture: ${fixture}" >&2
    exit 1
  fi
  printf '%s\n' "${fixture}"
}

# Stream a bounded sample of the access-log fixture to stdout for piping into a
# test container. The fixture is multi-GB (~10M lines); streaming it whole over
# a `kubectl exec` websocket breaks the connection ("broken pipe"/"i/o timeout")
# and makes results non-deterministic. A fixed head is a representative sample
# that streams quickly and reliably. Override the size with FIXTURE_LINES, or
# set FIXTURE_LINES=0 to stream the entire file.
stream_fixture() {
  local fixture="$1"
  local lines="${FIXTURE_LINES:-50000}"
  if [[ "${lines}" -le 0 ]]; then
    cat "${fixture}"
  else
    head -n "${lines}" "${fixture}"
  fi
}

ensure_output_dir() {
  local name="$1"
  local output_dir="${OUTPUT_DIR:-/tmp/pii-shield-sanitized/${name}}"
  mkdir -p "${output_dir}"
  printf '%s\n' "${output_dir}"
}

count_hidden() {
  local file="$1"
  grep -c '\[HIDDEN:' "${file}" || true
}

assert_sanitized_file() {
  local file="$1"
  local min_hidden_count="${MIN_HIDDEN_COUNT:-1}"
  local lines hidden
  lines="$(wc -l < "${file}" | tr -d ' ')"
  hidden="$(count_hidden "${file}")"
  echo "${file}: lines=${lines} hidden=${hidden}"
  if [[ "${lines}" -eq 0 ]]; then
    echo "FAIL: ${file} is empty" >&2
    exit 1
  fi
  if [[ "${hidden}" -lt "${min_hidden_count}" ]]; then
    echo "FAIL: hidden count ${hidden} is below ${min_hidden_count}" >&2
    exit 1
  fi
}

# assert_app_container_silent fails when the application container's own log
# stream carries an access-log line. In file mode the application writes to
# the shared volume and only the sidecar writes to a container stream, so a
# collector that reads container streams must see sanitized lines only; a
# raw line on the app container means the log collector can bypass the
# sidecar. The replay app's own "replay complete" marker is allowed.
assert_app_container_silent() {
  local pod="$1"
  local namespace="${2:-default}"
  local container="${3:-app}"
  local raw
  raw="$(kubectl logs "${pod}" -n "${namespace}" -c "${container}" 2>/dev/null | grep -c -E ' HTTP/[0-9.]+" [0-9]{3} ' || true)"
  echo "${pod}/${container}: raw access-log lines on the container stream=${raw}"
  if [[ "${raw}" -ne 0 ]]; then
    echo "FAIL: ${pod}/${container} writes raw log lines to its own stream; a collector reading container logs bypasses the sidecar" >&2
    kubectl logs "${pod}" -n "${namespace}" -c "${container}" --tail=5 >&2 || true
    exit 1
  fi
}

helm_update_pii_shield_repo() {
  helm repo add pii-shield https://pii-shield.github.io/pii-shield/ >/dev/null
  helm repo update pii-shield
}

install_cert_manager() {
  echo "cert-manager CRDs missing; installing cert-manager..." >&2
  helm repo add jetstack https://charts.jetstack.io >/dev/null
  helm repo update jetstack
  helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace cert-manager \
    --create-namespace \
    --set crds.enabled=true
  kubectl wait --for=condition=Available deployment/cert-manager-webhook \
    -n cert-manager --timeout="${CERT_MANAGER_WAIT_TIMEOUT:-180s}"
}

require_cert_manager_crds() {
  if kubectl get crd certificates.cert-manager.io issuers.cert-manager.io >/dev/null 2>&1; then
    return
  fi

  if [[ "${CERT_MANAGER_AUTO_INSTALL:-true}" == "true" ]]; then
    install_cert_manager
    if kubectl get crd certificates.cert-manager.io issuers.cert-manager.io >/dev/null 2>&1; then
      return
    fi
    echo "cert-manager install completed but CRDs are still missing" >&2
  fi

  cat >&2 <<'EOF'
cert-manager CRDs are required for this deployment path.

Install cert-manager in the current cluster first:

  helm repo add jetstack https://charts.jetstack.io
  helm repo update jetstack
  helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace cert-manager \
    --create-namespace \
    --set crds.enabled=true
  kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=180s
  kubectl get crd certificates.cert-manager.io issuers.cert-manager.io

Then re-run the deployment script.
EOF
  exit 1
}

# Guard for deployment paths that do not install the operator themselves and
# assume it is already running (operator-pipe, operator-ebpf). Without it, the
# first `kubectl apply` of a PiiPolicy fails with a cryptic API error:
#   the server could not find the requested resource (post piipolicies...)
require_operator_installed() {
  if kubectl get crd piipolicies.core.pii-shield.io >/dev/null 2>&1; then
    return
  fi

  cat >&2 <<'EOF'
The PII-Shield operator is not installed in this cluster
(CRD piipolicies.core.pii-shield.io not found).

This deployment path assumes the operator is already running. Install it first
with one of the operator deployment paths, e.g.:

  tests/deployments/operator-kustomize/run.sh
  # or
  tests/deployments/operator-helm-local/chart.sh upgrade

Then re-run this script.
EOF
  exit 1
}

# Make sure the PII-Shield operator is running in the current cluster, installing it if
# it is missing. The pipe and eBPF tests need the operator (its mutating webhook and the
# PiiPolicy CRD) to already be there. Instead of stopping and telling you to install it by
# hand (what require_operator_installed does), this sets it up for you so each test is
# self-contained. Override the chart with OPERATOR_CHART_REF if you need a different one.
ensure_operator_installed() {
  # The PiiPolicy CRD only exists after the operator chart is installed, so we use its
  # presence as the "is the operator already here?" check.
  if kubectl get crd piipolicies.core.pii-shield.io >/dev/null 2>&1; then
    return
  fi

  local repo_root chart
  repo_root="$(deployment_repo_root)"
  chart="${OPERATOR_CHART_REF:-${repo_root}/charts/pii-shield-operator}"

  echo "PII-Shield operator not found in this cluster; installing it from ${chart} ..." >&2

  # Install (or upgrade) the operator from its Helm chart using the chart's default
  # published images, so no local image build is required. webhook.useCertManager=false
  # lets the chart manage its own webhook certificates without needing cert-manager.
  helm upgrade --install pii-shield-operator "${chart}" \
    --namespace operator-system --create-namespace \
    --set webhook.useCertManager=false \
    --wait --timeout "${HELM_TIMEOUT:-180s}"

  # Wait until the operator pod is actually serving before the caller starts creating
  # PiiPolicies and pods that depend on the webhook.
  kubectl rollout status deployment/pii-shield-operator -n operator-system --timeout=120s
}

# Print the agent image the operator will inject, if discoverable. The operator
# deployment name differs by install path (operator-controller-manager for
# kustomize, pii-shield-operator for helm), so scan all deployments in the
# operator namespace for the AGENT_IMAGE env var.
operator_agent_image() {
  kubectl get deploy -n "${OPERATOR_NAMESPACE:-operator-system}" \
    -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*].env[?(@.name=="AGENT_IMAGE")]}{.value}{"\n"}{end}{end}' \
    2>/dev/null | head -1
}

# Pipe mode needs an agent that *follows* the injected FIFO (blocks waiting for a
# writer) instead of exiting on the empty pipe. Released agents through 2.1.0
# exit and crash-loop, so the native-sidecar never stays running and the pod
# never becomes Ready — the readiness wait then times out with no explanation.
# Warn up front (non-blocking) so that timeout is understood when it happens.
warn_pipe_agent_compat() {
  [[ "${PIPE_AGENT_COMPAT_SKIP:-false}" == "true" ]] && return 0
  local img
  img="$(operator_agent_image)"
  [[ -z "${img}" ]] && return 0

  echo "operator injects agent image: ${img}" >&2
  case "${img}" in
    ghcr.io/pii-shield/pii-shield-agent:*)
      cat >&2 <<EOF
WARNING: '${img}' is a published agent image. Released agents through 2.1.0 exit
on the empty pipe FIFO and crash-loop, so pii-pipe-test will not become Ready and
the readiness wait below will time out.

Pipe mode is a dev path: point the operator at a locally built agent first.

  docker build -t pii-shield-agent:manual -f Dockerfile.agent .
  kind load docker-image pii-shield-agent:manual --name "\${KIND_CLUSTER:-pii-shield-manual}"
  kubectl set env deployment -n "${OPERATOR_NAMESPACE:-operator-system}" --all AGENT_IMAGE=pii-shield-agent:manual
  kubectl rollout status deployment -n "${OPERATOR_NAMESPACE:-operator-system}" --timeout=120s

Set PIPE_AGENT_COMPAT_SKIP=true to silence this warning.
EOF
      ;;
  esac
}

# Ensure the local kind cluster behind the current kube-context actually exists,
# recreating it if missing. A common failure mode: the kubeconfig still has a
# `kind-<name>` context but the cluster behind it was deleted (e.g. a Docker
# Desktop reset), so every `kind load`/kubectl call fails with "no nodes found".
# Only acts on kind contexts (or no context at all); minikube/remote are left as
# is. Set ENSURE_CLUSTER_SKIP=true to bypass.
ensure_local_cluster() {
  [[ "${ENSURE_CLUSTER_SKIP:-false}" == "true" ]] && return 0
  local context
  context="$(kubectl config current-context 2>/dev/null || true)"

  # Leave non-kind targets (minikube, real clusters) to the caller.
  if [[ -n "${context}" && "${context}" != kind-* ]]; then
    return 0
  fi

  local cluster="${KIND_CLUSTER:-${context#kind-}}"
  cluster="${cluster:-pii-shield-manual}"

  if kind get clusters 2>/dev/null | grep -qx "${cluster}"; then
    return 0
  fi

  echo "kind cluster '${cluster}' not found; creating it" >&2
  kind create cluster --name "${cluster}" --wait 120s
  kubectl config use-context "kind-${cluster}" >/dev/null 2>&1 || true
}

load_image_into_current_local_cluster() {
  local image="$1"
  local context
  context="$(kubectl config current-context)"

  if [[ "${context}" == kind-* ]]; then
    local cluster="${KIND_CLUSTER:-${context#kind-}}"
    kind load docker-image "${image}" --name "${cluster}"
  elif [[ "${context}" == minikube ]]; then
    minikube image load "${image}"
  else
    echo "current context is ${context}; cannot infer local image load target" >&2
    echo "push ${image} to a registry or switch to kind/minikube" >&2
    exit 1
  fi
}

build_replay_image() {
  local repo_root="$1"
  local image="${REPLAY_IMAGE:-pii-shield-access-log-replay:manual}"
  local fixture
  fixture="$(require_access_log_fixture "${repo_root}")"
  # Stage the build context so the Dockerfile COPYs the resolved fixture
  # (PII_SHIELD_ACCESS_LOG included) instead of a hardcoded repo path, and
  # the docker daemon does not receive the whole repo as context.
  local context
  context="$(mktemp -d)"
  cp "${repo_root}/tests/deployments/shared/replay-image/replay-entrypoint.sh" "${context}/replay-entrypoint.sh"
  cp "${fixture}" "${context}/access.log"
  docker build -f "${repo_root}/tests/deployments/shared/replay-image/Dockerfile" -t "${image}" "${context}"
  rm -rf "${context}"
  echo "built ${image}"
}

load_replay_image() {
  local image="${REPLAY_IMAGE:-pii-shield-access-log-replay:manual}"
  load_image_into_current_local_cluster "${image}"
}

# Wait until the mutating webhook actually injects sidecars. Right after the
# operator is (re)installed its serving cert can lag behind the webhook
# caBundle (the kubelet refreshes the mounted Secret asynchronously), and with
# failurePolicy=ignore pods are then silently created without a sidecar. A
# server-side dry-run of a canary pod is a full end-to-end readiness probe:
# it exercises the API server -> webhook -> TLS -> policy lookup path without
# persisting anything.
wait_for_webhook_injection_ready() {
  local namespace="${1:-default}"
  local policy_name="${2:-access-log-replay-policy}"
  local timeout="${3:-120}"
  local deadline=$((SECONDS + timeout))
  local canary
  canary="$(cat <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: pii-webhook-readiness-canary
  labels:
    pii-shield.io/inject: "true"
  annotations:
    pii-shield.io/policy: ${policy_name}
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "1"]
YAML
)"
  echo "waiting for webhook injection readiness (namespace=${namespace} policy=${policy_name})"
  while true; do
    if printf '%s' "${canary}" | kubectl apply --dry-run=server -n "${namespace}" -f - \
        -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null \
        | grep -q pii-shield-sidecar; then
      echo "webhook injection ready"
      return 0
    fi
    if (( SECONDS >= deadline )); then
      echo "FAIL: webhook did not inject the canary pod within ${timeout}s" >&2
      echo "check operator logs: kubectl logs -n operator-system deploy/pii-shield-operator" >&2
      return 1
    fi
    sleep 3
  done
}

# Remove images built by a deployment test and prune dangling layers so
# repeated runs do not accumulate docker disk usage. Meant for `trap ... EXIT`
# in run.sh scripts; never fails the test itself.
cleanup_docker_images() {
  local image
  for image in "$@"; do
    [[ -n "${image}" ]] && docker image rm -f "${image}" >/dev/null 2>&1 || true
  done
  docker image prune -f >/dev/null 2>&1 || true
  echo "docker cleanup done ($*)"
}

deploy_operator_replay_pods() {
  local namespace="${NAMESPACE:-default}"
  local replicas="${REPLICAS:-4}"
  local image="${REPLAY_IMAGE:-pii-shield-access-log-replay:manual}"
  local policy_name="${POLICY_NAME:-access-log-replay-policy}"
  local app_label="${APP_LABEL:-pii-access-log-replay}"
  local fail_policy
  fail_policy="$(operator_fail_policy)"
  warn_operator_unsupported_pii_env

  kubectl label namespace "${namespace}" pii-shield.io/injection=enabled --overwrite

  # Replay pods use restartPolicy: Never, so a previous run leaves them Completed.
  # kubectl apply treats the identical manifest as unchanged and never recreates
  # them, which makes the readiness wait below time out forever. Delete any
  # leftovers first so each run starts from fresh pods.
  kubectl delete pod -n "${namespace}" -l "app=${app_label}" --ignore-not-found --wait

  kubectl apply -n "${namespace}" -f - <<YAML
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: ${policy_name}
spec:
  injectionMode: file
  logPath: /var/log/app/log.txt
  failPolicy: ${fail_policy}
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 500m
      memory: 256Mi
YAML

  wait_for_webhook_injection_ready "${namespace}" "${policy_name}"

  for i in $(seq 1 "${replicas}"); do
    kubectl apply -n "${namespace}" -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${app_label}-${i}
  labels:
    app: ${app_label}
    pii-shield.io/inject: "true"
  annotations:
    pii-shield.io/policy: ${policy_name}
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: ${image}
    imagePullPolicy: IfNotPresent
    env:
    - name: OUTPUT_FILE
      value: /var/log/app/log.txt
    - name: REPLAY_TO_STDOUT
      value: "false"
    - name: REPLAY_DONE_SLEEP_SECONDS
      value: "3600"
YAML
  done

  kubectl wait --for=condition=ready pod -n "${namespace}" -l "app=${app_label}" --timeout=180s

  for i in $(seq 1 "${replicas}"); do
    local pod="${app_label}-${i}"
    echo "=== ${pod} containers ==="
    kubectl get pod "${pod}" -n "${namespace}" -o jsonpath='{.spec.initContainers[*].name}{"\n"}{.spec.containers[*].name}{"\n"}'
  done
}

collect_operator_replay_logs() {
  local output_name="$1"
  local namespace="${NAMESPACE:-default}"
  local replicas="${REPLICAS:-4}"
  local app_label="${APP_LABEL:-pii-access-log-replay}"
  local output_dir
  output_dir="$(ensure_output_dir "${output_name}")"
  local drain_seconds="${DRAIN_SECONDS:-30}"
  local wait_timeout_seconds="${WAIT_TIMEOUT_SECONDS:-1800}"

  local deadline=$((SECONDS + wait_timeout_seconds))
  for i in $(seq 1 "${replicas}"); do
    local pod="${app_label}-${i}"
    while ! kubectl logs "${pod}" -n "${namespace}" -c app 2>/dev/null | grep -q "replay complete"; do
      if [[ "${SECONDS}" -ge "${deadline}" ]]; then
        echo "FAIL: timed out waiting for ${pod} replay completion" >&2
        kubectl logs "${pod}" -n "${namespace}" -c app --tail=50 || true
        exit 1
      fi
      sleep 5
    done
    echo "${pod}: replay complete"
  done

  sleep "${drain_seconds}"

  for i in $(seq 1 "${replicas}"); do
    local pod="${app_label}-${i}"
    local out="${output_dir}/${pod}.sanitized.log"
    kubectl logs "${pod}" -n "${namespace}" -c pii-shield-sidecar > "${out}"
    assert_sanitized_file "${out}"
    assert_app_container_silent "${pod}" "${namespace}"
  done

  ls -lh "${output_dir}"
}

cleanup_operator_replay() {
  local namespace="${NAMESPACE:-default}"
  local app_label="${APP_LABEL:-pii-access-log-replay}"
  local policy_name="${POLICY_NAME:-access-log-replay-policy}"
  kubectl delete pod -n "${namespace}" -l "app=${app_label}" --ignore-not-found
  kubectl delete piipolicy -n "${namespace}" "${policy_name}" --ignore-not-found
}
