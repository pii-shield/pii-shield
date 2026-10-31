#!/usr/bin/env bash
#
# End to end in kind: the operator pulls signed rules from a rule server in
# the cluster, a sidecar applies them, a new signed publication reaches the
# running pod without a restart, an untrusted key is refused, and the stats
# channel reports back to the server.
#
#   tests/deployments/operator-rules-server/run.sh
#
# Builds the operator, agent and rule server images from the working tree,
# creates the kind cluster KIND_CLUSTER (default pii-shield-rules-e2e) if it
# does not exist, and leaves it running for a look; delete it with
#   kind delete cluster --name pii-shield-rules-e2e
# Needs docker, kind, kubectl, helm, openssl (3 or later), jq and curl.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cluster="${KIND_CLUSTER:-pii-shield-rules-e2e}"
tag="e2e-$(date +%Y%m%d%H%M%S)"
operator_image="ghcr.io/pii-shield/pii-shield-operator:${tag}"
agent_image="ghcr.io/pii-shield/pii-shield-agent:${tag}"
rules_image="ghcr.io/pii-shield/pii-shield-rules:${tag}"
admin="e2e-admin-$(openssl rand -hex 8)"
work="$(mktemp -d)"
port=18180
pf_pids=()

cleanup() {
  for p in "${pf_pids[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
# wait_for <seconds> <description> <command...>: retry until the command succeeds.
wait_for() {
  local secs="$1" what="$2"; shift 2
  local end=$((SECONDS + secs))
  until "$@" >/dev/null 2>&1; do
    (( SECONDS < end )) || fail "timed out after ${secs}s waiting for: ${what}"
    sleep 3
  done
  echo "ok: ${what}"
}

step "cluster ${cluster}"
kind get clusters 2>/dev/null | grep -qx "$cluster" || kind create cluster --name "$cluster" --wait 120s
kubectl config use-context "kind-${cluster}" >/dev/null

step "images"
(cd "${repo_root}/operator" && docker build -q -t "$operator_image" . >/dev/null)
docker build -q -t "$agent_image" -f "${repo_root}/Dockerfile.agent" "$repo_root" >/dev/null
docker build -q -t "$rules_image" -f "${repo_root}/rules/Dockerfile" "$repo_root" >/dev/null
for img in "$operator_image" "$agent_image" "$rules_image"; do kind load docker-image "$img" --name "$cluster" >/dev/null; done
echo "built and loaded ${tag}"

step "operator"
helm upgrade --install pii-shield-operator "${repo_root}/charts/pii-shield-operator" -n operator-system --create-namespace \
  --set image.repository="${operator_image%:*}" --set image.tag="$tag" \
  --set sidecar.image.repository="${agent_image%:*}" --set sidecar.image.tag="$tag" \
  --set webhook.useCertManager=false --wait --timeout 180s >/dev/null
kubectl rollout status deployment/pii-shield-operator -n operator-system --timeout=120s

step "rule server"
kubectl create namespace rules --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n rules create secret generic rules-admin --from-literal=token="$admin" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: rules, namespace: rules }
spec:
  replicas: 1
  selector: { matchLabels: { app: rules } }
  template:
    metadata: { labels: { app: rules } }
    spec:
      containers:
      - name: rules
        image: ${rules_image}
        args: ["--single-tenant", "--insecure-cookies"]
        env:
        - { name: RULES_ADMIN_TOKEN, valueFrom: { secretKeyRef: { name: rules-admin, key: token } } }
        ports: [{ containerPort: 8080 }]
        readinessProbe: { httpGet: { path: /healthz, port: 8080 } }
        volumeMounts: [{ name: data, mountPath: /data }]
      volumes: [{ name: data, emptyDir: {} }]
---
apiVersion: v1
kind: Service
metadata: { name: rules, namespace: rules }
spec: { selector: { app: rules }, ports: [{ port: 8080 }] }
EOF
kubectl -n rules rollout status deployment/rules --timeout=120s
kubectl -n rules port-forward svc/rules "${port}:8080" >/dev/null 2>&1 & pf_pids+=($!)
B="http://127.0.0.1:${port}"; H="Authorization: Bearer ${admin}"
wait_for 30 "rule server reachable" curl -sf "$B/healthz"
api() { curl -sf -H "$H" "$@"; }

step "publish signed rules (revision 1: hide 'geheim')"
openssl genpkey -algorithm ed25519 -out "$work/key.pem"
pub="ed25519:$(openssl pkey -in "$work/key.pem" -pubout -outform DER | tail -c 32 | base64)"
openssl genpkey -algorithm ed25519 -out "$work/other.pem"
other="ed25519:$(openssl pkey -in "$work/other.pem" -pubout -outform DER | tail -c 32 | base64)"
api -X POST "$B/api/orgs/default/sets" -d '{"slug": "payments"}' >/dev/null
key_id="$(api -X POST "$B/api/orgs/default/signing-keys" -d "{\"name\": \"e2e\", \"publicKey\": \"$pub\"}" | jq -r .keyId)"
publish() { # publish <revision>: sign the statement and publish
  api "$B/api/orgs/default/sets/payments/publish/statement?revision=$1" > "$work/st.json"
  jq -j .text "$work/st.json" > "$work/st.txt"
  local sig; sig="$(openssl pkeyutl -sign -inkey "$work/key.pem" -rawin -in "$work/st.txt" | base64 | tr -d '\n')"
  api -X POST "$B/api/orgs/default/sets/payments/publish" \
    -d "{\"revision\": $1, \"publication\": $(jq .statement.publication "$work/st.json"), \"keyId\": \"$key_id\", \"signature\": \"$sig\"}" >/dev/null
}
api -X POST "$B/api/orgs/default/sets/payments/versions" -d '{"content": {"sensitive_keys": ["geheim"]}}' >/dev/null
publish 1
pull_token="$(api -X POST "$B/api/orgs/default/sets/payments/tokens" -d '{"name": "kind"}' | jq -r .value)"
report_token="$(api -X POST "$B/api/orgs/default/sets/payments/tokens" -d '{"name": "kind stats", "kind": "report"}' | jq -r .value)"
echo "key ${key_id}, publication 1"

step "policy with signed remote rules and stats"
kubectl create namespace apps --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# The webhook only looks at namespaces that ask for it.
kubectl label namespace apps pii-shield.io/injection=enabled --overwrite >/dev/null
kubectl -n apps create secret generic rules-token --from-literal=authorization="Bearer ${pull_token}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n apps create secret generic rules-stats-token --from-literal=authorization="Bearer ${report_token}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
policy() { # policy <trusted public key>
kubectl apply -f - >/dev/null <<EOF
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata: { name: default, namespace: apps }
spec:
  injectionMode: file
  logPath: /app/logs/log.txt
  salt: "e2e-salt-0123456789abcdef0123456789"
  remoteConfig:
    url: http://rules.rules.svc:8080/v1/default/payments/policy.json
    allowInsecure: true
    intervalSeconds: 30
    headerSecretRef: { name: rules-token, key: authorization }
    signature:
      publicKeys: ["$1"]
  stats:
    url: http://rules.rules.svc:8080/v1/default/payments/report
    allowInsecure: true
    intervalSeconds: 60
    clusterName: kind-e2e
    headerSecretRef: { name: rules-stats-token, key: authorization }
EOF
}
policy "$pub"
synced() { [[ "$(kubectl -n apps get piipolicy default -o jsonpath='{.status.remote.publication}/{.status.remote.signedBy}')" == "$1/${key_id}" ]]; }
wait_for 90 "operator accepted publication 1 signed by ${key_id}" synced 1
kubectl -n apps get configmap pii-shield-policy-default -o jsonpath='{.data.policy\.json}' | grep -q geheim || fail "the rendered policy lacks the remote rule"

step "application with an injected sidecar"
kubectl apply -f - >/dev/null <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: { name: talker, namespace: apps }
spec:
  replicas: 1
  selector: { matchLabels: { app: talker } }
  template:
    metadata: { labels: { app: talker, pii-shield.io/inject: "true" } }
    spec:
      containers:
      - name: app
        image: busybox:1.36
        # Plain words, so only the rules from the server hide them: a
        # random-looking value would be hidden by entropy anyway.
        command: ["sh", "-c", "mkdir -p /app/logs; i=0; while true; do i=$((i+1)); echo \"line=$i geheim=sonnenschein clave=mariposa user=anna\" >> /app/logs/log.txt; sleep 1; done"]
EOF
kubectl -n apps rollout status deployment/talker --timeout=180s
pod="$(kubectl -n apps get pod -l app=talker -o jsonpath='{.items[0].metadata.name}')"
sidecar="$(kubectl -n apps get pod "$pod" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' | tr ' ' '\n' | grep pii-shield | head -1 || true)"
[[ -n "$sidecar" ]] || fail "no sidecar was injected into ${pod}"
logs() { kubectl -n apps logs "$pod" -c "$sidecar" --tail=5 2>/dev/null; }
hides_geheim() { logs | grep -q 'geheim=\[HIDDEN' && ! logs | grep -q 'sonnenschein'; }
wait_for 60 "sidecar hides the value under the remote key 'geheim'" hides_geheim
logs | grep -q 'mariposa' || fail "'clave' must still pass: it is not in revision 1"
echo "sample: $(logs | grep line= | tail -1)"

step "a new signed publication reaches the running pod (revision 2: also 'clave')"
api -X POST "$B/api/orgs/default/sets/payments/versions" -d '{"content": {"sensitive_keys": ["geheim", "clave"]}}' >/dev/null
publish 2
wait_for 90 "operator accepted publication 2" synced 2
hides_clave() { logs | grep -q 'clave=\[HIDDEN' && ! logs | grep -q 'mariposa'; }
wait_for 180 "the running sidecar hides 'clave' too, without a restart" hides_clave
restarts="$(kubectl -n apps get pod "$pod" -o jsonpath='{.status.containerStatuses[*].restartCount} {.status.initContainerStatuses[*].restartCount}')"
[[ "$(echo $restarts | awk '{s=0; for(i=1;i<=NF;i++) s+=$i; print s}')" == 0 ]] || fail "containers restarted: $restarts"

step "stats reach the rule server"
reported() { api "$B/api/orgs/default/sets/payments/clusters" | jq -e '.clusters[] | select(.cluster == "kind-e2e" and .lines > 0 and (.redactions | length) > 0)'; }
wait_for 240 "a report from kind-e2e with lines and hidden values" reported
api "$B/api/orgs/default/sets/payments/clusters" | jq -c '.clusters[] | {cluster, lines, redactions, pods: "\(.latest.podsReporting)/\(.latest.podsTotal)", revisions: .latest.revisions, publication: .latest.remotePublication}'
kubectl -n apps get piipolicy default -o jsonpath='{.status.stats}'; echo

step "an untrusted key is refused"
policy "$other"
refused() { [[ "$(kubectl -n apps get piipolicy default -o jsonpath='{.status.conditions[?(@.type=="RemoteSynced")].reason}')" == SignatureUntrusted ]]; }
wait_for 90 "RemoteSynced is SignatureUntrusted" refused
policy "$pub"
wait_for 90 "trusted again after the key is restored" synced 2

printf '\nALL PASSED. Cluster %s is left running; delete it with: kind delete cluster --name %s\n' "$cluster" "$cluster"
