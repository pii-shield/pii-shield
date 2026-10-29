#!/usr/bin/env bash
#
# Smoke test of the rule server image: the container starts single-tenant,
# serves the panel, accepts a rule set through the management API and serves
# it as policy.json to a token, with an ETag and a 304. Used by CI and the
# release workflow after `docker build -f rules/Dockerfile .`.
#
#   scripts/smoke-rules-server.sh <image>
#
set -euo pipefail

image="${1:?usage: $0 <image>}"
port="${RULES_SMOKE_PORT:-18080}"
name="rules-smoke-$$"
base="http://127.0.0.1:${port}"

docker run -d --rm --name "$name" -p "127.0.0.1:${port}:8080" "$image" \
  --single-tenant --insecure-cookies >/dev/null
cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "--- container log" >&2
    docker logs "$name" >&2 || true
  fi
  docker stop "$name" >/dev/null 2>&1 || true
  rm -f "${headers:-}"
}
trap cleanup EXIT

for _ in $(seq 1 50); do
  curl -fsS "$base/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "$base/healthz" | grep -q '^ok$'
echo "✓ healthz"

curl -fsS "$base/" | grep -q '<title>PII-Shield rules</title>'
curl -fsS "$base/app.js" | grep -q 'X-Requested-With'
echo "✓ panel HTML and script served"

curl -fsS -X POST "$base/api/orgs/default/sets" -d '{"slug": "smoke"}' >/dev/null
curl -fsS -X POST "$base/api/orgs/default/sets/smoke/versions" \
  -d '{"content": {"sensitive_keys": ["geheim"], "custom_regexes": [{"name": "tx", "pattern": "^TX-\\d{6}$"}]}, "author": "ci"}' >/dev/null
curl -fsS -X POST "$base/api/orgs/default/sets/smoke/publish" -d '{"revision": 1, "author": "ci"}' >/dev/null
token="$(curl -fsS -X POST "$base/api/orgs/default/sets/smoke/tokens" -d '{"name": "ci"}' \
  | sed -n 's/.*"value": *"\([^"]*\)".*/\1/p' | tr -d "[:space:]")"
[[ -n "$token" ]]
echo "✓ rule set published, token issued"

headers="$(mktemp)"
body="$(curl -fsS -D "$headers" -H "Authorization: Bearer $token" "$base/v1/default/smoke/policy.json")"
grep -Eq '"revision": *"1"' <<<"$body"
grep -q '"geheim"' <<<"$body"
etag="$(sed -n 's/^[Ee][Tt][Aa][Gg]: *//p' "$headers" | tr -d '\r')"
[[ -n "$etag" ]]
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" -H "If-None-Match: $etag" "$base/v1/default/smoke/policy.json")"
[[ "$code" == "304" ]]
code="$(curl -s -o /dev/null -w '%{http_code}' "$base/v1/default/smoke/policy.json")"
[[ "$code" == "401" ]]
echo "✓ policy.json: 200 with ETag ${etag}, 304 on If-None-Match, 401 without a token"

curl -fsS -X POST "$base/api/orgs/default/sets/smoke/preview" \
  -d '{"text": "login geheim=abcabcabc id=TX-123456\nGET /health 200"}' | grep -Eq '"changed": *1'
echo "✓ preview runs the published rules on the scanner"

echo "rule server image smoke: ok"
