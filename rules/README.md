# PII-Shield rule server

The rule server keeps rule sets for the operator's `spec.remoteConfig`
(#36): a security team publishes a version here, and every cluster whose
`PiiPolicy` names the set pulls it with a read-only token, without a pod
restart. Nothing about a cluster is sent here; the server only answers
`GET`. One binary serves the hosted service and a self-hosted copy inside
your own perimeter.

Status: slices 1 and 2 of #95 (milestone 3.0). The model, the SQLite
store, the public `policy.json` with ETag and tokens, a management API
behind an admin token, and a validate and a preview call that run a draft
on the real scanner. The panel and the magic-link login come in later
changes; until then the management API is driven with `curl`.

## Run

```bash
cd rules
go build -o rules-server ./cmd/rules-server
RULES_ADMIN_TOKEN=$(openssl rand -hex 24) ./rules-server --listen :8080 --db rules.db
```

Flags and env: `--listen` (`RULES_LISTEN`, default `:8080`), `--db`
(`RULES_DB`, default `rules.db`, one SQLite file in WAL mode: back it up by
copying the file or with Litestream), `--policy-rate` (pulls per token per
second, default 1, burst 10), `--single-tenant` (`RULES_SINGLE_TENANT=true`:
one organization named `default`, no admin token, for a server that sits
behind a port-forward or your own access control). Without
`--single-tenant`, `RULES_ADMIN_TOKEN` is required and every `/api/` request
carries it as `Authorization: Bearer <token>`.

Put TLS in front of it (a reverse proxy or an ingress): the operator refuses
an `http://` source unless `allowInsecure` is set.

## Publish a rule set

```bash
H="Authorization: Bearer $RULES_ADMIN_TOKEN"; B=https://rules.example.internal
curl -X POST -H "$H" $B/api/orgs -d '{"slug": "acme", "name": "ACME"}'
curl -X POST -H "$H" $B/api/orgs/acme/sets -d '{"slug": "payments"}'
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/versions \
  -d '{"content": {"sensitive_keys": ["password", "token", "geheim"],
                   "custom_regexes": [{"name": "tx", "pattern": "^TX-\\d{6}$"}]},
       "author": "alice", "comment": "add the transaction id"}'
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/publish -d '{"revision": 1, "author": "alice"}'
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/tokens -d '{"name": "prod-eu cluster"}'
```

`content` is the rule set in the SDK `init_config` format, the same JSON
the sidecar reads from `PII_CONFIG_FILE`: `entropy_threshold`,
`confidence_score`, `min_secret_length`, `sensitive_keys`,
`sensitive_key_patterns`, `custom_regexes`, `safe_regexes`,
`disable_bigram_check`, `adaptive_threshold`, `entity_type_labels`. It is
validated whole with the scanner's own parser (`scanner.ParsePolicyJSON`),
so a set the server accepts is a set every sidecar accepts; a `salt` or
`fail_policy` is refused, they are settings of the pod. Versions are
immutable and numbered from 1; `revision` in the served file is that
number. Publishing an older revision is the rollback. The token value is
shown once in the response; only its hash is stored.

Other calls: `GET /api/orgs`, `GET /api/orgs/{org}/sets`,
`GET /api/orgs/{org}/sets/{set}` (set, versions, tokens, the policy path),
`GET .../versions`, `GET .../versions/{rev}`, `GET .../publications`
(publish history), `GET .../tokens`, `DELETE .../tokens/{id}` (revoke).

## Try a draft before publishing

```bash
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/validate \
  -d '{"content": {"sensitive_keys": ["geheim"]}}'
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/preview \
  -d '{"content": {"sensitive_keys": ["geheim"]},
       "text": "login ok geheim=abcabcabc user=anna\nGET /health 200\n"}'
```

`validate` runs the checks of a version create without storing anything:
the same `422` with the scanner's reason, or `200` with the effective
settings after defaults (`entropyThreshold`, `minSecretLength`, the counts
of keys and rules), so the author sees what a cluster will run, not only
what the draft spells out.

`preview` scans up to 200 log lines (`lines`, an array, or `text`, split on
newlines) with the draft and answers each line as `in`, `out` and
`changed`, plus the count of changed lines. Without `content` it runs the
published version and names its `revision`. Every preview runs on a
scanner built for that request alone (`scanner.NewScanner`), so two
previews never see each other's rules. The hashes are computed with a
fixed preview salt and match no cluster; the response says so in `note`.
`adaptive_threshold` is off in a preview: it learns from a running stream.

## Connect a cluster

```yaml
apiVersion: v1
kind: Secret
metadata: { name: rules-token, namespace: payments }
stringData:
  authorization: "Bearer psr_…"        # the token value from the call above
---
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata: { name: default, namespace: payments }
spec:
  injectionMode: file
  saltSecretKeyRef: { name: pii-shield-salt, key: salt }
  remoteConfig:
    url: https://rules.example.internal/v1/acme/payments/policy.json
    intervalSeconds: 300
    headerSecretRef: { name: rules-token, key: authorization }
```

The operator pulls `GET /v1/{org}/{set}/policy.json` with the token and
`If-None-Match`; the server answers `200` with the file, `ETag` and
`Cache-Control: no-cache`, or `304` when nothing changed. A missing, wrong
or revoked token is `401`; a token used on another set's path is `404`; a
set with nothing published is `404`. Pulls are rate-limited per token
(`429` with `Retry-After`). `GET /healthz` answers `ok`.

## Develop

```bash
cd rules && go test -race ./...
```

The module depends on the root module (`replace … => ../`) for
`pkg/scanner`, so a Docker build needs the repository root as its context.
