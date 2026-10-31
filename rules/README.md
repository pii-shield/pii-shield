# PII-Shield rule server

The rule server keeps rule sets for the operator's `spec.remoteConfig`
(#36): a security team publishes a version here, and every cluster whose
`PiiPolicy` names the set pulls it with a read-only token, without a pod
restart. Nothing about a cluster is sent here; the server only answers
`GET`. One binary serves the hosted service and a self-hosted copy inside
your own perimeter.

Status: first version (milestone 3.0, #95). The model, the store on
SQLite or Postgres,
the public `policy.json` with ETag and tokens, a management API, a validate
and a preview call that run a draft on the real scanner, a panel with a
magic-link sign-in, and the image `ghcr.io/pii-shield/pii-shield-rules`.
This file is for developing it; running it is described in
[docs/rules-server.md](../docs/rules-server.md).

## Run

```bash
cd rules
go build -o rules-server ./cmd/rules-server
RULES_ADMIN_TOKEN=$(openssl rand -hex 24) ./rules-server --listen :8080 --db rules.db
```

Flags and env: `--listen` (`RULES_LISTEN`, default `:8080`), `--db`
(`RULES_DB`, default `rules.db`, one SQLite file in WAL mode: back it up
with `sqlite3 .backup` or Litestream; or a `postgres://` URL that several
processes share), `--policy-rate` (pulls per token per
second, default 1, burst 10), `--single-tenant` (`RULES_SINGLE_TENANT=true`:
one organization named `default`, no sign-in, for a server that sits
behind a port-forward or your own access control), `--base-url`
(`RULES_BASE_URL`, the public address for the links in mail and their only
source, never the request's `Host`; required with SMTP, otherwise
`http://localhost:<port>`), `--signup`
(`RULES_SIGNUP=open|invite`, default open: a new address creates its own
organization by signing in; `invite` lets only invited addresses in),
`--trust-proxy` (`RULES_TRUST_PROXY=true`, read the client address from
`X-Forwarded-For` behind a reverse
proxy), `--insecure-cookies` (`RULES_INSECURE_COOKIES=true`, session cookie
without `Secure`, for plain http on localhost). Mail: `RULES_SMTP_ADDR`
(host:port; 465 is TLS at once, any other port starts clear and upgrades
with STARTTLS, required when a password is set), `RULES_SMTP_USER`,
`RULES_SMTP_PASSWORD`, `RULES_MAIL_FROM`. Without `RULES_SMTP_ADDR` the
sign-in links are written to the log with a warning: fine on your laptop,
not for a server other people reach. `RULES_ADMIN_TOKEN` opens every
organization to `curl` with `Authorization: Bearer <token>`; it is optional
once people sign in through the panel.

Put TLS in front of it (a reverse proxy or an ingress): the operator refuses
an `http://` source unless `allowInsecure` is set, and the session cookie
carries `Secure`.

## Panel and sign-in

Open the server's address in a browser. The panel is one page embedded in
the binary (`internal/panel`: `index.html`, `app.js`, `style.css`, no build
step, no package manager) and talks to the same API `curl` does.

There are no passwords. You enter your address, a link arrives by mail,
and the page it opens has one button that signs you in; the link works
once and for a quarter of an hour, and a mail scanner that opens it spends
nothing, because only the button does. The first sign-in of a new address
creates an organization for it (unless `RULES_SIGNUP=invite`); members are
added on the Members page by address and get the same kind of link. An
account belongs to one organization and sees nothing of the others.

The session is a cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, thirty
days, stored hashed like the tokens). Every call that changes something
must carry the `X-Requested-With` header and an `Origin` or `Referer` of
this host, which a cross-site form cannot do; a request without them is
`403`. Sign-in requests are limited per client address and per e-mail
address, link attempts per client address (`429` with `Retry-After`).

Screens: the rule sets of the organization; a set's rules (keys, key
patterns, custom and safe rules with a Validate button, thresholds), the
preview of a draft or the published version on pasted log lines, versions
with publish, roll back, a diff of two versions and the publish history,
tokens, and the `PiiPolicy` snippet that connects a cluster. A draft is
kept while you switch tabs and until you save it as a version.

On a `--single-tenant` server without `RULES_ADMIN_TOKEN` the panel needs
no sign-in; with the token set, the panel is closed and the API takes the
token.

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

Signed publications: `POST /api/orgs/{org}/signing-keys` registers a
public key (`{"name", "publicKey": "ed25519:<base64>"}`; `internal/signing`
defines the statement and the key id); from the first key on, `publish`
needs `publication`, `keyId` and `signature`, the Ed25519 signature of the
`text` from `GET .../publish/statement?revision=N`, checked inside the
publish transaction against the stored file. `GET /v1/{org}/{set}/policy.json.sig`
serves it to the cluster. The operator's check is
`operator/internal/remoterules/signature.go`; the two must stay in step.
The panel keeps its key as a non-extractable WebCrypto key in IndexedDB.
Described for users in [docs/rules-server.md](../docs/rules-server.md#signed-publications).

Activity log: `internal/store/audit.go` (append-only, triggers refuse
`UPDATE` and `DELETE`), written by `Server.audit` after each change in
`internal/server`; `GET /api/orgs/{org}/audit?limit=&before=`. A token keeps
its last pull (`last_used_at`, `last_used_ip`, written at most once a
minute) instead of an entry per pull.

Stats reports: a token has a kind, `pull` (`psr_`, reads `policy.json`
and `.sig`) or `report` (`pss_`, only `POST /v1/{org}/{set}/report`); each
is refused on the other's path with `403`. A report is the operator's
`pii-shield-stats-v1` JSON (`operator/internal/stats.Report`), checked and
stored in `reports` (`internal/store/reports.go`, kept 90 days);
`GET .../clusters?hours=` summarizes them per token, cluster and policy for
the panel's Clusters tab.

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
# the same store and server tests on Postgres: each test gets its own
# database on this server and drops it afterwards
RULES_TEST_POSTGRES='postgres://postgres:…@127.0.0.1:5432/postgres?sslmode=disable' go test -race ./internal/store/... ./internal/server/...
```

The store writes its queries once, with `?` placeholders and nothing only
one database has; `internal/store/db.go` rewrites the placeholders and the
schema for Postgres, ids come back with `RETURNING`, and a transaction
that numbers a set's versions or publications locks the set's row first
(`FOR UPDATE` on Postgres; SQLite's single connection already serializes
them).

The module depends on the root module (`replace … => ../`) for
`pkg/scanner`, so the image is built from the repository root:

```bash
docker build -t pii-shield-rules:dev -f rules/Dockerfile .
scripts/smoke-rules-server.sh pii-shield-rules:dev
```

The smoke script is what CI and the release workflow run: the container
starts single-tenant, serves the panel, takes a rule set through the API and
serves it as `policy.json` to a token with an ETag and a `304`.
