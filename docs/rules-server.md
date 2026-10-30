# Rule server

The rule server keeps the rule sets of your clusters in one place. A
security team edits a set in the browser, sees on the real scanner what a
draft does to pasted log lines, publishes a version, and every cluster whose
`PiiPolicy` names the set pulls it with a read-only token, without a pod
restart. Nothing about a cluster is sent to the server: the operator only
asks for a file, and the server only answers `GET`. The same binary serves
the hosted copy and a self-hosted copy inside your own perimeter; this page
is about running your own.

This is the first version (milestone 3.0, issue #95). What it does not do
yet is listed at the end; the one line to know before relying on it: the
served file is protected by HTTPS and the token, not by a signature of its
content.

## Run it

The image is `ghcr.io/pii-shield/pii-shield-rules` (the same tags as the
other images, from the 3.0 release on; `latest` follows the newest release).
It is a distroless image with one static binary, running as user 65532, and
it keeps one SQLite file in `/data`.

```bash
docker run -d --name pii-shield-rules \
  -p 127.0.0.1:8080:8080 \
  -v pii-shield-rules:/data \
  -e RULES_ADMIN_TOKEN="$(openssl rand -hex 24)" \
  ghcr.io/pii-shield/pii-shield-rules:2.3.1 --single-tenant
```

That is the smallest useful server: one organization named `default`, no
sign-in, the management API open to the admin token, the panel on
`http://127.0.0.1:8080/`. With `--single-tenant` and no `RULES_ADMIN_TOKEN`
the panel and the API are open to anyone who reaches the address, which is
fine behind a port-forward and wrong anywhere else; the server says so in
its log. A named volume as above works as it is; a bind mount must be
writable by uid 65532.

To build the image from the repository instead, build from the root, not
from `rules/`, because the rules module takes `pkg/scanner` from the root
module:

```bash
docker build -t pii-shield-rules -f rules/Dockerfile .
```

Or build the binary with Go and run it with the same flags:

```bash
cd rules && go build -o rules-server ./cmd/rules-server && ./rules-server --single-tenant
```

### Flags and environment

Every flag has an environment variable; the flag wins when both are set.

| Flag | Env | Default | What it does |
| --- | --- | --- | --- |
| `--listen` | `RULES_LISTEN` | `:8080` | Address to listen on. |
| `--db` | `RULES_DB` | `rules.db` (`/data/rules.db` in the image) | The SQLite file, WAL mode. |
| `--single-tenant` | `RULES_SINGLE_TENANT=true` | off | One organization `default`, no sign-in; for a server behind your own access control. |
| `--policy-rate` | | `1` | `policy.json` pulls allowed per token per second (burst 10). |
| `--base-url` | `RULES_BASE_URL` | required with SMTP; otherwise `http://localhost:<port>` from `--listen` | Public address of the server (`https://rules.example.com`), the only source of the sign-in links. They are never built from the request's `Host` header, which a client chooses: a forged `Host` would otherwise mail a real sign-in token inside a link to another site. With `RULES_SMTP_ADDR` set and no base URL the server refuses to start. |
| `--signup` | `RULES_SIGNUP=open\|invite` | `open` | `open`: a new address creates its own organization by signing in. `invite`: only invited addresses can sign in. |
| `--trust-proxy` | `RULES_TRUST_PROXY=true` | off | Read the client address from `X-Forwarded-For`. Only behind a proxy you control, because the rate limits key on that address. |
| `--insecure-cookies` | `RULES_INSECURE_COOKIES=true` | off | Session cookie without `Secure`, for plain http on localhost. |
| | `RULES_ADMIN_TOKEN` | unset | A token that opens every organization to `curl` (`Authorization: Bearer …`). Optional once people sign in through the panel. |
| | `RULES_SMTP_ADDR` | unset | `host:port` of the mail server for the sign-in links. Port 465 is TLS at once; any other port starts clear and upgrades with STARTTLS, which is required when a password is set, so a password never crosses the wire in clear. |
| | `RULES_SMTP_USER`, `RULES_SMTP_PASSWORD` | unset | SMTP credentials (PLAIN). |
| | `RULES_MAIL_FROM` | unset | The sender address; required when `RULES_SMTP_ADDR` is set. |

Without `RULES_SMTP_ADDR` a multi-tenant server writes the sign-in links to
its log with a warning instead of mailing them. That is enough for a laptop
and for a self-hosted copy whose log only its operators read; it is not
enough for a server other people sign in to.

### In front of it

Put TLS in front of the server, a reverse proxy or an ingress, and pass the
client address on (`--trust-proxy`) and set the public address (`--base-url`). The operator
refuses an `http://` source unless the policy sets `allowInsecure`, and the
session cookie carries `Secure`, so a plain-http server works only on
localhost with `--insecure-cookies`.

The database is one file in WAL mode. Back it up with SQLite's own copy
(`sqlite3 /data/rules.db ".backup /backup/rules.db"`) or with Litestream;
copying the file while the server runs can miss the write-ahead log. There
is one process and one file; a second instance on the same file is not
supported.

## Organizations, sets, versions, tokens

An organization owns rule sets; a rule set is a line of versions. A version
is immutable: the rule set as JSON, a number from 1, an author, a time and
a comment. One version of a set is published, and that is the file the
clusters get. Rolling back is publishing an older version. A token belongs
to a set, is read-only, and its value is shown once at creation; the server
stores a hash. Revoking a token is immediate.

The rule set is the SDK `init_config` JSON, the same file the sidecar reads
from `PII_CONFIG_FILE` and the operator renders into the policy ConfigMap:
`entropy_threshold`, `confidence_score`, `min_secret_length`,
`sensitive_keys`, `sensitive_key_patterns`, `custom_regexes`,
`safe_regexes`, `disable_bigram_check`, `adaptive_threshold`,
`entity_type_labels`. Every version is validated whole with the scanner's
own parser, so a set the server accepts is a set every sidecar accepts; a
`salt` or a `fail_policy` is refused, they are settings of the pod, not
rules. The served file carries `revision` set to the version number.

## The panel

Open the server's address in a browser. The panel is one page embedded in
the binary (no build step, no package manager) and it talks to the same API
`curl` does. Its screens: the rule sets of the organization; a set's rules
(keys, key patterns, custom and safe rules, thresholds) with a Validate
button; a preview of the draft or of the published version on pasted log
lines, run on the real scanner with a preview salt, so the markers show
what will be hidden while the hashes match no cluster; versions with
publish, roll back, a diff of two versions and the publish history; tokens;
the `PiiPolicy` snippet that connects a cluster; and members.

Sign-in is by magic link; there are no passwords. You enter your address,
a link arrives by mail, and the page it opens has one button that signs you
in. The link works once and for a quarter of an hour, and a mail scanner
that opens it spends nothing, because only the button does. The first
sign-in of a new address creates an organization for it (unless
`RULES_SIGNUP=invite`); members are added on the Members page by address
and get the same kind of link. An account belongs to one organization and
sees nothing of the others. The session is a cookie (`HttpOnly`, `Secure`,
`SameSite=Strict`, thirty days, stored hashed). Every request that changes
something must carry the `X-Requested-With` header and an `Origin` or
`Referer` of this host, which a cross-site form cannot send. Sign-in
requests are limited per client address and per e-mail address, link
attempts per client address; the limits live in the process's memory and
start over with it.

## The API

Everything the panel does is a JSON call under `/api/`, authenticated by
the session cookie, by `RULES_ADMIN_TOKEN` as a bearer token, or by nothing
on an open single-tenant server. The admin token sees every organization; a
session sees its own.

```bash
H="Authorization: Bearer $RULES_ADMIN_TOKEN"; B=https://rules.example.internal
curl -X POST -H "$H" $B/api/orgs -d '{"slug": "acme", "name": "ACME"}'
curl -X POST -H "$H" $B/api/orgs/acme/sets -d '{"slug": "payments"}'
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/validate \
  -d '{"content": {"sensitive_keys": ["password", "token", "geheim"]}}'
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/preview \
  -d '{"content": {"sensitive_keys": ["geheim"]}, "text": "login ok geheim=abcabcabc\nGET /health 200"}'
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/versions \
  -d '{"content": {"sensitive_keys": ["password", "token", "geheim"],
                   "custom_regexes": [{"name": "tx", "pattern": "^TX-\\d{6}$"}]},
       "author": "alice", "comment": "add the transaction id"}'
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/publish -d '{"revision": 1, "author": "alice"}'
curl -X POST -H "$H" $B/api/orgs/acme/sets/payments/tokens -d '{"name": "prod-eu cluster"}'
```

| Call | Answer |
| --- | --- |
| `GET /api/me` | Who you are: the mode (`admin`, `single-tenant`, `session`), address and organization. |
| `GET`, `POST /api/orgs` | Organizations (admin token only; a session sees its own). |
| `GET`, `POST /api/orgs/{org}/members` | Members; `POST` with `{"email": …}` invites one and mails the link. |
| `GET`, `POST /api/orgs/{org}/sets` | Rule sets of the organization. |
| `GET /api/orgs/{org}/sets/{set}` | The set, its versions, tokens and the policy path. |
| `GET`, `POST …/versions`, `GET …/versions/{rev}` | Versions; `POST` validates `content` whole and appends the next number; `422` names the scanner's reason. |
| `POST …/validate` | The checks of a version create without storing; `200` with the effective settings after defaults, or `422`. |
| `POST …/preview` | Up to 200 lines (`lines` or `text`) through the draft in `content`, or the published version without it; each line as `in`, `out`, `changed`. |
| `POST …/publish`, `GET …/publications` | Publish a revision (an older one is the rollback); the publish history. |
| `GET`, `POST …/tokens`, `DELETE …/tokens/{id}` | Tokens; the value is in the `POST` answer once. |
| `GET /healthz` | `ok`. |

A rule set may be up to 256 KiB, the same limit the operator applies to a
pulled file; a preview body may carry another 512 KiB of lines. A malformed
body is `400` with a reason, a missing or wrong token `401`, a set of
another organization `404`, a cross-site change `403`, a rate limit `429`
with `Retry-After`.

## Connect a cluster

Put the token into a Secret in the policy's namespace, as the whole
`Authorization` header value, and name it in `remoteConfig`
(operator `v3.0`+; the field is described in the
[operator README](../operator/README.md#central-rule-repository-remoteconfig)):

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

The operator pulls `GET /v1/{org}/{set}/policy.json` every
`intervalSeconds` with `If-None-Match` set to the ETag of its last good
copy. The server answers `200` with the file, `ETag` and `Cache-Control:
no-cache`, or `304` when nothing changed. A missing, wrong or revoked token
is `401`; a token used on another set's path is `404`; a set with nothing
published is `404`; pulls past `--policy-rate` are `429` with
`Retry-After`. The operator validates the file the way the sidecar does,
lays the policy's own fields over it (a local field always wins), renders
the result into the policy's ConfigMap, and the sidecars reload it. When the
server is unreachable the last good copy stays in use and the policy's
`RemoteSynced` condition says why; the salt never comes from the server.

The panel's Connect tab shows this snippet with the set's own path filled
in. The server learns nothing about the cluster from a pull beyond the
token used and the time; that is what its log records.

## What it does not do yet

- **Sign the file.** HTTPS and the token protect the channel; a server
  that is taken over can serve any rule set to the clusters that trust it.
  A signature of `policy.json` with a server key is the first candidate for
  the next version.
- **Run as more than one instance.** One process, one SQLite file. Postgres
  comes when a second instance is needed.
- **Report anything back.** No redaction analytics, no Slack alerting: they
  need a channel from the agent to a server, and that channel will be
  separate, explicitly enabled and carrying counters only.
- **Sign in any other way.** Magic link by e-mail; no passwords, no OAuth.
- **Keep an audit trail beyond the versions.** Who published what and when
  is in the publish history; sign-ins and token use are in the log only.
- **Serve a hosted copy yet.** The hosted service on a pii-shield.com
  subdomain opens by [waitlist](https://tally.so/r/PdY7Ze).

The code is in [`rules/`](../rules/) with its own README for development.
