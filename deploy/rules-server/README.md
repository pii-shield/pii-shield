# Rule server on one machine

A ready setup for running the [rule server](../../docs/rules-server.md) on
one small machine with Docker:

- `rules`: the server, SQLite in a Docker volume.
- `caddy`: HTTPS in front of it, with a certificate it gets and renews by
  itself.
- `litestream`: copies the database to an S3-compatible bucket as it
  changes, a few seconds behind.
- `restore`: on a machine whose volume is empty, brings the database back
  from the bucket before the server starts.

It is how the hosted copy is meant to run, and it suits a self-hosted copy
just as well. For more than one server process, see
[Several instances](#several-instances).

## What you need

- A machine with Docker and Docker Compose: 1 vCPU, 1 GB of memory, 10 GB
  of disk is plenty. The server uses about 20 MB of memory.
- A domain name for it, such as `rules.example.com`, with an `A` (and, for
  IPv6, `AAAA`) record pointing at the machine.
- Ports 80 and 443 open to the internet. Caddy needs 80 to get the
  certificate and to redirect to HTTPS.
- An SMTP account for the sign-in links (any provider; port 587 with
  STARTTLS or 465).
- A bucket in any S3-compatible storage (Cloudflare R2, AWS S3, Backblaze
  B2, MinIO) and a key that can read and write it. Nothing else should
  write there.

## Start

```bash
git clone https://github.com/pii-shield/pii-shield.git
cd pii-shield/deploy/rules-server
cp .env.example .env
chmod 600 .env
$EDITOR .env          # the domain, SMTP, the bucket; see the comments
docker compose up -d
docker compose logs -f rules caddy
```

When Caddy has the certificate, `https://<your domain>/healthz` answers
`ok`.

## The first organization

`.env.example` starts with `RULES_SIGNUP=invite`: only invited addresses can
sign in. To let yourself in, set `RULES_ADMIN_TOKEN` in `.env`
(`openssl rand -hex 24`), run `docker compose up -d` again, and:

```bash
H="Authorization: Bearer <the admin token>"; B=https://rules.example.com
curl -X POST -H "$H" $B/api/orgs -d '{"slug": "acme", "name": "ACME"}'
curl -X POST -H "$H" $B/api/orgs/acme/members -d '{"email": "you@acme.com"}'
```

The second call mails you a sign-in link. From then on, invite people from
the panel's Members page. Empty `RULES_ADMIN_TOKEN` again when you no longer
need it. With `RULES_SIGNUP=open`, any address that signs in gets an
organization of its own.

## Backups

Litestream writes every change to the bucket a few seconds after it
happens, and keeps snapshots there. The machine itself holds nothing that
cannot be rebuilt: the database comes back from the bucket, the
certificate from Let's Encrypt.

Test the restore before you need it, on the same machine or a new one:

```bash
docker compose down
docker volume rm pii-shield-rules_data      # the local database is gone
docker compose up -d                        # restore brings it back
```

Sign in: your organizations, rule sets, tokens and the activity log are
there again, and clusters keep pulling with the same tokens.
`docker compose ps -a` shows `restore` as exited with code 0; it prints
nothing when it succeeds.

What a restore can lose: the changes of the last few seconds before the
machine died. A cluster never loses rules either way: it keeps its last
good copy while the server is away.

## Upgrade

Change the version in `RULES_IMAGE` in `.env`, then:

```bash
docker compose pull rules && docker compose up -d rules
```

The server applies its schema changes when it starts. Read the release
notes of the version first. The Caddy and Litestream images are pinned by
digest in `compose.yaml`; update them on purpose, one at a time.

## Watch it

- `https://<your domain>/healthz` answers `ok`; point an uptime check at it.
- `docker compose logs rules`: sign-ins, publications, tokens issued and
  revoked. The panel's Activity page has the same, per organization.
- `docker compose logs litestream`: an error here means the copies stopped;
  fix it before anything else.

## Security notes

- `.env` holds the SMTP password, the bucket key and the admin token. Keep
  it readable by root only, out of any repository, and out of backups that
  others read.
- The server is reachable through Caddy only; its own port is not published
  on the host.
- Signed publications protect clusters even from a server that is taken
  over: register signing keys and list them in the policies
  ([Signed publications](../../docs/rules-server.md#signed-publications)).
- The machine's firewall should allow 22 (or your SSH port), 80 and 443,
  and nothing else.

## Several instances

SQLite serves one process. For several, behind one load balancer, use
Postgres instead: drop the `restore` and `litestream` services, set
`RULES_DB` of the `rules` service to a `postgres://` URL, and back the
database up with your Postgres tools. What the instances share and what
they do not is in
[Several instances](../../docs/rules-server.md#several-instances).
