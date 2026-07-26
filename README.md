# dsa-signal

## OIDC outage activation

Build, then use `npm --prefix backend run activate:oidc` with candidate state,
cookie, signing, client-secret descriptors and expected floor/sequence/head.
This is a migration-owner operation during a traffic-blocked outage, never a
runtime or rolling-deployment action. It requires migration-owner credentials,
a mandatory independent shared floor-head anchor update, and preserves shared
OIDC key identities/material and historical secret purposes. The exact owner-only procedure is in
`docs/runbooks/oidc-restore.md`.

Membership-gated encrypted communications app built on a private Matrix E2EE
substrate, with `dsa-proto` providing identity and organizational authority.

> This project is not affiliated or interoperable with Signal. Matrix E2EE protects message content, not service-visible account, room, device, timing, IP, or access metadata. The web client remains vulnerable to a compromised application origin.

## Quick start

```bash
make verify
```

## Local Matrix topology

Task 7's separate digest-pinned local Synapse/MAS/Caddy Compose topology and
commands are documented in [the Matrix local runbook](docs/runbooks/matrix-local.md).
Run `make matrix-policy` for its rendered policy contract and `make
matrix-negative` for the expensive live transport-isolation rehearsal. The full
profile requires real external Task 3--6 control-plane configuration and
secrets; tracked `deploy/local/example.env` is intentionally non-runnable.

The image-lock contract has six entries. Synapse, MAS, PostgreSQL, and Caddy
are runtime Compose images; Node and Nginx are build-only bases supplied as
required Docker build arguments. Node `24.18.0-alpine3.24` and Nginx
`1.29.8-alpine3.23` have exact operator-approved Docker Official Image
exceptions dated 2026-07-23, not index-level Cosign verification. A registry
base-image lock is not future BuildKit application-image provenance, attestation,
or platform/config identity chain. Root Compose commands must use both
`--env-file deploy/locks/images.env` and `--env-file .env.example` (or the
operator's configured `.env`) so runtime and build images bind to the locks.

### Task 8 browser gate

`make matrix-oauth-browser` is deliberately outside `make verify`. It is fixed
to `https://chat.localhost:8443` and creates an owner-only temporary fixture.
The locked Matrix/MAS/Synapse/web/gateway/Postgres topology is live, but its
production API/control plane is replaced only with metadata/CORS/DCR fixture
responses. It neither issues tokens nor claims login; it returns
`PASS_LOCAL_CALLBACK_PENDING_LIVE_LOGIN`. Task 9 owns the full-login gate.

### Task 9 evidence gates

`make task9-local` runs offline contract, storage-boundary, and scanner checks and
reports only `PASS_LOCAL_TASK9_PENDING_G2`. `make g2-encrypted-direct-chat` is an
external prerequisite gate: without two distinct entitled accounts and authorized
wire, database, log, and media access it reports
`PENDING_EXTERNAL_G2_MISSING_TWO_ENTITLED_ACCOUNTS` and fails the target; it never
treats mocks as G2. Supplying prerequisites runs only the isolated G2 Playwright
project, but it remains fail-closed until a strict external evidence artifact is
available. Prerequisites explicitly authorize each distinct account's entitlement
and wire-capture, PostgreSQL, logs, and media access.

The root `docker-compose.yml` starts PostgreSQL only as local infrastructure; it
does not provision the separated control-plane roles or run the migration.
Task 7's local Compose topology does provision its fresh-volume roles and runs
its one-shot migration. Before treating the root-stack API as
operational, create separate `migration_owner`, `control_plane_runtime`,
`control_plane_retention`, and `control_plane_revocation` login roles, then run `pnpm --filter '*api' build` and
`pnpm --filter '*api' migrate` with the migration-only variables from
`.env.example`. The runner applies the SQL, ledger checksum, grants, and catalog
assertions together; do not execute the SQL file directly. Replace every
key placeholder in `.env` with a distinct canonical 32-byte base64url value. The
runtime URL username must equal `CONTROL_PLANE_RUNTIME_ROLE`; `postgres` is the
container hostname (not `localhost`) for URLs used by the API container. Compose
passes an explicit runtime-only environment allowlist: the API receives its
runtime credential plus the retention and revocation role names only, never
migration-owner, retention, or revocation credentials.

### OIDC runtime secrets

The API image runs as the built-in `node` user (UID/GID `1000`). Create the three
host secret files as regular files owned by `1000:1000` and mode `0600` before
starting Compose (the loader rejects symlinks, other owners, and group/other-readable files):

```bash
install -d -m 0700 secrets
install -m 0600 -o 1000 -g 1000 /dev/null secrets/mas-client-secret
install -m 0600 -o 1000 -g 1000 /dev/null secrets/oidc-cookie-keys.json
install -m 0600 -o 1000 -g 1000 /dev/null secrets/oidc-signing-jwks.json
node -e "process.stdout.write(require('node:crypto').randomBytes(16).toString('base64url') + '\\n')" # OIDC_EPOCH
```

Schedule the retention-only cleanup described in
[`docs/runbooks/control-plane-retention.md`](docs/runbooks/control-plane-retention.md);
never place migration, retention, or revocation credentials in the API environment.

### Migration 0003 deployment

Deploy 0003 as an outage: stop old verification writers, drain the 60-second
idempotency window, run the migration runner, and then deploy the new binary.
The old binary cannot roll back after 0003 because the new columns are `NOT
NULL`. Run the migration/catalog gate immediately before API startup.

### Migration 0004 deployment

Migration 0004 is outage-only. Stop and fence every writer, drain at least 930
seconds, run the migration runner so it validates frozen 0003 before applying
0004 and exact 0004 afterward, then bootstrap a fresh active policy before
starting the API. Runtime write transactions take a shared maintenance lock;
migration and isolated restore take the exclusive lock. Do not use a rolling
deployment or roll back after any 0004-era row, token, or provider cookie has
been issued.

See the [policy refresh runbook](docs/runbooks/policy-refresh.md). Policy and
mapping erasure is deferred to the later privacy/operational-hardening task;
do not invent direct deletion procedures before product deletion inputs exist.

## Open Pilot

This repository preserves the Open Pilot issue and PR templates.

## License

GPL-3.0-only. See `LICENSE`.
