# Local Matrix topology (Task 7)

## Purpose and boundary

This runbook operates the digest-pinned local Synapse, Matrix Authentication
Service (MAS), PostgreSQL, and Caddy topology in `deploy/local/compose.yaml`.
Task 7 proves server prerequisites and transport isolation: private-network
placement, delegated authentication wiring, disabled unsafe server surfaces,
and the gateway's route boundary. It **does not** prove Task 8 application room
create/join/send enforcement, nor a direct-federation or remote-media
application path. Do not describe a passing rehearsal as either of those.

The external Task 6 OpenID Foundation gate remains separate and postponed; a
local Task 7 run does not satisfy it.

## Preconditions and inputs

Install Docker Compose and Docker Buildx, and make the loopback names
`chat.localhost`, `auth.localhost`, and `matrix.localhost` resolve locally.
The gateway binds only `127.0.0.1:${MATRIX_HTTPS_PORT:-8443}`. Caddy creates a
local CA; browsers must trust its exported root certificate before using the
HTTPS UI. Ensure the exact locked images are available/pullable for the host
architecture:

```bash
docker compose --env-file deploy/locks/images.env --env-file deploy/local/example.env -f deploy/local/compose.yaml --profile full --profile negative pull
```

That command can fetch images but does not approve them. Use only the immutable
references in `deploy/locks/images.env`, never a tag in Compose.

The full profile also needs the real Task 3--6 control-plane configuration and
secrets: OIDC signing JWKS, cookie keys, restore-floor data/head, MAS upstream
client secret, key rings, Foundation authority material, and real policy
values. The tracked `deploy/local/example.env` is deliberately non-runnable;
copy it outside the repository (or replace it externally) and replace every
placeholder. It is not a safe shortcut to a full startup.

Generated Matrix secret directories and their parent must be owner-only
directories (`0700`), with regular non-symlink input files. Generated files are
`0444`: this is the explicit local Compose compromise allowing different image
UIDs to read individually scoped file secrets inside a `0700` host directory;
it is not host-level secret isolation. The directories and generated files are
ignored. Never print, paste, put in an env file, or retain secret values in
shell history/logs.

## Image lock and provenance gate

Inspect the approved tag-to-digest evidence before use:

```bash
docker buildx imagetools inspect matrixdotorg/synapse:v1.156.0 --raw
node scripts/resolve-image-digests.mjs
git diff -- deploy/locks/images.env deploy/locks/images.provenance.json
```

The resolver interface is exactly `node scripts/resolve-image-digests.mjs`; it
re-resolves every approved tag, validates the index and linux/amd64 and
linux/arm64 children, then atomically writes `deploy/locks/images.env` only if
all agree. It creates `deploy/locks/images.env.lock`. If a guard remains, do
not age-delete it: verify its hostname and process start/PID identity (protect
PID reuse), inspect the target, ensure no resolver runs, remove that exact
guard, and fsync its parent. This is manual recovery only.

For Synapse and MAS, re-run the exact Cosign commands recorded in
`deploy/locks/images.provenance.json` (`images[].signature.command`) and verify
the GitHub Actions issuer and listed identity regex against the resolved index
digest. PostgreSQL and Caddy are Docker Official Images with no documented
index-level Cosign identity here. The repository operator approved the recorded
Docker Official Image exceptions for PostgreSQL `17.10-bookworm` and Caddy
`2.11.4-alpine` on 2026-07-21. This approval is not index-level Cosign
verification. Any future digest update requires fresh operator approval after
reviewing its tag, children, source evidence/signature or exception; do not
reuse this approval. Node `24.18.0-alpine3.24` and Nginx
`1.29.8-alpine3.23` are build-only locks (not runtime Compose image mappings)
with exact Docker Official Image exceptions approved on 2026-07-23. Their
recorded Official Images mapping commits are source evidence, not Cosign
signatures. These registry base locks do not establish future BuildKit
application-image provenance.

## Generate local Matrix secrets

Provide the upstream MAS client secret as a regular, owner-only (`0600` or
stricter), exactly 43-byte unpadded base64url file from the Task 3--6 control
plane. Create it externally; this example only shows the generator invocation.
The output directory must not exist or must be empty.

```bash
install -d -m 0700 secrets
install -m 0600 /secure/operator/mas-upstream-client-secret secrets/upstream-client-secret
node scripts/generate-matrix-local-secrets.mjs --upstream-client-secret secrets/upstream-client-secret --output secrets/matrix-local
```

Expected output is exactly `created Matrix local secrets`. The generator
refuses symlinks, insecure inputs/directories, a non-43-byte secret, existing
files, or a non-empty output; do not delete files merely to bypass that
refusal. It writes the directory `0700` and each generated service file `0444`.
This generator is bootstrap-only for a fresh empty state; never regenerate the
whole directory for rotation. Preserve the MAS encryption key and Synapse
signing identity with restored or existing state unless an explicit supported
migration/overlap procedure says otherwise. Rotate a database password only by
stopping dependent services, changing the selected role and its corresponding
secret/overlay atomically, then restarting. Rotate the upstream client secret
together in the API, MAS, and control-plane registration. Signing rotation
requires documented overlap/tool support; without it, it is unsupported here.
Preserve unrelated material.

## Validate policy and configuration

The policy checker renders both profiles, reads the Compose-bound redacted
fixtures, validates the exact pinned Caddy configurations, and compares the
reviewed topology:

```bash
make matrix-policy
docker compose --env-file deploy/locks/images.env --env-file deploy/local/policy.env -f deploy/local/compose.yaml --profile full --profile negative config --quiet
```

Expected result is exit status 0 (the checker is intentionally quiet). For
real external material, replace `deploy/local/policy.env` with the operator's
external env file in the second command; never use `example.env` as proof that
the full profile is runnable.

The checker image-validates Caddy. The negative rehearsal exercises pinned
Synapse; full startup below validates Synapse's effective mounted configuration
and secrets. To check MAS configuration without starting dependencies, use the
actual full-profile service, its layered configuration and secrets, and a real
external env file:

```bash
docker compose --env-file deploy/locks/images.env --env-file /secure/dsa-signal/matrix-local.env -f deploy/local/compose.yaml --profile full run --rm --no-deps --entrypoint mas-cli mas config check
```

This performs the MAS check; it does not validate Synapse independently. Do
not claim a configuration validation that was not run.

## Negative transport rehearsal

Run the expensive live rehearsal after topology, route, network, or image
changes:

```bash
make matrix-negative
```

Expected output is `Matrix negative validation passed (HTTPS <port>)`. The
negative profile generates temporary secrets, selects a collision-free subnet
trio and loopback port, and always runs `down -v --remove-orphans` then removes
its temporary tree. A Docker network may still collide after discovery; treat a
collision as a failed run and rerun only after resolving the competing network.

Expected fail-closed statuses are gateway `404` for federation, key, admin,
and server well-known; client well-known `200`; guest registration `403
M_FORBIDDEN`; public directory and URL preview `401 M_MISSING_TOKEN`; login
flow `404`; password login `404 M_UNRECOGNIZED`; and direct Synapse federation
`404`. A positive nonce must reach and appear in the canary log. The distinct
Synapse nonce must be unreachable and absent from that log. This proves
transport isolation, not a direct federation/remote-media application path.
Failure diagnostics are best-effort/redacted; do not enable raw secret logging.

## Full startup, readiness, CA, and shutdown

Make an external real env file, then start in the required env-file order:

```bash
docker compose --env-file deploy/locks/images.env --env-file /secure/dsa-signal/matrix-local.env -f deploy/local/compose.yaml --profile full up -d --wait
docker compose --env-file deploy/locks/images.env --env-file /secure/dsa-signal/matrix-local.env -f deploy/local/compose.yaml --profile full ps --all
docker compose --env-file deploy/locks/images.env --env-file /secure/dsa-signal/matrix-local.env -f deploy/local/compose.yaml --profile full cp gateway:/data/caddy/pki/authorities/local/root.crt /tmp/dsa-caddy-root.crt
curl --fail --cacert /tmp/dsa-caddy-root.crt https://chat.localhost:8443/_gateway/health
```

This is a dependency graph, not a total startup sequence: `control-db` gates
`migrate`, which gates `api`; `matrix-db` gates `mas-migrate`; and `synapse`
independently waits for both healthy `matrix-db` and completed
`synapse-data-init`. `gateway` starts independently, then gates
`gateway-ca-export`; MAS waits for its migration, API, Synapse, and that CA
export. `mas-ready` waits for MAS, and web waits for `mas-ready`. The `up --wait`
command waits for those declared health and completion conditions before the CA
copy and curl.

The full profile is fixed to host/public `:8443`: keep `MATRIX_HTTPS_PORT=8443`
for full OAuth unless all public URLs, configuration, and goldens are
intentionally revised and revalidated. Only the negative harness may select a
dynamic host port.

Trust `/tmp/dsa-caddy-root.crt` in the browser/OS trust store using that
platform's administrator procedure; remove it when the local environment is
destroyed. Expected gateway health body is `ok`; `ps --all` shows healthy databases,
API, Synapse, and gateway, a running MAS service, and completed
migration/init/ready jobs.

Browser Matrix login/token traffic goes directly browser -> `auth.localhost`
(MAS) and browser -> `matrix.localhost` (Synapse). Node supplies only the
upstream OIDC endpoints under `https://chat.localhost:8443/oidc` and must never
proxy, receive, log, or store Matrix access/refresh tokens. The stable auth
metadata endpoint is `/_matrix/client/v1/auth_metadata`; do not publish the
legacy `org.matrix.msc2965.authentication` key.

Stop while retaining named volumes, or destroy local data deliberately:

```bash
docker compose --env-file deploy/locks/images.env --env-file /secure/dsa-signal/matrix-local.env -f deploy/local/compose.yaml --profile full down
docker compose --env-file deploy/locks/images.env --env-file /secure/dsa-signal/matrix-local.env -f deploy/local/compose.yaml --profile full down -v --remove-orphans
```

The second command is destructive cleanup/rollback for a fresh local setup.

## Data, backup, rotation, and rollback

`control-db-data` and `matrix-db-data` are separate volumes. The latter holds
separate `synapse` and `mas` databases/roles; `synapse-data` holds Synapse
data/media. Init scripts run only on a fresh PostgreSQL volume. For a credential
rotation on an existing volume, stop dependent services, use an authenticated
owner session to `ALTER ROLE` for the affected role, generate/configure matching
new secret overlays, then restart; changing a secret file does not replay an
init script. Test this procedure from a backup first.

Back up and restore control and Matrix scopes separately. A Matrix restore requires a
quiesced/coordinated snapshot of `matrix-db-data` and `synapse-data`, plus
escrow of the matching Synapse/MAS encryption, signing, and shared material.
Do not restore a control-plane backup into Matrix DB or vice versa. Route every
control-plane/OIDC restore or rollback through
[`docs/runbooks/oidc-restore.md`](oidc-restore.md); do not bypass its
anti-rollback, fresh-key, or floor procedures. Before a Matrix configuration or
digest rollback, stop the profile, restore the prior reviewed lock/config and
the specifically required Matrix state/material, run `make matrix-policy`, then
start and check health. Never roll back a new database credential or signing
state by only reverting Compose.

For a digest update: stop the topology, inspect/re-resolve and verify
provenance as above, obtain fresh operator approval for any Docker Official
Image exception, update the reviewed locks/provenance, run policy
and negative checks, then start. For secret rotation, preserve existing state
and unrelated material. Change only selected database roles and their
corresponding secret/overlays atomically while stopped; coordinate upstream
client-secret changes across API, MAS, and control-plane registration. MAS
encryption and Synapse signing material stay with state. Do not attempt signing
rotation here without documented overlap/tooling support. Verify health/login
and securely remove retired material only after recovery requirements permit it.

For diagnosis, start with `docker compose ... ps` and `docker compose ... logs
--no-color <service>` using the same two env files; redact output before sharing.
Check image availability, hostname/SNI and CA trust, external material paths and
modes, database health/migrations, then gateway/Synapse/MAS health. Do not use
`docker inspect` or env dumps where they expose secrets.
