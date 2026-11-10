# dsa-signal

dsa-signal is a members-only encrypted chat app for an organization. Members
sign in with their AT Protocol identity, prove their membership with a signed
credential, and chat in a private Matrix server with end-to-end encryption in
the browser. Identity and membership authority come from a separate service,
`dsa-proto`.

It is in development. Encrypted one-to-one chat is the first goal, and it has
not yet been tested end to end with real member accounts. Do not rely on it
for sensitive conversations.

> This project is not affiliated or interoperable with Signal. Matrix E2EE protects message content, not service-visible account, room, device, timing, IP, or access metadata. The web client remains vulnerable to a compromised application origin.

## Features

- **Membership-gated sign-in.** The control plane exchanges a one-time identity
  handoff for an AT Protocol DID (`did:plc` or `did:web`), then checks a signed
  membership credential against a cached issuer policy.
- **OpenID Connect provider** for Matrix Authentication Service (MAS). Matrix
  sees a pairwise identifier, never the member's DID.
- **Private Matrix server.** Synapse with federation, guest access, public room
  discovery, open registration, password login, URL previews, remote media and
  identity-server lookup turned off. Rooms are invite-only and encrypted.
- **Browser encryption.** The React web app uses `matrix-js-sdk` with its
  Rust/WebAssembly crypto. It requires encryption before it syncs or sends, and
  verifies devices with short authentication strings (emoji comparison).
- **Encrypted direct chat** between two members.
- **Access revocation (partial).** Revoking a member suspends their
  control-plane mapping, entitlement and sessions. It does not yet remove them
  from Matrix rooms, end their MAS session or rotate room keys, so a revoked
  member can still reach conversations their devices already joined.
- **Retention cleanup** for control-plane records, run on a schedule the
  operator sets up.
- The control plane never receives Matrix tokens, messages, room state,
  attachments or recovery keys.

## Quick start

You need Node.js 24, pnpm 10 and Docker with Buildx and Compose.

```sh
make verify
```

This installs dependencies and runs formatting, lint, tests (including a
PostgreSQL integration suite), offline security contract and plaintext scanner
checks, the API and web builds, both Docker images, the Compose check and the
Matrix policy check. `make help` lists the other targets.

The full local stack (Synapse, MAS, PostgreSQL, the web app and a Caddy
gateway on `https://chat.localhost:8443`) is in `deploy/local/compose.yaml`.
[docs/runbooks/matrix-local.md](docs/runbooks/matrix-local.md) explains how to
set it up and run it. `make matrix-negative` runs a live check that the
disabled Matrix surfaces stay closed.

## Configuration

Copy `.env.example` to `.env`. Every key and secret placeholder must be
replaced with a distinct value. The settings are:

- **Database:** `POSTGRES_*`, `DATABASE_URL` (runtime role) and
  `MIGRATION_DATABASE_URL` (migration owner), with separate
  `CONTROL_PLANE_RUNTIME_ROLE`, `CONTROL_PLANE_RETENTION_ROLE` and
  `CONTROL_PLANE_REVOCATION_ROLE` login roles.
- **URLs:** `PUBLIC_BASE_URL`, `PWA_ORIGIN`, `FOUNDATION_BASE_URL`, `PORT`.
- **OIDC and MAS:** `OIDC_SECTOR`, `OIDC_EPOCH`, `OIDC_TRUSTED_PROXY_ADDRESS`,
  `MAS_CLIENT_ID`, `MAS_REDIRECT_URI`, and the paths to the MAS client secret,
  signing keys and cookie keys (`MAS_CLIENT_SECRET_PATH`,
  `OIDC_SIGNING_JWKS_PATH`, `OIDC_COOKIE_KEYS_PATH`).
- **Key rings:** `COOKIE_KEY` and the `*_KEY_RING` variables.
- **Membership authority:** `ROOT_DIDS`, `ROOT_PUBLIC_JWKS`,
  `AUTHORITY_POLICY_VERSION`, `POLICY_MAX_STALENESS_SECONDS`.

Secret files must be regular files owned by the API user (UID/GID 1000) with
mode `0600`. Never give migration, retention or revocation credentials to the
API.

## Deploy

The API and web app build as Docker images (`backend/Dockerfile` and
`web/Dockerfile`, the web image served by nginx). Base and runtime images are
pinned by digest in `deploy/locks/images.env`; pass it to Compose with
`--env-file deploy/locks/images.env` alongside your `.env`.

The root `docker-compose.yml` runs PostgreSQL, the API and the web app. It does
not create the database roles or run migrations: create the roles, then run
`pnpm --filter '*api' build` and `pnpm --filter '*api' migrate` with the
migration variables. Some migrations must run with the API stopped; read
`docs/runbooks/` before upgrading a running deployment.

## Project layout

- `backend/`: Node control plane (identity handoff, entitlements, OIDC
  provider, revocation)
- `web/`: React web app with the Matrix client
- `migrations/`: PostgreSQL migrations
- `deploy/`: local Matrix topology, gateway, Synapse and MAS configuration,
  image locks
- `patches/`: a patch to `matrix-js-sdk`
- `scripts/`: policy, security and test scripts
- `docs/`: design decisions, protocol contracts and procedures

## Contributing

Report bugs and request features in
[GitHub issues](https://github.com/subculture-collective/dsa-signal/issues).
For security problems, see [SECURITY.md](SECURITY.md).

Send code as a pull request on GitHub against `main`. CI runs `make verify` on
every pull request. [CONTRIBUTING.md](CONTRIBUTING.md) has the commit style.

## License

GPL-3.0-only. See [LICENSE](LICENSE).

Built by [SUBCULT](https://subcult.tv).
