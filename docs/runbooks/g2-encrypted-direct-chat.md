# External encrypted direct-chat G2 rehearsal

This runbook defines the approved host contract for the remaining Task 9 gate.
It does not make the currently disabled G2 runner executable and does not record
an external verdict.

## Approved first host and destructive boundary

- Run the first rehearsal host-locally on the **NUC** with an interactive headed
  browser.
- Use two newly provisioned, entitled, **disposable** accounts that have never
  bootstrapped Matrix cross-signing.
- Use a fresh generated Compose project. The rehearsal owns that project's
  containers, networks, volumes, and browser profiles.
- After every completed or failed catchable run, destroy the project's server
  volumes before deleting the two browser profiles. Do not preserve or reuse
  either account. Deleting first-bootstrap browser profiles without deleting
  the matching server state can strand the accounts in `recovery-required`.
- A crash, `SIGKILL`, or host loss may leave credentials, crypto keys, or Docker
  resources. A future launcher must retain a poisoned ownership marker and
  refuse another run until an operator completes reviewed recovery. Do not
  delete an unfamiliar lock, profile, volume, network, or container by name.

## Fixed repository-local configuration

The only accepted full-profile env location is:

```text
deploy/local/.env.g2
```

It is covered by the repository's `.env.*` ignore rule and must never be added
to Git. Create it from the tracked shape, then replace every placeholder with
the NUC's existing runnable values:

```bash
install -m 0600 deploy/local/example.env deploy/local/.env.g2
```

Requirements:

- the file is a regular non-symlink owned by the rehearsal operator and mode
  `0600`;
- it contains the exact key set from `deploy/local/example.env`, with no image,
  Docker, Compose, proxy, Node, npm, or pnpm overrides;
- `MATRIX_HTTPS_PORT` remains `8443`, and browser-facing origins remain
  `https://chat.localhost:8443`, `https://auth.localhost:8443`, and
  `https://matrix.localhost:8443` as defined by the locked topology;
- `MATRIX_LOCAL_SECRETS_DIR`, `OIDC_SIGNING_JWKS_SOURCE`,
  `OIDC_COOKIE_KEYS_SOURCE`, and `OIDC_RESTORE_FLOOR_DIR` resolve to the existing
  NUC inputs. Prefer absolute paths for the future launcher contract;
- secret directories remain owner-only (`0700`), secret inputs are regular
  non-symlinks, and no secret value is printed, pasted into commands, or stored
  in browser/evidence output;
- all placeholders described in `docs/runbooks/matrix-local.md` have been
  replaced. The tracked `example.env` is not runnable.

The six registry/base image locks remain sourced only from
`deploy/locks/images.env`. Do not duplicate or override those keys in
`.env.g2`.

## Human responsibilities

The repository-owned browser ceremony will automate only product navigation and
bounded observations. The human operator must:

1. complete real OAuth for each account in its own headed persistent browser;
2. verify that the app's opt-in rehearsal references show the expected account
   before any room is created;
3. compare every SAS emoji and decimal over a separate trusted channel and click
   **They match — confirm** independently in both browsers;
4. never supply credentials, OAuth callback values, access tokens, recovery
   material, private keys, or profile contents to the harness;
5. authorize destructive cleanup of the generated project and both profiles.

The app's Account, Device, Browser profile, Cross-signing identity, and Room
reference values are sensitive linkable metadata, not credentials and not proof
of another person's identity. Reveal them only for the local ceremony and hide
them immediately afterward.

## Evidence prerequisites still required

A real G2 PASS additionally requires all of the following from one run:

- a current approved OpenID Foundation conformance result;
- source/build/rendered-topology and runtime image/container provenance;
- gapless body-only Matrix capture that excludes OAuth, headers, and tokens;
- separate control, Synapse, and MAS PostgreSQL scans;
- complete 12-service logs including one-shot services;
- a read-only, no-network Synapse media-volume scan;
- fresh and restart cumulative scans for canaries A and B, with positive
  controls and zero plaintext matches;
- exact same-profile/account/device/cross-signing/room continuity, fresh human
  SAS, A first-to-second receipt, restart decryption of A without another SAS
  comparison, and B second-to-first receipt.

Task 9 local checks and Task 10 revocation checks do not substitute for this
external evidence.

## Current status

### Pinned SDK divergence

`matrix-js-sdk@42.0.0` and current upstream develop include Done/passive DM
requests in the documented "in progress" finder. The checked-in pnpm patch
excludes them; remove it only after an upstream equivalent and this regression
are adopted.

`make g2-encrypted-direct-chat` remains deliberately fail-closed with
`DISABLED_EXTERNAL_G2_COLLECTORS_UNAVAILABLE` after prerequisite checks. Do not
run the throwing Playwright placeholder directly and do not record
`PASS_EXTERNAL_G2_ENCRYPTED_DIRECT_CHAT`.

The next implementation boundary is a reviewed process-level launcher that owns
the disposable Compose project, browser process group, persistent profiles,
signals, poisoned state, and verified destructive cleanup. Browser automation
must not be enabled before that lifecycle is accepted.
