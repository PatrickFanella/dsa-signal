# Membership-Gated E2EE Chat Implementation Plan

> **For agentic workers:** Execute this plan task-by-task. Recommended path:
> dispatch a fresh subagent per task, review each result with `review-quality`,
> then continue. For complex multi-agent splits, use
> `parallel-feature-development`, `team-composition-patterns`, and
> `team-communication-protocols`. Steps use checkbox (`- [ ]`) syntax for
> tracking.

**Goal:** Turn `dsa-signal` into a web/PWA-first, membership-gated encrypted communications app that uses `dsa-proto` for ATProto identity and organizational authority while keeping membership evidence private.

**Architecture:** Use a hardened, non-federating Matrix deployment (Synapse, Matrix Authentication Service, and PostgreSQL) as the message transport and established E2EE substrate. The React PWA talks directly to MAS, Synapse, and media endpoints and initializes `matrix-js-sdk` Rust/WASM crypto; the Node service only handles `dsa-proto` identity handoff, private membership-entitlement proof, issuer policy, and standards-compliant upstream OIDC. Deliver a production-gated encrypted 1:1 vertical slice before groups, media, broader messaging UX, or experimental calls.

**Tech Stack:** Node 24, TypeScript 5.9, React 19, Vite 7, PostgreSQL 17, `@dsaslate/foundation-client` 0.2.0, JOSE/WebCrypto, a maintained OpenID Provider implementation, Synapse, MAS, `matrix-js-sdk` Rust crypto, Vitest, Playwright, Docker Compose; later Element Call, LiveKit, and MatrixRTC.

---

## Non-negotiable security contract

1. “E2EE” means message and attachment plaintext exists only on participating clients. `dsa-signal`, Synapse, MAS, PostgreSQL, media storage, logs, metrics, backups, and push infrastructure must not receive plaintext or private room keys.
2. Matrix E2EE does **not** hide account, room, membership, device, IP, timing, event-size, push, or media-access metadata. Operators can infer a social graph. Product owners must accept this limitation before production.
3. A compromised web origin can ship JavaScript that steals client keys. The PWA therefore cannot claim the operator-compromise resistance of a reproducibly built, signed native client.
4. Removing a member prevents future authorization and future-key access after rotation; it cannot erase plaintext or keys already downloaded by that member.
5. The service has no plaintext fallback. Unencrypted rooms and unencrypted sends fail closed.
6. `dsa-proto` never stores membership/entitlement credentials, downstream Matrix credentials, rosters, chat metadata, or messages. It may retain its own encrypted ATProto session credentials while supplying authenticated DID identity, public organizational records, and authority provenance.
7. The Node control plane never receives or proxies Matrix access/refresh tokens, Matrix message events, room state, attachment bytes, recovery keys, or cross-signing secrets.
8. Calls are excluded from the initial security boundary and may ship only after a separate MatrixRTC/LiveKit review.

## Delivery gates and roadmap

| Gate | Deliverable | Release rule |
| --- | --- | --- |
| G0 | Threat/privacy contract and architecture ADR | Product, security, API, data, and operations reviewers accept it |
| G1 | Cross-repository identity and authority contracts | `dsa-proto` 0.2.0 contract tests and both repositories’ `make verify` pass |
| G2 | Production-gated vertical prototype | Two verified browser devices exchange only ciphertext through Matrix; revocation blocks future access |
| G3 | Private beta | Groups, multi-device, encrypted media, verification/recovery, replies, reactions, disappearing-message policy |
| G4 | Hardened PWA | CSP, no third-party scripts, dependency review, IndexedDB/multi-tab/offline tests, runbooks and incident drills |
| G5 | Calls | Separate plan and threat model for Element Call, LiveKit, TURN, and evolving MatrixRTC contracts |

Do not use “Signal-grade,” “Signal clone,” or “secure messenger” in public claims before G4. “Not interoperable with Signal” must remain explicit.

## File responsibility map

### Cross-repository prerequisite (`../dsa-proto`)

- `backend/src/oauth-service.ts` — add a login-only, one-time PKCE identity handoff distinct from delegation writes.
- `backend/src/oauth-service.test.ts` — prove audience binding, one-time use, expiry, and absence of ATProto/AppView credentials.
- `backend/src/server.ts` — expose login-handoff begin/exchange routes and strict return-origin configuration.
- `backend/src/foundation-api.test.ts` — HTTP contract tests for the handoff.
- `packages/foundation-client/src/index.ts` — typed identity-handoff and authority APIs.
- `packages/foundation-client/package.json` — publish immutable version `0.2.0` to the suite registry.
- `docs/dsa-atproto/oauth-handoff.md` — document the login-only downstream-app contract and privacy boundary.

### `dsa-signal` control plane

- `backend/src/config.ts` — validated URLs, pinned trust roots, policy version, TTLs, cookie and OIDC settings.
- `backend/src/db.ts` — PostgreSQL pool and transaction helper.
- `backend/src/foundation/foundation-service.ts` — only boundary around `@dsaslate/foundation-client`.
- `backend/src/identity/identity-handoff.ts` — PKCE state lifecycle and DID result handling.
- `backend/src/entitlements/claims.ts` — exact JWT entitlement schema.
- `backend/src/entitlements/challenge-service.ts` — nonce issuance and one-time consumption.
- `backend/src/entitlements/verify-entitlement.ts` — issuer signature, audience, expiry, holder proof, and replay validation.
- `backend/src/entitlements/issuer-policy.ts` — pinned, versioned, cached authority-policy snapshots with fail-closed staleness.
- `backend/src/subjects/pairwise-subject.ts` — stable MAS-facing pseudonym derived from DID and sector identifier.
- `backend/src/oidc/provider.ts` — standards-library configuration for MAS; no handwritten protocol implementation.
- `backend/src/routes/*` — thin HTTP adapters for login, challenge, entitlement, session, health, and OIDC callbacks.
- `backend/src/server.ts` — composition root only.
- `migrations/0002_identity_control_plane.sql` — minimal identity, challenge, entitlement-status, policy-snapshot, and audit metadata.

### Infrastructure

- `deploy/local/compose.yaml` — local Synapse, MAS, two PostgreSQL databases, control plane, and web services.
- `deploy/local/synapse/homeserver.yaml` — non-federating private homeserver policy.
- `deploy/local/mas/config.yaml` — MAS with the control plane as upstream OIDC.
- `deploy/local/well-known/matrix-client.json` — client discovery.
- `deploy/locks/images.env` — immutable image references resolved to real registry digests.
- `scripts/resolve-image-digests.mjs` — resolve tags and write digest-pinned references before Compose is enabled.
- `docs/runbooks/matrix-local.md` and `docs/runbooks/revoke-member.md` — local operation and revocation procedures.

### PWA

- `web/src/auth/*` — dsa-proto login handoff, entitlement presentation, and MAS OAuth lifecycle.
- `web/src/crypto/*` — Rust crypto initialization, IndexedDB ownership, verification, cross-signing, backup, and recovery.
- `web/src/matrix/*` — direct Matrix client, encrypted-room policy, sync, and event adapters.
- `web/src/features/conversations/*` — conversation list and encrypted 1:1/group views.
- `web/src/features/messages/*` — text, replies, reactions, expiration UI, and encrypted attachments.
- `web/src/features/devices/*` — verification, recovery, and device revocation UX.
- `web/src/service-worker.ts` — PWA shell and authenticated encrypted-media transport; never cache plaintext.
- `web/public/manifest.webmanifest` — installable application metadata.

### Test and policy artifacts

- `docs/adr/0002-matrix-e2ee-substrate.md` — substrate decision and alternatives.
- `docs/reference/privacy-and-threat-contract.md` — assets, trust boundaries, metadata exposure, and accepted residual risk.
- `docs/reference/identity-and-entitlement-contract.md` — cross-repository identity and private entitlement contract.
- `tests/e2e/encrypted-vertical-slice.spec.ts` — browser-to-browser ciphertext and verification proof.
- `tests/security/no-plaintext-storage.test.ts` — database, logs, and media assertions.
- `tests/security/revocation.test.ts` — expiry/revocation propagation.

## Phase 0 — contract before code

### Task 1: Record architecture and accepted privacy limits

**Files:**
- Create: `docs/adr/0002-matrix-e2ee-substrate.md`
- Create: `docs/reference/privacy-and-threat-contract.md`
- Modify: `README.md`
- Test: `docs/reference/privacy-and-threat-contract.md`

- [ ] **Step 1: Write the documentation assertion test**

Add `scripts/check-security-contract.mjs`:

```js
import { readFileSync } from 'node:fs';

const contract = readFileSync('docs/reference/privacy-and-threat-contract.md', 'utf8');
for (const statement of ['social graph', 'web origin', 'previously downloaded', 'no plaintext fallback', 'calls are outside']) {
  if (!contract.toLowerCase().includes(statement)) throw new Error(`missing security statement: ${statement}`);
}
```

Add `"security-contract": "node scripts/check-security-contract.mjs"` to root `package.json` and invoke it from `make verify` before build.

- [ ] **Step 2: Run the assertion and confirm it fails**

Run: `pnpm run security-contract`

Expected: failure because `docs/reference/privacy-and-threat-contract.md` does not exist.

- [ ] **Step 3: Write the ADR and threat/privacy contract**

The ADR must choose Matrix over greenfield OpenMLS because MLS does not provide delivery, device lifecycle, media, recovery, or an audited browser client. Record Synapse + MAS + Rust crypto, non-federation, direct browser-to-Matrix credentials, and calls as a later experimental subsystem.

The threat contract must enumerate: client, web origin, control plane, issuer, `dsa-proto`, MAS, Synapse, databases, media, push, TURN/SFU, network observer, malicious member, stolen device, compromised operator, and dependency compromise. For every boundary, state visible plaintext, visible metadata, credentials held, and fail-closed behavior.

- [ ] **Step 4: Make scope visible in the README**

Replace the template title and description. Include this exact warning:

```md
> This project is not affiliated or interoperable with Signal. Matrix E2EE protects message content, not service-visible account, room, device, timing, IP, or access metadata. The web client remains vulnerable to a compromised application origin.
```

- [ ] **Step 5: Verify and review G0**

Run: `pnpm run security-contract && make verify`

Expected: both pass. Obtain explicit security, API, data, operations, and product acceptance before Task 2.

Suggested checkpoint: `docs: define encrypted chat trust boundary`.

## Phase 1 — cross-repository foundation

### Task 2: Add a least-privilege identity handoff to `dsa-proto`

**Files (`../dsa-proto`):**
- Create: `migrations/0008_identity_handoff.sql`
- Modify: `backend/src/oauth-service.ts`
- Modify: `backend/src/oauth-service.test.ts`
- Modify: `backend/src/server.ts`
- Modify: `backend/src/foundation-api.test.ts`
- Modify: `packages/foundation-client/src/index.ts`
- Modify: `packages/foundation-client/src/index.test.ts`
- Modify: `packages/foundation-client/package.json`
- Modify: `docs/dsa-atproto/oauth-handoff.md`

- [ ] **Step 1: Write failing service tests**

Cover this typed result and no broader credential:

```ts
type IdentityHandoffResult = {
  did: string;
  audience: string;
  authenticatedAt: string;
  expiresIn: 60;
};
```

Tests must prove HTTPS allowlisting, PKCE S256, client-generated 128-bit state, canonical audience equality with the return origin, database-anchored 60-second expiry, atomic one-time code consumption, replay rejection, stable versioned errors, and that serialized output contains none of `accessToken`, `refreshToken`, `dpop`, `cookie`, or `session`.

- [ ] **Step 2: Confirm the new tests fail**

Run: `pnpm --filter @dsaslate/foundation-api test -- oauth-service.test.ts foundation-api.test.ts`

Expected: failures for absent identity-handoff methods/routes.

- [ ] **Step 3: Implement a distinct login-only handoff mode**

Create a dedicated `/oauth/identity/v1/*` OAuth client, metadata document, callback, configuration, encrypted state namespace, database rows, hash domain separators, and routes. Request only the login scope `atproto`. The OAuth library necessarily handles ATProto credentials transiently during callback, so use a non-persistent session store, extract only `session.did`, discard the session immediately, and never expose `restore()` or write/session APIs to this flow. Missing or expired callback correlation must fail closed rather than create a browser or delegation session. Bind the canonical HTTPS audience to the return origin from request through code exchange. Generate `authenticated_at` and the 60-second expiry from PostgreSQL time. The versioned exchange response contains only the four fields above.

- [ ] **Step 4: Publish the typed client contract**

Add `beginIdentityHandoff()` to generate the PKCE verifier, S256 challenge, and 128-bit client state before constructing the URL, plus a runtime-validating `exchangeIdentityHandoff()` method. Set the package version to `0.2.0`, remove `private: true`, and set `publishConfig.registry` to `https://git.subcult.tv/api/packages/subculture-collective/npm/` with public access. Publish only after confirming 0.2.0 is unused and reviewing the built tarball contents and provenance; consumers must use exact `@dsaslate/foundation-client@0.2.0`, not `link:../dsa-proto`.

- [ ] **Step 5: Verify the upstream repository**

Run from `../dsa-proto`: `make verify`

Expected: generated bindings are clean and every check passes. Security and maintainer review are required before publishing 0.2.0.

Suggested checkpoint in `dsa-proto`: `feat: add downstream identity handoff`.

### Task 3: Define identity, entitlement, and issuer-policy contracts

**Files:**
- Create: `docs/reference/identity-and-entitlement-contract.md`
- Create: `backend/src/entitlements/claims.ts`
- Create: `backend/src/entitlements/claims.test.ts`
- Create: `backend/src/subjects/pairwise-subject.ts`
- Create: `backend/src/subjects/pairwise-subject.test.ts`

- [ ] **Step 1: Write failing schema and subject tests**

Use this exact entitlement shape:

```ts
export type MembershipEntitlement = {
  iss: string;
  sub: string;
  aud: 'dsa-signal';
  iat: number;
  exp: number;
  jti: string;
  cnf: { jkt: string };
  entitlement: 'chat';
  policyVersion: string;
};
```

Tests must reject additional roster/profile fields, an expiry over 15 minutes, wrong audience, malformed issuer/subject/JTI/thumbprint, and missing confirmation binding. Pairwise subjects must be deterministic for the same DID and sector, different across sectors, and computed as base64url HMAC-SHA-256 with a 256-bit server key.

- [ ] **Step 2: Confirm tests fail**

Run: `pnpm --filter '*api' test -- src/entitlements/claims.test.ts src/subjects/pairwise-subject.test.ts`

Expected: failures because modules do not exist.

- [ ] **Step 3: Implement strict Zod parsing and pairwise subjects**

Use `.strict()` schemas, constant-time comparisons where secrets are compared, and a versioned HMAC input:

```ts
const input = new TextEncoder().encode(`dsa-signal-subject:v1\0${sector}\0${did}`);
```

Do not store the DID in Matrix identifiers or OIDC `sub`; persist the encrypted DID mapping only in the control-plane database.

- [ ] **Step 4: Document protocol and lifecycle**

Specify identity handoff, issuer credential issuance, P-256 WebCrypto key generation, RFC 7638 JWK thumbprint in `cnf.jkt`, challenge signing, replay prevention, issuer rotation, account recovery, entitlement expiry, and revocation. State that the credential body is verified in memory and never persisted.

- [ ] **Step 5: Verify**

Run: `make verify`

Expected: all checks pass. API and security reviewers must approve the contract before database or OIDC work.

Suggested checkpoint: `feat: define private membership entitlement contract`.

## Phase 2 — control plane

### Task 4: Add minimal control-plane persistence and configuration

**Files:**
- Create: `backend/src/config.ts`
- Create: `backend/src/config.test.ts`
- Create: `backend/src/db.ts`
- Create: `migrations/0002_identity_control_plane.sql`
- Create: `backend/src/db.integration.test.ts`
- Modify: `.env.example`

- [ ] **Step 1: Write failing config and migration tests**

Require HTTPS production URLs, 32-byte subject and cookie keys, pinned root DIDs, a pinned authority-policy version, maximum policy staleness, secure cookie mode, and exact OIDC/MAS redirect origins. Reject wildcard origins and default secrets outside test mode.

- [ ] **Step 2: Define minimal tables**

Use tables for encrypted DID mappings, one-time login states, one-time proof challenges, active entitlement status, issuer-policy snapshots, OIDC grants/consents required by the selected library, and append-only security audit events. Add expiry indexes and uniqueness on state/challenge/JTI hashes. Do not add message, room, device-key, attachment, roster, or credential-body columns.

- [ ] **Step 3: Prove the privacy boundary in SQL tests**

Query `information_schema.columns` and fail if a control-plane table contains `message`, `plaintext`, `room_state`, `matrix_token`, `credential_body`, `roster`, or `refresh_token`.

- [ ] **Step 4: Run integration tests and full verification**

Run: `pnpm --filter '*api' test && make verify`

Expected: migration applies twice safely in disposable PostgreSQL and every check passes.

Suggested checkpoint: `feat: add minimal identity control-plane storage`.

### Task 5: Implement identity handoff and holder-bound entitlement proof

**Files:**
- Create: `backend/src/foundation/foundation-service.ts`
- Create: `backend/src/identity/identity-handoff.ts`
- Create: `backend/src/identity/identity-handoff.test.ts`
- Create: `backend/src/entitlements/challenge-service.ts`
- Create: `backend/src/entitlements/verify-entitlement.ts`
- Create: `backend/src/entitlements/verify-entitlement.test.ts`
- Create: `backend/src/entitlements/issuer-policy.ts`
- Create: `backend/src/entitlements/issuer-policy.test.ts`

- [ ] **Step 1: Add dependencies through pnpm**

Run:

```bash
pnpm --filter '*api' add @dsaslate/foundation-client@0.2.0 jose
```

Expected: lockfile records immutable package versions; no sibling link is present.

- [ ] **Step 2: Write adversarial tests first**

Test expired/wrong-audience credentials, unknown or rotated issuer keys, stale authority snapshots, live `dsa-proto` disagreement, reused JTI, reused/expired challenge, wrong origin, wrong P-256 signature, thumbprint mismatch, DID/subject mismatch, clock skew over 30 seconds, and database/log redaction.

- [ ] **Step 3: Implement issuer-policy snapshots**

Bootstrap from configured root DIDs and policy version. Resolve authority through `FoundationClient`, store provenance and a canonical digest, and activate snapshots only through an audited refresh operation. Authentication uses the active cached snapshot and fails closed after configured staleness; it never authorizes directly from one live response.

- [ ] **Step 4: Implement one-time proof**

Issue a random 32-byte challenge bound to browser session, expected JWK thumbprint, audience, and origin. Verify the credential with `jose`, import the P-256 public JWK, verify a signature over:

```text
dsa-signal-proof:v1\n<challenge>\n<origin>\n<credential-jti>
```

Consume challenge and JTI atomically. Persist only issuer, pairwise subject, policy version, JTI hash, decision, timestamps, and reason code.

- [ ] **Step 5: Verify**

Run: `pnpm --filter '*api' test && make verify`

Expected: tests pass and snapshots/JWTs never appear in logs. Obtain security and data review.

Suggested checkpoint: `feat: verify holder-bound membership entitlements`.

### Task 6: Provide a standards-compliant upstream OIDC boundary for MAS

**Files:**
- Create: `backend/src/oidc/provider.ts`
- Create: `backend/src/oidc/provider.test.ts`
- Create: `backend/src/routes/auth.ts`
- Create: `backend/src/routes/oidc.ts`
- Refactor: `backend/src/server.ts`
- Modify: `backend/src/index.ts`

- [ ] **Step 1: Select and lock the maintained OpenID Provider package**

Record the package, version, Node 24 support, security policy, discovery metadata, PKCE support, pairwise-subject support, persistence adapter, and conformance status in the ADR. Add it with `pnpm`; do not implement authorization, token, discovery, JWKS, refresh, or revocation endpoints manually.

- [ ] **Step 2: Write protocol-boundary tests**

Test discovery, exact redirect URI, authorization-code flow with S256 PKCE, `state` and `nonce`, pairwise `sub`, `aud` restricted to MAS, short authorization/session lifetime, key rotation, logout, entitlement lapse, consent reuse, and absence of Matrix tokens at every Node route.

- [ ] **Step 3: Configure the provider**

Expose only scopes `openid` and `dsa_signal_entitlement`. Claims are `sub`, `iss`, `aud`, `iat`, `exp`, and an entitlement policy version; omit DID, chapter, profile, email, roster, and credential contents. Disable implicit, password, device-code, dynamic client registration, wildcard redirects, and unneeded grants.

- [ ] **Step 4: Run an OIDC conformance smoke suite**

Run the selected provider’s official conformance tests plus `pnpm --filter '*api' test`.

Expected: authorization-code + PKCE passes; disabled grants fail; revocation terminates new authorization. Security review is mandatory.

Suggested checkpoint: `feat: expose MAS upstream OIDC identity`.

## Phase 3 — hardened Matrix prototype

### Task 7: Add digest-pinned local Synapse and MAS topology

**Files:**
- Create: `scripts/resolve-image-digests.mjs`
- Create: `deploy/locks/images.env`
- Create: `deploy/local/compose.yaml`
- Create: `deploy/local/synapse/homeserver.yaml`
- Create: `deploy/local/mas/config.yaml`
- Create: `deploy/local/well-known/matrix-client.json`
- Create: `docs/runbooks/matrix-local.md`
- Modify: `Makefile`

- [ ] **Step 1: Write a configuration policy checker**

Create `scripts/check-matrix-policy.mjs` that parses rendered configuration and fails unless federation listeners, guests, public room directory, URL previews, bridges, legacy password login, open registration, remote media, and identity-server lookup are disabled; encrypted private rooms are the only application-created room type.

- [ ] **Step 2: Resolve real image digests**

The resolver must call `docker buildx imagetools inspect <approved-tag>`, extract the Linux/amd64 and Linux/arm64 manifest digests, and atomically write `NAME=image@sha256:<resolved-digest>` entries. Review release notes and signatures before committing the resulting lock file. Compose references only variables from `deploy/locks/images.env`.

- [ ] **Step 3: Configure MAS delegation**

MAS uses the control plane’s OIDC discovery and exact client credentials. The browser authenticates directly with MAS; neither callback nor reverse proxy routes Matrix tokens through Node. Synapse delegates auth to MAS and disables legacy login.

- [ ] **Step 4: Validate topology**

Run:

```bash
node scripts/check-matrix-policy.mjs
docker compose --env-file deploy/locks/images.env -f deploy/local/compose.yaml config --quiet
make verify
```

Expected: all pass. Network tests must show federation, guest login, public directory, URL preview, and password login fail closed.

Suggested checkpoint: `infra: add private Matrix authentication topology`.

### Task 8: Bootstrap direct Matrix OAuth and Rust crypto in the PWA

**Files:**
- Create: `web/src/auth/matrix-oauth.ts`
- Create: `web/src/auth/session-store.ts`
- Create: `web/src/matrix/create-client.ts`
- Create: `web/src/matrix/encryption-policy.ts`
- Create: `web/src/crypto/bootstrap-crypto.ts`
- Create: `web/src/crypto/crypto-owner.ts`
- Create: `web/src/crypto/bootstrap-crypto.test.ts`
- Refactor: `web/src/App.tsx`

- [ ] **Step 1: Add and lock `matrix-js-sdk`**

Run: `pnpm --filter '*web' add matrix-js-sdk`

Expected: the lockfile includes the supported Rust/WASM crypto path. Legacy `initCrypto`, `initLegacyCrypto`, and direct `@matrix-org/olm` imports are forbidden by lint.

- [ ] **Step 2: Write failing client-policy tests**

Prove crypto initializes before sync, IndexedDB uses one owner per profile, a second tab coordinates instead of opening a conflicting crypto machine, unencrypted rooms are rejected, unverified-device state is visible, and browser storage failure blocks sending rather than silently using ephemeral keys.

- [ ] **Step 3: Implement OAuth and crypto startup order**

Discover MAS with Matrix auth metadata, use authorization code + PKCE, return directly to the PWA, create the Matrix client, call `initRustCrypto()`, register crypto callbacks, then begin sync. Never place access or refresh tokens in `localStorage`, URLs, logs, analytics, error reports, or the Node service.

- [ ] **Step 4: Enforce room encryption**

The application may create/join only invite-only rooms with `m.room.encryption` using the supported Matrix encryption algorithm. Sending is disabled until encryption state is observed and device trust has been evaluated.

- [ ] **Step 5: Verify**

Run: `pnpm --filter '*web' test && make verify`

Expected: all tests pass and a source search finds no legacy crypto API.

Suggested checkpoint: `feat: bootstrap Matrix Rust crypto in PWA`.

### Task 9: Prove the verified encrypted 1:1 vertical slice

**Files:**
- Create: `web/src/features/conversations/create-direct-room.ts`
- Create: `web/src/features/conversations/ConversationView.tsx`
- Create: `web/src/features/messages/send-text.ts`
- Create: `web/src/features/devices/VerificationFlow.tsx`
- Create: `tests/e2e/encrypted-vertical-slice.spec.ts`
- Create: `tests/security/no-plaintext-storage.test.ts`

- [ ] **Step 1: Write the failing browser test**

The test provisions two eligible accounts and two browsers, completes emoji/SAS verification, creates an invite-only encrypted direct room, sends a unique canary string, receives and decrypts it on the peer, and asserts the sender/receiver show verified device state.

- [ ] **Step 2: Add ciphertext-only assertions**

After sending, search Synapse and control-plane PostgreSQL text columns, captured service logs, rendered Matrix event JSON, and media storage for the canary. The recipient UI must contain it; every server-side search must return zero matches. Assert the event type is encrypted and no `m.room.message` plaintext reaches the homeserver API capture.

- [ ] **Step 3: Implement minimal direct chat**

Support conversation list, verified peer identity, text compose/send, ordered timeline, delivery/error state, and explicit warnings for new or unverified devices. Do not add groups, media, reactions, or calls in this gate.

- [ ] **Step 4: Run G2**

Run: `pnpm test && pnpm exec playwright test tests/e2e/encrypted-vertical-slice.spec.ts && make verify`

Expected: all pass in a fresh stack and after browser restart. Security review must inspect captured traffic and database/log queries.

Suggested checkpoint: `feat: prove verified encrypted direct messaging`.

### Task 10: Enforce entitlement expiry and revocation

**Files:**
- Create: `backend/src/entitlements/revocation-service.ts`
- Create: `backend/src/entitlements/revocation-service.test.ts`
- Create: `tests/security/revocation.test.ts`
- Create: `docs/runbooks/revoke-member.md`

- [ ] **Step 1: Write lifecycle tests**

Test active, expired, issuer-revoked, policy-revoked, lost-device, and issuer-key-compromise cases. Revocation must terminate control-plane sessions and future MAS authorization, revoke grants through supported APIs, suspend future Matrix login, remove organization-managed room membership, rotate room keys for remaining members, and record reason-coded audit metadata.

- [ ] **Step 2: Explicitly test the irreversible boundary**

Assert the removed member cannot decrypt messages sent after removal/key rotation. Also assert that previously decrypted content remains visible on that member’s device; document this as expected, not as a test failure.

- [ ] **Step 3: Implement idempotent reconciliation**

Use a durable state transition with retries and a terminal state only after OIDC/MAS/room enforcement confirms success. Never ingest Matrix tokens or copy room state into Node; invoke narrowly scoped administration interfaces from a separate worker identity.

- [ ] **Step 4: Run the revocation drill**

Run: `pnpm exec vitest run tests/security/revocation.test.ts && make verify`

Expected: future authorization and decryption are blocked within the documented target. Operations and security reviewers sign off before private beta.

Suggested checkpoint: `feat: propagate membership revocation`.

## Phase 4 — private beta capabilities

Before each task, create and approve the named follow-up plan. Each plan inherits this security contract and cannot weaken G2.

### Task 11: Multi-device trust, cross-signing, backup, and recovery

**Plan:** `docs/superpowers/plans/2026-07-16-device-trust-and-recovery.md`

**Target files:**
- `web/src/features/devices/DeviceList.tsx`
- `web/src/features/devices/VerificationFlow.tsx`
- `web/src/features/devices/RecoverySetup.tsx`
- `web/src/crypto/cross-signing.ts`
- `web/src/crypto/key-backup.ts`
- `tests/e2e/device-recovery.spec.ts`

- [ ] Specify first-device bootstrap, second-device verification, cross-signing, encrypted key backup, user-held recovery key, lost-device revocation, browser-storage loss, and “no recovery key means no recovery” UX.
- [ ] Test two tabs, two browsers, offline restart, IndexedDB eviction, wrong recovery key, compromised/unverified device, and recovery without server-readable secrets.
- [ ] Block beta until every key-state transition has explicit UI and the test suite passes after a clean browser restart.

Acceptance: a second verified device decrypts authorized history through encrypted backup; an unverified or revoked device cannot silently become trusted.

### Task 12: Private encrypted groups and membership changes

**Plan:** `docs/superpowers/plans/2026-07-16-encrypted-groups.md`

**Target files:**
- `web/src/features/conversations/create-group-room.ts`
- `web/src/features/conversations/GroupDetails.tsx`
- `web/src/matrix/membership-policy.ts`
- `tests/e2e/encrypted-groups.spec.ts`

- [ ] Implement invite-only encrypted rooms, least-privilege power levels, eligible-member invites, member removal, key rotation, new-device warnings, and organization-managed versus personal-group policy.
- [ ] Test invite races, concurrent removals, stale clients, rejoin attempts, entitlement lapse, and post-removal ciphertext.

Acceptance: ineligible accounts cannot join; removed devices cannot decrypt later epochs; Synapse still sees group membership and this remains disclosed.

### Task 13: Encrypted attachments and authenticated media

**Plan:** `docs/superpowers/plans/2026-07-16-encrypted-attachments.md`

**Target files:**
- `web/src/features/messages/encrypt-upload.ts`
- `web/src/features/messages/decrypt-download.ts`
- `web/src/features/messages/AttachmentView.tsx`
- `web/src/service-worker.ts`
- `tests/e2e/encrypted-attachments.spec.ts`

- [ ] Use Matrix encrypted-file events and SDK-supported attachment encryption; upload only ciphertext and retain key/IV/hash in the encrypted event.
- [ ] Enforce size/type limits before encryption, stream large files, verify ciphertext hash before decrypting, use authenticated media requests, and prevent service-worker/browser caches from storing plaintext.
- [ ] Search media storage, HTTP captures, logs, and caches for unique plaintext canaries.

Acceptance: only clients with room keys can recover attachment bytes; operators can still observe sizes and access timing.

### Task 14: Replies, reactions, edits, and disappearing-message policy

**Plan:** `docs/superpowers/plans/2026-07-16-message-interactions-and-retention.md`

**Target files:**
- `web/src/features/messages/relations.ts`
- `web/src/features/messages/MessageActions.tsx`
- `web/src/features/messages/expiration-policy.ts`
- `web/src/features/messages/expiration-worker.ts`
- `tests/e2e/message-relations-and-expiry.spec.ts`

- [ ] Use standard encrypted Matrix relations for replies, reactions, and edits.
- [ ] Define disappearing messages as coordinated client deletion/redaction with a visible room policy, not guaranteed erasure from malicious clients, screenshots, notifications, backups, or prior exports.
- [ ] Test out-of-order relations, redacted parents, offline expiry, clock skew, multiple devices, and backup restore after expiration.

Acceptance: UX never represents expiration as cryptographic deletion from recipients.

## Phase 5 — PWA and operational hardening

### Task 15: Harden the web origin and operational boundary

**Files:**
- Create: `web/src/security/csp.test.ts`
- Create: `tests/e2e/multi-tab-and-storage.spec.ts`
- Create: `docs/runbooks/security-incident.md`
- Create: `docs/runbooks/dependency-update.md`
- Modify: web serving configuration and `web/public/manifest.webmanifest`

- [ ] Set a nonce/hash-based CSP with no `unsafe-eval`, no third-party script origins, constrained `connect-src`, `frame-ancestors 'none'`, secure headers, and Trusted Types where supported.
- [ ] Add dependency allowlisting, lockfile review, provenance checks, SBOM generation, vulnerability scanning, and an emergency web-origin shutdown procedure.
- [ ] Test XSS payloads, malicious links/previews, storage eviction, two-tab crypto ownership, offline queues, update activation, and rollback. Never cache decrypted messages or attachment bytes in the service worker.
- [ ] Run `make verify`, browser E2E, dependency audit, container scan, backup restore, revocation drill, and incident tabletop.

Acceptance: G4 receives security, privacy, operations, and product approval. Only then may public security claims use the approved wording.

## Phase 6 — calls as a separate security program

### Task 16: Plan and gate E2EE calls

**Plan:** `docs/superpowers/plans/2026-07-16-e2ee-calls.md`

**Target files:**
- `deploy/calls/compose.yaml`
- `deploy/calls/element-call/config.json`
- `deploy/calls/livekit/livekit.yaml`
- `web/src/features/calls/*`
- `tests/e2e/e2ee-calls.spec.ts`

- [ ] Threat-model Element Call, LiveKit SFU, MatrixRTC Authorization Service, TURN, participant authorization, IP metadata, recordings, moderation, browser encoded-transform support, and protocol instability.
- [ ] Pin reviewed images by digest and isolate call credentials, networks, logs, and databases from chat services.
- [ ] Require SFrame/MatrixRTC E2EE support and fail closed on unsupported browsers; never silently downgrade to server-readable media.
- [ ] Test one-to-one and group calls, participant removal/rekey, malicious join, TURN-only networks, unsupported browsers, SFU compromise assumptions, and absence of media plaintext at SFU/TURN.

Acceptance: calls remain disabled unless the separate review proves participant authorization, E2EE behavior, and acceptable metadata exposure for every supported browser.

## Final verification matrix

Run from clean clones and empty volumes:

```bash
make verify
(cd ../dsa-proto && make verify)
node scripts/check-security-contract.mjs
node scripts/check-matrix-policy.mjs
docker compose --env-file deploy/locks/images.env -f deploy/local/compose.yaml config --quiet
pnpm exec playwright test
```

Additionally verify:

- no source, lockfile, Compose file, or CI path uses a sibling `link:` dependency;
- no Node route receives Matrix credentials or message/media payloads;
- no plaintext canary appears in databases, object/media storage, logs, traces, metrics, backups, push payloads, or captured server traffic;
- authority decisions use an active pinned snapshot rather than one live response;
- entitlement expiry/revocation stops new authorization and future-key access;
- all rooms created by the app are private and encrypted;
- federation, guests, public directory, URL previews, bridges, remote media, legacy login, and open registration fail closed;
- recovery and device verification work after browser restart and fail safely after storage loss;
- operational docs state that metadata remains visible and prior recipient plaintext cannot be revoked.

## Review and execution rules

1. G0, G1, G2, G4, and G5 are stop-the-line review gates.
2. Security reviews cover auth, holder binding, browser key custody, OIDC/MAS, E2EE enforcement, revocation, and calls.
3. API reviews cover cross-repository handoff, OIDC claims, stable errors, audience binding, and versioning.
4. Data reviews cover minimal storage, encrypted DID mapping, snapshot integrity, expiry indexes, audit retention, and plaintext-canary searches.
5. Operations reviews cover digest pinning, secrets, backups, key rotation, monitoring without sensitive payloads, rollback, revocation, and incident response.
6. Suggested checkpoint messages in this plan are guidance only; agents must not commit unless the user explicitly requests commits.

## Self-review

- Requirements coverage: broad scope is represented by G2–G5; the initial deliverable is deliberately the G2 vertical slice.
- Privacy boundary: membership stays outside `dsa-proto`; Matrix metadata exposure and web-origin compromise are explicit.
- Crypto boundary: established Matrix Rust crypto is used; neither TypeScript nor Node implements message cryptography.
- Identity consistency: ATProto DID authenticates at `dsa-proto`; the control plane derives a stable pairwise OIDC subject; rotating credentials do not create new Matrix identities.
- Revocation consistency: future authorization and keys are blocked; downloaded plaintext is acknowledged as irreversible.
- Infrastructure consistency: browser receives Matrix credentials directly from MAS; Node remains control plane only.
- Placeholder scan: every phase has named paths, commands, acceptance criteria, and explicit gates; digest values are resolved from registries rather than fabricated.
