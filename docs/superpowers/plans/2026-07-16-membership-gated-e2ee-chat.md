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

- `deploy/local/compose.yaml` — local Synapse, MAS, an isolated control-plane PostgreSQL service, a Matrix PostgreSQL service with separate Synapse/MAS logical databases and roles, control plane, gateway, and web services.
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

Specify DID Core constrained ATProto DID parsing, mandatory 60-second identity-handoff freshness, exact versioned HTTP schemas/statuses, P-256 WebCrypto key generation, RFC 7638 JWK thumbprint, challenge signing, keyed replay/idempotency fingerprints, issuer rotation, entitlement expiry, and revocation. State that credential bodies are verified only in memory and never persisted.

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

Require separate runtime and migration database URLs; HTTPS production URLs; versioned exact 32-byte subject and AES-256-GCM key rings; 32-byte cookie key; dedicated versioned 32-byte challenge, session-binding, JTI, idempotency, and request-fingerprint HMAC key rings; pinned root DIDs; a pinned authority-policy version; maximum policy staleness; secure cookie mode; and exact OIDC/MAS redirect origins. Reject wildcard origins, URL credentials in public URLs, and default secrets outside test mode. Retain each fingerprint key ID through its contract-defined maximum row TTL, each subject key for the lifetime of referenced mappings, and each encryption key through the lifetime of referenced envelopes.

- [ ] **Step 2: Define minimal tables**

Use a dedicated `control_plane` schema for encrypted DID mappings, one-time login states, fingerprint-only identity sessions/proof challenges/JTIs/idempotency results and rotation aliases, active entitlement status, encrypted issuer-policy snapshots, the active-policy pointer, and append-only coarse security audit events. Add expiry indexes, exact constraints, and transactional uniqueness on every retained-key alias. v1 HMAC activation is outage/quiescence-only: writers stop, traffic is blocked, retention drains, and all instances restart on one new active epoch; rolling mixed epochs, online activation, and dual-write are prohibited. Defer all provider-specific OIDC grant/consent/token/adapter tables to a separate Task 6 migration after provider selection; do not add generic JSONB adapter blobs. Do not add raw state/challenge/JTI/idempotency/request bytes, plaintext DID/issuer/`kid`, message, room, device-key, attachment, roster, token, credential-body, or free-form audit columns. Migration-owner, runtime, and retention roles are distinct; runtime cannot own schema objects and has `INSERT`-only audit access. Runtime receives no migration-owner or retention credential and no direct delete/truncate privilege; retention receives no direct table privilege and can invoke only the expiry-guarded cleanup function.

- [ ] **Step 3: Prove the privacy boundary in SQL tests**

Compare `information_schema.columns` bidirectionally against an exact positive allowlist of table, column, type, and nullability; any missing or extra column fails. Separately assert checks, foreign keys, unique constraints, indexes, and runtime grants through `pg_catalog`, including the absence of JSON/JSONB and generic payload/body/token/code/JWK/signature/DID columns.

- [ ] **Step 4: Run integration tests and full verification**

Run: `pnpm --filter '*api' test && make verify`

Expected: a migration ledger plus immutable checksum and advisory lock make a second identical application a no-op while schema drift fails closed; disposable-PostgreSQL catalog, constraint, role/grant, and privacy checks pass.

Suggested checkpoint: `feat: add minimal identity control-plane storage`.

### Task 5: Implement identity handoff and holder-bound entitlement proof

**Files:**
- Modify: `.npmrc`
- Modify: `.env.example`
- Modify: `backend/package.json`
- Modify: `pnpm-lock.yaml`
- Modify: `backend/src/config.ts`
- Modify: `backend/src/config.test.ts`
- Modify: `backend/src/db.ts`
- Modify: `backend/src/db.integration.test.ts`
- Modify: `backend/src/migrate.ts`
- Modify: `backend/scripts/copy-migration.mjs`
- Modify: `backend/src/server.ts`
- Modify: `backend/src/server.test.ts`
- Modify: `backend/src/index.ts`
- Create: `migrations/0003_entitlement_session_binding.sql`
- Create: `backend/src/refresh-policy.ts`
- Create: `backend/src/foundation/foundation-service.ts`
- Create: `backend/src/http/strict-json.ts`
- Create: `backend/src/identity/identity-handoff.ts`
- Create: `backend/src/identity/identity-handoff.test.ts`
- Create: `backend/src/identity/session-cookie.ts`
- Create: `backend/src/entitlements/challenge-service.ts`
- Create: `backend/src/entitlements/verify-entitlement.ts`
- Create: `backend/src/entitlements/verify-entitlement.test.ts`
- Create: `backend/src/entitlements/issuer-policy.ts`
- Create: `backend/src/entitlements/issuer-policy.test.ts`

- [ ] **Step 1: Add dependencies through pnpm**

Run:

```bash
pnpm --filter '*api' add @dsaslate/foundation-client@0.2.0 jose@6.2.3 lossless-json@4.2.0
```

Expected: lockfile records immutable package versions; no sibling link is present.

- [ ] **Step 2: Write adversarial tests first**

Test constrained DID parsing (including percent encoding), server-side handoff exchange and cookie establishment, handoff freshness boundaries, expired/wrong-audience credentials, unknown or rotated issuer keys, stale authority snapshots, live `dsa-proto` disagreement during refresh, reused JTI, reused/expired challenge, idempotency ordering/session conflict, exact HTTP status schemas and parsing precedence, wrong origin/signature/thumbprint/DID binding, and database/log redaction. Also test strict JOSE/nested schemas, exact token/body/`kid` caps, recursive duplicate JSON rejection, one captured clock, atomic policy transitions, DB uniqueness/concurrency, and exact log/APM exclusions.

- [ ] **Step 3: Implement issuer-policy snapshots**

Bootstrap through the operator-only `refresh-policy --file` command from configured root DIDs, exact root JWKs, and policy version. Resolve authority through `FoundationClient`, store the strict selected provenance plus SHA-256 of the exact compact-JWS UTF-8 bytes without canonicalization, and activate snapshots only through an audited refresh transaction. Authentication uses the active cached snapshot and fails closed after configured staleness; it never authorizes directly from one live response.

- [ ] **Step 4: Implement one-time proof**

Implement the versioned challenge and verification wire schemas, exact
holder-proof transcript, atomic replay/idempotency behavior, and coarse errors
in `docs/reference/identity-and-entitlement-contract.md`. Issue a random
32-byte challenge bound to browser session, exact DID, expected JWK thumbprint,
entitlement audience, and canonical allowlisted origin. Consume challenge and
issuer-scoped JTI atomically with authorization and idempotency result commits.
Persist only the contract's encrypted mapping references, coarse audit metadata,
and versioned keyed replay/idempotency fingerprints; never raw credentials or
replay inputs.

- [ ] **Step 5: Mount the exact HTTP adapters**

Wire the identity-session, challenge, and verification routes through `server.ts` and `index.ts` with the contract's dependency injection, singleton-header precedence, raw-octet caps, duplicate-aware parsing, secure cookie behavior, headers, and coarse errors. Exercise the real HTTP adapters, not only service methods.

- [ ] **Step 6: Verify**

Run: `pnpm --filter '*api' test && make verify`

Expected: tests pass and snapshots/JWTs never appear in logs. Obtain security and data review.

Suggested checkpoint: `feat: verify holder-bound membership entitlements`.

### Task 6: Provide a standards-compliant upstream OIDC boundary for MAS

**Files:**
- Create: `docs/reference/mas-upstream-oidc-contract.md`
- Create: `docs/adr/0003-oidc-provider-for-mas.md`
- Modify: `docs/reference/identity-and-entitlement-contract.md`
- Modify: `.env.example`, `docker-compose.yml`, `backend/package.json`, and `pnpm-lock.yaml`
- Create: `backend/src/oidc/provider.ts`
- Create: `backend/src/oidc/provider.test.ts`
- Create: `backend/src/oidc/adapter.ts`
- Create: `backend/src/oidc/adapter.test.ts`
- Create: `backend/src/oidc/authorization-decision.ts`
- Create: `backend/src/oidc/authorization-decision.test.ts`
- Modify: `backend/src/entitlements/verify-entitlement.ts` and `backend/src/entitlements/verify-entitlement.test.ts`
- Modify: `backend/src/refresh-policy.ts` and `backend/src/refresh-policy.test.ts`
- Create: `backend/src/routes/auth.ts`
- Create: `backend/src/routes/oidc.ts`
- Refactor: `backend/src/server.ts`
- Modify: `backend/src/index.ts`
- Modify: `backend/src/config.ts`, `backend/src/config.test.ts`, `backend/src/db.ts`, `backend/src/db.integration.test.ts`, `backend/src/migrate.ts`, and `backend/scripts/copy-migration.mjs`
- Create: `migrations/0004_mas_upstream_oidc.sql`
- Create: `migrations/catalog/0003-pre.json`, `migrations/catalog/0004-post.json`, and catalog/ACL fixture tests
- Create: `backend/src/oidc/compatibility-harness.test.ts`
- Create: `backend/src/oidc/fixtures/openid-configuration.http` and `backend/src/oidc/fixtures/oauth-authorization-server.http`
- Create: `docs/runbooks/oidc-restore.md`

- [x] **Step 1: Pin the compatibility spike before implementation**

Add exact ESM `oidc-provider@9.9.1` for Node 24 and build a pinned compatibility harness around public provider middleware, adapter, `findAccount`, `interactionResult`, and application-owned AsyncLocalStorage. It must prove mounted `/token`, the exact 43-character authorization-resume UID grammar and narrow resume-cookie path, exact five-model persisted adapter allowlist plus non-persisting `Client` lookup and `findByUid` scope, exact payload shape, both OAuth metadata routes and their full provider-owned fixtures, external/disabled route response matrix, exact ID-token claim set, provider handled-error buffering/commit behavior, transaction ordering/savepoint behavior, and selected APIs. It must prove `interactionFinished` is not used because it writes before commit. Record the OpenID Certified package choice, upgrade harness requirement, and external OpenID Foundation conformance pre-G2 gate in ADR 0003. Never handwrite discovery, authorization, token, JWKS, or other provider protocol endpoints.

- [x] **Step 2: Write protocol-boundary tests**

Test exact discovery fixture acceptance and external route allowlist; static-client runtime code/query restriction, redirect, scopes, and RS256; authorization-code query mode with mandatory S256 PKCE, state, and nonce; Strict-cookie first GET and same-origin one-time CSRF POST; exact session-bound entitlement, generation, and policy snapshot; pairwise subject/minimal claims; fresh Grant per authorization and second-cookie authorization nonreuse; context-to-code binding; double exchange; expiry/revocation races; complete savepoint/commit matrix including signing/rendering/storage failure; product logout; key/epoch/restore/cleanup; encrypted payload canary scan; runtime role; frozen migration catalog/ACL manifests; no Matrix-token routes; signing overlap; and conformance smoke.

- [x] **Step 3: Configure the provider**

Implement the normative MAS upstream OIDC contract exactly: derive issuer only as `${PWA_ORIGIN}/oidc`, remove legacy issuer/plural-redirect inputs, configure one confidential MAS client and one exact redirect, runtime code/query/PKCE-S256/state/nonce/scopes, RS256, minimal ID token, opaque 256-bit upstream-only access token, exact 60/300/900-second TTL bounds, and all disabled surfaces. Make migration 0004 outage-only: preserve the existing policy-snapshot FK, replace drained legacy entitlement uniqueness with one session-bound durable entitlement row and positive generation, then create encrypted adapter rows, artifact epoch, versioned catalog/ACL manifests, and retention controls with no forbidden plaintext columns. Use dedicated non-reused key rings and descriptor-read owner-only signing/secret files.

- [x] **Step 4: Implement interaction, decision, adapter, and atomic token exchange**

Use `/oidc/interaction` GET/POST with fixed CSP/no-store/no-referrer HTML and exact one-time HMAC CSRF binding; initial GET cannot bind the absent Strict control cookie and local interaction failures never use the product JSON envelope. Recheck the control session and entitlement, create one fresh Grant and the exact login/custom-prompt/consent result, and finish fixed login/consent. `loadExistingGrant` accepts only that current consent result. Atomically bind interaction/session/Grant context to AuthorizationCode. Application-owned ALS wraps all provider and interaction routes; every adapter mutation uses its checked-out client. POST, resolved resume, token exchange, and logout acquire the common session-binding advisory lock and row locks in the contract order: session, entitlement, policy, context, artifact/code, CSRF. Savepoint immediately after consume, roll back late writes while retaining consume, commit reuse `revokeByGrantId`, buffer every transactional response until commit, and poison indeterminate-commit connections without emitting buffered output. Product logout uses its exact v1 JSON transport and revokes control session, contexts, and provider artifacts by Grant fingerprint without receiving Matrix credentials.

- [ ] **Step 5: Run local evidence and external conformance**

Run `pnpm --filter '*api' test` and the local conformance smoke suite. Before G2, run the official OpenID Foundation conformance suite as an external gate; do not represent it as a local package test.

Local evidence recorded 2026-07-20: API suite 386/386, local OIDC compatibility smoke 18/18, and `make verify` passed. The checkbox remains open solely for the official external OpenID Foundation conformance gate.

Expected: only the contract surface is externally reachable; authorization-code + PKCE succeeds; disabled grants fail; fresh Grants prevent reuse ambiguity; revocation/lapse terminates new authorization and exchange; and no Node route accepts Matrix credentials. Security, data, API, and operations review are mandatory.

Suggested checkpoint: `feat: expose MAS upstream OIDC identity`.

## Phase 3 — hardened Matrix prototype

### Task 7: Add digest-pinned local Synapse and MAS topology

**Files:**
- Create: `scripts/resolve-image-digests.mjs`
- Create: `deploy/locks/images.env`
- Create: `deploy/local/compose.yaml`
- Create: `deploy/local/synapse/homeserver.yaml`
- Create: `deploy/local/mas/config.yaml`
- Create: `deploy/local/gateway/Caddyfile`
- Create: `deploy/local/postgres/init-matrix-databases.sh`
- Create: `deploy/local/well-known/matrix-client.json`
- Create: `deploy/locks/images.provenance.json`
- Create: `scripts/generate-matrix-local-secrets.mjs`
- Create: `scripts/test-matrix-negative.mjs`
- Create: `docs/runbooks/matrix-local.md`
- Modify: `Makefile`

- [x] **Step 1: Write a configuration policy checker**

Create `scripts/check-matrix-policy.mjs` that parses rendered configuration and fails unless federation listeners, guests, public room directory, URL previews, bridges, legacy password login, open registration, remote media, and identity-server lookup are disabled. Task 7 proves the server prerequisites: invite rooms default to encryption and public room discovery/publication is disabled. Task 8 enforces that the application creates and joins only encrypted private rooms; Task 9 supplies end-to-end proof.

- [x] **Step 2: Resolve real image digests**

The resolver must call `docker buildx imagetools inspect <approved-tag>`, extract the Linux/amd64 and Linux/arm64 manifest digests, and atomically write `NAME=image@sha256:<resolved-digest>` entries. Review release notes and signatures before committing the resulting lock file. Compose references only variables from `deploy/locks/images.env`.

- [x] **Step 3: Configure MAS delegation**

MAS uses the control plane’s OIDC discovery and exact client credentials. The browser authenticates directly with MAS; neither callback nor reverse proxy routes Matrix tokens through Node. Synapse delegates auth to MAS and disables legacy login.

- [x] **Step 4: Validate topology**

Run:

```bash
node scripts/check-matrix-policy.mjs
docker compose --env-file deploy/locks/images.env --env-file deploy/local/policy.env -f deploy/local/compose.yaml --profile full --profile negative config --quiet
make matrix-negative
make verify
```

Expected: all pass. Network tests must show federation, guest login, public directory, URL preview, and password login fail closed, and must prove transport isolation: Synapse cannot reach an isolated egress canary. This is not direct federation or remote-media application-path execution evidence.

Local evidence recorded 2026-07-21: the rendered policy and dual-profile Compose checks passed, `make verify` passed, and two consecutive clean `make matrix-negative` rehearsals passed after one non-reproduced Synapse startup exit. The repository operator approved the recorded PostgreSQL `17.10-bookworm` and Caddy `2.11.4-alpine` Docker Official Image provenance exceptions via OpenCode session on 2026-07-21; future digest updates require fresh approval. Task 7 is locally complete. Task 6 Step 5 remains postponed solely for its separate external OpenID Foundation conformance gate.

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

- [x] **Step 1: Add and lock `matrix-js-sdk`**

Run: `pnpm --filter '*web' add matrix-js-sdk`

Expected: the lockfile includes the supported Rust/WASM crypto path. Legacy `initCrypto`, `initLegacyCrypto`, and direct `@matrix-org/olm` imports are forbidden by lint.

- [x] **Step 2: Write failing client-policy tests**

Prove crypto initializes before sync, IndexedDB uses one owner per profile, a second tab coordinates instead of opening a conflicting crypto machine, unencrypted rooms are rejected, unverified-device state is visible, and browser storage failure blocks sending rather than silently using ephemeral keys.

- [x] **Step 3: Implement OAuth and crypto startup order**

Discover MAS with Matrix auth metadata, use authorization code + PKCE, return directly to the PWA, create the Matrix client, call `initRustCrypto()`, register crypto callbacks, then begin sync. Never place access or refresh tokens in `localStorage`, URLs, logs, analytics, error reports, or the Node service.

- [x] **Step 4: Enforce room encryption**

The application may create/join only invite-only rooms with `m.room.encryption` using the supported Matrix encryption algorithm. Sending is disabled until encryption state is observed and device trust has been evaluated.

- [x] **Step 5: Verify**

Run: `pnpm --filter '*web' test && make verify`

Expected: all tests pass and a source search finds no legacy crypto API.

Local evidence recorded 2026-07-22: `matrix-js-sdk@42.0.0` is exactly locked; SDK import quarantine, IndexedDB session storage, Web Lock ownership, Rust crypto startup, owner-safe refresh/logout, and invite-only Megolm room admission tests pass. `make verify` passes. The fixture-owned production-Caddy Chromium gate passes as `PASS_LOCAL_CALLBACK_PENDING_LIVE_LOGIN` and records strict secret-free evidence for callback scrubbing, live metadata/CORS/DCR, owner page-close takeover, reload/store identity continuity, and IndexedDB failure handling. The upstream-entitled callback remains explicitly `pending-pre-g2-live-login` for Task 9 and is not represented as a local pass.

Suggested checkpoint: `feat: bootstrap Matrix Rust crypto in PWA`.

### Task 9: Prove the verified encrypted 1:1 vertical slice

**Detailed plan:** `docs/superpowers/plans/2026-07-22-verified-encrypted-direct-chat.md`

**Files:**
- Create: `web/src/features/conversations/create-direct-room.ts`
- Create: `web/src/features/conversations/ConversationView.tsx`
- Create: `web/src/features/messages/send-text.ts`
- Create: `web/src/features/devices/VerificationFlow.tsx`
- Create: `web/e2e/encrypted-vertical-slice.spec.ts`
- Create: `web/test/no-plaintext-storage.test.ts`
- Refactor: `web/src/matrix/contract.ts`
- Refactor: `web/src/matrix/encryption-policy.ts`
- Refactor: `web/src/matrix/internal/sdk.ts`

- [ ] **Step 1: Write the failing browser test**

The test provisions two eligible accounts and two browsers, completes emoji/SAS verification, creates an invite-only encrypted direct room, sends a unique canary string, receives and decrypts it on the peer, and asserts the sender/receiver show verified device state.

- [ ] **Step 2: Add ciphertext-only assertions**

After sending, search Synapse and control-plane PostgreSQL text columns, captured service logs, rendered Matrix event JSON, and media storage for the canary. The recipient UI must contain it; every server-side search must return zero matches. Assert each application chat event reaches the homeserver as `m.room.encrypted`, never as plaintext `m.room.message`. Exact SDK-v42 verification-control schemas are the sole approved server-visible exception: the initial request may use the standard outer `m.room.message`, and later events may contain protocol-mandated public ephemeral keys/commitments/hashes/MACs, but none may contain the chat canary, derived SAS values, private/secret keys, or nonstandard application content.

- [x] **Step 3: Implement minimal direct chat**

Support conversation list, verified peer identity, text compose/send, ordered timeline, delivery/error state, and explicit warnings for new or unverified devices. Do not add groups, media, reactions, or calls in this gate.

- [ ] **Step 4: Run local verification, then external G2**

Local run: `pnpm test && make verify`

Expected local verdict before eligible identities are supplied: `PASS_LOCAL_TASK9_PENDING_G2` plus `PENDING_EXTERNAL_G2_MISSING_TWO_ENTITLED_ACCOUNTS`. This does not check Steps 1–2 or G2.

External run: `make g2-encrypted-direct-chat` against the approved fresh two-account environment, then run `make verify`.

Expected: all pass in a fresh stack and after browser restart. Security review must inspect captured traffic and database/log queries.

Local evidence recorded 2026-07-22: the exact one-peer SDK boundary, cross-signing/SAS state machine, plaintext-free IndexedDB v3 outbox, encrypted timeline/send/retry path, complete room/peer/epoch UI isolation, eight-event verification classifier, bounded positive-control scanner, and fail-closed external G2 skeleton are implemented. `make task9-local` emits `PASS_LOCAL_TASK9_PENDING_G2`; 211 web tests, lint/build, `make verify`, and `git diff --check` pass. Oracle and Designer accepted the local implementation. Steps 1–2 and external G2 remain unchecked because two distinct entitled accounts and the fresh/restart live evidence are not available.

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
