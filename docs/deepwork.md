# OAuth Task 8 decisions

- Dormant G2 provenance-preparation helpers now strictly inspect real Git ustar/PAX
  archives and bounded OCI byte chains; focused tests cover a clean temporary Git
  archive plus adversarial tar, lock, and OCI inputs. They perform no network I/O,
  extraction, capability minting, or production G2 enablement. Focused script tests
  passed on 2026-07-23.

- Six-image lock follow-up: root PostgreSQL and every supported API/web build
  argument now bind to the checked-in lock file; Dockerfile stage policy accepts
  only the locked Node/Nginx variables, and both final images carry the custom
  `org.dsa-signal.build-marker` label. `make verify` builds and smoke-checks both
  images. This is not a claim of BuildKit attestation or a platform/config
  identity chain.

- Task 9 Phase 2D production-blocker follow-up: direct trust is now a fresh,
  immutable SDK-owned proof used by SAS, send admission, and public `sendReady`.
  Sends require atomic initial outbox creation, preserve retry event identity,
  and recheck stop/epoch/room state adjacent to raw transport. Timeline and sync
  handling now fail closed across stop, unencrypted direct text, terminal
  decryption, and reconciliation failure. Focused SDK tests, full web lint/build,
  and `make verify` passed on 2026-07-22.

- Task 9 Phase 2D presentation boundary: before durable outbox admission fails,
  the UI phase owns any failed-row presentation. Phase 2D guarantees only that
  no durable outbox row is created and no raw send is invoked; it does not yet
  claim the full UI transition.

- Task 9 Phase 2D follow-up: the private SDK port consumes the owner abort
  signal, synchronously revokes transport/publication on abort, and removes its
  abort listener on normal stop. Timeline classification uses v42 wire type,
  immediately projects already-decrypted encrypted events, and isolates timeline
  subscribers. Initial outbox creation now atomically captures the current sync
  baseline with the plaintext-free record; deterministic store coverage includes
  the atomic baseline and duplicate path. Focused SDK/store tests, full web
  tests, lint/build, `make verify`, and `git diff --check` passed on 2026-07-22.

- Task 9 Phase 2D SDK seam now installs timeline, local-echo, and decrypted
  listeners before sync, rebases unresolved plaintext-free outbox metadata before
  client start, and advances durable sync generation only after Syncing callback
  reconciliation. Incoming projections retain encrypted SDK events privately and
  expose plaintext only after a validated text decryption; direct sends persist
  only a SHA-256 hash, reconcile echoes, and treat transport uncertainty as an
  indeterminate retry-barrier. Focused SDK tests, full web checks, and
  `make verify` passed on 2026-07-22.

- Task 9 Phase 2C store prerequisites: startup now atomically rebases every
  unresolved no-event local-pending row (including ordinary crash-window rows),
  marks it indeterminate, advances its CAS generation, and requires a later
  completed sync. Explicit acceptance and echo APIs return discriminated
  updated/unchanged/missing/conflict outcomes and preserve global event-ID
  uniqueness; no plaintext is durable. The SDK adapter remains intentionally
  unchanged in this phase.

- Final SAS race follow-up: recovery discovers and claims the exact persisted
  SDK request under one SAS-operation authority acquisition; listener delivery
  of that same request is an idempotent no-op. Deterministic overlap coverage
  blocks recovery immediately before claim, queues the SDK callback, then
  proves one active recovered verifier/SAS projection without cancellation or
  disposal before exercising normal terminal cleanup. Focused SDK/store, full
  web, lint/build, and `make verify` passed on 2026-07-22.

- Final SAS Oracle follow-up: persisted callback recovery is serialized under
  one in-process operation authority, revalidates the exact durable generation
  and identity immediately before publication, and clears stale in-memory
  authority only after an absent/tombstoned durable read. The Started/CAS race
  test waits for an explicit bind-entry handshake before cancellation.
- Browser evidence closes the real owner page so its `pagehide` listener releases the Web Lock before follower takeover. It then reloads and re-injects the harness against the same profile and Rust IndexedDB prefix. The gate records deterministic bootstrap IndexedDB-open failure (with `startClient` uncalled) and a real IndexedDB connection `blocked`/`versionchange`/close sequence. It does not claim that an unsafe private Rust-store post-bootstrap failure was forced; that is not exposed by supported browser/SDK APIs.

> Gate hardening: external env topology/supply-chain keys are forbidden; signal interruption terminates and settles the active group before fresh-signal cleanup; the test-only Rust harness compares nonempty own-device public identity and its initial IndexedDB inventory through takeover/reopen without logging it.

- Task 8's optional browser gate is `make matrix-oauth-browser`, fixed to
  `https://chat.localhost:8443`. It owns and removes a temporary fixture env,
  runs the locked Matrix/MAS/Synapse/web/gateway/Postgres services, and replaces
  only production API/control-plane metadata, CORS, and DCR with a Caddy fixture.
  It does not issue tokens, prove entitlement, or claim a live callback/login;
  Task 9 supplies that full-login gate.

- `main.tsx` imports only the synchronous callback preflight, captures and scrubs before its dynamic application import, and the captured callback is transferred once without browser-global storage. Production completion wiring remains blocked on the SDK port/runtime composition adapter in the next phase; OAuth is not accepted yet.
- The immutable Task 7 topology and non-secret DCR metadata version live in `web/src/auth/matrix-topology.ts`; persisted registrations, attempts, sessions, OAuth discovery, and client startup validate that exact contract.
- Discovery persists whether the issuer response parameter is supported. A supported parameter is mandatory and must match; when omitted by discovery, exact pinned authorization/token origins, exact metadata, and the single durable attempt provide the mix-up boundary.
- A committed session is never revoked when lock release acknowledgement fails. It remains blocked under retained authority rather than being treated as released.
- Task 8 adapter work added an SDK-free single-flight refresh coordinator. It re-reads the active locator/session and exact discovery metadata before requesting a refresh, commits the response before returning it, retains an omitted refresh token, and terminally shuts down on invalid grants or persistence failure. Transport errors remain retryable.
- Task 8 now uses root `matrix-js-sdk` exports for `OAuth2` (the installed `lib/matrix.d.ts:26` re-exports `./oauth/index.ts`). The sole SDK seam owns OAuth, refresh callbacks, private client lifecycle, security state, and the encrypted-room facade. Callback completion runs before React mounts.
- Oracle alignment: the SDK adapter caches the exact v42 metadata object from explicit discovery; DCR, authorize, exchange, revoke, and refresh require it and never rediscover. Registration is the v42 string client ID, OAuth receives the persisted verifier/device ID, and revoke carries its token-type hint.
- The v42 event constants and CryptoApi are used at the private seam. Room admission DTOs are derived from Room, MatrixEvent, RoomMember, and CryptoApi data before private raw create/join calls. The public runtime exposes coarse startup state, owned gateway capability, and validated sign-in only; it does not expose a session.
- Task 8 room creation fixes `m.room.history_visibility` to `joined`; the adapter waits for a joined local room with the complete fixed state before post-admission, so a raw create/join result is never returned from an unstabilized cache. Refresh terminal shutdown now awaits the owner close path, and public startup derives its state from the gateway subscription rather than assuming `ready`.

Oracle follow-up: OAuth metadata is endpoint-keyed rather than a mutable “latest discovery” slot, so refresh remains pinned to its session token endpoint without rediscovery. Runtime close now stops and releases a begun operation before readiness settles; terminal closures are operation-local. Room cache stabilization is bounded at 12 seconds in production.

Evidence: adapter runtime tests are in `web/src/matrix/internal/sdk.test.ts`; verification was rerun on 2026-07-21.

Oracle latest follow-up: the startup coordinator maps each close function to its exact
published promise and clears that pair only after a successful close. Takeovers replace
the mapping independently, so a stale predecessor terminal cannot evict a successor.
Terminal refresh shutdown stops/releases before an atomic locator-and-generation-checked
session deletion; a replacement locator is never deleted. Public gateway stop delegates
to the runtime-handle close, while SDK operation stop remains private. Adapter room
stabilization has an internal injected clock seam for deterministic tests.

Evidence: focused Matrix coordinator, adapter, and public-runtime tests passed:
38 tests in 3 files on 2026-07-21. Stabilization and timeout paths use the
injected room clock rather than wall-clock timers.

Final Task 8 follow-up: refresh deletes an exact session only after the runtime
close succeeds; direct terminal listeners now expose a failed owner close while
the bootstrap event path observes it best-effort. Expected cache events can
temporarily demote readiness during room stabilization, but a fully rechecked,
epoch-stable admission restores `ready`; drift and failed shutdown retain
authority. Focused adapter/coordinator/refresh tests (50), the full web suite
(87), lint/build/source policy, and `make verify` passed on 2026-07-21.

- SAS follow-up: terminal completion no longer re-enters its own serialization
  queue after a failed completion disposition. Recovery claims the persisted
  generation before terminal disposal, and successful terminal disposal uses
  generation-checked authority cleanup while clearing its indexed wire events.
  Focused adapter coverage includes failed completion disposal/replacement,
  recovery replacement, pre-binding wire cleanup, and a Started CAS whose fake
  mutation itself is deferred. Focused SDK (53), full web (181), lint/build,
  `make verify`, and `git diff --check` passed on 2026-07-22.
