# Verified encrypted direct chat — Task 9 implementation plan

## Status and gate

This plan implements the local Task 9 product/security surface. It inherits the
privacy contract and cannot weaken Task 8's SDK, storage, crypto-owner, or room
admission boundaries.

Local completion reports only:

```text
PASS_LOCAL_TASK9_PENDING_G2
```

External G2 requires two distinct eligible accounts and authorized access to
wire, database, log, and media evidence. Until supplied, the repository records:

```text
PENDING_EXTERNAL_G2_MISSING_TWO_ENTITLED_ACCOUNTS
```

Mocks never satisfy G2.

## Required implementation files

- Extend `web/src/matrix/contract.ts` and compile-time assertions.
- Extend pure policy in `web/src/matrix/encryption-policy.ts`.
- Implement only inside the SDK seam `web/src/matrix/internal/sdk.ts`.
- Extend `web/src/auth/session-store.ts` with durable cross-signing bootstrap
  disposition, durable SAS operation binding, and durable text outbox records.
- Update `web/src/matrix/index.ts`, `web/src/App.tsx`, and their tests/exports.
- Add `web/src/features/conversations/create-direct-room.ts`.
- Add `web/src/features/conversations/ConversationView.tsx`.
- Add `web/src/features/messages/send-text.ts`.
- Add `web/src/features/devices/VerificationFlow.tsx`.
- Add unit/component tests beside each module.
- Add `web/e2e/encrypted-vertical-slice.spec.ts` to the existing Playwright root.
- Add `web/test/no-plaintext-storage.test.ts` and root scanner helpers/tests.
- Add `scripts/scan-task9-plaintext.mjs` and
  `scripts/scan-task9-plaintext.test.mjs`.
- Add `scripts/test-g2-encrypted-direct-chat.mjs` and its unit test.
- Add `web/e2e/g2-encrypted-direct-chat.evidence.schema.json`.
- Update `web/playwright.config.ts`, `web/package.json`, root `package.json`, and
  `Makefile` with isolated local/G2 projects and targets.

## SDK-free boundary

The application sees immutable owned DTOs and narrow commands only. It never
receives `MatrixClient`, `Room`, `MatrixEvent`, `VerificationRequest`, verifier,
crypto objects, generic event content, arbitrary callbacks, or a generic send
method.

The public direct-chat capability supports:

- list/subscribe to exact one-peer conversations;
- create or join one structurally safe direct room;
- subscribe to owned text timeline DTOs;
- send one text message under current send readiness;
- subscribe to peer/device/verification state;
- initiate, accept, confirm, mismatch, cancel SAS through one-shot commands.

## Structural room and send policy

`activeMembership` includes `join`, `invite`, and `knock`.

Verification-only admission requires all of:

1. exact current `m.room.join_rules` value `invite`;
2. exact current `m.room.history_visibility` value `joined`;
3. exact `m.room.encryption.algorithm = m.megolm.v1.aes-sha2`;
4. Rust persistent encryption belief;
5. active membership exactly `{self, peer}` and no third active member.

This state exposes SAS controls but **never** text sending.
SAS initiation additionally requires both self and peer currently joined; an
invited/knocking peer may enter verification-only room state but receives no
request until joined.

Send readiness additionally requires:

1. self and peer both currently joined;
2. encryption targets exactly `{self, peer}`;
3. own current device and cross-signing identity ready;
4. peer identity known, cross-signing verified, and not awaiting user approval;
5. direct authenticated `downloadKeysForUsers([self,peer])` (`/keys/query`) with
   zero failures;
6. exact authoritative device IDs and Ed25519/Curve25519 key fingerprints equal
   the nonempty Rust trust projection for both users;
7. every device known, owner-signed, and verified;
8. one unchanged room epoch followed immediately by private `sendMessage`.

`getUserDeviceInfo(..., true)` alone is never described as fresh or complete.
Room state, membership, encryption, keys, devices, identity, trust, and SAS
terminal events synchronously advance the room epoch and revoke send readiness.

## Cross-signing bootstrap

The session store records one durable bootstrap disposition per exact
`{homeserver,userId,deviceId}`: `never-attempted | pending-uia | published |
recovery-required`. Read and CAS that disposition **before** any network refresh
or Rust/Secret Storage inspection. If its state permits inspection,
force-refresh the user's public identity and device set. Inspect local Rust readiness plus every public master/self-signing/
user-signing key ID. Any cross-signing material in Secret Storage is
`recovery-required`: Task 9 cannot prove those private keys match the published
identity without decrypting/exporting them; Task 11 owns that recovery flow.

| Public identity | Matching private state | Result |
| --- | --- | --- |
| Absent | No Rust DB history, no durable prior attempt, only the current device, and no local or Secret Storage private state | Atomically mark `pending-uia`, bootstrap once with `setupNewCrossSigning:false`, complete delegated-auth/UIA, refresh, require all three exact published/local key IDs and signatures, then mark `published`. |
| Present | Ready and matching, Secret Storage absent, with durable disposition `never-attempted` or `published` | Reuse; never bootstrap/reset. |
| Present | Missing, unavailable, or mismatched | `recovery-required`; Task 11 owns recovery. |
| Absent | Complete-but-unpublished local keys, any Secret Storage cross-signing material, partial local state, durable `pending-uia`, prior UIA failure, or post-bootstrap mismatch | Atomically mark `recovery-required`; no automatic retry. |
| Partial public master/self-signing/user-signing identity | Any | `recovery-required`; no upload completion guess, retry, or reset. |

Durable disposition is evaluated first. `pending-uia` after reload/crash always
becomes `recovery-required`, even if public/local keys now appear complete; this
is an indeterminate publication, not reusable success. Only the same live
bootstrap operation may move `pending-uia → published` after `makeRequest(null)`
returns, forced public refresh matches all local key IDs/signatures, and the
single IndexedDB transaction commits. A crash before that commit never infers
success.

Reusing an already published, cryptographically verified identity from
`never-attempted` deliberately does not promote the disposition to `published`:
no upload was attempted, and each startup must revalidate the authoritative raw
response before reuse.

The implementation never calls local trust setters, silently resets identity,
or retries a partial bootstrap without an explicit recovery path.

The UIA callback is intentionally noninteractive under delegated Matrix OAuth:
it calls the SDK-supplied `makeRequest(null)` exactly once. Success must publish
the expected key IDs. Any UIA challenge, redirect requirement, unsupported
stage, request ambiguity, reload while `pending-uia`, or partial upload becomes
durable `recovery-required`. The app never collects a Matrix password, stores
UIA session material, or resumes a failed upload automatically.

The `sasOperations` store has one unique active key per exact
`{homeserver,userId,deviceId}`. An atomic CAS creates an intent containing exact
profile, room, peer user, local device ID, direction, phase `intent`, expiry,
and generation before any request. After `requestVerificationDM` returns, a
second generation-CAS binds the exact request event ID and transaction ID.
Outgoing flow binds the selected peer `from_device` only on the first validated
peer ready/start event; incoming flow binds it atomically from the validated
request. That peer-device binding is a one-time CAS and every later event must
match it. A crash/reload with unbound intent becomes failed and
cannot auto-retry; the user must explicitly dispose it before a new intent.
The operation later stores the unique selected start event ID. A recovered
Started operation must match every field. Zero or more than one valid related
start event is fail-closed; no tie-break is guessed.

## SAS protocol state machine

Install incoming verification listeners before sync and recover any in-progress
expected-room request after startup.

The executable transition table is:

| Current | Input | Guard/effect | Next |
| --- | --- | --- | --- |
| idle | initiate | Structurally safe exact room/peer **and both users joined**; persist one operation; call `requestVerificationDM`. | requested |
| idle | incoming raw request | Exact locked wire schema, expected room/peer, in-room request, **both users joined**, outer `origin_server_ts` no older than 10 minutes and no more than 5 minutes in the future, no active operation; bind the matching SDK request without reading its unimplemented `methods` getter. | requested |
| requested (incoming) | accept incoming | One-shot user-consent `accept`; wait for SDK change/phase, never assume synchronous Ready. | accepted |
| accepted (incoming) | remote ready | Exact request identity, bound incoming peer device, and SDK phase Ready. | ready |
| requested (outgoing) | remote ready | Exact request identity, SDK phase Ready, and first validated peer `from_device` bound by CAS. | ready |
| ready | start | Recheck both users joined and unchanged room epoch; attach request-change guards; `startVerification('m.sas.v1')`; attach verifier cancel/SAS listeners before `verify`. | started |
| requested or ready | remote SDK phase Started | Both users remain joined. Locate and validate the raw `m.key.verification.start` bound by relation to the exact request event ID, expected sender/room, and locked schema; require SDK phase Started, chosen method `m.sas.v1`, matching request/transaction/relation identity, and non-null `request.verifier`; attach cancel/SAS listeners before `verify`, and never call local start. | started |
| started | recovered after reload/subscription | Locate the same validated raw start event and exact relation/request/transaction identity; require both joined, SDK phase Started, chosen method `m.sas.v1`, and non-null verifier. Attach listeners before `verify`; if `getShowSasCallbacks()` already returns values, publish them once. Any missing/mismatch becomes failed. | started or sas-shown |
| started | show_sas | Read `getShowSasCallbacks()` if subscription was late; expose transient emoji/decimal DTO and one-shot actions. | sas-shown |
| sas-shown | confirm | Consume action once; dispose display values immediately; await callback `confirm`. | confirming |
| sas-shown | mismatch | Consume once; dispose values; invoke mismatch cancellation. | cancelled |
| sas-shown | cancel | Consume once; dispose values; invoke cancel. | cancelled |
| confirming | verifier resolved + request phase Done | Force-refresh identity/devices and require send-ready trust. | done |
| any nonterminal | SDK cancel, wrong transition, timeout, room/peer drift, duplicate/simultaneous request, unsupported method, verifier rejection, page/storage terminal | Cancel best effort, dispose request/verifier/SAS references, advance epoch, keep send blocked. | cancelled or failed |

Simultaneous starts are resolved only by the SDK-bound request identity; any
second local/remote operation is rejected. Passive/stale requests expire under
a bounded monotonic deadline. `VerificationRequest.methods` is never read
because SDK v42's Rust wrapper does not implement it; supported-method policy is
enforced from the validated raw request schema and explicit local method.
Every cancellation/failure input is accepted from every nonterminal state and
is idempotent. One-shot commands reject repeats after their first effect.

Accept exactly one current request for the expected peer and structurally safe
room. Reject self, wrong room/peer, to-device, duplicate, stale, unknown-field,
or unsupported-method requests. Advertise/start only `m.sas.v1`.

Transient SAS DTOs contain display emoji/decimal values and one-shot `confirm`,
`mismatch`, and `cancel` commands. Human confirmation is mandatory. Completion
requires verifier success, request phase Done, then a fresh authoritative
identity/device/send-ready evaluation. Terminal states dispose SAS values.

## Exact server-visible verification allowlist

The privacy exception is limited to locked SDK-v42 output. The machine-readable
field contract is checked in at
`docs/reference/matrix-verification-v42-wire-contract.json`. Its recursive
unknown-field policy is `reject`. Before any adapter merge, an SDK-v42 live
fixture must match it byte-for-field; drift requires security review and a
versioned contract update. The scanner accepts only these event shapes:

- Initial outer `m.room.message` with
  `msgtype=m.key.verification.request` and standard fallback/request fields
  (`body`, `to`, `from_device`, `methods`). Freshness uses only outer
  `origin_server_ts` with the 10-minute past / 5-minute future bounds above.
- `m.key.verification.ready`: `from_device`, `methods`, required relation.
- `m.key.verification.start`: `from_device`, `method`, negotiated protocol/hash/
  MAC/SAS lists, required relation.
- `m.key.verification.accept`: commitment plus selected protocol/hash/MAC/SAS
  values and required relation.
- `m.key.verification.key`: public ephemeral `key` and relation.
- `m.key.verification.mac`: protocol MAC map/keys and relation.
- `m.key.verification.done`: relation only.
- `m.key.verification.cancel`: standard code/reason and relation.

Protocol public ephemeral keys, commitments, hashes, and MACs are allowed.
Private/secret keys, derived emoji/decimal SAS values, chat canaries, and any
nonstandard application body remain forbidden.

The request fallback body is the exact locked Rust-SDK v18.3.1 template:
`<expected sender Matrix user ID> is requesting to verify your key, but your
client does not support in-chat key verification. You will need to use legacy
key verification to verify keys.` Any other body fails closed.

At runtime the forbidden-value set is expanded with the exact unique chat
canary and the actual transient SAS decimal strings, emoji glyphs, and emoji
labels shown to the clients. Raw values are used only in-memory for scanning;
retained evidence stores hashes/counts. Test-only private/secret-key markers are
also scanned where planted; production private key bytes are never exported
from Rust crypto merely to scan them.

## Timeline and delivery DTOs

Text-only timeline DTOs include owned IDs, peer/direction, timestamp, plaintext
only after client decryption, and one state:

```text
decrypting | local-pending | homeserver-accepted | synced | failed |
decryption-failed
```

`homeserver-accepted` never means recipient delivery/read. Keep encrypted
events until `Event.decrypted`; expose no fallback text on decryption failure.
Reconcile local/remote echoes by transaction/event identity without duplicates.

Outgoing transitions are exact:

| Current | Input | Next/effect |
| --- | --- | --- |
| none | submit nonempty bounded text with a caller-generated canonical transaction ID | Durably retain that transaction ID and body hash; publish `local-pending`; invoke private send once. The application owns transaction generation so an explicit retry can resupply the same identity. |
| local-pending | send promise resolves with event ID | Bind event ID; `homeserver-accepted`. |
| none | failure before durable outbox creation/raw SDK invocation | Publish an in-memory `failed` row for UI error state only; create no durable outbox record. Reload may discard this diagnostic row. |
| local-pending | any raw SDK send rejection | `local-pending` with indeterminate marker and a required later-sync generation; v42 exposes no reliable proof that the homeserver did not accept it. Do not generate a new transaction ID. |
| local-pending or homeserver-accepted | matching remote echo | Replace/reconcile the same row by transaction/event identity; `synced` terminal. |
| homeserver-accepted | no echo before deadline | Remain `homeserver-accepted`; never relabel failed or delivered. |
| failed (in-memory only) | explicit submit | Treat as a new admission attempt with the same caller-owned transaction ID; it does not consume durable retry authority because raw send was never invoked. |
| local-pending (indeterminate) | explicit retry before reconciliation point | Deny retry; continue reconciliation to avoid duplicate acceptance. |
| local-pending (indeterminate) | at least one subsequent completed `/sync` generation | Retry once with the **same** transaction ID only when plaintext is supplied again and its hash exactly matches the persisted body hash; Matrix transaction-id idempotency is the duplicate-prevention authority. Continue to reconcile any remote echo to one row. |
| synced | late send promise resolves with the same event ID or rejects | Ignore transport outcome; remote echo is authoritative and terminal. A different response event ID blocks the gateway while retaining the already-synced durable identity. |

Incoming transitions are `decrypting → synced` after valid text decryption, or
`decrypting → decryption-failed`. Incoming rows never use local send states.
The application row retains one stable local identity while the exact final event
ID is attached after acceptance/echo. Temporary SDK local IDs never become public
Matrix event IDs. Duplicate or mismatched transaction/event identities block the
gateway rather than rewriting the durable row or rendering two messages.

`sendMessage` promise resolution moves only to `homeserver-accepted`; remote
echo may win first. Every rejection after raw invocation is indeterminate because
SDK v42 provides no reliable pre-accept classifier. In-process retries use
`resendEvent` on the retained local echo; after reload, when no SDK local event
exists, the adapter uses `sendMessage` with the exact original transaction ID.

The outbox persists an integer application `syncGeneration` captured before the
attempt, `retryConsumed`, transaction ID, body hash, and state. A “later sync”
means a completed sync callback increments the integer beyond the persisted
baseline; sync-token strings are never compared. No timer is a retry authority.
On reload, enumerate unresolved metadata-only rows and rebase **every** unresolved
`local-pending` row without an event ID to indeterminate with the next completed
sync generation. This closes crashes after durable outbox creation but before or
immediately after raw invocation. Recovered rows remain internal metadata and are
not rendered until plaintext with the exact body hash is explicitly resupplied.
Immediately before retry, one
IndexedDB transaction CASes the same record using its current generation and
exact body hash, marks `retryConsumed:true`, and
rechecks that no remote echo, event ID, or synced terminal state exists.
The current profile-wide `syncGeneration` is itself durable and monotonically
incremented in the same store; startup resumes from the stored value, so reload
cannot restart below an outbox baseline. On every startup, one transaction sets
each unresolved local-pending outbox record's `requiredGeneration` to at least
`currentSyncGeneration + 1`; retry remains blocked until a subsequently
completed sync atomically reaches that value. Persisted pre-reload increments
therefore never satisfy the post-reload barrier.

Only `ClientEvent.Sync` callbacks with current state `SyncState.Syncing` advance
the durable generation; the initial `Prepared` transition is not counted again.
Startup rebase completes before `startClient` begins. All outbox callbacks honor
the owner abort signal, are serialized per transaction, and publish nothing after
stop.

### Recovery operator note

An over-cap unresolved outbox profile fails closed. Preserve the available
evidence and resolve or prune only terminal rows through supported maintenance;
never blindly delete unresolved rows.

Store APIs return discriminated `updated | unchanged | missing | conflict`
outcomes for acceptance and remote-echo reconciliation. Event-ID mismatch is a
`conflict`, never an ordinary CAS miss; the adapter retains the existing durable
identity and blocks the gateway. Generic state mutation is not an adapter
boundary. The pure timeline reducer may project a retry only after the atomic
store CAS has already returned an authorized updated record; it never derives
retry authority from an in-memory sync counter.

## Ciphertext evidence

Every scanner must first detect a planted positive control. It then searches
for the unique chat canary in:

- ephemeral Matrix request/response bodies (never headers or tokens);
- Synapse and control-plane textual, JSON/JSONB, and bytea representations;
- all service/container logs;
- Matrix media bytes.

Push, metrics, traces, backups, and support tooling are explicitly marked
disabled/not configured or scanned. Persist only counts, event types/statuses,
and canary hashes. Disable traces, screenshots, and video; redact failures.
Decrypted browser DTOs/UI are expected to contain plaintext and are not treated
as server representations.

The concrete positive-control catalog is:

| Surface | Representation | Planted detection control | Isolation/cleanup | Retained evidence |
| --- | --- | --- | --- | --- |
| Browser→Synapse capture | Request/response body bytes only | Fixture request body containing a separate scanner marker | In-memory capture destroyed after run; headers/tokens never persisted | marker hash, matched count, event types/statuses |
| Synapse PostgreSQL | Every user table text/varchar/citext plus canonical JSON/JSONB text and bytea hex/escaped text | Dedicated transaction rolled back after scanner detects one marker in each representation class | Rollback; fresh database for G2 | schema/table/type inventory hash and counts |
| Control PostgreSQL | Same representation classes | Dedicated rollback transaction per class | Rollback; no production row retained | catalog hash and counts |
| Service logs | Raw bounded container stdout/stderr bytes for every G2 service | One nonsecret startup marker emitted by a dedicated test canary service and detected by the same log scanner | Owned Compose project removed | service inventory hash and counts |
| Matrix media volume | Recursive regular-file bytes | Dedicated canary file in isolated test-only media subdirectory | Delete canary before application send; destroy volume after run | file inventory hash and counts |
| Push | Disabled/not configured in locked topology | Policy checker proves no push service/config | N/A | policy result |
| Metrics/traces/support export | Disabled/not configured | Policy checker rejects exporters/support sinks | N/A | policy result |
| Backups | No backup job runs in G2 | Compose/service inventory proves absence | N/A | inventory result |

Each planted marker differs from the chat canary. A missing positive control
aborts before any zero-match assertion.

`scripts/scan-task9-plaintext.mjs` exports exactly:

- `validatePositiveControl(surface, marker, matches)`;
- `scanCapturedBodies(capture, canary)` for request/response bodies only;
- `scanPostgresCatalog(client, canary)` for catalog-driven text/JSON/JSONB/bytea;
- `scanServiceLogs(logs, canary)` for every owned service byte stream;
- `scanMediaTree(root, canary)` for regular files only, rejecting links/devices;
- `assertNoCanary(results)` requiring all named surfaces/positive controls;
- `buildTask9Evidence(results)` returning hashes/inventories/counts only.

`scripts/scan-task9-plaintext.test.mjs` tests every helper and maps the catalog
rows above one-to-one. `web/test/no-plaintext-storage.test.ts` tests the exact
verification schemas and browser capture classification.

Application chat must reach Synapse as `m.room.encrypted`; plaintext
`m.room.message` is allowed only for the exact verification-request schema.

## Test sequence

### Local

1. Pure policy/DTO/state-machine tests fail first.
2. Adapter tests cover structural admission without send, third-member/knock
   drift, authoritative-key mismatch/failure, all trust failures, epoch races,
   timeline decrypt/local echo reconciliation, and SAS transitions.
3. Component tests cover conversation list, peer trust warnings, SAS human
   actions, ordered timeline, and local-pending/homeserver-accepted/failed states.
4. Scanner catalog tests use positive controls and exact verification fixtures.
5. Add web package script `test:task9-local` and Make target `task9-local`.
   `make task9-local` runs the contract/adapter/component/scanner tests and emits
   only `PASS_LOCAL_TASK9_PENDING_G2`; it is included in `make verify` only when
   it has no live external dependency.
6. `pnpm test`, `make task9-local`, and `make verify` pass.

### External G2

1. Wipe stack volumes and browser profiles.
2. Log in two distinct eligible identities with real OAuth.
3. Bootstrap only confirmed first identities; create/join one exact direct room.
4. Complete real SAS and re-evaluate both send-ready gates.
5. Send canary A, decrypt/render on peer, and run all ciphertext scans.
6. Fully stop owners and browsers while preserving IndexedDB.
7. Reopen the same users/devices/cross-signing identities; decrypt canary A
   without repeat SAS/key reset/new device.
8. Send canary B in the reverse direction and rerun all scans.

Only this external sequence may mark master Task 9 Steps 1–2 and G2 complete.
It runs via named Make target `g2-encrypted-direct-chat`, web Playwright project
`g2-encrypted-direct-chat`, and web script `test:g2-encrypted-direct-chat`.
Missing environment/accounts/inspection access is a hard failure with exact
`PENDING_EXTERNAL_G2_MISSING_TWO_ENTITLED_ACCOUNTS`, never a skip or PASS.

`web/playwright.config.ts` uses explicit project `testMatch` values: the Task 8
project matches only `task8-matrix-oauth.spec.ts`; G2 matches only
`encrypted-vertical-slice.spec.ts`. Every script passes `--project` explicitly,
so unrelated browser gates never collect G2.
