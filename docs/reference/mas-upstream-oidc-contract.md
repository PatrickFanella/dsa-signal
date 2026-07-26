# MAS Upstream OIDC Contract

## External restore/activation ledger

The immutable ledger preserves pre-G2 v2 semantics. A v2 prefix may be followed
by v3, but v2 never follows v3. Domain-separated v3 `restore` records strictly
advance the issue floor; v3 `activation` records bind material at the unchanged
floor. v3 binds epoch, active IDs, sorted adapter/index fingerprints, ordered
cookie fingerprints, client-secret fingerprint, and signing-key order (first
key active). Legacy v2 signing remains kid-sorted for startup compatibility.
The visible ledger cap is 1024 records; migrate before exhaustion.

This normative Task 6 v1 profile is implemented only with ESM
`oidc-provider@9.9.1` on Node 24. The provider owns discovery, authorization,
token, JWKS, and OAuth errors; they are never handwritten. OpenID Foundation
conformance is an external pre-G2 gate.

## Issuer, ingress, client, and discovery

The issuer is exactly `${PWA_ORIGIN}/oidc`; startup rejects a byte-unequal
origin. The sole static opaque confidential MAS client uses `client_secret_basic`,
one configured redirect URI `${OIDC_SECTOR}/upstream/callback/<26 uppercase
Crockford-ULID chars>`, code grant/response type, `query` at runtime, scopes
`openid dsa_signal_entitlement`, and mandatory S256 PKCE, state, and nonce.
Only RS256 is enabled. Implicit, hybrid, password, device, client credentials,
refresh/offline tokens, registration, PAR, CIBA, introspection, UserInfo,
revocation, resource indicators, RP and backchannel logout are disabled.

The external allowlist is GET `/oidc/.well-known/openid-configuration`, GET
`/.well-known/oauth-authorization-server/oidc`, GET `/oidc/jwks`, initial GET
`/oidc/auth`, resume GET `/oidc/auth/:uid`, POST `/oidc/token`, and GET/POST
`/oidc/interaction`. The harness pins the provider's 9.9.1 UID grammar for
`:uid`; it is sensitive and excluded from every log. This allowlist governs
provider-owned OIDC routes only; existing `/v1/*` product routes retain their
own contracts. All other provider routes, including `/session/end/confirm`,
reject externally. The compatibility harness proves the mounted internal token
path is `/token`.

The pinned resume UID is exactly 43 characters matching
`[A-Za-z0-9_-]{43}`; 42/44-character values, percent encodings, separators,
dots, and non-ASCII reject at host dispatch. Omitted `response_mode` is accepted
as OIDC's effective `query`; explicit `query` is accepted and explicit
`form_post` or `fragment` rejects for the static MAS client despite metadata
advertisement. Every method/path pair outside the allowlist—including HEAD,
OPTIONS, wrong methods on listed paths, malformed resume UIDs, and query-bearing
non-authorization routes—returns exactly HTTP 404 with
`application/json`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
and `{"error":"not_found"}`; HEAD has those headers and an empty body as HTTP
requires. Host dispatch maps the root RFC 8414 path to the
provider-owned metadata action without modifying its response. Two checked-in
fixtures pin complete status, headers, and body bytes separately for the OIDC
and OAuth metadata routes.

The provider-owned checked-in fixtures are byte-for-byte discovery responses
captured from 9.9.1 after configuration. They are never rewritten or handwritten.
Its expected metadata permits the provider's `response_modes_supported` superset
`form_post`, `fragment`, and `query`; static-client and runtime tests separately
permit only code plus query. The adapter has a non-persisting `Client` model
whose unknown lookup returns `undefined`; persisted models are exactly
`AuthorizationCode`, `AccessToken`, `Session`, `Grant`, and `Interaction`.
All provider features are pinned by explicit allowlist rather than defaults;
`devInteractions`, claims parameter, request objects, DPoP, and every feature
not required by this contract are disabled. The single-audience profile always
omits `azp`, `acr`, `amr`, `sid`, `at_hash`, `c_hash`, and request-selected
extra claims.

Task 6 removes legacy `OIDC_ISSUER_URL` and plural `MAS_REDIRECT_URIS` inputs.
Issuer is derived only as `${PWA_ORIGIN}/oidc`; one `MAS_REDIRECT_URI` must
exactly match the ULID callback grammar above. `OIDC_SECTOR` remains the
immutable MAS HTTPS DNS origin and must equal that callback's origin. Presence
of either removed legacy variable fails startup rather than being ignored.

Canonical ingress trusts only the configured proxy peer and its pinned Host,
authority, and forwarded-proto values. It rejects aliases, trailing dots,
double slashes, encoded routes, unexpected query on non-authorization routes,
and unpinned authorities. Token requests are admitted through rate limiting
first, then `Content-Length` must be absent or an exact singleton canonical
decimal value at most 4096; content encoding is forbidden. The form is
stream-read once with an exact 4096-byte cap before the pinned provider receives
its pre-read-body fallback. Invalid length, content encoding, or declared or
streamed oversize returns fixed `400 {"error":"invalid_request"}` with
no-store/no-referrer and never invokes the provider; limiter denial alone is
`429`. Artifact-creating and invalid requests are rate-limited.
Proxy/WAF/access/APM/trace/support/core,
heap, crash, provider-event, request, and response capture excludes auth query,
resume UID, Authorization, Cookie, Set-Cookie, Referer, token and CSRF form
bodies, Location, and provider events. Forwarded authority/proto/host inputs are
singletons; duplicates or comma-joined values reject before dispatch.

## Identity, interaction, and fresh consent

`accountId` is `did_mappings.id`; `pairwiseIdentifier` returns its stored
authoritative `did_mappings.subject`. It never decrypts a DID or derives a
subject. ID tokens contain only `iss`, `aud`, `iat`, `exp`, `auth_time`,
`nonce`, pairwise `sub`, and `dsa_signal_entitlement_policy_version`; `azp` is
always absent in this single-audience profile. The authorization clock captured
from PostgreSQL supplies `auth_time` and login timestamps. The custom claim is
read only from the locked captured context.

Provider cookies cannot establish eligibility. `loadExistingGrant` loads only
`ctx.oidc.result?.consent?.grantId` for this authorization's custom consent
result; it never consults a provider-session historical Grant. The unrequestable
prompt has `name: dsa_signal_fresh_entitlement`. After the live decision each
authorization creates exactly one new Grant and finishes with exactly these
application-controlled result members: `login: {accountId: <mapping UUID>,
remember: false, ts: <captured PostgreSQL Unix second>}`,
`dsa_signal_fresh_entitlement: {verified: true}`, and `consent: {grantId:
<fresh Grant ID>}`. The Grant ID appears only under `consent`. The harness
performs a second authorization
with the same provider cookie, proves no prior Grant ID is loaded or bound, and
proves one distinct newly created Grant is used. Thus `loadExistingGrant` is not
always undefined, but historical reuse is impossible.

The application uses public `provider.interactionResult()` to obtain the resume
URL and sends the 303 through its buffered responder only after commit. It MUST
NOT call `interactionFinished()`, which ends the Node response before the
application transaction can commit.

The cross-site GET interaction renders fixed data-free HTML with `Cache-Control:
no-store`, `Referrer-Policy: no-referrer`, and CSP `default-src 'none';
frame-ancestors 'none'; form-action 'self'; base-uri 'none'`; it cannot decide.
The provider Session cookie is exactly `__Host-dsa_signal_oidc_session` with
`Path=/`. The provider-enforced narrow cookies are
`dsa_signal_oidc_interaction` with `Path=/oidc/interaction` and
`dsa_signal_oidc_interaction_resume` with dynamic
`Path=/oidc/auth/<exact UID>`; they deliberately lack the `__Host-` prefix
because v9.9.1 forces those narrow paths. All three are signed Koa cookies and
therefore each has an exact same-attribute `.sig` companion, for six provider
cookies total. All are harness-pinned `Secure; HttpOnly; SameSite=Lax` with no
Domain. Because `login.remember` is false, v9.9.1 emits the Session/companion as
nonpersistent browser-session cookies without `Expires` or `Max-Age`; the
server-side provider Session artifact remains capped at 900 seconds.
Interaction/resume cookies and their companions carry `Expires` no later than
300 seconds after emission. The control cookie remains
`__Host-dsa_signal_session`, Strict, and is
sent only on the same-origin POST. POST accepts exactly one form member, exact
`application/x-www-form-urlencoded` without parameters or content encoding, no
query, a capped body, exact Origin, and rejects duplicate members. It requires
exactly one well-formed target control cookie; malformed or duplicate target
cookies reject and clear it. The form has one hidden dynamic member named
`csrf`; aside from that token the HTML is byte-fixed and contains no client,
redirect, account, or entitlement data. The form supplies only that token;
provider `interactionDetails` supplies client/redirect details. `access_denied`
is emitted only after those details validate client and redirect; otherwise use
fixed generic HTML.

The CSRF input is 32 random bytes encoded as 43 unpadded base64url characters.
It is stored as 32-byte `bytea` HMAC output (encoded outside PostgreSQL only as
canonical base64url) and atomically consumed. Every live decision captures and
locks one active `control_plane.entitlements` row matching the exact session
binding and captures `{mapping_id, entitlement_id, generation, jkt,
policy_snapshot_id, policy_version, expires_at}`. Context revalidation compares
all fields exactly. Because the Strict control cookie is absent on the initial
cross-site GET, its CSRF row binds only the provider Interaction `jti`, the
provider Interaction chain `cid`, and sole-client fingerprint. Version 9.9.1
does not persist a provider Session UID until login resumes. `jti` and `cid`
are public `interactionDetails()` fields and pinned adapter-payload compatibility
surfaces; both must be canonical 43-character values. The same-origin POST validates the
control cookie and introduces its session binding into the authorization
context; GET never guesses or persists a control-session binding.

AuthorizationCode lifetime is exactly 60 seconds. Access and ID token lifetimes
are at most 300 seconds and are synchronously capped to the positive remaining
control-session and entitlement lifetime. Interaction and authorization-context
lifetimes are at most 300 seconds; CSRF is exactly 300 seconds. Grant and
provider Session lifetimes are at most 900 seconds. Access tokens contain 256
bits of opaque randomness and have no application resource endpoint. TTL
callbacks read only precomputed ALS values and never perform I/O.
Dynamic token TTL is `floor(min(300, sessionRemaining, entitlementRemaining))`;
it never rounds upward and issuance fails before consume when the result is less
than one positive integer second.

## Epoch, cryptography, and storage manifest

Artifact epoch is externally configured 16 random bytes as exactly 22 unpadded
base64url characters; every row carries it. All HMAC outputs below are 32-byte
`bytea` in PostgreSQL; any external representation is canonical unpadded
base64url. With NUL delimiters and UTF-8/ASCII fields exactly as shown:

```text
dsa-signal-oidc-artifact-id:v1\0${epoch}\0${model}\0${rawId}
dsa-signal-oidc-session-uid:v1\0${epoch}\0${rawUid}
dsa-signal-oidc-grant-id:v1\0${epoch}\0${rawGrantId}
dsa-signal-oidc-interaction-uid:v1\0${epoch}\0${rawUid}
dsa-signal-oidc-interaction-chain:v1\0${epoch}\0${rawCid}
dsa-signal-oidc-csrf:v1\0${epoch}\0${decodedTokenBytes}
dsa-signal-oidc-client:v1\0${epoch}\0${opaqueClientId}
```

Every textual field above is encoded as UTF-8 exactly; the CSRF prefix and its
NUL are concatenated directly with the decoded 32 token bytes rather than
interpolating arbitrary bytes as text.

No raw client ID is persisted: it is validated in memory and its sole-client
fingerprint is stored. Retained index-ring keys are tried for lookup; active keys
write. AES-256-GCM uses a fresh 12-byte nonce, tag-inclusive ciphertext, and AAD
`dsa-signal-oidc-adapter:v1\0<row UUID>\0<model>\0<artifact fingerprint>\0<epoch>`.
The AAD artifact-fingerprint field is the canonical 43-character unpadded
base64url encoding of the stored 32 bytes.
Payload is exact provider UTF-8 JSON, uncanonicalized, at most 32768 bytes both
before encryption and after decryption. Private adapter AES/index, provider
cookie, RS256 signing, and MAS client-secret purposes are non-reused.

Migration 0004 creates this exact catalog (all `id uuid not null`, timestamps
`timestamptz not null`, and `epoch char(22) not null` with base64url check):
Every listed column is NOT NULL and has no default unless this manifest says
`nullable`; application code supplies UUIDs and clocks. No unlisted column,
sequence, generated value, or default is permitted.

* `oidc.provider_artifacts`: `id` PK, `model text` checked to five persisted
  models, `artifact_key_id text`, `artifact_fingerprint bytea check octet_length=32`,
  `session_uid_key_id text nullable`, `session_uid_fingerprint bytea nullable
  check 32`, `grant_key_id text nullable`, `grant_fingerprint bytea nullable
  check 32`, `cipher_key_id text`, `nonce bytea
  check octet_length=12`, `ciphertext bytea check octet_length between 16 and
  32784`, `created_at`, `expires_at`, `consumed_at nullable`, `revoked_at
  nullable`, and `retained_until`. It has unique
  `(epoch,model,artifact_key_id,artifact_fingerprint)`, Session-only unique
  `(epoch,session_uid_key_id,session_uid_fingerprint)` where model is Session,
  nonunique `(epoch,grant_key_id,grant_fingerprint)` revocation index, expiry and
  retained-until indexes, and global unique `(cipher_key_id,nonce)`. Model TTL
  checks enforce `expires_at > created_at`, AuthorizationCode exactly 60
  seconds, AccessToken and Interaction at most 300 seconds, and Grant and
  Session at most 900 seconds. `retained_until = expires_at +
  interval '30 seconds'`; consumed/revoked timestamps are between creation and
  retention. Session UID key/fingerprint are both present only for Session.
  Grant key/fingerprint are required for Grant, AuthorizationCode, and
  AccessToken and forbidden for Session/Interaction; the Grant model indexes
  its own raw ID and child artifacts index payload `grantId`.
  Adapter `find` and `findByUid` use one captured PostgreSQL `decision_now` and
  return rows only when `expires_at > decision_now` and `revoked_at IS NULL`.
  A consumed AuthorizationCode remains readable only for provider replay
  handling; initial redemption uses `SELECT ... FOR UPDATE` with those live
  predicates and `consumed_at IS NULL`.
* `oidc.authorization_contexts`: `id` PK, epoch, `client_key_id`,
  `client_fingerprint bytea check 32`, `grant_key_id`, `grant_fingerprint bytea
  check 32`, `interaction_chain_key_id`, `interaction_chain_fingerprint bytea
  check 32`, `interaction_uid_key_id`, `interaction_uid_fingerprint bytea check
  32`, `provider_session_uid_key_id nullable`, `provider_session_uid_fingerprint
  bytea nullable check 32`,
  `control_session_key_id`, `control_session_fingerprint bytea check 32`,
  `authorization_code_key_id nullable`, `authorization_code_fingerprint bytea
  nullable check 32`, `mapping_id uuid`, `entitlement_id uuid`, `generation
  bigint check generation>0 and generation<=9223372036854775807`, `jkt char(43)`,
  `policy_snapshot_id uuid`, `policy_version text`, `created_at`, `expires_at`,
  `grant_expires_at`, `retained_until`, `revoked_at nullable`. Unique constraints
  are `(epoch,grant_key_id,grant_fingerprint)`,
  `(epoch,interaction_chain_key_id,interaction_chain_fingerprint,interaction_uid_key_id,
  interaction_uid_fingerprint)`, and partial
  `(epoch,authorization_code_key_id,authorization_code_fingerprint)` when code
  fields are non-null. Nonunique
  `(epoch,control_session_key_id,control_session_fingerprint)` supports logout.
  `expires_at > created_at` and
  `expires_at <= created_at + interval '300 seconds'`,
  `grant_expires_at = created_at + interval '900 seconds'`, and
  `retained_until = grant_expires_at + interval '30 seconds'`; revoked time is
  bounded by retention. Expiry and retention indexes exist.
* `oidc.interaction_csrf`: `id` PK, epoch, `csrf_key_id`, `csrf_fingerprint
  bytea check 32`, the client/interaction-chain/interaction fingerprint/key-id pairs,
  `created_at`, `expires_at`, `consumed_at nullable`, `retained_until`; unique
  `(epoch,csrf_key_id,csrf_fingerprint)` and an atomic `UPDATE ... WHERE
  consumed_at IS NULL AND expires_at>clock_timestamp()` consume path,
  `expires_at = created_at + interval '300 seconds'`,
  `retained_until = expires_at + interval '30 seconds'`, and consumed time
  between creation and retention. Unique
  `(epoch,interaction_uid_key_id,interaction_uid_fingerprint)` permits one CSRF
  row per interaction; expiry and retained-until indexes exist.
  A repeated interaction GET locks an existing unconsumed row and atomically
  replaces its CSRF key/fingerprint and all three lifecycle clocks before
  rendering a new token, invalidating the old token. A consumed interaction
  cannot reload and fails closed with generic HTML.
* `control_plane.entitlements` additions: non-null `oidc_epoch char(22)` with
  the base64url check, non-null session-binding key ID and 32-byte fingerprint,
  positive bounded `generation`. Existing `policy_snapshot_id` and its FK are
  preserved and validated, not re-added. Migration replaces legacy mapping/JKT
  uniqueness after the drained table is empty with one durable row per
  `(session_binding_key_id,session_binding_fingerprint,entitlement)`; each
  first successful non-cached verification inserts generation 1, and each later
  one atomically checks mapping/session identity, sets the configured epoch,
  JKT, policy snapshot/version, state active, authorization/expiry timestamps,
  sets `revoked_at=NULL` and required `reason='membership_verified'`, and
  increments generation with overflow
  rejection. Cached/rejected requests perform no write. Exact durable UNIQUE
  `(session_binding_key_id,session_binding_fingerprint,entitlement)` permits one
  row of each entitlement kind for the exact session binding; no redundant
  partial active index exists.

Contexts and CSRF deliberately have no restrictive source-row foreign keys and
outlive source artifacts. Runtime uses SELECT/INSERT/UPDATE only. A retention
role with no table privilege invokes only migration-owner execute-only cleanup.
Logical/physical deadlines are artifact expiry/+30 seconds, CSRF expiry/+30,
and context through Grant expiry (900 seconds)/+30; cleanup is CSRF, contexts,
then artifacts. External key deletion is an operator action after retained-key
preflight, never a database cleanup side effect. Keys remain until no retained
row references them.

Migration owner owns both schemas, every object, and
`oidc.cleanup_expired(p_now timestamptz)`, a SECURITY DEFINER function with fixed
safe search path. It captures `v_now := clock_timestamp()`, rejects NULL,
non-finite, or `p_now > v_now`, and deletes in the stated order only where
`retained_until <= p_now`. PUBLIC has no schema, relation, sequence, or function
privilege; default privileges are revoked. Runtime has `USAGE` on both schemas
and only explicit `SELECT,INSERT,UPDATE` on OIDC tables plus the already
manifested control-plane grants needed for the enumerated entitlement columns;
it has no DELETE, TRUNCATE, REFERENCES, TRIGGER, ownership, or cleanup EXECUTE.
Retention has `USAGE` on both schemas and EXECUTE only on
`control_plane.cleanup_expired` and `oidc.cleanup_expired`, with no table
privilege. Cleanup deletes expired CSRF, contexts, then artifacts. Exact
owners, grants, grant options, column ACLs, function body/attributes, defaults,
predicates, and absence of extra grantees are positive-catalog assertions.

All key-ID/fingerprint pairs are all-null or all-non-null as their model permits;
every artifact/configuration key ID matches `[a-z][a-z0-9_-]{0,31}`. Signing
`kid` matches `[A-Za-z0-9._-]{1,128}`. Context JKT is canonical
43-character base64url, policy version follows the membership grammar, and
client, mapping, entitlement, policy, and provider IDs are never accepted from
the browser form. Context `mapping_id`, `entitlement_id`, and policy snapshot are
opaque captured UUID values without cascading source FKs so the retained context
survives source revocation long enough to deny replay. CSRF contains only its
CSRF, Interaction chain CID, Interaction UID, and sole-client key/fingerprint
pairs plus lifecycle fields; it contains no control-session binding.
The session advisory-lock value is the signed big-endian 64-bit interpretation
of the first eight bytes of the stored control-session binding fingerprint;
collisions only over-serialize unrelated sessions.

## Migration, locking, and token atomicity

0004 is outage-only: stop old writers, block traffic, drain 930 seconds, lock
entitlements, delete only expired rows, assert none remain, then add only the
non-null epoch/session-binding/generation columns with no invented defaults and
validate the already-existing policy-snapshot column/FK.
Generation increments only for each newly committed, non-cached successful
verification; cached and rejected requests do not mutate it. The runner stores
versioned pre/post catalog manifests: an existing database validates frozen 0003
before 0004, applies 0004, installs exact ACLs for both schemas, then validates
the final 0004 catalog. A fresh install grants then final-asserts. Existing
versions never silently repair ACLs.

ALS is application-owned, initialized before routing, and wraps provider
middleware and interaction routes; setup never reads `Provider.ctx`. Initial
`/auth` and interaction GET use request transactions for provider/CSRF writes
but no session advisory lock. Every adapter mutation on every provider route
uses the ALS-bound checked-out client. Interaction POST, resolved `/auth/:uid`
resume, token exchange, and authenticated logout acquire the same
session-binding transaction advisory lock, refresh the PostgreSQL decision clock,
then lock in one order: control session, entitlement, active-policy
pointer/snapshot, authorization context, artifact/code, CSRF. This order governs
contended existing-row and advisory locks. A fresh random Grant insert has no
existing artifact row to lock and may precede its dependent context insert in the
same transaction. In every terminal POST branch, `interactionResult()` is awaited
first so its provider artifacts and output are staged, then the decision clock is
refreshed with exactly `SELECT clock_timestamp() AS decision_now`, and finally the
conditional CSRF consume uses that refreshed timestamp in its exact expiry
predicate; this consume is the final database mutation. Token handling may pre-resolve code to context without
trusting it, then re-resolves and revalidates under that order. During
authorization resume
`findAccount` only resolves the stored pairwise subject after the live decision;
during redemption it locks/revalidates context, session, entitlement, generation,
and policy from the captured DB clock.
Resume `/auth/:uid` permits only the exact terminal `{error:"access_denied",
error_description:"Access denied"}` Interaction result (exact `jti`/`cid`, no
Grant) to redirect without context, ALS mutation, or code issuance. Success
resumes pre-resolve the exact Interaction `jti`/`cid` and fresh-Grant context
only to derive the session advisory-lock value, carry that validated binding in
application ALS, then re-resolve and compare the same context under the advisory
and row locks before any adapter mutation or redirect.
The AuthorizationCode payload has no `cid`; its upsert may use only the ALS-bound
resume context plus its fresh `grantId`. AuthorizationCode persistence precedes
provider Session persistence in 9.9.1, so code upsert records a pending
`{context, code, sessionUid}` claim. After provider post-middleware confirms the
Session upsert, the application verifies the live matching Session artifact and
atomically finalizes both code and provider-Session fingerprints before commit.

AuthorizationCode save/claim binds exactly one unclaimed context to its code.
The exact matrix is: pre-consume/pre-revoke error rolls back all; consume plus
success commits all. Universally, any failure or cancellation after consume and
before successful commit—including present or future account, context, session,
entitlement, generation, policy, pairwise-subject, claims, RNG, encryption,
serialization, ALS, buffering, timeout, provider-hook, signing, rendering, or
storage failures—rolls back to the post-consume savepoint and commits consumption
only, except for the explicit savepoint-recovery and commit-failure branches;
reuse plus successful `revokeByGrantId` commits revocation. Missing savepoint or
savepoint-recovery failure fully rolls back and returns `server_error`. A COMMIT
attempt that returns a definite database error known not to have committed
discards the buffer and returns `server_error`; it does not reclassify ordinary
pre-COMMIT post-consume work as a full rollback. An
indeterminate COMMIT outcome poisons the connection, emits no buffered response,
and is treated like a post-commit disconnect because persistence may have
committed. A second exchange
blocks, observes consumed, then commits grant revocation. No access-token artifact
survives signing/rendering/storage failure before successful commit; definite
commit failure discards the buffered response. Headers, redirects, provider-
handled OAuth errors, and success bodies for every transactional outcome remain
buffered until the applicable commit succeeds. In particular, unsent headers
staged by `interactionResult()` are flushed only after commit. A post-commit disconnect may
burn code and leave its short-lived encrypted token.

`POST /v1/identity/logout` is a product route, not provider protocol. It uses
the existing strict JSON transport: exact same-origin `Origin`, one valid target
cookie or no cookie, `Accept: application/json`, exact JSON content type, no
content encoding or query, and body `{"version":"v1"}`. Success and already-
logged-out cases return `200 {"version":"v1","result":"logged_out"}` and
always clear the control cookie with its original attributes and `Max-Age=0`.
Invalid or duplicate target cookies return the existing coarse `400` response
and clear the cookie. Under the session advisory lock, one transaction revokes
the live control session, every unexpired authorization context bound to it,
and associated provider artifacts by Grant fingerprint. New authorization and
exchange fail afterward. Existing upstream access/ID tokens may remain usable
for at most 300 seconds. This route does not invalidate MAS or Matrix sessions;
Task 10 owns that work.
For logout, "unexpired context" means `grant_expires_at > decision_now`; the
shorter authorization `expires_at` never excludes a retained Grant association.

Logout uses the existing transport precedence exactly: route/query/method
(`405` includes `Allow: POST`), duplicate or malformed singleton headers `400`,
unacceptable/missing Accept `406`, wrong Content-Type or any Content-Encoding
`415`, declared/streamed body above 1024 raw octets `413`, wrong/missing Origin
`400`, malformed/duplicate target cookie `400`, then fatal UTF-8/duplicate-member/
schema errors `400`. Every non-405 response is the existing no-store/no-referrer
JSON profile. The exact `400` body is
`{"version":"v1","result":"rejected","error":"invalid_request"}`. A
well-formed but missing, unknown, expired, or revoked session is idempotent 200
logged-out and clears the cookie; only malformed/duplicate cookie syntax is 400.
The 406, 413, and 415 responses use that same exact `invalid_request` body. The
405 body is exactly `{"error":"method_not_allowed"}` with the same security
headers. Singleton duplicate checks cover Accept, Content-Type, Content-Encoding,
Content-Length, Origin, Cookie, Host, and every trusted forwarded header.
Definite database or transaction failure returns
`503 {"version":"v1","result":"rejected","error":"unavailable"}` without
clearing a well-formed valid cookie so the caller can retry; an indeterminate
commit emits no buffered response.

## Secrets and restoration

RSA keys are >=2048 bits and private JWK math (`n,e,d,p,q,dp,dq,qi`) is validated.
Each signing JWK has exactly `kty,n,e,d,p,q,dp,dq,qi,kid,use,alg`, with
`kty="RSA"`, `use="sig"`, `alg="RS256"`, canonical base64url unsigned-integer
members, and a nonempty bounded unique `kid`. The first key is deterministically
active and every key publishes only its public members. Old public keys remain
advertised for at least the 300-second token lifetime plus configured clock and
MAS JWKS-cache overlap.
Published JWKS is recursively exact `{"keys":[...]}`; each public entry has
exactly `kty,n,e,kid,use,alg` and no private or extra member. The harness pins
schema and emitted bytes for active/overlap order.
The MAS secret is canonical unpadded base64url of 32--256 random bytes. Provider
cookie/signing/client files are read through descriptors with `O_NOFOLLOW`, must
be regular, expected-owner, restrictive-mode, <=64 KiB, valid UTF-8 and strict
JSON where JSON, and fail startup otherwise; cookie keys are canonical 32-byte
base64url. The external restore-floor directory uses the same ownership and
symlink rules and remains outside database backup/PITR scope. Records are
immutable regular files named by zero-padded 20-digit contiguous sequence and
strict v2 JSON containing exactly `version`, `sequence`, whole-second RFC3339
`minimumIssuedAt`, canonical 32-byte base64url `previousHead`, and `activation`.
The activation contains the exact epoch, active ID plus sorted key-ID/SHA-256
fingerprint pairs for adapter and index rings, ordered cookie-key fingerprints,
the MAS client-secret fingerprint, and sorted signing `kid`/public-JWK
fingerprints. V3 additionally has `kind` (`restore` or `activation`) and ordered signing keys.
It contains no secret bytes. Visible bytes must be exactly UTF-8 `JSON.stringify` of the
validated record; no whitespace, alternate escaping, key order, or trailing bytes is accepted.
Each record hash uses its v2/v3 domain and those exact bytes. Publication creates or validates
a persistent owner-only `0700` `.staging` directory, writes and fsyncs one owner-only `0600`
unique candidate, hard-links it without replacement to the numeric name, then fsyncs the root.
Only that publisher's candidate is removed and staging is fsynced; orphan candidates are ignored.
A concurrent winner succeeds only for an exact retry. Filename sequence must equal JSON `sequence`. Startup scans
and validates the full chain, rejects gaps, duplicates, invalid entries, a
`restore` `minimumIssuedAt` that does not strictly increase, an `activation`
floor that does not exactly preserve its predecessor, or previous-head mismatch. A cumulative
domain-separated SHA-256 head commits each exact record. Startup must match the
latest computed head to independently managed `OIDC_RESTORE_FLOOR_HEAD` and
match current runtime material to the latest activation. The initial empty
chain has one fixed published head. Prefix truncation therefore fails unless
the external configuration anchor is also rolled back; that config/WORM store
is an explicit trust boundary outside database backup/PITR. Each new floor is the first whole UTC second
strictly after both trusted restore time and the previous floor. No secret or
payload is logged. Activation candidates retain shared adapter/index IDs with
exactly the same symmetric material and shared signing `kid`s with exactly the
same public JWK; any candidate reuse of current OIDC symmetric bytes is allowed
only within its identical historical purpose (and adapter/index ID).

Restore uses the isolated normative runbook `docs/runbooks/oidc-restore.md`.
Traffic remains blocked. In the isolated restored database, escrowed backup-era
keys first authenticate/decrypt representative retained rows and canaries; only
then migration owner purges all OIDC rows and the exact control-plane ephemeral
rows listed in the runbook, all control sessions/entitlements, and the active-
policy pointer in FK-safe order. Ninety-day audit rows, DID mappings, policy
snapshots, and their envelopes remain with referenced keys. Sessions are deleted
rather than assigned an invalid late revocation timestamp. Fresh artifact epoch,
adapter/index/cookie keys, and RS256 signing keys are installed. Restore JWKS is
fresh-only with every backup-era `kid` absent; MAS cache is restarted/evicted,
new-key validation and old-`kid` rejection are proven, and every backup-era
private signing key is destroyed before traffic. All backup-required keys travel in
separate escrow; only unreferenced OIDC keys are destroyed. No database active
policy survives restore. The next append-only external floor record sets
`minimumIssuedAt` to the first whole UTC second strictly after the trusted
restore clock; operators must create a newly root-signed policy with
`issuedAt >= minimumIssuedAt` and live-verified Foundation provenance. The
refresh and live-authorization paths enforce the selected latest floor. The floor remains an
immutable append-only external record outside database backup/PITR scope and is
read by every later startup/refresh. If Foundation or the signer is unavailable,
traffic remains blocked. This avoids reliance on a rollbackable database high-
water mark. Before traffic, catalog, retained-key,
decryption, and plaintext-canary gates pass. Continuation of a pre-restore
authorization is unsupported without an external replay ledger. Restore audit
metadata is a restricted external operational record, not a new free-form DB
column or event. Tests cover restore before consume, logout, regeneration, and
policy revocation.

Normal rotation is outage-only. Block all writers and deploy one uniform
configuration. Adapter AES, index HMAC, and cookie keys retain old entries until
preflight proves no retained row can use them. Old cookie keys remain for at
least 900 seconds plus configured clock skew after the last old-key cookie was
emitted; browser-cookie expiry, not a DB query, is the removal proof. An epoch change requires
a 930-second drain and offline OIDC-row purge; mixed epochs and dual writes are
prohibited. Signing rotation publishes the new public key before it becomes
first/active and retains old public overlap. MAS client-secret rotation is
coordinated while traffic is blocked. Rollback is allowed only before any
new-key/new-epoch row, token, or cookie is emitted. Retained-key preflight includes
entitlement binding keys and every artifact/context/CSRF key-ID column.
