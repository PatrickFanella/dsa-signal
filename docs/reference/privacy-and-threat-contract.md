# Privacy and Threat Contract

## Scope and acceptance

This is the G0 contract for the initial membership-gated Matrix E2EE chat
boundary. “E2EE” means a participating PWA necessarily decrypts message and
attachment plaintext. Only server-side `dsa-signal` services must not receive
that plaintext or private room keys: Node, Synapse, MAS, databases, media
storage, observability/support systems, backups, push infrastructure, and
their operators are server-side services for this invariant.

Product, security, API, data, and operations acceptance is required before
Task 2 begins. This product is not interoperable with Signal and does not
make “Signal-grade,” “Signal clone,” or “secure messenger” claims before the
hardened PWA gate.

Acceptance was recorded on 2026-07-16: the product owner explicitly accepted
the residual limits, and security, API, data, and operations review found no
remaining G0 blocker after the cross-document credential boundary was aligned.
This acceptance authorizes Task 2 only; later delivery gates still require
their named reviews.

## Explicit limits and invariants

- Matrix can expose account, room, membership, device, IP, timing, event-size,
  push, and media-access metadata. This Matrix social graph metadata can let
  operators infer relationships.
- A compromised web origin can serve JavaScript that steals client keys. A PWA
  therefore lacks the operator-compromise resistance of a reproducibly built,
  signed native client.
- Revocation and room-key rotation block future authorization and future-key
  access; plaintext or keys previously downloaded by a removed member are
  irreversible.
- There is no plaintext fallback: unencrypted rooms and unencrypted sends fail
  closed.
- Matrix v1.16 / matrix-js-sdk v42 cross-user SAS necessarily exposes standard
  verification-control event metadata to Synapse. This narrowly approved
  exception covers only exact SDK-v42 verification request/state-machine
  schemas and required relation metadata. The initial request may use the
  standard outer `m.room.message` with exact
  `msgtype: m.key.verification.request`; later control events may expose
  protocol-mandated public ephemeral keys, commitments, hashes, and MAC fields.
  It never permits chat bodies, attachments, private/secret keys, derived SAS
  values, or arbitrary application content server-side.
- `dsa-proto` is excluded from downstream membership and Matrix operation: it
  must not store membership/entitlement credentials, downstream Matrix
  credentials, rosters, chat metadata, or messages. It legitimately holds its
  own ATProto session credentials to provide authenticated DID identity,
  public organizational records, and authority provenance.
- Calls are outside the initial security boundary. TURN/SFU, Element Call,
  LiveKit, and MatrixRTC require a separate review; no unsupported client may
  silently downgrade to server-readable media.

## Trust-boundary register

For each boundary, “plaintext” means message or attachment plaintext;
“metadata” includes the observable information listed below. Credentials are
only credentials held at that boundary. Every failure must deny the sensitive
operation rather than select an unencrypted or broader-privilege path.

| Boundary | Visible plaintext | Visible metadata | Credentials held | Fail-closed behavior |
| --- | --- | --- | --- | --- |
| Participating client | Its decrypted messages and attachments | Its accounts, rooms, membership, devices, timing, IP/network context, event sizes, and media access | Matrix OAuth tokens, device/room keys, cross-signing/recovery material, and holder proof key | Do not sync/send until Rust crypto, encrypted room state, storage, and device-trust policy are available. |
| Web origin | None by design, but a compromised origin can execute code in the client and steal plaintext/keys | Requests, releases, IP, timing, and browser characteristics | Deployment/signing and delivery credentials; malicious delivered code may reach client-held secrets | CSP, no third-party scripts, and origin controls are later gates; suspected compromise disables delivery rather than claiming key safety. |
| Node control plane | None | Pairwise subject, entitlement decision/status, issuer/policy version, audit timestamps and reason codes | OIDC/provider keys, encrypted DID mapping, and control-plane session material; never Matrix tokens | Reject absent, expired, replayed, wrong-audience, wrong-origin, unbound, or stale-policy entitlement proofs; never proxy Matrix traffic. |
| Membership credential issuer | Membership decision and credential issuance inputs, not chat plaintext and never the control-plane proof challenge | Subject, issuer, entitlement, issuance/expiry, and JTI | Issuer signing keys and membership authority data | Refuse unsigned, expired, audience-mismatched, or unbound issuance; do not disclose roster data to chat services. |
| `dsa-proto` | None | Authenticated DID identity, public organizational records, and authority provenance | Its own ATProto identity/session credentials only; never membership/entitlement credentials or downstream Matrix credentials | Login handoff is audience-bound, brief, and one-time; no membership/entitlement credentials, downstream Matrix credentials, rosters, chat metadata, or messages are persisted. |
| MAS | None | Account/subject, login/grant, client, IP, timing, and token lifecycle metadata | MAS sessions, authorization codes, and Matrix OAuth access/refresh tokens | Exact redirect/client policy and entitlement lapse deny authorization; tokens go directly between browser and MAS, never Node. |
| Synapse | No chat or attachment plaintext; encrypted application events plus narrowly approved exact SDK-v42 verification-control schemas only, including the standard initial verification-request `m.room.message` envelope | Matrix account, room, membership, device, verification-control linkage/public ephemeral values, IP, timing, event size, event routing, and media-access metadata | Server/service credentials and ciphertext; no private/secret room or verification keys and no derived SAS values | Disable federation, guests, public directory, registration, password login, bridges, previews, remote media, and identity lookup; reject unencrypted application chat events, nonstandard verification fields, and any other plaintext application content. |
| Control-plane and Matrix databases | None; ciphertext and minimal control-plane records only | Stored account/room/event or narrowly allowed entitlement metadata: encrypted DID mapping reference, JKT, audience/origin, issuer/policy/decision/timestamps, and versioned keyed replay/idempotency fingerprints with expiry | Database credentials and encrypted-at-rest data | Schema/policy rejects message plaintext, credential bodies, raw challenges/JTIs/idempotency keys/request bodies, rosters, Matrix tokens, and room-state copies; unavailable storage denies authorization. |
| Media storage | None; opaque bytes whose plaintext/ciphertext status it cannot prove | Object identifier, size, upload/download time, requester/access metadata | Storage and authenticated-media credentials; no attachment keys | Storage only authenticates access and stores opaque bytes; clients encrypt before upload and verify the ciphertext hash before use, denying hash/authentication failures. |
| Push infrastructure | None | Device/push token, delivery timing, and notification metadata | Push provider credentials and device tokens | No plaintext notification content; disable or minimize notifications if safe encrypted delivery is unavailable. |
| Logs, metrics, traces, and support tooling | None | Redacted service, request, account/room identifier, timing, size, error, and operational metadata | Observability and support access credentials; never user, Matrix, recovery, or room-key credentials | Redaction/scrubbing failure, unknown field, or plaintext canary blocks export and support access rather than recording sensitive data. |
| Backups | None | Encrypted database/object backup metadata, backup time, size, retention, and restore audit metadata | Backup encryption, storage, and restore credentials; never plaintext, Matrix tokens, recovery keys, or room keys | Backup jobs reject plaintext/credential bodies; failed encryption, retention, or restore authorization stops backup/restore. |
| TLS terminators and reverse proxies | None while TLS is correctly terminated; encrypted Matrix event/media payload bytes may transit after TLS termination | Client/server IP, host/SNI, path, request timing, sizes, status, and routing metadata | TLS private keys and proxy/service authentication credentials; no E2EE room or attachment keys | Certificate, upstream TLS, route, or authentication failure denies the request; never downgrade to plaintext HTTP or bypass authentication. |
| TURN/SFU and calls infrastructure | Not in scope for initial chat; no chat plaintext | For any later call: IP, timing, participant, routing, and media-access metadata | Later call/TURN/SFU credentials | Calls are outside this boundary and remain disabled until a separate review proves E2EE and denies unsupported-browser downgrade. |
| Network observer | None when TLS/E2EE operate correctly | IP endpoints, DNS/TLS characteristics, timing, packet/event sizes, and traffic volume | None | TLS/certificate or protocol failure stops connection; never retry with plaintext transport. |
| Malicious member | Plaintext and keys they are authorized to decrypt, including previously downloaded material | Their rooms, members, message timing, sizes, and shared media access | Their client tokens, device/room keys, and recovery material | Removal and rotation block future authorization/keys, not prior plaintext; clients do not treat recipient deletion as erasure. |
| Stolen device | Locally available decrypted content and keys while unlocked or recoverable | Its account, device, room, network, and activity metadata | Device tokens, device/room keys, and possibly recovery/cross-signing material | Revoke device and rotate future keys; require verification/recovery policy and never promise recovery of already exposed plaintext. |
| Compromised operator | No server-held plaintext/room keys by design; a web-origin operator may steal client material | All infrastructure-visible Matrix and operations metadata, including social graph inferences | Infrastructure, deployment, database, MAS, and service credentials | E2EE does not solve web-origin compromise; incident response stops unsafe origin/service operation and no plaintext mode is permitted. |
| Client dependency compromise | A compromised dependency executing in the participating client can expose its plaintext and keys | Build, package, runtime, browser, and network telemetry available to that dependency | Client-reachable Matrix tokens, device/room keys, recovery material, and holder proof key | Integrity/provenance or review failure blocks client release; do not claim E2EE protects a client from code it executes. |
| Server/build dependency compromise | No plaintext or room keys by the server-side invariant, unless it compromises a client-delivery path | Build, package, runtime, deployment, and infrastructure telemetry available to that dependency | Build/package, deployment, and server/service credentials reachable in its process | Integrity/provenance or review failure blocks build, deployment, or service operation; never weaken crypto, transport, or access policy. |

## Operational assertions

The control plane never receives Matrix access or refresh tokens, Matrix events,
room state, attachment bytes, recovery keys, or cross-signing secrets. Logs,
metrics, traces, backups, and support tooling must redact credentials and never
record plaintext. Later verification must search all server-side stores and
captures for plaintext canaries and must prove revocation prevents decryption
of messages sent after removal/key rotation while acknowledging prior content
remains available to a malicious recipient.

The Task 9 ciphertext scan distinguishes approved Matrix verification-control
metadata from application chat content. Exact SDK-v42 verification schemas may
be visible to Synapse, including the initial standard verification-request
`m.room.message`, required relations, and protocol-mandated public ephemeral
keys, commitments, hashes, and MAC fields. The unique chat canary, derived SAS
values, private/secret keys, and application message bodies must remain absent
from every wire/server representation. This exception was explicitly approved by the repository
operator on 2026-07-22 because matrix-js-sdk v42 provides no supported
metadata-private, room-bound cross-user SAS transport.
