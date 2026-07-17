# ADR 0002: Use Matrix as the E2EE Communications Substrate

## Status

Accepted conditionally for the G0 design gate. Product, security, API, data,
and operations acceptance is required before Task 2 begins; those human
approvals are not asserted by this ADR. Subsequent delivery gates remain
required for production use.

## Context

`dsa-signal` needs a web/PWA-first, membership-gated communications system.
Membership authority originates with `dsa-proto`, but it must not store
membership/entitlement credentials, downstream Matrix credentials, rosters,
Matrix metadata, or messages. It may hold its own ATProto session credentials.
The initial release must provide encrypted one-to-one chat without designing a
new cryptographic messaging protocol.

The principal alternative is a greenfield OpenMLS deployment. MLS supplies a
group key-agreement protocol, but not message delivery, device lifecycle,
encrypted media handling, key backup and recovery, browser-client integration,
or an audited browser client. Building those layers would enlarge the security
critical surface and delay an independently testable encrypted vertical slice.

## Decision

Use a private, non-federating Matrix deployment as the messaging substrate:

- Synapse provides Matrix transport and stores ciphertext events.
- Matrix Authentication Service (MAS) authenticates Matrix users through the
  control plane's standards-compliant upstream OIDC integration.
- The React PWA talks directly to MAS, Synapse, and Matrix media endpoints;
  it uses `matrix-js-sdk` Rust/WASM crypto for client-side E2EE.
- The Node control plane handles only `dsa-proto` identity handoff, private
  membership-entitlement proof, issuer policy, and upstream OIDC. It never
  receives or proxies Matrix access/refresh tokens, events, room state,
  attachments, recovery keys, or cross-signing secrets.
- Federation, guest access, public room discovery, open registration, legacy
  password login, bridges, URL previews, remote media, and identity-server
  lookup will be disabled. Application-created rooms must be invite-only and
  encrypted.

This decision is conditional: Matrix E2EE must be initialized and enforced by
the browser before sync/send, and the deployment and browser behavior must
pass the later policy and ciphertext-only verification gates. Calls are a later
experimental subsystem, outside this decision's initial security boundary,
pending a separate MatrixRTC/LiveKit review.

## Consequences

- The project gains an established transport, device model, encrypted-media
  path, recovery ecosystem, and maintained browser crypto implementation
  rather than creating them around OpenMLS.
- A participating PWA necessarily decrypts message and attachment plaintext;
  only server-side `dsa-signal` services (including Matrix infrastructure and
  associated operations systems) receive no plaintext or private room keys.
- Matrix still exposes service-visible account, room, membership, device, IP,
  timing, event-size, push, and media-access metadata. Operators can infer a
  social graph, which product owners must explicitly accept before production.
- A compromised web origin can deliver JavaScript that steals client keys, so
  this PWA does not claim the operator-compromise resistance of a reproducibly
  built, signed native client.
- Removing a member blocks future authorization and future-key access after
  rotation, but cannot retract plaintext or keys previously downloaded by that
  member.
- There is no plaintext fallback: unencrypted rooms and sends fail closed.

## Alternatives considered

### Greenfield OpenMLS

Rejected for the initial product. It would still require secure delivery,
device enrollment and verification, media encryption and storage, key backup
and recovery, browser storage coordination, a usable audited web client, and
operations tooling. Those missing components are at least as consequential as
the MLS primitive and would make the initial boundary less reviewable.

### Server-readable chat

Rejected. It violates the requirement that server-side systems receive neither
message/attachment plaintext nor private room keys, and it would create a
plaintext fallback that this project expressly forbids.
