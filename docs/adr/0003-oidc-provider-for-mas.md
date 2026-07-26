# ADR 0003: Use `oidc-provider` for MAS Upstream OIDC

## G2 external activation records

The external ledger retains v2 restore records unchanged. G2 adds typed v3
restore and activation records: restore advances the policy issue floor, while
outage-only activation non-destructively binds new material at the same floor.
This preserves pre-G2 external semantics and audits active signing-key order.

## Status

Accepted for Task 6 design and implementation. This ADR does not assert OpenID
Foundation certification for this deployment; official conformance is a named
external pre-G2 gate.

## Context

MAS needs an upstream OpenID Connect provider that can make a short-lived,
session-bound membership decision without receiving Matrix credentials in the
Node control plane. Handwritten discovery, authorization, token, and JWKS
endpoints would create an unacceptable protocol-critical surface.

## Decision

Use exact ESM package `oidc-provider@9.9.1` on Node 24. It is an OpenID
Certified provider. Its public provider protocol endpoints, including discovery,
authorization, token, and JWKS, MUST be used; the application MUST NOT
handwrite them.

The issuer is exactly `${PWA_ORIGIN}/oidc` and startup MUST fail unless its
origin exactly equals `PWA_ORIGIN`. The provider is mounted under `/oidc` and
uses only the fixed custom interaction route `/oidc/interaction` for GET and
POST. It serves one configured opaque confidential MAS client, with exact
`OIDC_SECTOR` and one exact callback URI as specified by the MAS upstream OIDC
contract.

The provider uses encrypted PostgreSQL adapter storage in the `oidc` schema, an
external 16-byte artifact epoch, RS256 signing only, a narrow enabled protocol
surface, and a per-authorization fresh Grant. `loadExistingGrant` reads only
the current custom prompt result's Grant ID, never a historical provider-session
Grant. Authentication and token redemption are bound to the active
control session and exact verified entitlement, not to a provider cookie or
Grant. The five-model adapter allowlist, exact serialized payload, fingerprint
and AAD grammars, and public middleware/adapter/`findAccount` token-transaction
seam are compatibility surfaces protected by a pinned-version harness.

The internal provider token route is `/token`; the only corresponding external
route is `/oidc/token`. The harness proves exact external and disabled route
behavior, both provider-owned OAuth metadata routes, exact ID-token claims,
discovery fixture metadata, payload shape, provider handled-error commit
behavior, and consume/savepoint/reuse ordering before production implementation
and every provider upgrade.

## Consequences

- Upgrades of `oidc-provider` require compatibility-harness review before use.
- The Node service necessarily receives MAS's upstream authorization code and
  client authentication at its provider endpoint. Its access token is an
  upstream OIDC artifact issued to MAS; Node MUST NOT receive MAS-issued
  downstream Matrix OAuth tokens, refresh tokens, callbacks, or Matrix routes.
- Task 6 blocks new authorization and exchange after lapse or revocation, but
  cannot retract issued MAS or Matrix tokens. Task 10 owns downstream
  backchannel and administrative revocation.
- Product logout is a strict coarse-JSON control-plane endpoint, not OIDC RP
  logout; interaction validation is fixed HTML or safe provider redirect.
- Signing rotation must overlap published public keys. Adapter/index/cookie
  activation, artifact-epoch changes, and client-secret rotation require the
  normative blocked-writer procedure. Backup restore invalidates all OIDC
  continuity and requires fresh live policy bootstrap before traffic.

## Alternatives considered

### Handwritten OAuth/OIDC endpoints

Rejected. Discovery, authorization, token handling, JWKS, and protocol error
semantics are security-critical and MUST remain provider-owned.

### A broad multi-client or dynamic-registration provider

Rejected. MAS is the sole intended relying party; broader client and grant
surfaces create unsupported authorization paths.
