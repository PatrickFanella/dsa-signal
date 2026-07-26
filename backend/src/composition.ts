import { FoundationClient } from '@dsaslate/foundation-client';
import type { Pool } from 'pg';
import type { Config } from './config.js';
import { createChallengeService } from './entitlements/challenge-service.js';
import { createVerificationService } from './entitlements/verify-entitlement.js';
import { FoundationService } from './foundation/foundation-service.js';
import { createSessionRepository } from './identity/session-repository.js';
import { PolicyRefreshService } from './refresh-policy.js';
import { createOidcAdapter } from './oidc/adapter.js';
import { createAuthorizationCodeClaim, createAuthorizationHooks, createResumePreflight, createTokenPreflight } from './oidc/authorization-decision.js';
import { createInteractionHandler } from './oidc/interaction.js';
import { createOidcProvider } from './oidc/provider.js';
import { assertOidcSecretSeparation, type OidcSecrets } from './oidc/secrets.js';
import { createOidcDispatcher, createTransactionalProviderInvocation } from './routes/oidc.js';
import { createLogoutService } from './routes/auth.js';
import type { AppDependencies } from './server.js';

export type Composition = AppDependencies & Readonly<{ policyRefresh: PolicyRefreshService; minimumIssuedAt: number }>;
export const FOUNDATION_RESPONSE_MAX_BYTES = 65_536;

/** Deliberately coarse: Foundation response details are never an application diagnostic. */
export class FoundationResponseUnavailableError extends Error {
  constructor() { super('Foundation response unavailable'); this.name = 'FoundationResponseUnavailableError'; }
}

function declaredLength(headers: Headers): number | undefined {
  const value = headers.get('content-length');
  if (value === null) return undefined;
  if (!/^(?:0|[1-9]\d*)$/.test(value)) throw new FoundationResponseUnavailableError();
  const length = Number(value);
  if (!Number.isSafeInteger(length)) throw new FoundationResponseUnavailableError();
  return length;
}

/** Bounds bytes before the published client performs status or JSON handling. */
export function createBoundedFoundationFetch(underlyingFetch: typeof fetch): typeof fetch {
  return async (input, init) => {
    let response: Response;
    try { response = await underlyingFetch(input, init); } catch { throw new FoundationResponseUnavailableError(); }
    try {
      const length = declaredLength(response.headers);
      if (length !== undefined && length > FOUNDATION_RESPONSE_MAX_BYTES) {
        await response.body?.cancel().catch(() => undefined);
        throw new FoundationResponseUnavailableError();
      }
      if (!response.body) throw new FoundationResponseUnavailableError();
      const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
      try {
        while (true) {
          const next = await reader.read();
          if (next.done) break;
          if (next.value.byteLength > FOUNDATION_RESPONSE_MAX_BYTES - size) {
            await reader.cancel().catch(() => undefined);
            throw new FoundationResponseUnavailableError();
          }
          chunks.push(next.value); size += next.value.byteLength;
        }
      } catch (error) {
        await reader.cancel().catch(() => undefined);
        if (error instanceof FoundationResponseUnavailableError) throw error;
        throw new FoundationResponseUnavailableError();
      }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return new Response(bytes, { status: response.status, statusText: response.statusText, headers: response.headers });
    } catch (error) {
      if (error instanceof FoundationResponseUnavailableError) throw error;
      throw new FoundationResponseUnavailableError();
    }
  };
}

export function createComposition(config: Config, pool: Pool, underlyingFetch: typeof fetch = fetch, oidcSecrets?: OidcSecrets, minimumIssuedAt = 0): Composition {
  if (oidcSecrets) assertOidcSecretSeparation(config, oidcSecrets);
  const foundationClient = new FoundationClient(config.FOUNDATION_BASE_URL, { fetch: createBoundedFoundationFetch(underlyingFetch) });
  const foundation = new FoundationService(foundationClient);
  const policyRefresh = new PolicyRefreshService(pool, foundation, config.ROOT_PUBLIC_JWKS, config.AUTHORITY_POLICY_VERSION, {
    active: { id: config.ENVELOPE_KEY_RING.active, key: config.ENVELOPE_KEY_RING.keys[config.ENVELOPE_KEY_RING.active]! },
    keys: Object.entries(config.ENVELOPE_KEY_RING.keys).map(([id, key]) => ({ id, key })),
  }, config.POLICY_MAX_STALENESS_SECONDS, minimumIssuedAt);
  const sessions = createSessionRepository({ pool, pwaOrigin: config.PWA_ORIGIN, sector: config.OIDC_SECTOR, subjectKeys: config.SUBJECT_KEY_RING, envelopeKeys: config.ENVELOPE_KEY_RING, bindingKeys: config.SESSION_BINDING_KEY_RING });
  const oidcDispatcher = oidcSecrets === undefined ? undefined : (() => {
    const index = config.OIDC_INDEX_KEY_RING;
    const adapter = createOidcAdapter(
      { epoch: config.OIDC_EPOCH, adapter: config.OIDC_ADAPTER_KEY_RING, index },
      createAuthorizationCodeClaim(config.OIDC_EPOCH, index),
      createTokenPreflight(config.OIDC_EPOCH, config.MAS_CLIENT_ID, index, minimumIssuedAt),
    );
    const provider = createOidcProvider(
      config,
      oidcSecrets,
      adapter,
      createAuthorizationHooks(config.OIDC_EPOCH, index),
    );
    const interaction = createInteractionHandler({
      pool,
      provider,
      epoch: config.OIDC_EPOCH,
      clientId: config.MAS_CLIENT_ID,
      redirectUri: config.MAS_REDIRECT_URI,
      origin: config.PWA_ORIGIN,
      cookieKey: config.COOKIE_KEY,
      indexKeys: index,
      bindingKeys: config.SESSION_BINDING_KEY_RING,
      minimumIssuedAt,
    });
    return createOidcDispatcher(
      { issuer: config.OIDC_ISSUER, trustedProxyAddress: config.OIDC_TRUSTED_PROXY_ADDRESS },
      provider,
      interaction,
      createTransactionalProviderInvocation(pool, provider, createResumePreflight(config.OIDC_EPOCH, index, adapter, minimumIssuedAt)),
    );
  })();
  return {
    config,
    foundation,
    policyRefresh,
    minimumIssuedAt,
    sessions,
    logout: createLogoutService({ pool, oidcEpoch: config.OIDC_EPOCH, bindingKeys: config.SESSION_BINDING_KEY_RING }),
    challenges: createChallengeService({ pool, challengeKeys: config.CHALLENGE_KEY_RING, bindingKeys: config.SESSION_BINDING_KEY_RING, pwaOrigin: config.PWA_ORIGIN, policyRefresh }),
    verifications: createVerificationService({ pool, envelopeKeys: config.ENVELOPE_KEY_RING, challengeKeys: config.CHALLENGE_KEY_RING, bindingKeys: config.SESSION_BINDING_KEY_RING, jtiKeys: config.JTI_KEY_RING, idempotencyKeys: config.IDEMPOTENCY_KEY_RING, requestKeys: config.REQUEST_FINGERPRINT_KEY_RING, revocationEvidenceKeys: config.REVOCATION_EVIDENCE_KEY_RING, oidcEpoch: config.OIDC_EPOCH, pwaOrigin: config.PWA_ORIGIN, sector: config.OIDC_SECTOR, policyRefresh }),
    ...(oidcDispatcher ? { oidcDispatcher } : {}),
  };
}
