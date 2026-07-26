import type { IncomingMessage, ServerResponse } from 'node:http';
// oidc-provider intentionally does not publish declarations.
// @ts-expect-error exact, isolated ESM dependency
import Provider, { errors, interactionPolicy } from 'oidc-provider';
import type { Config } from '../config.js';
import type { OidcSecrets } from './secrets.js';
import { requireOidcRequestContext } from './request-context.js';

export type OidcProvider = Readonly<{
  callback(): (request: IncomingMessage, response: ServerResponse) => void;
  use(middleware: (context: { oidc?: { route?: string } }, next: () => Promise<void>) => Promise<void>): void;
  interactionDetails(request: IncomingMessage, response: ServerResponse): Promise<Record<string, unknown>>;
  interactionResult(request: IncomingMessage, response: ServerResponse, result: Record<string, unknown>, options?: Record<string, unknown>): Promise<string>;
  interactionFinished(request: IncomingMessage, response: ServerResponse, result: Record<string, unknown>, options?: Record<string, unknown>): Promise<void>;
  Grant: { new (payload: { accountId: string; clientId: string }): { addOIDCScope(scope: string): void; save(ttl?: number): Promise<string> }; find(id: string): Promise<unknown> };
  proxy: boolean;
}>;
export type OidcHooks = Readonly<{ findAccount: (context: unknown, accountId: string) => Promise<unknown>; pairwiseIdentifier: (context: unknown, accountId: string, client: unknown) => Promise<string>; loadExistingGrant?: (context: unknown) => Promise<unknown>; tokenLifetime?: () => number }>;
export type AdapterFactory = new (modelName: string) => unknown;
const tokenTtl = (): number => { const ttl = requireOidcRequestContext().pendingTokenRedemption?.ttl; if (!ttl) throw new Error('token lifetime unavailable'); return ttl; };
/** Creates the protocol library boundary; persistence and decisions are injected by its caller. */
export function createOidcProvider(config: Pick<Config, 'OIDC_ISSUER' | 'MAS_CLIENT_ID' | 'MAS_REDIRECT_URI'>, secrets: OidcSecrets, adapter: AdapterFactory, hooks: OidcHooks): OidcProvider {
  const policy = interactionPolicy.base();
  policy.add(new interactionPolicy.Prompt({ name: 'dsa_signal_fresh_entitlement', requestable: false }, new interactionPolicy.Check('fresh_entitlement_required', 'a fresh holder-bound entitlement decision is required', 'interaction_required', (context: { oidc: { result?: { dsa_signal_fresh_entitlement?: { verified?: boolean } } } }) => context.oidc.result?.dsa_signal_fresh_entitlement?.verified !== true)), 0);
  const holder: { instance?: OidcProvider } = {};
  const instance = new Provider(config.OIDC_ISSUER, {
    adapter,
    clients: [{ client_id: config.MAS_CLIENT_ID, client_secret: Buffer.from(secrets.clientSecret).toString('base64url'), redirect_uris: [config.MAS_REDIRECT_URI], response_types: ['code'], grant_types: ['authorization_code'], response_modes: ['query'], token_endpoint_auth_method: 'client_secret_basic', subject_type: 'pairwise', require_auth_time: true }],
    clientDefaults: { response_types: ['code'], grant_types: ['authorization_code'], token_endpoint_auth_method: 'client_secret_basic', subject_type: 'pairwise' }, responseTypes: ['code'], clientAuthMethods: ['client_secret_basic'], scopes: ['openid', 'dsa_signal_entitlement'], subjectTypes: ['pairwise'], jwks: { keys: secrets.signingKeys },
    cookies: { keys: secrets.cookieKeys.map((key) => Buffer.from(key).toString('base64url')), names: { session: '__Host-dsa_signal_oidc_session', interaction: 'dsa_signal_oidc_interaction', resume: 'dsa_signal_oidc_interaction_resume' }, long: { httpOnly: true, sameSite: 'lax', secure: true, path: '/' }, short: { httpOnly: true, sameSite: 'lax', secure: true } },
    claims: { openid: ['sub'], dsa_signal_entitlement: ['dsa_signal_entitlement_policy_version'] },
    extraParams: { dsa_signal_contract(context: { oidc: { params: Record<string, string | undefined> } }) { const { nonce, scope, state } = context.oidc.params; if (!state || !nonce) throw new errors.InvalidRequest('state and nonce are required'); if (scope !== 'openid dsa_signal_entitlement') throw new errors.InvalidScope('exact scopes are required'); } },
    conformIdTokenClaims: false, findAccount: hooks.findAccount, pairwiseIdentifier: hooks.pairwiseIdentifier, loadExistingGrant: hooks.loadExistingGrant ?? (async (context: { oidc?: { result?: { consent?: { grantId?: unknown } } } }) => { const grantId = context.oidc?.result?.consent?.grantId; const current = holder.instance; return typeof grantId === 'string' && current ? current.Grant.find(grantId) : undefined; }),
    features: { attestClientAuth: { enabled: false }, backchannelLogout: { enabled: false }, ciba: { enabled: false }, claimsParameter: { enabled: false }, clientCredentials: { enabled: false }, clientIdMetadataDocument: { enabled: false }, dPoP: { enabled: false }, devInteractions: { enabled: false }, deviceFlow: { enabled: false }, encryption: { enabled: false }, externalSigningSupport: { enabled: false }, fapi: { enabled: false }, introspection: { enabled: false }, jwtIntrospection: { enabled: false }, jwtResponseModes: { enabled: false }, jwtUserinfo: { enabled: false }, mTLS: { enabled: false }, pushedAuthorizationRequests: { enabled: false }, registration: { enabled: false }, registrationManagement: { enabled: false }, requestObjects: { enabled: false }, resourceIndicators: { enabled: false }, revocation: { enabled: false }, richAuthorizationRequests: { enabled: false }, rpInitiatedLogout: { enabled: false }, rpMetadataChoices: { enabled: false }, userinfo: { enabled: false }, webMessageResponseMode: { enabled: false } },
    pkce: { required: () => true, methods: ['S256'] }, ttl: { AuthorizationCode: 60, AccessToken: hooks.tokenLifetime ?? tokenTtl, IdToken: hooks.tokenLifetime ?? tokenTtl, Session: 900, Grant: 900, Interaction: 300 }, routes: { authorization: '/auth', token: '/token', jwks: '/jwks' }, interactions: { policy, url: () => '/oidc/interaction' },
  }) as OidcProvider;
  holder.instance = instance;
  (instance as unknown as { proxy: boolean }).proxy = true;
  return instance;
}
