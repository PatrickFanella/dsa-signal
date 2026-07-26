/** SDK-free, fail-closed orchestration for the browser-direct Matrix OAuth flow. */
import { canonicalProfileId } from './canonical-profile';
import { commitWhoamiSession, type ProfileLockPort } from '../matrix/create-client';
import { equalEndpointMetadata, type ActiveProfileLocator, type EndpointMetadata, type IndexedDbSessionStore, type MatrixSession, type OAuthAttempt, type RefreshTokens } from './session-store';
import { MATRIX_AUTHORIZATION_ENDPOINT, MATRIX_CLIENT_METADATA_VERSION, MATRIX_HOMESERVER, MATRIX_ISSUER, MATRIX_REDIRECT_URI, MATRIX_REGISTRATION_ENDPOINT, MATRIX_REVOCATION_ENDPOINT, MATRIX_TOKEN_ENDPOINT } from './matrix-topology';
import type { OAuthCallback } from './oauth-callback';
import { parseMatrixUserId } from '../matrix/identifiers';
export { MATRIX_AUTHORIZATION_ENDPOINT, MATRIX_HOMESERVER, MATRIX_ISSUER, MATRIX_REDIRECT_URI } from './matrix-topology';
export { captureAndScrubOAuthCallback, OAuthAbortError, type OAuthBrowser, type OAuthCallback } from './oauth-callback';
const B64URL43 = /^[A-Za-z0-9_-]{43}$/;

export interface MatrixOAuthPort {
  discoverAuthMetadata(homeserver: string): Promise<unknown>;
  registerClient(endpoint: string, request: OAuthRegistrationRequest): Promise<string>;
  authorizationUrl(request: AuthorizationRequest): Promise<string> | string;
  exchange(request: TokenExchangeRequest): Promise<unknown>;
  whoami(homeserver: string, accessToken: string): Promise<unknown>;
  revoke(endpoint: string, token: string, clientId: string, hint: 'refresh_token' | 'access_token'): Promise<void>;
  /** Internal adapter capability: uses the metadata established by discovery. */
  refresh?(session: MatrixSession, refreshToken: string): Promise<unknown>;
}
export interface OAuthRegistrationRequest { application_type: 'web'; client_name: 'DSA Signal'; client_uri: string; redirect_uris: readonly [string]; grant_types: readonly ['authorization_code', 'refresh_token']; response_types: readonly ['code']; token_endpoint_auth_method: 'none'; }
export interface AuthorizationRequest { authorizationEndpoint: string; clientId: string; redirectUri: string; state: string; codeVerifier: string; deviceId: string; codeChallenge: string; scope: string; responseMode: 'fragment'; }
export interface TokenExchangeRequest { tokenEndpoint: string; clientId: string; redirectUri: string; codeVerifier: string; code: string; }
export class MatrixOAuthError extends Error { public constructor(message = 'Matrix sign-in failed') { super(message); this.name = 'MatrixOAuthError'; } }
/** A rotation was accepted by MAS but could not be made durable.  The runtime is no
 * longer allowed to use either token and must shut down before releasing its lock. */
export class MatrixReauthenticationRequiredError extends Error { public constructor() { super('Matrix reauthentication is required'); this.name = 'MatrixReauthenticationRequiredError'; } }

const url = (value: unknown, exact: string): boolean => {
  if (value !== exact || typeof value !== 'string') return false;
  try { const parsed = new URL(value); return parsed.protocol === 'https:' && !parsed.username && !parsed.password && !parsed.search && !parsed.hash; } catch { return false; }
};
const record = (value: unknown): Record<string, unknown> | undefined => value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
const includes = (value: unknown, needed: string): boolean => Array.isArray(value) && value.includes(needed);

/** Turns untrusted discovery into the one immutable local topology contract. */
export function validateEndpointMetadata(value: unknown): EndpointMetadata {
  const raw = record(value);
  if (!raw || !url(raw.issuer, MATRIX_ISSUER) || !url(raw.authorization_endpoint, MATRIX_AUTHORIZATION_ENDPOINT) || !url(raw.token_endpoint, MATRIX_TOKEN_ENDPOINT)
    || !url(raw.registration_endpoint, MATRIX_REGISTRATION_ENDPOINT) || !url(raw.revocation_endpoint, MATRIX_REVOCATION_ENDPOINT)
    || !includes(raw.response_types_supported, 'code') || !includes(raw.response_modes_supported, 'fragment')
    || !includes(raw.grant_types_supported, 'authorization_code') || !includes(raw.grant_types_supported, 'refresh_token')
    || !includes(raw.code_challenge_methods_supported, 'S256')) throw new MatrixOAuthError('Matrix authorization metadata is unavailable');
  return Object.freeze({ key: MATRIX_ISSUER, issuer: MATRIX_ISSUER, authorizationEndpoint: MATRIX_AUTHORIZATION_ENDPOINT, tokenEndpoint: MATRIX_TOKEN_ENDPOINT, registrationEndpoint: MATRIX_REGISTRATION_ENDPOINT, revocationEndpoint: MATRIX_REVOCATION_ENDPOINT, issuerParameterSupported: raw.authorization_response_iss_parameter_supported === true });
}
const random43 = (random: Crypto): string => { const bytes = new Uint8Array(32); random.getRandomValues(bytes); return bytesToBase64url(bytes); };
const bytesToBase64url = (bytes: Uint8Array): string => { let binary = ''; for (const b of bytes) binary += String.fromCharCode(b); return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); };
async function challenge(verifier: string): Promise<string> { return bytesToBase64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))); }
const validText = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

export interface StartOAuthOptions { store: IndexedDbSessionStore; port: MatrixOAuthPort; random?: Crypto; now?: () => number; ttlMs?: number; }
export async function startMatrixOAuth(options: StartOAuthOptions): Promise<string> {
  try {
  const now = options.now?.() ?? Date.now(); const random = options.random ?? crypto;
  const state = random43(random); const codeVerifier = random43(random); const deviceId = random43(random);
  const metadata = validateEndpointMetadata(await options.port.discoverAuthMetadata(MATRIX_HOMESERVER));
  let registration = await options.store.getRegistration(metadata.key);
  if (!registration || !equalEndpointMetadata(registration.metadata, metadata) || registration.redirectUri !== MATRIX_REDIRECT_URI || registration.clientMetadataVersion !== MATRIX_CLIENT_METADATA_VERSION) {
    const clientId = await options.port.registerClient(metadata.registrationEndpoint!, { application_type: 'web', client_name: 'DSA Signal', client_uri: MATRIX_REDIRECT_URI, redirect_uris: [MATRIX_REDIRECT_URI], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' });
    if (!validText(clientId)) throw new MatrixOAuthError('Matrix sign-in cannot start');
    registration = { metadataKey: metadata.key, clientId, redirectUri: MATRIX_REDIRECT_URI, metadata, createdAt: now, clientMetadataVersion: MATRIX_CLIENT_METADATA_VERSION };
    await options.store.putRegistration(registration);
  }
  const codeChallenge = await challenge(codeVerifier); if (!B64URL43.test(codeChallenge)) throw new MatrixOAuthError();
  const attempt: OAuthAttempt = { state, codeVerifier, clientId: registration.clientId, redirectUri: MATRIX_REDIRECT_URI, deviceId, homeserver: MATRIX_HOMESERVER, metadata, createdAt: now, expiresAt: now + (options.ttlMs ?? 10 * 60_000), spent: false };
  await options.store.createAttempt(attempt, now);
  const scope = `urn:matrix:client:api:* urn:matrix:client:device:${deviceId}`;
  const authorizationUrl = await options.port.authorizationUrl({ authorizationEndpoint: metadata.authorizationEndpoint, clientId: registration.clientId, redirectUri: MATRIX_REDIRECT_URI, state, codeVerifier, deviceId, codeChallenge, scope, responseMode: 'fragment' });
  validateAuthorizationUrl(authorizationUrl, { clientId: registration.clientId, state, codeChallenge, scope });
  return authorizationUrl;
  } catch { throw new MatrixOAuthError('Matrix sign-in cannot start'); }
}
function validateAuthorizationUrl(value: string, expected: { clientId: string; state: string; codeChallenge: string; scope: string }): void {
  let parsed: URL; try { parsed = new URL(value); } catch { throw new MatrixOAuthError(); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || `${parsed.origin}${parsed.pathname}` !== MATRIX_AUTHORIZATION_ENDPOINT || parsed.hash || [...parsed.searchParams.keys()].length !== 8
    || parsed.searchParams.get('client_id') !== expected.clientId || parsed.searchParams.get('redirect_uri') !== MATRIX_REDIRECT_URI || parsed.searchParams.get('state') !== expected.state || parsed.searchParams.get('scope') !== expected.scope
    || parsed.searchParams.get('response_type') !== 'code' || parsed.searchParams.get('response_mode') !== 'fragment' || parsed.searchParams.get('code_challenge_method') !== 'S256' || parsed.searchParams.get('code_challenge') !== expected.codeChallenge || !B64URL43.test(expected.codeChallenge)) throw new MatrixOAuthError();
}

export interface CompleteOAuthOptions { store: IndexedDbSessionStore; locks: ProfileLockPort; port: MatrixOAuthPort; callback: OAuthCallback; now?: () => number; }
export async function completeMatrixOAuth(options: CompleteOAuthOptions): Promise<MatrixSession | undefined> {
  if (options.callback.kind === 'none') return undefined;
  if (options.callback.kind === 'invalid') throw new MatrixOAuthError('Matrix sign-in callback is invalid');
  let attempt: OAuthAttempt;
  try { attempt = await options.store.consumeAttempt(options.callback.state, options.now?.() ?? Date.now()); } catch { throw new MatrixOAuthError('Matrix sign-in callback is invalid'); }
  let rawTokens: { accessToken?: string; refreshToken?: string } | undefined; let committed = false;
  try {
    if (options.callback.kind === 'error') throw new MatrixOAuthError('Matrix authorization was declined');
    const metadata = validateEndpointMetadata(await options.port.discoverAuthMetadata(MATRIX_HOMESERVER));
    if (!equalEndpointMetadata(metadata, attempt.metadata) || (options.callback.issuer !== undefined && options.callback.issuer !== metadata.issuer) || (metadata.issuerParameterSupported && options.callback.issuer === undefined)) throw new MatrixOAuthError();
    const exchanged = await options.port.exchange({ tokenEndpoint: metadata.tokenEndpoint, clientId: attempt.clientId, redirectUri: attempt.redirectUri, codeVerifier: attempt.codeVerifier, code: options.callback.code }); rawTokens = rawTokenStrings(exchanged); const tokens = parseTokens(exchanged);
    const identity = record(await options.port.whoami(attempt.homeserver, tokens.accessToken));
    const userId = identity && parseMatrixUserId(identity.user_id);
    if (!userId || identity.is_guest === true || identity.device_id !== attempt.deviceId) throw new MatrixOAuthError();
    const profileId = await canonicalProfileId({ homeserver: attempt.homeserver, userId, deviceId: attempt.deviceId });
    const session: MatrixSession = { profileId, homeserver: attempt.homeserver, issuer: metadata.issuer, metadata, clientId: attempt.clientId, redirectUri: attempt.redirectUri, userId, deviceId: attempt.deviceId, ...tokens, generation: 1 };
    const result = await commitWhoamiSession(options.store, options.locks, session, attempt.state); committed = true;
    if (result.releaseError) throw new MatrixOAuthError('Matrix sign-in is committed but blocked');
    return session;
  } catch (error) {
    if (rawTokens && !committed) await revoke(options.port, attempt.metadata.revocationEndpoint, attempt.clientId, rawTokens);
    if (error instanceof MatrixOAuthError) throw error;
    throw new MatrixOAuthError();
  } finally { await options.store.finalizeAttempt(attempt.state).catch(() => undefined); }
}
function parseTokens(value: unknown): { accessToken: string; refreshToken?: string; expiresAt: number } {
  const raw = record(value); const expiresIn = raw?.expires_in;
  if (!raw || !validText(raw.access_token) || (raw.refresh_token !== undefined && !validText(raw.refresh_token)) || typeof expiresIn !== 'number' || !Number.isFinite(expiresIn) || expiresIn <= 0) throw new MatrixOAuthError();
  return { accessToken: raw.access_token, ...(raw.refresh_token === undefined ? {} : { refreshToken: raw.refresh_token }), expiresAt: Date.now() + expiresIn * 1000 };
}
function rawTokenStrings(value: unknown): { accessToken?: string; refreshToken?: string } { const raw = record(value); return { ...(validText(raw?.access_token) ? { accessToken: raw.access_token } : {}), ...(validText(raw?.refresh_token) ? { refreshToken: raw.refresh_token } : {}) }; }
async function revoke(port: MatrixOAuthPort, endpoint: string, clientId: string, tokens: { accessToken?: string; refreshToken?: string }): Promise<void> { const safely = async (token: string | undefined, hint: 'refresh_token' | 'access_token'): Promise<void> => { if (!token) return; try { await Promise.resolve(port.revoke(endpoint, token, clientId, hint)); } catch { /* cleanup is best effort */ } }; await safely(tokens.refreshToken, 'refresh_token'); await safely(tokens.accessToken, 'access_token'); }

export interface RefreshCoordinatorOptions {
  readonly store: IndexedDbSessionStore;
  /** This is supplied by the lock-owning runtime; followers never construct it. */
  readonly locator: ActiveProfileLocator;
  readonly discoverAuthMetadata: (homeserver: string) => Promise<unknown>;
  readonly refresh: (session: MatrixSession, refreshToken: string) => Promise<unknown>;
  readonly terminalShutdown: () => Promise<void> | void;
}

export interface TokenRefreshCoordinator {
  (refreshToken: string): Promise<{ accessToken: string; refreshToken?: string; expiry: Date }>;
  quiesce(): Promise<void>;
}

const invalidGrant = (error: unknown): boolean => error instanceof Error && /invalid_grant|invalid[_ -]?token|unauthori[sz]ed/i.test(error.message);

/**
 * SDK-free token rotation boundary.  It deliberately re-reads both the locator
 * and durable session before every request: an SDK callback can outlive a tab
 * or a session replacement.  A successful rotation is not returned until its
 * replacement is committed.
 */
export function createTokenRefreshCoordinator(options: RefreshCoordinatorOptions): TokenRefreshCoordinator {
  let flight: Promise<{ accessToken: string; refreshToken?: string; expiry: Date }> | undefined;
  let quiescing = false;
  const terminal = async (): Promise<never> => {
    // Logout owns shutdown after it has begun draining.  In particular, do not
    // re-enter the runtime's before-release finalizer from this flight.
    if (quiescing) throw new MatrixReauthenticationRequiredError();
    // Shutdown retains authority through stop; only a successful shutdown may
    // permit deletion of this exact durable session.
    // A terminal refresh can synchronously stop the runtime. Do not make that
    // runtime's before-release drain await the promise executing this callback.
    quiescing = true;
    flight = undefined;
    try { await options.terminalShutdown(); } catch { throw new MatrixReauthenticationRequiredError(); }
    try { await options.store.clearSessionForLocator(options.locator); } catch { /* stale durable state is retained */ }
    throw new MatrixReauthenticationRequiredError();
  };
  const refresh: TokenRefreshCoordinator = ((providedRefreshToken: string) => {
    if (quiescing) return Promise.reject(new MatrixReauthenticationRequiredError());
    return flight ??= (async () => {
    try {
      const active = await options.store.getActiveProfile();
      if (!active || active.profileId !== options.locator.profileId || active.generation !== options.locator.generation) return terminal();
      const session = await options.store.loadSession(active);
      if (!session || session.refreshToken !== providedRefreshToken || session.homeserver !== MATRIX_HOMESERVER) return terminal();
      const metadata = validateEndpointMetadata(await options.discoverAuthMetadata(session.homeserver));
      if (!equalEndpointMetadata(metadata, session.metadata) || metadata.issuer !== session.issuer) return terminal();
      let raw: unknown;
      try { raw = await options.refresh(session, providedRefreshToken); } catch (error) { if (invalidGrant(error)) return terminal(); throw error; }
      const parsed = parseTokens(raw);
      const tokens: RefreshTokens = { accessToken: parsed.accessToken, expiresAt: parsed.expiresAt, ...(parsed.refreshToken === undefined ? { refreshToken: session.refreshToken } : { refreshToken: parsed.refreshToken }) };
      let committed: MatrixSession | undefined;
      try { committed = await options.store.commitRefreshedTokens(active, tokens); } catch { return terminal(); }
      if (!committed) return terminal();
      return { accessToken: committed.accessToken, ...(committed.refreshToken === undefined ? {} : { refreshToken: committed.refreshToken }), expiry: new Date(committed.expiresAt) };
    } finally { flight = undefined; }
    })();
  }) as TokenRefreshCoordinator;
  refresh.quiesce = async (): Promise<void> => {
    quiescing = true;
    // The logout finalizer owns cleanup after a drained terminal refresh.
    // Its refresh failure must not prevent the owner from stopping, re-reading,
    // revoking, clearing, and releasing the session.
    await flight?.catch(() => undefined);
  };
  return refresh;
}
