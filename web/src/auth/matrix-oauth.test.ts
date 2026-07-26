import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import { captureAndScrubOAuthCallback, completeMatrixOAuth, createTokenRefreshCoordinator, MATRIX_AUTHORIZATION_ENDPOINT, MATRIX_HOMESERVER, MATRIX_ISSUER, MATRIX_REDIRECT_URI, MatrixReauthenticationRequiredError, OAuthAbortError, startMatrixOAuth, validateEndpointMetadata, type MatrixOAuthPort } from './matrix-oauth';
import { canonicalProfileId } from './canonical-profile';
import { IndexedDbSessionStore } from './session-store';
import { captureInstalledOAuthCallback, takeCapturedOAuthCallback } from './oauth-callback';

const names: string[] = [];
afterEach(async () => { await Promise.all(names.splice(0).map(name => new Promise<void>(done => { const request = indexedDB.deleteDatabase(name); request.onsuccess = request.onerror = request.onblocked = () => done(); }))); });
const metadata = { issuer: MATRIX_ISSUER, authorization_endpoint: MATRIX_AUTHORIZATION_ENDPOINT, token_endpoint: 'https://auth.localhost:8443/oauth2/token', registration_endpoint: 'https://auth.localhost:8443/oauth2/registration', revocation_endpoint: 'https://auth.localhost:8443/oauth2/revoke', response_types_supported: ['code'], response_modes_supported: ['fragment'], grant_types_supported: ['authorization_code', 'refresh_token'], code_challenge_methods_supported: ['S256'] };
const port = (overrides: Partial<MatrixOAuthPort> = {}): MatrixOAuthPort => ({ discoverAuthMetadata: async homeserver => { expect(homeserver).toBe(MATRIX_HOMESERVER); return metadata; }, registerClient: async () => 'client', authorizationUrl: request => `${MATRIX_AUTHORIZATION_ENDPOINT}?client_id=${request.clientId}&redirect_uri=${encodeURIComponent(request.redirectUri)}&state=${request.state}&scope=${encodeURIComponent(request.scope)}&response_type=code&response_mode=fragment&code_challenge_method=S256&code_challenge=${request.codeChallenge}`, exchange: async () => ({ access_token: 'access', refresh_token: 'refresh', expires_in: 60 }), whoami: async () => ({ user_id: '@u:matrix.localhost', device_id: 'x'.repeat(43) }), revoke: async () => {}, ...overrides });
const browser = (pathname: string, search: string, hash: string) => { const calls: string[] = []; return { calls, value: { location: { pathname, search, hash }, history: { replaceState: (_: unknown, __: string, url?: string | URL | null) => calls.push(String(url)) }, hardNavigate: (url: string) => calls.push(`nav:${url}`) } }; };

describe('matrix OAuth callback capture', () => {
  it('installs synchronously exactly once for later integration', () => {
    const b = browser('/', '', ''); captureInstalledOAuthCallback(b.value);
    expect(takeCapturedOAuthCallback()).toEqual({ kind: 'none' }); expect(() => takeCapturedOAuthCallback()).toThrow(OAuthAbortError);
  });
  it('scrubs before returning success and rejects query, duplicates, mixed input, errors, and wrong paths', () => {
    const state = 's'.repeat(43);
    for (const [path, query, hash] of [['/', '', `#code=c&state=${state}`], ['/', '?code=c', ''], ['/', '', `#code=c&code=d&state=${state}`], ['/', '?x=1', `#code=c&state=${state}`], ['/', '', `#error=access_denied&state=${state}`], ['/wrong', '', `#code=c&state=${state}`]] as const) {
      const b = browser(path, query, hash); const result = captureAndScrubOAuthCallback(b.value); expect(b.calls).toEqual([MATRIX_REDIRECT_URI]);
      if (hash.startsWith('#code=') && path === '/' && !query && !hash.includes('code=d')) expect(result.kind).toBe('success'); else expect(['invalid', 'error']).toContain(result.kind);
    }
  });
  it('hard-navigates and aborts if synchronous scrubbing fails', () => {
    const b = browser('/', '', `#code=c&state=${'s'.repeat(43)}`); b.value.history.replaceState = () => { throw new Error('no'); };
    expect(() => captureAndScrubOAuthCallback(b.value)).toThrow(OAuthAbortError); expect(b.calls).toEqual([`nav:${MATRIX_REDIRECT_URI}`]);
  });
});

describe('matrix OAuth start', () => {
  it('uses independent 32-byte values, exact DCR, scope, and metadata-bound cache', async () => {
    const name = `oauth-${crypto.randomUUID()}`; names.push(name); const store = await IndexedDbSessionStore.open(indexedDB, name);
    let byte = 0; const random = { getRandomValues: (array: Uint8Array) => { array.fill(byte++); return array; } } as Crypto;
    const registrations: unknown[] = []; const authorization: unknown[] = [];
    const url = await startMatrixOAuth({ store, random, now: () => 10, port: port({ registerClient: async (_endpoint, request) => { registrations.push(request); return 'client'; }, authorizationUrl: request => { authorization.push(request); return `${MATRIX_AUTHORIZATION_ENDPOINT}?client_id=${request.clientId}&redirect_uri=${encodeURIComponent(request.redirectUri)}&state=${request.state}&scope=${encodeURIComponent(request.scope)}&response_type=code&response_mode=fragment&code_challenge_method=S256&code_challenge=${request.codeChallenge}`; } }) });
    expect(url).toContain('response_mode=fragment'); expect(registrations).toEqual([{ application_type: 'web', client_name: 'DSA Signal', client_uri: MATRIX_REDIRECT_URI, redirect_uris: [MATRIX_REDIRECT_URI], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' }]);
    const request = authorization[0] as { state: string; codeChallenge: string; scope: string }; expect(request.state).toHaveLength(43); expect(request.codeChallenge).toHaveLength(43); expect(request.scope).toMatch(/^urn:matrix:client:api:\* urn:matrix:client:device:[A-Za-z0-9_-]{43}$/);
    expect(validateEndpointMetadata(metadata).revocationEndpoint).toBe('https://auth.localhost:8443/oauth2/revoke');
  });
  it('reuses only an exact DCR binding and invalidates changed deep metadata', async () => {
    const name = `oauth-${crypto.randomUUID()}`; names.push(name); const store = await IndexedDbSessionStore.open(indexedDB, name); let registrations = 0;
    const first = await startMatrixOAuth({ store, now: () => 10, port: port({ registerClient: async () => `client-${++registrations}` }) });
    await store.clearAttempts();
    const second = await startMatrixOAuth({ store, now: () => 20, port: port({ registerClient: async () => `client-${++registrations}` }) });
    expect([first, second]).toHaveLength(2); expect(registrations).toBe(1);
  });
});

describe('matrix OAuth completion', () => {
  it('commits the canonical session and never exposes callback or dependency secrets on failure', async () => {
    const name = `oauth-${crypto.randomUUID()}`; names.push(name); const store = await IndexedDbSessionStore.open(indexedDB, name);
    const state = 's'.repeat(43), deviceId = 'd'.repeat(43); const persisted = validateEndpointMetadata(metadata);
    await store.createAttempt({ state, codeVerifier: 'v'.repeat(43), clientId: 'client-id', redirectUri: MATRIX_REDIRECT_URI, deviceId, homeserver: MATRIX_HOMESERVER, metadata: persisted, createdAt: 1, expiresAt: 1000, spent: false }, 10);
    const profileId = await canonicalProfileId({ homeserver: MATRIX_HOMESERVER, userId: '@u:matrix.localhost', deviceId });
    const result = await completeMatrixOAuth({ store, now: () => 10, locks: { acquire: async () => ({ ownership: 'owner', signal: new AbortController().signal, close: async () => {} }) }, port: port({ whoami: async () => ({ user_id: '@u:matrix.localhost', device_id: deviceId }) }), callback: { kind: 'success', state, code: 'callback-code', issuer: MATRIX_ISSUER } });
    expect(result?.profileId).toBe(profileId); expect(await store.getActiveProfile()).toEqual({ profileId, generation: 1 });
  });
  it('revokes refresh then access after an uncommitted conflict even if revocation throws', async () => {
    const name = `oauth-${crypto.randomUUID()}`; names.push(name); const store = await IndexedDbSessionStore.open(indexedDB, name);
    const state = 's'.repeat(43), deviceId = 'd'.repeat(43), persisted = validateEndpointMetadata(metadata); await store.createAttempt({ state, codeVerifier: 'v'.repeat(43), clientId: 'client', redirectUri: MATRIX_REDIRECT_URI, deviceId, homeserver: MATRIX_HOMESERVER, metadata: persisted, createdAt: 1, expiresAt: 1000, spent: false }, 10);
    const calls: string[] = [];
    await expect(completeMatrixOAuth({ store, now: () => 10, locks: { acquire: async () => ({ ownership: 'blocked', signal: new AbortController().signal, close: async () => {} }) }, port: port({ whoami: async () => ({ user_id: '@u:matrix.localhost', device_id: deviceId }), revoke: (_endpoint, token) => { calls.push(token); throw new Error('dependency refresh access client callback-code state'); } }), callback: { kind: 'success', state, code: 'callback-code', issuer: MATRIX_ISSUER } })).rejects.toThrow('Matrix sign-in failed');
    expect(calls).toEqual(['refresh', 'access']);
  });
});

describe('token refresh coordinator', () => {
  const active = { profileId: 'a'.repeat(64), generation: 1 };
  const refreshSession = { ...active, homeserver: MATRIX_HOMESERVER, issuer: MATRIX_ISSUER, metadata: validateEndpointMetadata(metadata), clientId: 'client', redirectUri: MATRIX_REDIRECT_URI, userId: '@u:matrix.localhost', deviceId: 'd'.repeat(43), accessToken: 'old-access', refreshToken: 'old-refresh', expiresAt: 1 };
  const fixture = () => {
    const calls: string[] = []; let terminal = 0;
    const store = { getActiveProfile: async () => { calls.push('locator'); return active; }, loadSession: async () => { calls.push('session'); return refreshSession; }, commitRefreshedTokens: async (_: unknown, tokens: unknown) => { calls.push(`commit:${JSON.stringify(tokens)}`); return { ...refreshSession, ...(tokens as object) }; }, clearSessionForLocator: async () => { calls.push('clear'); return true; } } as unknown as IndexedDbSessionStore;
    return { calls, store, terminal: () => terminal, shutdown: () => { terminal += 1; } };
  };
  it('rediscovers, single-flights, retains an omitted refresh token, and commits before returning', async () => {
    const f = fixture(); let release!: () => void; const pending = new Promise<void>(done => { release = done; }); let refreshes = 0;
    const run = createTokenRefreshCoordinator({ store: f.store, locator: active, discoverAuthMetadata: async () => { f.calls.push('discovery'); return metadata; }, refresh: async () => { refreshes += 1; await pending; return { access_token: 'new-access', expires_in: 60 }; }, terminalShutdown: f.shutdown });
    const first = run('old-refresh'); const second = run('old-refresh'); release();
    await expect(Promise.all([first, second])).resolves.toEqual([expect.objectContaining({ accessToken: 'new-access', refreshToken: 'old-refresh', expiry: expect.any(Date) }), expect.objectContaining({ accessToken: 'new-access', refreshToken: 'old-refresh', expiry: expect.any(Date) })]);
    expect(refreshes).toBe(1); expect(f.calls.slice(0, 3)).toEqual(['locator', 'session', 'discovery']); expect(f.calls[3]).toContain('"refreshToken":"old-refresh"');
  });
  it('makes invalid grants and durable commit failures terminal without returning tokens', async () => {
    const invalid = fixture(); const reject = createTokenRefreshCoordinator({ store: invalid.store, locator: active, discoverAuthMetadata: async () => metadata, refresh: async () => { throw new Error('invalid_grant'); }, terminalShutdown: invalid.shutdown });
    await expect(reject('old-refresh')).rejects.toBeInstanceOf(MatrixReauthenticationRequiredError); expect(invalid.terminal()).toBe(1); expect(invalid.calls.at(-1)).toBe('clear');
    const failed = fixture(); failed.store.commitRefreshedTokens = async () => { throw new Error('storage'); };
    const commit = createTokenRefreshCoordinator({ store: failed.store, locator: active, discoverAuthMetadata: async () => metadata, refresh: async () => ({ access_token: 'new', refresh_token: 'rotated', expires_in: 60 }), terminalShutdown: failed.shutdown });
    await expect(commit('old-refresh')).rejects.toBeInstanceOf(MatrixReauthenticationRequiredError); expect(failed.terminal()).toBe(1); expect(failed.calls.at(-1)).toBe('clear');
  });
  it('leaves transport failures retryable', async () => {
    const f = fixture(); const run = createTokenRefreshCoordinator({ store: f.store, locator: active, discoverAuthMetadata: async () => metadata, refresh: async () => { throw new Error('network down'); }, terminalShutdown: f.shutdown });
    await expect(run('old-refresh')).rejects.toThrow('network down'); expect(f.terminal()).toBe(0);
  });
  it('drains an in-flight refresh and blocks new work once quiesced', async () => {
    const f = fixture(); let release!: () => void; const pending = new Promise<void>(done => { release = done; });
    const run = createTokenRefreshCoordinator({ store: f.store, locator: active, discoverAuthMetadata: async () => metadata, refresh: async () => { await pending; return { access_token: 'new', expires_in: 60 }; }, terminalShutdown: f.shutdown });
    const inFlight = run('old-refresh'); const drained = run.quiesce();
    await expect(run('old-refresh')).rejects.toBeInstanceOf(MatrixReauthenticationRequiredError);
    release(); await expect(inFlight).resolves.toEqual(expect.objectContaining({ accessToken: 'new' })); await expect(drained).resolves.toBeUndefined();
  });
  it('lets logout own cleanup when its drained refresh receives invalid_grant', async () => {
    const f = fixture(); const calls: string[] = []; let started!: () => void; let release!: () => void;
    const startedRefresh = new Promise<void>(done => { started = done; });
    const pending = new Promise<void>(done => { release = done; });
    const run = createTokenRefreshCoordinator({ store: f.store, locator: active, discoverAuthMetadata: async () => metadata, refresh: async () => { calls.push('refresh'); started(); await pending; throw new Error('invalid_grant'); }, terminalShutdown: () => { calls.push('terminal shutdown'); } });
    const inFlight = run('old-refresh');
    await startedRefresh;
    const logout = (async () => {
      calls.push('quiesce'); await run.quiesce(); calls.push('stop');
      calls.push('re-read'); calls.push('revoke'); calls.push('clear'); calls.push('release');
    })();
    await expect(run('old-refresh')).rejects.toBeInstanceOf(MatrixReauthenticationRequiredError);
    release();
    await expect(inFlight).rejects.toBeInstanceOf(MatrixReauthenticationRequiredError);
    await expect(logout).resolves.toBeUndefined();
    expect(f.terminal()).toBe(0); expect(f.calls).not.toContain('clear');
    expect(calls).toEqual(['refresh', 'quiesce', 'stop', 're-read', 'revoke', 'clear', 'release']);
  });
  it('does not deadlock when a terminal refresh shuts down through a draining finalizer', async () => {
    const f = fixture(); const run = createTokenRefreshCoordinator({ store: f.store, locator: active, discoverAuthMetadata: async () => metadata, refresh: async () => { throw new Error('invalid_grant'); }, terminalShutdown: async () => { await run.quiesce(); } });
    await expect(run('old-refresh')).rejects.toBeInstanceOf(MatrixReauthenticationRequiredError);
  });
  it('retains the exact session when terminal shutdown cannot release authority', async () => {
    const f = fixture(); f.shutdown = async () => { f.calls.push('shutdown'); throw new Error('release failed'); };
    const run = createTokenRefreshCoordinator({ store: f.store, locator: active, discoverAuthMetadata: async () => metadata, refresh: async () => { throw new Error('invalid_grant'); }, terminalShutdown: f.shutdown });
    await expect(run('old-refresh')).rejects.toBeInstanceOf(MatrixReauthenticationRequiredError);
    expect(f.calls).toEqual(['locator', 'session', 'shutdown']);
  });
});
