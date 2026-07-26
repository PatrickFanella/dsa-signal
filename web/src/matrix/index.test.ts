import { expect, it, vi } from 'vitest';

const fixture = vi.hoisted(() => { const refresh = Object.assign(vi.fn(), { quiesce: vi.fn(async () => {}) }); return { close: vi.fn(async () => {}), release: vi.fn(), storeClose: vi.fn(), clear: vi.fn<(locator: unknown) => Promise<boolean>>(async () => true), revoke: vi.fn<(...args: string[]) => Promise<void>>(async () => {}), open: vi.fn(), refresh, beforeRelease: undefined as undefined | (() => Promise<void>), calls: [] as string[] }; });
vi.mock('../auth/session-store', () => ({ IndexedDbSessionStore: { open: fixture.open } }));
vi.mock('../auth/matrix-oauth', () => ({ completeMatrixOAuth: vi.fn(), createTokenRefreshCoordinator: () => fixture.refresh, startMatrixOAuth: vi.fn() }));
vi.mock('../auth/oauth-callback', () => ({ takeCapturedOAuthCallback: () => ({ kind: 'none' }) }));
vi.mock('../crypto/crypto-owner', () => ({ CryptoOwnerCoordinator: class {}, browserCryptoOwnerDependencies: () => ({}) }));
vi.mock('./internal/sdk', () => ({ createSdkBootstrapPort: () => ({ begin: () => ({}) }), createSdkOAuthPort: () => ({ revoke: fixture.revoke }), refreshSdkOAuth: vi.fn() }));
vi.mock('./create-client', () => ({ MatrixStartupCoordinator: class { public start = async (_store: unknown, _locks: unknown, bootstrap: { begin: (session: object, signal: AbortSignal) => unknown }) => { const session = { profileId: 'a'.repeat(64), generation: 1, metadata: { revocationEndpoint: 'https://auth.localhost:8443/oauth2/revoke' }, clientId: 'client', refreshToken: 'refresh', accessToken: 'access' }; bootstrap.begin(session, new AbortController().signal); return { kind: 'runtime' as const, session, gateway: { start: async () => {}, stop: async () => {}, subscribeSecurityState: (listener: (state: 'ready') => void) => { listener('ready'); return () => {}; } }, beforeRelease: (fn: () => Promise<void>) => { fixture.beforeRelease = fn; }, close: async () => { fixture.calls.push('stop'); await fixture.close(); await fixture.beforeRelease?.(); fixture.calls.push('release'); fixture.release(); } }; }; public close = async () => { fixture.calls.push('stop'); await fixture.close(); await fixture.beforeRelease?.(); fixture.calls.push('release'); fixture.release(); }; } }));

import { createMatrixRuntime } from './index';

it('public gateway stop invokes runtime close and releases ownership', async () => {
  fixture.open.mockResolvedValue({ close: fixture.storeClose });
  const runtime = await createMatrixRuntime(); await runtime.startup; await runtime.gateway!.stop();
  expect(fixture.close).toHaveBeenCalledOnce(); expect(fixture.release).toHaveBeenCalledOnce(); expect(fixture.clear).not.toHaveBeenCalled();
});

it('logout stops, revokes refresh then access, clears the exact locator, then releases', async () => {
  fixture.calls.length = 0; fixture.beforeRelease = undefined; fixture.revoke.mockClear(); fixture.clear.mockClear(); fixture.close.mockClear(); fixture.release.mockClear();
  fixture.open.mockResolvedValue({ close: fixture.storeClose, getActiveProfile: async () => ({ profileId: 'a'.repeat(64), generation: 1 }), loadSession: async () => ({ profileId: 'a'.repeat(64), generation: 1, metadata: { revocationEndpoint: 'https://auth.localhost:8443/oauth2/revoke' }, clientId: 'client', refreshToken: 'refresh', accessToken: 'access' }), clearSessionAndAttemptsForLocator: async (locator: unknown) => { fixture.calls.push('clear'); return fixture.clear(locator); } });
  fixture.revoke.mockImplementation(async (_endpoint: string, _token: string, _client: string, hint: string) => { fixture.calls.push(`revoke:${hint}`); });
  const runtime = await createMatrixRuntime(); await runtime.startup; await Promise.all([runtime.logout(), runtime.logout()]);
  expect(fixture.calls).toEqual(['stop', 'revoke:refresh_token', 'revoke:access_token', 'clear', 'release']);
  expect(fixture.clear).toHaveBeenCalledWith({ profileId: 'a'.repeat(64), generation: 1 });
});

it('continues logout after revocation failures but fails closed when stop fails', async () => {
  fixture.calls.length = 0; fixture.beforeRelease = undefined; fixture.revoke.mockClear(); fixture.clear.mockClear(); fixture.release.mockClear();
  fixture.open.mockResolvedValue({ close: fixture.storeClose, getActiveProfile: async () => ({ profileId: 'a'.repeat(64), generation: 1 }), loadSession: async () => ({ profileId: 'a'.repeat(64), generation: 1, metadata: { revocationEndpoint: 'https://auth.localhost:8443/oauth2/revoke' }, clientId: 'client', refreshToken: 'refresh', accessToken: 'access' }), clearSessionAndAttemptsForLocator: async () => { fixture.calls.push('clear'); return true; } });
  fixture.close.mockResolvedValueOnce(undefined);
  fixture.revoke.mockImplementation(async (_endpoint: string, _token: string, _client: string, hint: string) => { fixture.calls.push(`revoke:${hint}`); throw new Error('network'); });
  const runtime = await createMatrixRuntime(); await runtime.startup; await runtime.logout();
  expect(fixture.calls).toEqual(['stop', 'revoke:refresh_token', 'revoke:access_token', 'clear', 'release']);

  fixture.calls.length = 0; fixture.beforeRelease = undefined; fixture.revoke.mockClear(); fixture.clear.mockClear(); fixture.release.mockClear(); fixture.close.mockRejectedValueOnce(new Error('stop'));
  const failed = await createMatrixRuntime(); await failed.startup; await expect(failed.logout()).rejects.toThrow('stop');
  expect(fixture.revoke).not.toHaveBeenCalled(); expect(fixture.clear).not.toHaveBeenCalled(); expect(fixture.release).not.toHaveBeenCalled();
  fixture.close.mockResolvedValue(undefined);
});

it('retains a replacement session when the held-lock locator has changed', async () => {
  fixture.calls.length = 0; fixture.beforeRelease = undefined; fixture.revoke.mockClear(); fixture.release.mockClear(); fixture.close.mockClear();
  fixture.open.mockResolvedValue({ close: fixture.storeClose, getActiveProfile: async () => ({ profileId: 'b'.repeat(64), generation: 2 }), loadSession: async () => undefined, clearSessionAndAttemptsForLocator: fixture.clear });
  const runtime = await createMatrixRuntime(); await runtime.startup;
  await expect(runtime.logout()).rejects.toThrow('logout locator drift');
  expect(fixture.revoke).not.toHaveBeenCalled(); expect(fixture.clear).not.toHaveBeenCalled(); expect(fixture.release).not.toHaveBeenCalled();
});
