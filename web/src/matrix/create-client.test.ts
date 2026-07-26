import { describe, expect, it, vi } from 'vitest';
import { commitWhoamiSession, createClientForActiveProfile, MatrixStartupCoordinator, SessionCommitError } from './create-client';
import type { ClientStartupResult } from './create-client';
import type { IndexedDbSessionStore, MatrixSession } from '../auth/session-store';
import { beginCryptoBootstrap, type CryptoBootstrapPort, type SyncState } from '../crypto/bootstrap-crypto';
import { EncryptionPolicyEpoch } from './encryption-policy';

const locator = { profileId: '6b205cf7dcb89314a62d740a4cc075e0d1226457b5b09233f2a381d04041fba1', generation: 1 };
const flush = async (): Promise<void> => { for (let i = 0; i < 12; i += 1) await Promise.resolve(); };
const session = { ...locator, homeserver: 'https://matrix.localhost:8443', issuer: 'https://auth.localhost:8443/', metadata: { key: 'https://auth.localhost:8443/', issuer: 'https://auth.localhost:8443/', authorizationEndpoint: 'https://auth.localhost:8443/authorize', tokenEndpoint: 'https://auth.localhost:8443/oauth2/token', registrationEndpoint: 'https://auth.localhost:8443/oauth2/registration', revocationEndpoint: 'https://auth.localhost:8443/oauth2/revoke', issuerParameterSupported: false }, clientId: 'client', redirectUri: 'https://chat.localhost:8443/', userId: '@u:hs', deviceId: 'd'.repeat(43), accessToken: 'token', expiresAt: 1 } as MatrixSession;
describe('createClientForActiveProfile', () => {
  it('releases the owner after a definitely uncommitted durable failure without exposing its cause', async () => {
    let closed = 0;
    const store = { commitSession: async () => { throw new Error('access-token-secret'); } } as unknown as IndexedDbSessionStore;
    const locks = { acquire: async () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { closed += 1; } }) };
    await expect(commitWhoamiSession(store, locks, session, 's'.repeat(43))).rejects.toMatchObject({ outcome: 'uncommitted', releaseError: false });
    await expect(commitWhoamiSession(store, locks, session, 's'.repeat(43))).rejects.toBeInstanceOf(SessionCommitError);
    expect(closed).toBe(2);
  });
  it('keeps a successful durable commit authoritative when its release acknowledgement fails', async () => {
    const store = { commitSession: async () => locator } as unknown as IndexedDbSessionStore;
    const locks = { acquire: async () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { throw new Error('release'); } }) };
    await expect(commitWhoamiSession(store, locks, session, 's'.repeat(43))).resolves.toEqual({ locator, releaseError: true });
  });
  it('never loads credentials or constructs a client for a follower', async () => {
    let loaded = false; let booted = false;
    const store = { getActiveProfile: async () => locator, loadSession: async () => { loaded = true; return session; } } as unknown as IndexedDbSessionStore;
    await expect(createClientForActiveProfile(store, { acquire: async () => ({ ownership: 'follower', signal: new AbortController().signal, close: async () => {} }) }, { begin: () => { booted = true; return { readiness: Promise.resolve(), stop: async () => {} }; } })).resolves.toMatchObject({ kind: 'follower' });
    expect(loaded).toBe(false); expect(booted).toBe(false);
  });
  it('retries locator generation drift and starts with the subsequent stable locator', async () => {
    let reads = 0; const closed: string[] = []; const started: MatrixSession[] = [];
    const stable = { ...locator, generation: 2 };
    const stableSession = { ...session, generation: stable.generation };
    const store = { getActiveProfile: async () => { reads += 1; return reads === 2 ? stable : reads > 2 ? stable : locator; }, loadSession: async (current: typeof locator) => current.generation === stable.generation ? stableSession : session } as unknown as IndexedDbSessionStore;
    await expect(createClientForActiveProfile(store, { acquire: async (profileId: string) => ({ ownership: 'owner', signal: new AbortController().signal, close: async () => { closed.push(profileId); } }) }, { begin: (activeSession: MatrixSession) => { started.push(activeSession); return { readiness: Promise.resolve(), stop: async () => {} }; } }, 2)).resolves.toMatchObject({ kind: 'runtime', session: stableSession });
    expect(closed).toEqual([locator.profileId]); expect(started).toEqual([stableSession]);
  });
  it.each(['readiness', 'storage', 'crypto'] as const)('does not retry a terminal %s failure after ownership', async (failure) => {
    let begins = 0; let loads = 0;
    const store = { getActiveProfile: async () => locator, loadSession: async () => { loads += 1; if (failure === 'storage') throw new Error('storage'); return session; } } as unknown as IndexedDbSessionStore;
    const port = failure === 'crypto'
      ? { begin: () => { begins += 1; const crypto: CryptoBootstrapPort = { installSyncListener: () => {}, installRoomListener: () => {}, installMembershipListener: () => {}, installCryptoListener: () => {}, installTrustListener: () => {}, installDeviceListener: () => {}, installTerminalListener: () => {}, initRustCrypto: async () => { throw new Error('crypto'); }, getCrypto: () => ({ kind: 'rust-crypto' }), configureSignedDeviceIsolation: () => {}, startClient: () => {}, stopClient: async () => {} }; return beginCryptoBootstrap(crypto, { cryptoDatabasePrefix: locator.profileId, syncReadyTimeoutMs: 1, evaluatePostSyncPolicy: () => 'ready' }); } }
      : { begin: () => { begins += 1; return { readiness: failure === 'readiness' ? Promise.reject(new Error(failure)) : Promise.resolve(), stop: async () => {} }; } };
    await expect(createClientForActiveProfile(store, { acquire: async () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: async () => {} }) }, port)).resolves.toMatchObject({ kind: 'blocked' });
    expect(begins).toBe(failure === 'storage' ? 0 : 1); expect(loads).toBe(1);
  });
  it('shares one complete StrictMode startup operation', async () => {
    let acquired = 0; let booted = 0;
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const coordinator = new MatrixStartupCoordinator();
    const locks = { acquire: async () => { acquired += 1; return { ownership: 'owner' as const, signal: new AbortController().signal, close: async () => {} }; } };
    const port = { begin: () => { booted += 1; return { readiness: Promise.resolve(), stop: async () => {} }; } };
    const [first, second] = await Promise.all([coordinator.start(store, locks, port), coordinator.start(store, locks, port)]);
    expect(first.kind).toBe('runtime'); expect(second.kind).toBe('runtime'); expect(acquired).toBe(1); expect(booted).toBe(1);
  });
  it('closes a pending beginning operation without waiting for readiness', async () => {
    let release = 0; const stop = vi.fn(async () => {}); let resolveReady!: () => void;
    const never = new Promise<void>(resolve => { resolveReady = resolve; });
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const locks = { acquire: async () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { release += 1; } }) };
    let begun = false; const coordinator = new MatrixStartupCoordinator(); const startup = coordinator.start(store, locks, { begin: () => { begun = true; return { readiness: never, stop }; } });
    await vi.waitFor(() => expect(begun).toBe(true)); await coordinator.close();
    expect(stop).toHaveBeenCalledOnce(); expect(release).toBe(1); await expect(startup).resolves.toMatchObject({ kind: 'blocked' }); resolveReady();
  });
  it('closes a taken-over owner before loading when the profile drifts', async () => {
    let closed = 0; let loaded = false; const next = { ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { closed += 1; } };
    let reads = 0; const store = { getActiveProfile: async () => (++reads === 1 ? locator : { ...locator, profileId: 'b'.repeat(64) }), loadSession: async () => { loaded = true; return session; } } as unknown as IndexedDbSessionStore;
    const follower = { ownership: 'follower' as const, signal: new AbortController().signal, close: async () => {}, takeOver: async () => next };
    const result = await createClientForActiveProfile(store, { acquire: async () => follower }, { begin: () => ({ readiness: Promise.resolve(), stop: async () => {} }) });
    expect(result.kind).toBe('follower');
    await expect((result as { takeOver(): Promise<unknown> }).takeOver()).resolves.toMatchObject({ kind: 'blocked' });
    expect(loaded).toBe(false); expect(closed).toBe(1);
  });
  it('retains owner authority when bootstrap and stop both fail', async () => {
    let held = false;
    const failingStop = vi.fn(async () => { throw new Error('stop failed'); });
    const locks = { acquire: async (profileId: string, stop: () => Promise<void>) => { void profileId; return held ? { ownership: 'blocked' as const, signal: new AbortController().signal, close: async () => {} } : (held = true, { ownership: 'owner' as const, signal: new AbortController().signal, close: stop }); } };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const crypto: CryptoBootstrapPort = {
      installSyncListener: () => {}, installRoomListener: () => {}, installMembershipListener: () => {}, installCryptoListener: () => {}, installTrustListener: () => {}, installDeviceListener: () => {}, installTerminalListener: () => {},
      initRustCrypto: async () => { throw new Error('bootstrap failed'); }, getCrypto: () => ({ kind: 'rust-crypto' }), configureSignedDeviceIsolation: () => {}, startClient: () => {}, stopClient: failingStop,
    };
    const result = await createClientForActiveProfile(store, locks, { begin: () => beginCryptoBootstrap(crypto, { cryptoDatabasePrefix: locator.profileId, syncReadyTimeoutMs: 1, evaluatePostSyncPolicy: () => 'ready' }) }, 1);
    expect(result.kind).toBe('blocked'); expect(failingStop).toHaveBeenCalledOnce();
    expect((await locks.acquire(locator.profileId, async () => {})).ownership).toBe('blocked');
  });
  it('releases ownership after a post-ready terminal signal, allowing a successor', async () => {
    let held = false; let terminal: (() => void) | undefined; const stops = vi.fn(async () => {});
    const locks = { acquire: async () => held ? { ownership: 'blocked' as const, signal: new AbortController().signal, close: async () => {} } : (held = true, { ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { await stops(); held = false; } }) };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const port = { begin: () => ({ readiness: Promise.resolve(), stop: stops, onTerminal: (listener: () => void) => { terminal = listener; } }) };
    expect((await createClientForActiveProfile(store, locks, port)).kind).toBe('runtime'); void Promise.resolve(terminal?.()).catch(() => undefined); await vi.waitFor(() => expect(held).toBe(false));
    expect(stops).toHaveBeenCalledOnce(); expect((await locks.acquire()).ownership).toBe('owner');
  });
  it('runs terminal through owner close, acquisition stop, bootstrap stop, stopClient, then lock release', async () => {
    let held = false; let sync: ((state: SyncState) => void) | undefined; const calls: string[] = [];
    const locks = { acquire: async (_profileId: string, stop: () => Promise<void>) => held ? { ownership: 'blocked' as const, signal: new AbortController().signal, close: async () => {} } : (held = true, { ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { calls.push('owner-close'); await stop(); calls.push('lock-release'); held = false; } }) };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const crypto: CryptoBootstrapPort = {
      installSyncListener: listener => { sync = listener; }, installRoomListener: () => {}, installMembershipListener: () => {}, installCryptoListener: () => {}, installTrustListener: () => {}, installDeviceListener: () => {}, installTerminalListener: () => {},
      initRustCrypto: async () => {}, getCrypto: () => ({ kind: 'rust-crypto' }), configureSignedDeviceIsolation: () => {}, startClient: () => {}, stopClient: async () => { calls.push('stop-client'); },
    };
    const startup = createClientForActiveProfile(store, locks, { begin: () => beginCryptoBootstrap(crypto, { cryptoDatabasePrefix: locator.profileId, syncReadyTimeoutMs: 1_000, evaluatePostSyncPolicy: () => 'ready' }) });
    await vi.waitFor(() => expect(sync).toBeTypeOf('function')); sync?.('PREPARED'); expect((await startup).kind).toBe('runtime'); sync?.('STOPPED');
    await vi.waitFor(() => expect(held).toBe(false)); expect(calls).toEqual(['owner-close', 'stop-client', 'lock-release']); expect((await locks.acquire(locator.profileId, async () => {})).ownership).toBe('owner');
  });
  it('holds ownership until a terminally-cancelled post-sync policy evaluation settles', async () => {
    let held = false; let sync: ((state: SyncState) => void) | undefined; let resolvePolicy!: () => void; const policy = new Promise<'ready'>(done => { resolvePolicy = () => done('ready'); }); const calls: string[] = [];
    const locks = { acquire: async (_profileId: string, stop: () => Promise<void>) => held ? { ownership: 'blocked' as const, signal: new AbortController().signal, close: async () => {} } : (held = true, { ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { calls.push('owner-close'); await stop(); calls.push('lock-release'); held = false; } }) };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const crypto: CryptoBootstrapPort = {
      installSyncListener: listener => { sync = listener; }, installRoomListener: () => {}, installMembershipListener: () => {}, installCryptoListener: () => {}, installTrustListener: () => {}, installDeviceListener: () => {}, installTerminalListener: () => {},
      initRustCrypto: async () => {}, getCrypto: () => ({ kind: 'rust-crypto' }), configureSignedDeviceIsolation: () => {}, startClient: () => {}, stopClient: async () => { calls.push('stop-client'); },
    };
    const startup = createClientForActiveProfile(store, locks, { begin: () => beginCryptoBootstrap(crypto, { cryptoDatabasePrefix: locator.profileId, syncReadyTimeoutMs: 1_000, evaluatePostSyncPolicy: () => policy }) });
    await vi.waitFor(() => expect(sync).toBeTypeOf('function')); sync?.('PREPARED'); await flush(); sync?.('STOPPED'); await flush();
    expect(held).toBe(true); expect(calls).toEqual(['owner-close']); resolvePolicy();
    await expect(startup).resolves.toMatchObject({ kind: 'blocked' }); expect(calls).toEqual(['owner-close', 'stop-client', 'lock-release']);
  });
  it('clears a coordinator operation only after successful automatic terminal cleanup', async () => {
    let held = false; let terminal: (() => void) | undefined; let acquisitions = 0; let boots = 0;
    const locks = { acquire: async (_profileId: string, stop: () => Promise<void>) => { acquisitions += 1; return held ? { ownership: 'blocked' as const, signal: new AbortController().signal, close: async () => {} } : (held = true, { ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { await stop(); held = false; } }); } };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const port = { begin: () => { boots += 1; return { readiness: Promise.resolve(), stop: async () => {}, onTerminal: (listener: () => void) => { terminal = listener; } }; } };
    const coordinator = new MatrixStartupCoordinator(); await coordinator.start(store, locks, port); void Promise.resolve(terminal?.()).catch(() => undefined); await vi.waitFor(() => expect(held).toBe(false));
    await coordinator.start(store, locks, port); expect(acquisitions).toBe(2); expect(boots).toBe(2);
  });
  it('keeps a coordinator operation cached when automatic terminal cleanup fails', async () => {
    let terminal: (() => void) | undefined; let acquisitions = 0; const stop = vi.fn(async () => { throw new Error('stop'); });
    const locks = { acquire: async () => { acquisitions += 1; return { ownership: 'owner' as const, signal: new AbortController().signal, close: stop }; } };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const port = { begin: () => ({ readiness: Promise.resolve(), stop: async () => {}, onTerminal: (listener: () => void) => { terminal = listener; } }) };
    const coordinator = new MatrixStartupCoordinator(); await coordinator.start(store, locks, port); void Promise.resolve(terminal?.()).catch(() => undefined); await vi.waitFor(() => expect(stop).toHaveBeenCalledOnce()); await coordinator.start(store, locks, port);
    expect(acquisitions).toBe(1);
  });
  it('retains ownership when post-ready terminal cleanup cannot stop the client', async () => {
    let held = false; let terminal: (() => void) | undefined; const stops = vi.fn(async () => { throw new Error('stop'); });
    const locks = { acquire: async () => held ? { ownership: 'blocked' as const, signal: new AbortController().signal, close: async () => {} } : (held = true, { ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { await stops(); held = false; } }) };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const port = { begin: () => ({ readiness: Promise.resolve(), stop: stops, onTerminal: (listener: () => void) => { terminal = listener; } }) };
    await createClientForActiveProfile(store, locks, port); void Promise.resolve(terminal?.()).catch(() => undefined); await vi.waitFor(() => expect(stops).toHaveBeenCalledOnce());
    expect(held).toBe(true); expect((await locks.acquire()).ownership).toBe('blocked');
  });
  it('propagates owner terminal close rejection to its direct runtime listener', async () => {
    let terminal: (() => Promise<void> | void) | undefined; const stop = vi.fn(async () => { throw new Error('stop'); });
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const port = { begin: () => ({ readiness: Promise.resolve(), stop: async () => {}, onTerminal: (listener: () => Promise<void> | void) => { terminal = listener; } }) };
    await createClientForActiveProfile(store, { acquire: async () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: stop }) }, port);
    await expect(Promise.resolve(terminal?.())).rejects.toThrow('stop'); expect(stop).toHaveBeenCalledOnce();
  });
  it.each([{ stopFails: false }, { stopFails: true }])('routes an epoch-drift unverified runtime terminal signal through owner cleanup (stop fails: $stopFails)', async ({ stopFails }) => {
    let held = false; let acquisitions = 0; let boots = 0; let sync: ((state: SyncState) => void) | undefined; let room: (() => void) | undefined; let bootstrapState: Promise<{ readonly state: string }> | undefined;
    const stopClient = vi.fn(async () => { if (stopFails) throw new Error('stop'); });
    const locks = { acquire: async (_profileId: string, stop: () => Promise<void>) => {
      acquisitions += 1;
      return held ? { ownership: 'blocked' as const, signal: new AbortController().signal, close: async () => {} } : (held = true, { ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { await stop(); held = false; } });
    } };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const port = { begin: () => {
      boots += 1; const epoch = new EncryptionPolicyEpoch();
      const crypto: CryptoBootstrapPort = {
        installSyncListener: listener => { sync = listener; }, installRoomListener: listener => { room = listener; }, installMembershipListener: () => {}, installCryptoListener: () => {}, installTrustListener: () => {}, installDeviceListener: () => {}, installTerminalListener: () => {},
        initRustCrypto: async () => {}, getCrypto: () => ({ kind: 'rust-crypto' }), configureSignedDeviceIsolation: () => {}, startClient: () => {}, stopClient,
      };
      const operation = beginCryptoBootstrap(crypto, { cryptoDatabasePrefix: locator.profileId, syncReadyTimeoutMs: 1_000, policyEpoch: epoch, evaluatePostSyncPolicy: () => { room?.(); return 'ready'; } });
      bootstrapState = operation.readiness;
      return operation;
    } };
    const coordinator = new MatrixStartupCoordinator(); const startup = coordinator.start(store, locks, port);
    await vi.waitFor(() => expect(sync).toBeTypeOf('function')); sync?.('PREPARED'); expect((await startup).kind).toBe('runtime'); expect((await bootstrapState!).state).toBe('unverified'); sync?.('STOPPED');
    await vi.waitFor(() => expect(stopClient).toHaveBeenCalledOnce());
    if (stopFails) {
      expect(held).toBe(true); await coordinator.start(store, locks, port); expect(acquisitions).toBe(1); expect(boots).toBe(1);
    } else {
      await vi.waitFor(() => expect(held).toBe(false)); const successor = coordinator.start(store, locks, port);
      await vi.waitFor(() => expect(boots).toBe(2)); sync?.('PREPARED'); expect((await successor).kind).toBe('runtime'); expect(acquisitions).toBe(2);
    }
  });
  it('terminal cleanup after follower takeover clears takeover and permits fresh start', async () => {
    let acquisitions = 0; let boots = 0; const owner = () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: async () => {} });
    const follower = { ownership: 'follower' as const, signal: new AbortController().signal, close: async () => {}, takeOver: async () => owner() };
    const locks = { acquire: async () => ++acquisitions === 1 ? follower : owner() };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const coordinator = new MatrixStartupCoordinator(); const port = { begin: () => ({ readiness: Promise.resolve(++boots), stop: async () => {} }) };
    const first = await coordinator.start(store, locks, port); expect(first.kind).toBe('follower');
    const [one, two] = await Promise.all([(first as { takeOver(): Promise<unknown> }).takeOver(), (first as { takeOver(): Promise<unknown> }).takeOver()]);
    expect(one).toBe(two); expect((one as { kind: string }).kind).toBe('runtime'); expect(boots).toBe(1);
    await (one as { close(): Promise<void> }).close(); await coordinator.start(store, locks, port);
    expect(acquisitions).toBe(2); expect(boots).toBe(2);
  });
  it('takeover terminal clears its published operation and permits a fresh start', async () => {
    let boots = 0; const terminals: (() => Promise<void> | void)[] = [];
    const follower = { ownership: 'follower' as const, signal: new AbortController().signal, close: async () => {}, takeOver: async () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: async () => {} }) };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const coordinator = new MatrixStartupCoordinator();
    const port = { begin: () => ({ readiness: Promise.resolve(++boots), stop: async () => {}, onTerminal: (listener: () => Promise<void> | void) => { terminals.push(listener); } }) };
    const first = await coordinator.start(store, { acquire: async () => follower }, port); await (first as { takeOver(): Promise<unknown> }).takeOver();
    expect(boots).toBe(1); await Promise.resolve(terminals[0]?.()); await flush();
    const fresh = await coordinator.start(store, { acquire: async () => follower }, port);
    await (fresh as { takeOver(): Promise<unknown> }).takeOver(); expect(boots).toBe(2);
  });
  it('failed takeover stop retains takeover operation', async () => {
    let begun = false; const stop = vi.fn(async () => { throw new Error('stop'); });
    const follower = { ownership: 'follower' as const, signal: new AbortController().signal, close: async () => {}, takeOver: async () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: async () => {} }) };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const coordinator = new MatrixStartupCoordinator(); const port = { begin: () => { begun = true; return { readiness: new Promise<void>(() => {}), stop }; } };
    const first = await coordinator.start(store, { acquire: async () => follower }, port); void (first as { takeOver(): Promise<unknown> }).takeOver();
    await vi.waitFor(() => expect(begun).toBe(true)); await expect(coordinator.close()).rejects.toThrow('stop');
    await coordinator.start(store, { acquire: async () => follower }, port); expect(stop).toHaveBeenCalledOnce();
  });
  it('close during pending takeover closes takeover owner', async () => {
    let begun = false; const stop = vi.fn(async () => {});
    const follower = { ownership: 'follower' as const, signal: new AbortController().signal, close: async () => {}, takeOver: async () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: async () => {} }) };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const coordinator = new MatrixStartupCoordinator(); const port = { begin: () => { begun = true; return { readiness: new Promise<void>(() => {}), stop }; } };
    const first = await coordinator.start(store, { acquire: async () => follower }, port); void (first as { takeOver(): Promise<unknown> }).takeOver();
    await vi.waitFor(() => expect(begun).toBe(true)); await coordinator.close(); expect(stop).toHaveBeenCalledOnce();
  });
  it('keeps a published successor live when its predecessor terminal arrives stale, then clears on successor terminal', async () => {
    let held = false; let boots = 0; const terminals: (() => void)[] = [];
    const locks = { acquire: async (_profileId: string, stop: () => Promise<void>) => held
      ? { ownership: 'blocked' as const, signal: new AbortController().signal, close: async () => {} }
      : (held = true, { ownership: 'owner' as const, signal: new AbortController().signal, close: async () => { await stop(); held = false; } }) };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const port = { begin: () => ({ readiness: Promise.resolve(++boots), stop: async () => {}, onTerminal: (listener: () => void) => { terminals.push(listener); } }) };
    const coordinator = new MatrixStartupCoordinator(); const predecessor = await coordinator.start(store, locks, port);
    await predecessor.close(); const successor = await coordinator.start(store, locks, port); expect(boots).toBe(2);
    void Promise.resolve(terminals[0]?.()).catch(() => undefined); await flush();
    expect(await coordinator.start(store, locks, port)).toBe(successor); expect(boots).toBe(2);
    void Promise.resolve(terminals[1]?.()).catch(() => undefined); await vi.waitFor(() => expect(held).toBe(false));
    await coordinator.start(store, locks, port); expect(boots).toBe(3);
  });
  it('keeps a follower takeover successor live when an earlier runtime terminal arrives stale', async () => {
    let acquisition = 0; let boots = 0; const terminals: (() => Promise<void> | void)[] = [];
    const owner = () => ({ ownership: 'owner' as const, signal: new AbortController().signal, close: async () => {} });
    const follower = { ownership: 'follower' as const, signal: new AbortController().signal, close: async () => {}, takeOver: async () => owner() };
    const locks = { acquire: async () => { acquisition += 1; return acquisition === 2 ? follower : owner(); } };
    const store = { getActiveProfile: async () => locator, loadSession: async () => session } as unknown as IndexedDbSessionStore;
    const port = { begin: () => ({ readiness: Promise.resolve(++boots), stop: async () => {}, onTerminal: (listener: () => Promise<void> | void) => { terminals.push(listener); } }) };
    const coordinator = new MatrixStartupCoordinator();

    const predecessor = await coordinator.start(store, locks, port);
    expect(predecessor.kind).toBe('runtime');
    await predecessor.close();

    const following = await coordinator.start(store, locks, port);
    expect(following.kind).toBe('follower');
    const takeover = await (following as { takeOver(): Promise<ClientStartupResult> }).takeOver();
    expect(takeover.kind).toBe('runtime');
    expect(boots).toBe(2);

    await Promise.resolve(terminals[0]?.());
    await flush();
    expect(await coordinator.start(store, locks, port)).toBe(takeover);
    expect(boots).toBe(2);

    await Promise.resolve(terminals[1]?.());
    await flush();
    const fresh = await coordinator.start(store, locks, port);
    expect(fresh.kind).toBe('runtime');
    expect(boots).toBe(3);
  });
});
