import { describe, expect, it, vi } from 'vitest';
import { beginCryptoBootstrap, bootstrapCrypto, type CryptoBootstrapPort, type SyncState } from './bootstrap-crypto';

const flush = async (): Promise<void> => { for (let i = 0; i < 12; i += 1) await Promise.resolve(); };

function portFixture() {
  const calls: string[] = [];
  let sync: ((state: SyncState) => void) | undefined;
  let terminal: (() => void) | undefined;
  const port: CryptoBootstrapPort = {
    installSyncListener: (listener) => { calls.push('sync-listener'); sync = listener; },
    installRoomListener: () => { calls.push('room-listener'); },
    installMembershipListener: () => { calls.push('membership-listener'); },
    installCryptoListener: () => { calls.push('crypto-listener'); },
    installTrustListener: () => { calls.push('trust-listener'); },
    installDeviceListener: () => { calls.push('device-listener'); },
    installTerminalListener: (listener) => { calls.push('terminal-listener'); terminal = listener; },
    initRustCrypto: (options) => { calls.push(`init:${JSON.stringify(options)}`); return Promise.resolve(); },
    getCrypto: () => { calls.push('get-crypto'); return { kind: 'rust-crypto' }; },
    configureSignedDeviceIsolation: () => { calls.push('isolate'); },
    startClient: () => { calls.push('start'); },
    stopClient: async () => { calls.push('stop'); },
  };
  return { calls, port, emit: (state: SyncState) => sync?.(state), terminal: () => terminal?.() };
}

const options = (policy: 'ready' | 'unverified' | 'blocked' = 'ready') => ({
  cryptoDatabasePrefix: 'profile-a', syncReadyTimeoutMs: 1000,
  evaluatePostSyncPolicy: vi.fn(async () => policy),
});

describe('bootstrapCrypto', () => {
  it('installs listeners, initializes durable crypto, then syncs and evaluates policy', async () => {
    const fixture = portFixture(); const boot = bootstrapCrypto(fixture.port, options());
    await flush(); fixture.emit('PREPARED'); await boot;
    expect(fixture.calls).toEqual([
      'sync-listener', 'terminal-listener', 'room-listener', 'membership-listener', 'crypto-listener', 'trust-listener', 'device-listener',
      'init:{"useIndexedDB":true,"cryptoDatabasePrefix":"profile-a"}', 'get-crypto', 'isolate', 'start',
    ]);
  });

  it('does not sync when initialization fails or crypto is absent', async () => {
    const failed = portFixture(); failed.port.initRustCrypto = async () => { throw new Error('private'); };
    await expect(bootstrapCrypto(failed.port, options())).rejects.toThrow('bootstrap_blocked');
    expect(failed.calls).not.toContain('start');
    const absent = portFixture(); absent.port.getCrypto = () => undefined;
    await expect(bootstrapCrypto(absent.port, options())).rejects.toThrow('bootstrap_blocked');
    expect(absent.calls).not.toContain('start');
  });

  it('waits through retry states for PREPARED', async () => {
    const fixture = portFixture(); const policy = options(); const boot = bootstrapCrypto(fixture.port, policy); await flush();
    fixture.emit('ERROR'); fixture.emit('RECONNECTING'); await flush();
    expect(policy.evaluatePostSyncPolicy).not.toHaveBeenCalled();
    fixture.emit('PREPARED'); expect((await boot).state).toBe('ready');
  });

  it('stops before releasing on sync timeout', async () => {
    vi.useFakeTimers(); const fixture = portFixture(); const boot = bootstrapCrypto(fixture.port, { ...options(), syncReadyTimeoutMs: 1 });
    const rejection = expect(boot).rejects.toThrow('bootstrap_blocked');
    await flush(); await vi.advanceTimersByTimeAsync(1);
    await rejection;
    expect(fixture.calls.slice(-1)).toEqual(['stop']); vi.useRealTimers();
  });

  it('exposes unverified policy and invalidates a ready client', async () => {
    const unverified = portFixture(); const boot = bootstrapCrypto(unverified.port, options('unverified')); await flush(); unverified.emit('PREPARED');
    expect((await boot).state).toBe('unverified');
    const states: string[] = []; const ready = portFixture(); const running = bootstrapCrypto(ready.port, { ...options(), onStateChange: (s) => states.push(s) });
    await flush(); ready.emit('PREPARED'); await running; ready.emit('STOPPED'); await flush();
    expect(states).toContain('ready'); expect(states).toContain('stopped'); expect(ready.calls.slice(-1)).toEqual(['stop']);
  });
  it('rejects readiness promptly but waits to stop during deferred policy evaluation', async () => {
    let resolve!: () => void; const policy = new Promise<'ready'>(done => { resolve = () => done('ready'); }); const fixture = portFixture();
    const operation = beginCryptoBootstrap(fixture.port, { ...options(), evaluatePostSyncPolicy: () => policy });
    await flush(); fixture.emit('PREPARED'); await flush(); fixture.emit('STOPPED');
    await expect(operation.readiness).rejects.toThrow('bootstrap_blocked');
    expect(fixture.calls).not.toContain('stop'); resolve(); await operation.stop();
    expect(fixture.calls.slice(-1)).toEqual(['stop']);
  });
  it('settles stop while PREPARED never arrives', async () => {
    const fixture = portFixture(); const operation = beginCryptoBootstrap(fixture.port, options());
    await flush(); await operation.stop();
    await expect(operation.readiness).rejects.toThrow('bootstrap_blocked');
    expect(fixture.calls.slice(-1)).toEqual(['stop']);
  });
  it('waits for a later listener install after its installed terminal listener cancels, without starting subsequent phases', async () => {
    let resolve!: () => void; const pending = new Promise<void>(done => { resolve = done; }); const fixture = portFixture();
    fixture.port.installRoomListener = () => { fixture.calls.push('room-listener'); return pending; };
    const policy = options(); const operation = beginCryptoBootstrap(fixture.port, policy);
    await vi.waitFor(() => expect(fixture.calls).toEqual(['sync-listener', 'terminal-listener', 'room-listener']));
    fixture.terminal(); await flush(); expect(fixture.calls).toEqual(['sync-listener', 'terminal-listener', 'room-listener']);
    resolve(); await expect(operation.readiness).rejects.toThrow('bootstrap_blocked');
    expect(fixture.calls).toEqual(['sync-listener', 'terminal-listener', 'room-listener', 'stop']);
  });
  it.each(['init', 'isolation', 'start'] as const)('waits for an in-flight %s phase before stopping after cancellation', async (phase) => {
    let resolve!: () => void; const pending = new Promise<void>(done => { resolve = done; }); const fixture = portFixture();
    if (phase === 'init') fixture.port.initRustCrypto = () => { fixture.calls.push('init:{"useIndexedDB":true,"cryptoDatabasePrefix":"profile-a"}'); return pending; };
    if (phase === 'isolation') fixture.port.configureSignedDeviceIsolation = () => { fixture.calls.push('isolate'); return pending; };
    if (phase === 'start') fixture.port.startClient = () => { fixture.calls.push('start'); return pending; };
    const policy = options(); const operation = beginCryptoBootstrap(fixture.port, policy);
    await vi.waitFor(() => expect(fixture.calls).toContain(phase === 'init' ? 'init:{"useIndexedDB":true,"cryptoDatabasePrefix":"profile-a"}' : phase === 'isolation' ? 'isolate' : 'start'));
    fixture.terminal();
    await flush(); expect(fixture.calls).not.toContain('stop');
    if (phase === 'init') expect(fixture.calls).not.toContain('isolate');
    if (phase !== 'start') expect(fixture.calls).not.toContain('start');
    expect(policy.evaluatePostSyncPolicy).not.toHaveBeenCalled();
    resolve();
    await expect(operation.readiness).rejects.toThrow('bootstrap_blocked'); expect(fixture.calls.slice(-1)).toEqual(['stop']);
  });
});
