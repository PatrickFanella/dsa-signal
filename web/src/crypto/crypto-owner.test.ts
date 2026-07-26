import { describe, expect, it } from 'vitest';
import { canonicalProfileId, CryptoBroadcastChannel, CryptoOwnerCoordinator, cryptoLockName, isCryptoLifecycleMessage, WebLockManager } from './crypto-owner';
const profileId = 'a'.repeat(64);
class Locks implements WebLockManager { held = false; async request<T>(_n: string, _o: { ifAvailable: true }, callback: (lock: unknown | null) => Promise<T> | T): Promise<T> { if (this.held) return callback(null); this.held = true; try { return await callback({}); } finally { this.held = false; } } }
class Channel implements CryptoBroadcastChannel { sent: unknown[] = []; listeners = new Set<(event: MessageEvent<unknown>) => void>(); postMessage(m: unknown): void { this.sent.push(m); } addEventListener(_t: 'message', l: (e: MessageEvent<unknown>) => void): void { this.listeners.add(l); } removeEventListener(_t: 'message', l: (e: MessageEvent<unknown>) => void): void { this.listeners.delete(l); } close(): void {} receive(m: unknown): void { this.listeners.forEach(l => l({ data: m } as MessageEvent<unknown>)); } }
describe('crypto ownership', () => {
  it('uses framed canonical profile ids and validates lifecycle DTOs', async () => { await expect(canonicalProfileId({ homeserver: 'ab', userId: 'c', deviceId: '' })).resolves.not.toBe(await canonicalProfileId({ homeserver: 'a', userId: 'bc', deviceId: '' })); expect(isCryptoLifecycleMessage({ kind: 'matrix-crypto-lifecycle', version: 1, profileId, state: 'active' }, profileId)).toBe(true); expect(cryptoLockName(profileId)).toBe(`matrix-crypto:${profileId}`); });
  it('holds an owner lease until stop resolves and lets a durable follower explicitly take over', async () => {
    const locks = new Locks(); const owner = new CryptoOwnerCoordinator({ locks, createChannel: () => new Channel() }); const follower = new CryptoOwnerCoordinator({ locks, createChannel: () => new Channel() });
    let stop = 0; const first = await owner.acquire({ profileId, stop: async () => { stop += 1; } }); const second = await follower.acquire({ profileId, stop: async () => {} });
    expect(first.ownership).toBe('owner'); expect(second.ownership).toBe('follower'); await first.close(); expect(stop).toBe(1); const takeover = await second.takeOver(); expect(takeover.ownership).toBe('owner'); await takeover.close();
  });
  it('blocks unsupported browser primitives', async () => { expect((await new CryptoOwnerCoordinator({}).acquire({ profileId, stop: async () => {} })).ownership).toBe('blocked'); });
  it('resolves acquisition from an asynchronously scheduled callback and waits for release acknowledgement', async () => {
    let release!: () => void; let released = false;
    const locks: WebLockManager = { request: async <T>(_name: string, _options: { ifAvailable?: boolean; signal?: AbortSignal }, callback: (lock: unknown | null) => Promise<T> | T): Promise<T> => new Promise<T>((resolve, reject) => queueMicrotask(() => { void Promise.resolve(callback({})).then(value => { released = true; resolve(value); }, reject); })) };
    const handle = await new CryptoOwnerCoordinator({ locks, createChannel: () => ({ postMessage: () => { throw new Error('best effort'); }, addEventListener: () => {}, removeEventListener: () => {}, close: () => {} }) }).acquire({ profileId, stop: async () => { await new Promise<void>(done => { release = done; }); } });
    const closing = handle.close(); await Promise.resolve(); expect(released).toBe(false); release(); await closing; expect(released).toBe(true);
  });
  it('aborts the owner signal synchronously when close begins', async () => {
    let release!: () => void;
    const handle = await new CryptoOwnerCoordinator({ locks: new Locks(), createChannel: () => new Channel() }).acquire({ profileId, stop: async () => { await new Promise<void>(done => { release = done; }); } });
    const closing = handle.close();
    expect(handle.signal.aborted).toBe(true);
    release(); await closing;
  });
  it('blocks duplicate callers and retains authority when stopping fails', async () => {
    const coordinator = new CryptoOwnerCoordinator({ locks: new Locks(), createChannel: () => new Channel() });
    const first = await coordinator.acquire({ profileId, stop: async () => { throw new Error('stop failed'); } });
    expect((await coordinator.acquire({ profileId, stop: async () => {} })).ownership).toBe('blocked');
    const closing = first.close(); await expect(closing).rejects.toThrow('stop failed');
    expect(first.close()).toBe(closing);
    expect((await coordinator.acquire({ profileId, stop: async () => {} })).ownership).toBe('blocked');
  });
  it('runs a registered finalizer after stop and before releasing the lock', async () => {
    const calls: string[] = []; const locks = new Locks();
    const handle = await new CryptoOwnerCoordinator({ locks, createChannel: () => new Channel() }).acquire({ profileId, stop: async () => { calls.push('stop'); } });
    handle.beforeRelease(async () => { calls.push('finalize'); });
    await handle.close();
    expect(calls).toEqual(['stop', 'finalize']); expect(locks.held).toBe(false);
  });
  it('does not run its finalizer or release authority when stop fails', async () => {
    const locks = new Locks(); let finalized = false;
    const handle = await new CryptoOwnerCoordinator({ locks, createChannel: () => new Channel() }).acquire({ profileId, stop: async () => { throw new Error('stop'); } });
    handle.beforeRelease(async () => { finalized = true; });
    await expect(handle.close()).rejects.toThrow('stop'); expect(finalized).toBe(false); expect(locks.held).toBe(true);
  });
});
