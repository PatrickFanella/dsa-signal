/** Cross-tab, fail-closed ownership for a Matrix crypto profile. */
import { type CanonicalProfile } from '../auth/canonical-profile';
export { canonicalProfileId } from '../auth/canonical-profile';
export type CryptoProfile = CanonicalProfile;
export interface WebLockManager { request<T>(name: string, options: { ifAvailable?: boolean; signal?: AbortSignal }, callback: (lock: unknown | null) => Promise<T> | T): Promise<T>; }
export interface CryptoBroadcastChannel { postMessage(message: unknown): void; addEventListener(type: 'message', listener: (event: MessageEvent<unknown>) => void): void; removeEventListener(type: 'message', listener: (event: MessageEvent<unknown>) => void): void; close(): void; }
export interface PageLifecycleTarget { addEventListener(type: 'pagehide', listener: () => void): void; removeEventListener(type: 'pagehide', listener: () => void): void; }
export interface CryptoOwnerDependencies { locks?: WebLockManager; createChannel?: (name: string) => CryptoBroadcastChannel; pageLifecycle?: PageLifecycleTarget; takeoverDeadlineMs?: number; setTimer?: (callback: () => void, ms: number) => ReturnType<typeof setTimeout>; clearTimer?: (timer: ReturnType<typeof setTimeout>) => void; }
export type CryptoLifecycleState = 'active' | 'stopping' | 'stopped';
export interface CryptoLifecycleMessage { kind: 'matrix-crypto-lifecycle'; version: 1; profileId: string; state: CryptoLifecycleState; }
export type CryptoOwnership = 'owner' | 'follower' | 'blocked';
export interface CryptoOwnerAcquireOptions { profileId: string; stop: () => Promise<void>; onLifecycle?: (message: CryptoLifecycleMessage) => void; }
export interface CryptoOwnerHandle { readonly ownership: CryptoOwnership; readonly profileId: string; readonly lockName: string; readonly signal: AbortSignal; close(): Promise<void>; beforeRelease(finalizer: () => Promise<void>): void; takeOver(): Promise<CryptoOwnerHandle>; }
const PROFILE_ID = /^[a-f0-9]{64}$/;
const STATES = new Set<CryptoLifecycleState>(['active', 'stopping', 'stopped']);
export const cryptoLockName = (profileId: string): string => `matrix-crypto:${profileId}`;
export function isCryptoLifecycleMessage(value: unknown, profileId: string): value is CryptoLifecycleMessage { if (value === null || typeof value !== 'object' || Array.isArray(value)) return false; const record = value as Record<string, unknown>; return Object.keys(record).length === 4 && record.kind === 'matrix-crypto-lifecycle' && record.version === 1 && record.profileId === profileId && typeof record.state === 'string' && STATES.has(record.state as CryptoLifecycleState); }
const deferred = <T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (reason: unknown) => void } => { let resolve!: (value: T) => void; let reject!: (reason: unknown) => void; return { promise: new Promise((ok, no) => { resolve = ok; reject = no; }), resolve, reject }; };
const bestEffort = (fn: () => void): void => { try { fn(); } catch { /* cleanup cannot change authority */ } };

/** A coordinator is app-scoped: one profile may be live at a time. */
export class CryptoOwnerCoordinator {
  private live: { profileId: string; handle: CryptoOwnerHandle } | undefined;
  private acquiring: Promise<CryptoOwnerHandle> | undefined;
  private acquiringProfile: string | undefined;
  public constructor(private readonly dependencies: CryptoOwnerDependencies) {}
  public acquire(options: CryptoOwnerAcquireOptions): Promise<CryptoOwnerHandle> {
    // Handles carry the authority to release a lease; they must never be shared.
    if (this.live) return Promise.resolve(this.blocked(options));
    if (this.acquiring) return Promise.resolve(this.blocked(options));
    const operation = this.acquireInternal(options, true);
    this.acquiring = operation; this.acquiringProfile = options.profileId;
    void operation.then(handle => { if (handle.ownership !== 'blocked') this.live = { profileId: options.profileId, handle }; }).finally(() => { if (this.acquiring === operation) { this.acquiring = undefined; this.acquiringProfile = undefined; } }).catch(() => undefined);
    return operation;
  }
  public start(options: CryptoOwnerAcquireOptions): Promise<CryptoOwnerHandle> { return this.acquire(options); }
  private blocked(options: CryptoOwnerAcquireOptions): CryptoOwnerHandle { const controller = new AbortController(); return { ownership: 'blocked', profileId: options.profileId, lockName: cryptoLockName(options.profileId), signal: controller.signal, close: async () => { controller.abort(); }, beforeRelease: () => {}, takeOver: async () => this.blocked(options) }; }
  private async acquireInternal(options: CryptoOwnerAcquireOptions, ifAvailable: boolean, signal?: AbortSignal): Promise<CryptoOwnerHandle> {
    const lockName = cryptoLockName(options.profileId);
    if (!PROFILE_ID.test(options.profileId) || !this.dependencies.locks || !this.dependencies.createChannel) return this.blocked(options);
    let channel: CryptoBroadcastChannel;
    try { channel = this.dependencies.createChannel(lockName); } catch { return this.blocked(options); }
    const receive = (event: MessageEvent<unknown>): void => { if (isCryptoLifecycleMessage(event.data, options.profileId)) options.onLifecycle?.(event.data); };
    try { channel.addEventListener('message', receive); } catch { bestEffort(() => channel.close()); return this.blocked(options); }
    const acquired = deferred<CryptoOwnerHandle>();
    let request!: Promise<void>;
    try {
      request = this.dependencies.locks.request(lockName, { ...(ifAvailable ? { ifAvailable: true } : {}), ...(signal ? { signal } : {}) }, async lock => {
        if (lock === null) { const lease = deferred<void>(); const handle = this.makeHandle('follower', options, lockName, channel, lease, () => request); acquired.resolve(handle); await lease.promise; return; }
        const lease = deferred<void>(); const handle = this.makeHandle('owner', options, lockName, channel, lease, () => request); acquired.resolve(handle); this.broadcast(channel, options.profileId, 'active'); await lease.promise;
      });
    } catch { bestEffort(() => channel.removeEventListener('message', receive)); bestEffort(() => channel.close()); return this.blocked(options); }
    void request.finally(() => { bestEffort(() => channel.removeEventListener('message', receive)); }).catch(error => acquired.reject(error));
    try { return await acquired.promise; } catch { bestEffort(() => channel.close()); return this.blocked(options); }
  }
  private broadcast(channel: CryptoBroadcastChannel, profileId: string, state: CryptoLifecycleState): void { bestEffort(() => channel.postMessage({ kind: 'matrix-crypto-lifecycle', version: 1, profileId, state } satisfies CryptoLifecycleMessage)); }
  private makeHandle(ownership: CryptoOwnership, options: CryptoOwnerAcquireOptions, lockName: string, channel: CryptoBroadcastChannel, lease: { resolve: (v: void) => void }, request: () => Promise<void>): CryptoOwnerHandle {
    const controller = new AbortController(); let closePromise: Promise<void> | undefined; let finalizer: () => Promise<void> = async () => {};
    const close = (): Promise<void> => {
      controller.abort(); // cancellation is observable before any asynchronous cleanup begins.
      return closePromise ??= (async () => {
        if (ownership === 'owner') { this.broadcast(channel, options.profileId, 'stopping'); await options.stop(); await finalizer(); this.broadcast(channel, options.profileId, 'stopped'); }
        bestEffort(() => this.dependencies.pageLifecycle?.removeEventListener('pagehide', pagehide)); bestEffort(() => channel.close()); lease.resolve();
        await request(); // completion is the Web Locks release acknowledgement.
      })().then(() => { if (this.live?.handle === handle) this.live = undefined; });
    };
    const pagehide = (): void => { void close().catch(() => undefined); };
    if (ownership === 'owner') bestEffort(() => this.dependencies.pageLifecycle?.addEventListener('pagehide', pagehide));
    const handle: CryptoOwnerHandle = { ownership, profileId: options.profileId, lockName, signal: controller.signal, close, beforeRelease: next => { if (ownership !== 'owner' || closePromise) throw new Error('owner finalizer unavailable'); finalizer = next; }, takeOver: async () => {
      if (ownership !== 'follower') return this.blocked(options);
      await close();
      const deadline = new AbortController(); const timer = (this.dependencies.setTimer ?? setTimeout)(() => deadline.abort(), this.dependencies.takeoverDeadlineMs ?? 5_000);
      try {
        const next = await this.acquireInternal(options, false, deadline.signal);
        if (next.ownership === 'owner') this.live = { profileId: options.profileId, handle: next };
        else await next.close().catch(() => undefined);
        return next.ownership === 'owner' ? next : this.blocked(options);
      } finally { (this.dependencies.clearTimer ?? clearTimeout)(timer); }
    } };
    return handle;
  }
}
export function browserCryptoOwnerDependencies(): CryptoOwnerDependencies { return { locks: typeof navigator !== 'undefined' ? navigator.locks : undefined, createChannel: typeof BroadcastChannel !== 'undefined' ? (name) => new BroadcastChannel(name) : undefined, pageLifecycle: typeof window !== 'undefined' ? window : undefined }; }
