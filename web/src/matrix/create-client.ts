/** SDK-free startup coordinator: credentials are read only by the lock owner. */
import { type ActiveProfileLocator, type IndexedDbSessionStore, type MatrixSession } from '../auth/session-store';
import { canonicalProfileId } from '../crypto/crypto-owner';
import { MATRIX_HOMESERVER } from '../auth/matrix-topology';
import type { MatrixGateway } from './contract';
export interface ProfileLock { readonly ownership: 'owner' | 'follower' | 'blocked'; readonly signal: AbortSignal; close(): Promise<void>; beforeRelease?(finalizer: () => Promise<void>): void; takeOver?(): Promise<ProfileLock>; }
export interface ProfileLockPort { acquire(profileId: string, stop: () => Promise<void>): Promise<ProfileLock>; }
export interface ClientBootstrapOperation { readonly readiness: Promise<unknown>; readonly gateway?: MatrixGateway; stop(): Promise<void>; onTerminal?(listener: () => Promise<void> | void): void; }
export interface ClientBootstrapPort { begin(session: MatrixSession, signal: AbortSignal): ClientBootstrapOperation; }
export type ClientBeginToken = object;
export type ClientStartupResult = ClientRuntimeHandle | ClientFollowerHandle | ClientBlockedHandle | ClientSignedOutHandle;
export interface ClientBaseHandle { readonly kind: 'runtime' | 'follower' | 'blocked' | 'signed-out'; close(): Promise<void>; }
export interface ClientRuntimeHandle extends ClientBaseHandle { readonly kind: 'runtime'; readonly session: MatrixSession; readonly gateway?: MatrixGateway; beforeRelease?(finalizer: () => Promise<void>): void; }
export interface ClientFollowerHandle extends ClientBaseHandle { readonly kind: 'follower'; takeOver(): Promise<ClientStartupResult>; }
export interface ClientBlockedHandle extends ClientBaseHandle { readonly kind: 'blocked'; }
export interface ClientSignedOutHandle extends ClientBaseHandle { readonly kind: 'signed-out'; }
const inert = <T extends 'blocked' | 'signed-out'>(kind: T): ClientBaseHandle & { kind: T } => ({ kind, close: async () => {} });
const settled = (): { promise: Promise<void>; resolve: () => void } => { let resolve!: () => void; return { promise: new Promise(done => { resolve = done; }), resolve }; };
const sameLocator = (left: ActiveProfileLocator, right: ActiveProfileLocator | undefined): boolean => right?.profileId === left.profileId && right.generation === left.generation;

/** App-scoped boundary for StrictMode: callers share a runtime result, never a lock handle. */
export class MatrixStartupCoordinator {
  private operation: Promise<ClientStartupResult> | undefined;
  private closeForOperation: (() => Promise<void>) | undefined;
  private tokenForOperation: ClientBeginToken | undefined;
  private readonly operationsByToken = new Map<ClientBeginToken, Promise<ClientStartupResult>>();
  /** Close only the operation that is currently published; stale terminals cannot affect a successor. */
  public close(): Promise<void> {
    const operation = this.operation;
    if (!operation) return Promise.resolve();
    const close = this.closeForOperation;
    return (close ? close() : operation.then(result => result.close())).then(() => {
      if (this.operation === operation) this.clear(operation);
    });
  }
  public start(store: IndexedDbSessionStore, locks: ProfileLockPort, port: ClientBootstrapPort, retries = 2): Promise<ClientStartupResult> {
    if (this.operation) return this.operation;
    const manage = (operation: Promise<ClientStartupResult>): Promise<ClientStartupResult> => {
      let takeover: Promise<ClientStartupResult> | undefined;
      const shared = operation.then(result => {
        if (result.kind === 'follower') {
          const close = result.close;
          return { ...result, close: () => close().then(() => { if (this.operation === shared) this.clear(shared); }), takeOver: () => {
            if (!takeover) { takeover = manage(result.takeOver()); this.operation = takeover; this.closeForOperation = undefined; this.tokenForOperation = undefined; }
            return takeover;
          } };
        }
        if (result.kind === 'runtime') {
          const close = result.close;
          return { ...result, close: () => close().then(() => { if (this.operation === shared) this.clear(shared); }) } as ClientStartupResult;
        }
        if (result.kind === 'signed-out' && this.operation === shared) this.clear(shared);
        return result;
      }).catch(error => { if (this.operation === shared) this.clear(shared); throw error; });
      return shared;
    };
    const operation = createClientForActiveProfile(store, locks, port, retries,
      token => { const mapped = this.operationsByToken.get(token); if (mapped && this.operation === mapped) this.clear(mapped); },
      (token, close) => { const current = this.operation; if (current) { this.operationsByToken.set(token, current); if (this.operation === current) { this.tokenForOperation = token; this.closeForOperation = close; } } });
    const shared = manage(operation);
    this.operation = shared;
    return shared;
  }
  private clear(operation: Promise<ClientStartupResult>): void {
    if (this.operation !== operation) return;
    for (const [token, mapped] of this.operationsByToken) if (mapped === operation) this.operationsByToken.delete(token);
    this.operation = undefined; this.closeForOperation = undefined; this.tokenForOperation = undefined;
  }
}

/** Re-reads the locator after ownership, so a stale non-secret locator cannot cause token use. */
export async function createClientForActiveProfile(store: IndexedDbSessionStore, locks: ProfileLockPort, port: ClientBootstrapPort, retries = 2, onAutomaticClose?: (token: ClientBeginToken, close: () => Promise<void>) => void, onBeginning?: (token: ClientBeginToken, close: () => Promise<void>) => void): Promise<ClientStartupResult> {
  let unsubscribe: (() => void) | undefined;
  let activeClose: (() => Promise<void>) | undefined;
  const installLossGuard = (): void => { unsubscribe ??= store.subscribeStorageLoss?.(() => { void activeClose?.().catch(() => undefined); }) ?? (() => {}); };
  const forgetGuard = (): void => { unsubscribe?.(); unsubscribe = undefined; activeClose = undefined; };
  const retain = (owner: ProfileLock): (() => Promise<void>) => {
    installLossGuard();
    let closing: Promise<void> | undefined;
    const close = (): Promise<void> => closing ??= owner.close().then(() => { forgetGuard(); });
    activeClose = close;
    return close;
  };
  try {
    for (let attempt = 0; attempt < retries; attempt += 1) {
      let locator: ActiveProfileLocator | undefined;
      try { locator = await store.getActiveProfile(); } catch { return inert('blocked'); }
      if (!locator) return inert('signed-out');
      const startup = settled(); let operation: ClientBootstrapOperation | undefined; let stopPromise: Promise<void> | undefined;
      const stop = (): Promise<void> => stopPromise ??= (async () => { if (!operation) startup.resolve(); await operation?.stop(); })();
      let owner: ProfileLock;
      try { owner = await locks.acquire(locator.profileId, stop); } catch { return inert('blocked'); }
      if (owner.ownership === 'blocked') { startup.resolve(); await owner.close().catch(() => undefined); return inert('blocked'); }
      if (owner.ownership === 'follower') {
        const close = retain(owner);
        return { kind: 'follower', close, takeOver: async () => {
          await close();
          if (!owner.takeOver) { startup.resolve(); return inert('blocked'); }
          let next: ProfileLock | undefined;
          try {
            next = await owner.takeOver();
            if (next.ownership !== 'owner') { startup.resolve(); await next.close().catch(() => undefined); return inert('blocked'); }
            // Retain authority before touching storage; loss can occur in any following await.
            const nextClose = retain(next);
            const current = await store.getActiveProfile();
            if (!current || !sameLocator(locator, current) || next.signal.aborted) throw new Error('locator_drift');
            const activeSession = await store.loadSession(current);
            if (!activeSession || next.signal.aborted || activeSession.homeserver !== MATRIX_HOMESERVER || activeSession.profileId !== await canonicalProfileId({ homeserver: MATRIX_HOMESERVER, userId: activeSession.userId, deviceId: activeSession.deviceId })) throw new Error('startup_blocked');
            operation = port.begin(activeSession, next.signal); const token: ClientBeginToken = {}; let cancelBeginning!: () => void; const beginningCancelled = new Promise<never>((_, reject) => { cancelBeginning = () => reject(new Error('startup_closed')); }); void beginningCancelled.catch(() => undefined); const closeBeginning = async (): Promise<void> => { cancelBeginning(); await operation!.stop(); await nextClose(); }; onBeginning?.(token, closeBeginning); operation.onTerminal?.(async () => { await nextClose(); onAutomaticClose?.(token, closeBeginning); }); startup.resolve(); await Promise.race([operation.readiness, beginningCancelled]);
            if (next.signal.aborted) throw new Error('startup_aborted');
            return { kind: 'runtime', session: activeSession, ...(operation.gateway ? { gateway: operation.gateway } : {}), close: nextClose, ...(next.beforeRelease ? { beforeRelease: next.beforeRelease.bind(next) } : {}) };
          } catch {
            startup.resolve();
            if (next?.ownership === 'owner') {
              try { await (activeClose ?? next.close.bind(next))(); } catch { return { kind: 'blocked', close: activeClose ?? next.close.bind(next) }; }
            }
            return inert('blocked');
          }
        } };
      }
      const close = retain(owner); // install before rereading storage, not after bootstrap.
      let current: ActiveProfileLocator | undefined;
      try { current = await store.getActiveProfile(); } catch { startup.resolve(); try { await close(); } catch { return { kind: 'blocked', close }; } return inert('blocked'); }
      if (!current || !sameLocator(locator, current)) {
        startup.resolve();
        try { await close(); } catch { return { kind: 'blocked', close }; }
        if (!current) return inert('blocked');
        continue;
      }
      if (owner.signal.aborted) { startup.resolve(); try { await close(); } catch { return { kind: 'blocked', close }; } return inert('blocked'); }
      let session: MatrixSession | undefined;
      try { session = await store.loadSession(current); } catch { startup.resolve(); try { await close(); } catch { return { kind: 'blocked', close }; } return inert('blocked'); }
      if (!session || owner.signal.aborted || session.homeserver !== MATRIX_HOMESERVER || session.profileId !== await canonicalProfileId({ homeserver: MATRIX_HOMESERVER, userId: session.userId, deviceId: session.deviceId })) { startup.resolve(); try { await close(); } catch { return { kind: 'blocked', close }; } return inert('blocked'); }
      try {
        operation = port.begin(session, owner.signal); const token: ClientBeginToken = {}; let cancelBeginning!: () => void; const beginningCancelled = new Promise<never>((_, reject) => { cancelBeginning = () => reject(new Error('startup_closed')); }); void beginningCancelled.catch(() => undefined); const closeBeginning = async (): Promise<void> => { cancelBeginning(); await operation!.stop(); await close(); }; onBeginning?.(token, closeBeginning); operation.onTerminal?.(async () => { await close(); onAutomaticClose?.(token, closeBeginning); }); startup.resolve(); await Promise.race([operation.readiness, beginningCancelled]);
        if (owner.signal.aborted) throw new Error('startup_aborted');
        return { kind: 'runtime', session, ...(operation.gateway ? { gateway: operation.gateway } : {}), close, ...(owner.beforeRelease ? { beforeRelease: owner.beforeRelease.bind(owner) } : {}) };
      } catch {
        startup.resolve();
        try { await close(); } catch { return { kind: 'blocked', close }; }
        return inert('blocked');
      }
    }
    return inert('blocked');
  } finally { if (!activeClose) forgetGuard(); }
}
export class SessionCommitError extends Error { public constructor(public readonly outcome: 'uncommitted', public readonly releaseError: boolean) { super('Matrix session was not committed'); this.name = 'SessionCommitError'; } }
/** WHOAMI computes the canonical profile externally; commit is serialized under that profile lock. */
/** A release failure after durable commit remains authority-retained; callers must not revoke persisted tokens. */
export async function commitWhoamiSession(store: IndexedDbSessionStore, locks: ProfileLockPort, session: MatrixSession, spentState: string): Promise<{ locator: ActiveProfileLocator; releaseError?: true }> { const owner = await locks.acquire(session.profileId, async () => {}); if (owner.ownership !== 'owner') { try { await owner.close(); } catch { /* authority remains unavailable */ } throw new SessionCommitError('uncommitted', false); } let locator: ActiveProfileLocator; try { locator = await store.commitSession(session, spentState); } catch { let releaseError = false; try { await owner.close(); } catch { releaseError = true; } throw new SessionCommitError('uncommitted', releaseError); } try { await owner.close(); return { locator }; } catch { return { locator, releaseError: true }; } }
