/** SDK-free bootstrap. Ownership is acquired outside this boundary. */
import type { EncryptionPolicyEpoch } from '../matrix/encryption-policy';
export type CryptoDatabaseOptions = Readonly<{ useIndexedDB: true; cryptoDatabasePrefix: string }>;
export type SyncState = 'PREPARED' | 'RECONNECTING' | 'ERROR' | 'STOPPED';
export type CryptoBootstrapState = 'starting' | 'unverified' | 'blocked' | 'ready' | 'stopped';
export type PostSyncPolicy = 'ready' | 'unverified' | 'blocked';
export interface CryptoFacade { readonly kind: 'rust-crypto'; }
export interface CryptoBootstrapPort {
  installSyncListener(listener: (state: SyncState) => void): void | Promise<void>;
  installRoomListener(listener: () => void): void | Promise<void>; installMembershipListener(listener: () => void): void | Promise<void>; installCryptoListener(listener: () => void): void | Promise<void>; installTrustListener(listener: () => void): void | Promise<void>; installDeviceListener(listener: () => void): void | Promise<void>;
  installTerminalListener(listener: () => void): void | Promise<void>;
  initRustCrypto(options: CryptoDatabaseOptions): Promise<void>; getCrypto(): CryptoFacade | undefined; configureSignedDeviceIsolation(crypto: CryptoFacade): void | Promise<void>; startClient(): void | Promise<void>; stopClient(): Promise<void>;
}
export type BootstrapCryptoOptions = Readonly<{ cryptoDatabasePrefix: string; syncReadyTimeoutMs: number; evaluatePostSyncPolicy: (crypto: CryptoFacade) => PostSyncPolicy | Promise<PostSyncPolicy>; policyEpoch?: EncryptionPolicyEpoch; onStateChange?: (state: CryptoBootstrapState) => void; }>;
export type BootstrapCryptoResult = Readonly<{ state: 'ready' | 'unverified' | 'blocked' | 'stopped'; stop: () => Promise<void>; }>;
export type CryptoBootstrapOperation = Readonly<{ readiness: Promise<BootstrapCryptoResult>; stop: () => Promise<void>; onTerminal(listener: () => Promise<void> | void): void; }>;
const error = (): Error => new Error('bootstrap_blocked');
export function beginCryptoBootstrap(port: CryptoBootstrapPort, options: BootstrapCryptoOptions): CryptoBootstrapOperation {
  let terminal = false; let liveRuntime = false; let stopped: Promise<void> | undefined; let timer: ReturnType<typeof setTimeout> | undefined;
  let resolvePrepared!: () => void; let rejectPrepared!: (reason: Error) => void;
  const transition = (state: CryptoBootstrapState): void => options.onStateChange?.(state);
  let phase: Promise<void> = Promise.resolve();
  const inPhase = async <T>(work: () => T | Promise<T>): Promise<T> => {
    let finish!: () => void;
    const current = new Promise<void>(resolve => { finish = resolve; });
    phase = current;
    try { return await work(); } finally { finish(); if (phase === current) phase = Promise.resolve(); }
  };
  let cancelWait: ((reason: Error) => void) | undefined;
  const cancel = (): void => cancelWait?.(error());
  const stop = (): Promise<void> => stopped ??= (async () => { terminal = true; cancel(); if (timer !== undefined) clearTimeout(timer); await phase.catch(() => undefined); await port.stopClient(); transition('stopped'); })();
  let terminalListener: (() => Promise<void> | void) | undefined;
  const terminalSignal = (): void => { terminal = true; cancel(); if (liveRuntime && terminalListener) void Promise.resolve(terminalListener()).catch(() => undefined); else void stop().catch(() => undefined); };
  const changed = (change: () => void): void => { change(); if (!terminal) transition('unverified'); };
  const prepared = new Promise<void>((resolve, reject) => { resolvePrepared = resolve; rejectPrepared = reject; });
  void prepared.catch(() => undefined);
  const readiness = (async (): Promise<BootstrapCryptoResult> => { try {
    transition('starting');
    await inPhase(() => port.installSyncListener(state => { if (state === 'PREPARED') resolvePrepared(); else if (state === 'STOPPED') { rejectPrepared(error()); terminalSignal(); } })); if (terminal) throw error();
    // Install this before the remaining listeners: it is the only terminal signal
    // which can cancel a later, non-abandonable listener installation.
    await inPhase(() => port.installTerminalListener(terminalSignal)); if (terminal) throw error();
    await inPhase(() => port.installRoomListener(() => changed(() => options.policyEpoch?.roomStateChanged()))); if (terminal) throw error();
    await inPhase(() => port.installMembershipListener(() => changed(() => options.policyEpoch?.membershipChanged()))); if (terminal) throw error();
    await inPhase(() => port.installCryptoListener(() => changed(() => options.policyEpoch?.devicesChanged()))); if (terminal) throw error();
    await inPhase(() => port.installTrustListener(() => changed(() => options.policyEpoch?.userTrustOrKeysChanged()))); if (terminal) throw error();
    await inPhase(() => port.installDeviceListener(() => changed(() => options.policyEpoch?.devicesChanged()))); if (terminal) throw error();
    if (terminal) throw error();
    await inPhase(() => port.initRustCrypto({ useIndexedDB: true, cryptoDatabasePrefix: options.cryptoDatabasePrefix })); if (terminal) throw error();
    const crypto = port.getCrypto(); if (!crypto) throw error(); await inPhase(() => port.configureSignedDeviceIsolation(crypto)); if (terminal) throw error(); await inPhase(() => port.startClient()); liveRuntime = true;
    if (terminal) throw error();
    const cancellation = new Promise<never>((_, reject) => { cancelWait = reject; });
    void cancellation.catch(() => undefined);
    try { await Promise.race([prepared, cancellation, new Promise<void>((_, reject) => { timer = setTimeout(() => reject(error()), options.syncReadyTimeoutMs); })]); } finally { if (timer !== undefined) clearTimeout(timer); }
    if (terminal) throw error();
    const epoch = options.policyEpoch?.value;
    // Cancellation may reject readiness, but policy evaluation has touched the
    // current crypto machine and must settle before cleanup can stop it.
    const policyEvaluation = inPhase(() => Promise.resolve().then(() => options.evaluatePostSyncPolicy(crypto)));
    const policy = await Promise.race([policyEvaluation, cancellation]); if (terminal) throw error(); if (epoch !== options.policyEpoch?.value) return { state: 'unverified', stop };
    transition(policy); return { state: policy, stop };
  } catch {
    transition('blocked');
    const cleanup = stop();
    // Do not make a terminal policy cancellation wait on its non-abandonable
    // callback; cleanup is already sequenced behind the active phase.
    if (terminal) void cleanup.catch(() => undefined);
    else try { await cleanup; } catch { /* stop rejection means the outer owner must remain held */ }
    throw error();
  } })();
  return { readiness, stop, onTerminal: listener => { terminalListener = listener; } };
}
/** Compatibility helper for callers that do not need the operation handle. */
export async function bootstrapCrypto(port: CryptoBootstrapPort, options: BootstrapCryptoOptions): Promise<BootstrapCryptoResult> {
  return beginCryptoBootstrap(port, options).readiness;
}
