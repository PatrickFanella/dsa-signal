/** The sole production Matrix SDK boundary. Nothing SDK-shaped leaves here. */
import { ClientEvent, createClient, HttpApiEvent, MatrixEventEvent, OAuth2, RoomEvent, RoomMemberEvent, RoomStateEvent, SyncState, type IDownloadKeyResult, type MatrixEvent, type Room, type RoomMember, type ValidatedAuthMetadata } from 'matrix-js-sdk';
import { CryptoEvent, CrossSigningKey, OnlySignedDevicesIsolationMode, type CryptoApi } from 'matrix-js-sdk/lib/crypto-api';
import { matchesSasWireContext, type CrossSigningBootstrapBinding, type IndexedDbSessionStore, type MatrixSession, type SasOperation, type SasStableGrantBinding, type SasWireContext, type TextOutboxRecord } from '../../auth/session-store';
import type { ClientBootstrapOperation, ClientBootstrapPort } from '../create-client';
import { beginCryptoBootstrap, type CryptoBootstrapPort } from '../../crypto/bootstrap-crypto';
import { assessDirectSendReadiness, assessPostAdmission, assessPreJoinAdmission, buildEncryptedRoomCreateRequest, EncryptionPolicyEpoch, INVITE_JOIN_RULE, JOINED_HISTORY_VISIBILITY, MEGOLM_V1_AES_SHA2, type AuthoritativeDeviceKey, type DeviceEnumeration, type RoomStateEvent as PolicyRoomStateEvent } from '../encryption-policy';
import type { DirectConversation, DirectConversationIdentity, DirectConversationListener, DirectTrustListener, MatrixGateway, MatrixSecurityState, MatrixSecurityStateListener, TimelineListener, TimelineTextMessage, VerificationListener } from '../contract';
import type { MatrixOAuthPort } from '../../auth/matrix-oauth';
import { ownedVerificationEnvelope, validateVerificationEnvelope } from '../verification-wire';
import { reduceIncoming } from '../message-timeline';
import { parseMatrixDeviceId, parseMatrixUserId, parseSupportedDomainRoomId } from '../identifiers';
import { canonicalProfileId } from '../../auth/canonical-profile';
import { MATRIX_HOMESERVER } from '../../auth/matrix-topology';

/** These are the v42 public verification enum wire values. They are not
 * re-exported by either permitted SDK entry point, so retain them narrowly. */
const VerificationPhase = { Requested: 2, Ready: 3, Started: 4, Cancelled: 5, Done: 6 } as const;
const VerificationRequestEvent = { Change: 'change' } as const;
const VerifierEvent = { Cancel: 'cancel', ShowSas: 'show_sas' } as const;
interface Verifier { readonly userId: string; verify(): Promise<void>; on(event: string, listener: (value: unknown) => void): void; getShowSasCallbacks?(): ShowSasCallbacks | null | undefined; }
interface ShowSasCallbacks { readonly sas: { readonly emoji?: readonly [string, string][]; readonly decimal?: readonly number[] }; confirm(): Promise<void>; mismatch(): void; cancel(): void; }
interface SdkVerificationRequest { readonly transactionId: string | undefined; readonly roomId: string | undefined; readonly initiatedByMe: boolean; readonly otherUserId: string; readonly otherDeviceId: string | undefined; readonly isSelfVerification: boolean; readonly phase: number; readonly chosenMethod: string | null; readonly verifier: Verifier | undefined; accept(): Promise<void>; cancel(): Promise<void>; startVerification(method: string): Promise<Verifier>; on(event: string, listener: () => void): void; }
type VerificationWireRequest = SdkVerificationRequest;
const onVerifier = (verifier: Verifier, event: string, listener: (value: unknown) => void): void => { verifier.on(event, listener); };
const onRequest = (request: SdkVerificationRequest, listener: () => void): void => { request.on(VerificationRequestEvent.Change, listener); };
const wireContext = (event: MatrixEvent | undefined, context: Parameters<typeof validateVerificationEnvelope>[1], localDeviceId: string): SasWireContext | undefined => {
  if (!event) return undefined;
  const envelope = ownedVerificationEnvelope(event);
  if (!envelope) return undefined;
  const validated = validateVerificationEnvelope(envelope, context);
  return validated === undefined ? undefined : { roomId: validated.roomId, sender: validated.sender, requestEventId: validated.requestEventId, peerDeviceId: validated.peerDeviceId, localDeviceId };
};

interface SilentLogger { trace(..._values: readonly unknown[]): void; debug(..._values: readonly unknown[]): void; info(..._values: readonly unknown[]): void; warn(..._values: readonly unknown[]): void; error(..._values: readonly unknown[]): void; getChild(_name: string): SilentLogger; }
const silentLogger: SilentLogger = Object.freeze({ trace: () => undefined, debug: () => undefined, info: () => undefined, warn: () => undefined, error: () => undefined, getChild: () => silentLogger });
const unavailable = (): never => { throw new Error('Matrix room admission is unavailable'); };
const policyEvent = (event: MatrixEvent): PolicyRoomStateEvent => ({ type: event.getType(), stateKey: event.getStateKey() ?? '', content: event.getContent() });
const state = (room: Room): readonly PolicyRoomStateEvent[] => ['m.room.join_rules', 'm.room.encryption', 'm.room.history_visibility'].flatMap(type => room.currentState.getStateEvents(type).map(policyEvent));
const roomId = (value: string): import('../contract').MatrixRoomId => parseSupportedDomainRoomId(value) ?? unavailable();
const userId = (value: string): import('../contract').MatrixUserId => parseMatrixUserId(value) ?? unavailable();
const deviceId = (value: string): import('../contract').MatrixDeviceId => parseMatrixDeviceId(value) ?? unavailable();
/** Cache propagation after create/join can take several sync turns in production. */
const ROOM_STATE_STABILIZATION_TIMEOUT_MS = 12_000;
const ROOM_STATE_STABILIZATION_POLL_MS = 25;
/** Internal-only clock seam: production keeps the absolute 12 second bound. */
export interface RoomStabilizationClock { now(): number; sleep(milliseconds: number): Promise<void>; }
const productionRoomClock: RoomStabilizationClock = { now: () => Date.now(), sleep: milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)) };
const hasRequiredRoomState = (room: Room): boolean => {
  const events = state(room);
  const exact = (type: string, key: string, field: string, value: string): boolean => events.filter(event => event.type === type && event.stateKey === key && event.content[field] === value).length === 1;
  return events.length === 3
    && exact('m.room.join_rules', '', 'join_rule', INVITE_JOIN_RULE)
    && exact('m.room.encryption', '', 'algorithm', MEGOLM_V1_AES_SHA2)
    && exact('m.room.history_visibility', '', 'history_visibility', JOINED_HISTORY_VISIBILITY);
};
const waitForJoinedRoom = async (raw: ReturnType<typeof createClient>, id: import('../contract').MatrixRoomId, clock: RoomStabilizationClock): Promise<Room | undefined> => {
  const deadline = clock.now() + ROOM_STATE_STABILIZATION_TIMEOUT_MS;
  do {
    const room = raw.getRoom(id);
    if (room?.getMyMembership() === 'join' && hasRequiredRoomState(room)) return room;
    const remaining = deadline - clock.now();
    if (remaining <= 0) return undefined;
    await clock.sleep(Math.min(ROOM_STATE_STABILIZATION_POLL_MS, remaining));
  } while (clock.now() < deadline);
  return undefined;
};

/** Creates no client until the startup coordinator has acquired ownership. */
type BootstrapStore = Pick<IndexedDbSessionStore, 'getBootstrapDisposition' | 'compareAndSetBootstrapDisposition'>;
/** Internal query seam: production uses the SDK's authenticated key query. */
type RawChainVerifier = (result: IDownloadKeyResult, session: MatrixSession) => Promise<boolean>;
/** Expiry scheduling is monotonic in a running process.  The persisted wall-clock
 * expiry remains deliberately conservative after a reload. */
interface SasScheduler { now?(): number; setTimeout(callback: () => void, milliseconds: number): unknown; clearTimeout(handle: unknown): void; }
const productionSasScheduler: SasScheduler = { now: () => globalThis.performance.now(), setTimeout: (callback, milliseconds) => setTimeout(callback, milliseconds), clearTimeout: handle => clearTimeout(handle as ReturnType<typeof setTimeout>) };
type BootstrapDependencies = { readonly store: BootstrapStore & Pick<IndexedDbSessionStore, 'getSasOperation' | 'createSasIntent' | 'createIncomingSasOperation' | 'bindSasRequest' | 'bindSasPeerDevice' | 'bindSasStartEvent' | 'advanceSasPhase' | 'disposeSasOperation' | 'getSyncGeneration' | 'incrementSyncGeneration' | 'rebaseUnresolvedOutbox' | 'listUnresolvedTextOutboxRecords' | 'getTextOutboxRecord' | 'createInitialTextOutboxRecord' | 'markOutboxIndeterminate' | 'recordOutboxAcceptance' | 'reconcileOutboxRemoteEcho' | 'consumeOutboxRetry' | 'rollbackOutboxRetry'>; readonly roomClock?: RoomStabilizationClock; /** Private deterministic expiry seam. */ readonly sasScheduler?: SasScheduler; readonly querySelf?: (raw: ReturnType<typeof createClient>, userId: string) => Promise<IDownloadKeyResult>; /** Test-only seam; production always uses WebCrypto. */ readonly verifyRawChain?: RawChainVerifier };
const keyKinds = [CrossSigningKey.Master, CrossSigningKey.SelfSigning, CrossSigningKey.UserSigning] as const;
const keyUsages = ['master', 'self_signing', 'user_signing'] as const;
const v42DeviceAlgorithms = ['m.olm.v1.curve25519-aes-sha2', 'm.megolm.v1.aes-sha2'] as const;
type KeyState = 'absent' | 'partial' | 'malformed' | 'complete';
type Keys = readonly [string, string, string];
const localKeys = async (crypto: CryptoApi): Promise<Keys | undefined> => {
  const ids = await Promise.all(keyKinds.map(kind => crypto.getCrossSigningKeyId(kind)));
  return ids.every((id): id is string => typeof id === 'string' && id.length > 0) ? ids as unknown as Keys : undefined;
};
const object = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const nonemptySignature = (signatures: unknown, user: string, key: string): boolean => {
  if (!object(signatures) || !object(signatures[user])) return false;
  const signature = signatures[user][`ed25519:${key}`]; return typeof signature === 'string' && signature.length > 0;
};
const exactUserMap = (value: unknown, user: string): Record<string, unknown> | undefined => object(value) && Object.keys(value).length === 1 && Object.prototype.hasOwnProperty.call(value, user) ? value : undefined;
const rawKey = (value: unknown, user: string, usage: string): { id: string; signatures: unknown } | undefined => {
  if (!object(value) || value.user_id !== user || !Array.isArray(value.usage) || value.usage.length !== 1 || value.usage[0] !== usage || !object(value.keys) || !object(value.signatures) || Object.keys(value.signatures).length === 0) return undefined;
  const entries = Object.entries(value.keys);
  return entries.length === 1 && typeof entries[0][1] === 'string' && canonicalBase64(entries[0][1], 32) && entries[0][0] === `ed25519:${entries[0][1]}` ? { id: entries[0][1], signatures: value.signatures } : undefined;
};
const classifyPublic = (result: IDownloadKeyResult, user: string): { state: KeyState; ids?: Keys } => {
  if (!object(result.failures) || Object.keys(result.failures).length !== 0) return { state: 'malformed' };
  const maps = [result.master_keys, result.self_signing_keys, result.user_signing_keys];
  if (maps.every(map => map === undefined || (object(map) && Object.keys(map).length === 0))) return { state: 'absent' };
  if (maps.some(map => exactUserMap(map, user) === undefined)) return { state: 'partial' };
  const values = maps.map((map, index) => rawKey(exactUserMap(map, user)![user], user, keyUsages[index]));
  if (values.some(value => value === undefined)) return { state: 'malformed' };
  const complete = values as { id: string; signatures: unknown }[];
  const signedOnlyByMaster = (signatures: unknown): boolean => { const signed = exactUserMap(signatures, user)?.[user]; return object(signed) && Object.keys(signed).length === 1 && nonemptySignature(signatures, user, complete[0].id); };
  if (!signedOnlyByMaster(complete[1].signatures) || !signedOnlyByMaster(complete[2].signatures)) return { state: 'malformed' };
  return { state: 'complete', ids: complete.map(value => value.id) as unknown as Keys };
};
const sameKeys = (left: readonly string[] | undefined, right: readonly string[] | undefined): boolean => left !== undefined && right !== undefined && left.length === right.length && left.every((key, index) => key === right[index]);
const bindingFor = (session: MatrixSession): CrossSigningBootstrapBinding => ({ profileId: session.profileId, locatorGeneration: session.generation, sessionGeneration: session.generation, localDeviceId: session.deviceId });
const localState = async (crypto: CryptoApi): Promise<{ state: 'none' | 'partial' | 'complete'; ids?: Keys; publicKeysOnDevice: boolean }> => {
  const status = await crypto.getCrossSigningStatus(); const ids = await localKeys(crypto);
  const cached = [status.privateKeysCachedLocally.masterKey, status.privateKeysCachedLocally.selfSigningKey, status.privateKeysCachedLocally.userSigningKey];
  if (!cached.some(Boolean) && ids === undefined) return { state: 'none', publicKeysOnDevice: status.publicKeysOnDevice };
  return cached.every(Boolean) && ids !== undefined ? { state: 'complete', ids, publicKeysOnDevice: status.publicKeysOnDevice } : { state: 'partial', publicKeysOnDevice: status.publicKeysOnDevice };
};
type AuthoritativeDevice = { readonly id: string; readonly ed25519: string; readonly curve25519: string };
const exactStrings = (actual: unknown, expected: readonly string[]): boolean => Array.isArray(actual) && actual.length === expected.length && actual.every((value, index) => value === expected[index]);
const rawDevices = (result: IDownloadKeyResult, session: MatrixSession, selfSigning?: string, firstBootstrap = false): readonly AuthoritativeDevice[] | undefined => {
  const users = exactUserMap(result.device_keys, session.userId); if (!users) return undefined;
  const devices = users[session.userId]; if (!object(devices) || (firstBootstrap && Object.keys(devices).length !== 1)) return undefined;
  const parsed: AuthoritativeDevice[] = [];
  for (const [id, device] of Object.entries(devices)) {
    if (!object(device) || id.length === 0 || device.user_id !== session.userId || device.device_id !== id || !exactStrings(device.algorithms, v42DeviceAlgorithms) || !object(device.keys)) return undefined;
    const ed = device.keys[`ed25519:${id}`]; const curve = device.keys[`curve25519:${id}`];
    if (Object.keys(device.keys).length !== 2 || typeof ed !== 'string' || !canonicalBase64(ed, 32) || typeof curve !== 'string' || !canonicalBase64(curve, 32) || !exactUserMap(device.signatures, session.userId)) return undefined;
    parsed.push({ id, ed25519: ed, curve25519: curve });
  }
  return parsed.length === 0 ? undefined : parsed;
};
const ssssState = async (raw: ReturnType<typeof createClient>, expected: boolean): Promise<'none' | 'present' | 'contradictory'> => {
  const names = ['m.cross_signing.master', 'm.cross_signing.self_signing', 'm.cross_signing.user_signing'] as const;
  const values = await Promise.all(names.map(name => raw.secretStorage.isStored(name)));
  const state = values.some(value => value !== null) ? 'present' : 'none';
  return (expected || state === 'present') ? (state === 'none' && expected ? 'contradictory' : state) : 'none';
};
const hasUnpairedSurrogate = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) { const unit = value.charCodeAt(index); if (unit >= 0xd800 && unit <= 0xdbff) { if (index + 1 >= value.length || value.charCodeAt(index + 1) < 0xdc00 || value.charCodeAt(index + 1) > 0xdfff) return true; index += 1; } else if (unit >= 0xdc00 && unit <= 0xdfff) return true; }
  return false;
};
/** Compare Unicode scalar values (Matrix canonical JSON), never UTF-16 units. */
const compareCodePoints = (left: string, right: string): number => {
  const a = left[Symbol.iterator](); const b = right[Symbol.iterator]();
  for (;;) {
    const nextA = a.next(); const nextB = b.next();
    if (nextA.done || nextB.done) return nextA.done === nextB.done ? 0 : nextA.done ? -1 : 1;
    const difference = nextA.value.codePointAt(0)! - nextB.value.codePointAt(0)!;
    if (difference !== 0) return difference;
  }
};
/** Matrix canonical JSON: JSON-compatible, lossless, and sorted by Unicode code point. */
export const canonicalJsonForTest = (value: unknown): string => {
  if (typeof value === 'string') { if (hasUnpairedSurrogate(value)) throw new Error('non-canonical-string'); return JSON.stringify(value); }
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') { if (!Number.isSafeInteger(value)) throw new Error('non-canonical-number'); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(canonicalJsonForTest).join(',')}]`;
  if (!object(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error('non-canonical-value');
  return `{${Object.keys(value).sort(compareCodePoints).map(key => { if (hasUnpairedSurrogate(key)) throw new Error('non-canonical-key'); return `${JSON.stringify(key)}:${canonicalJsonForTest(value[key])}`; }).join(',')}}`;
};
const signedBytes = (value: Record<string, unknown>): Uint8Array => {
  return new TextEncoder().encode(canonicalJsonForTest(Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'signatures' && key !== 'unsigned'))));
};
const canonicalBase64 = (value: unknown, length: number): Uint8Array | undefined => {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}|[A-Za-z0-9+/]{3})?$/.test(value)) throw new Error('invalid-base64');
  const binary = globalThis.atob(value); const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (bytes.length !== length || globalThis.btoa(binary).replace(/=+$/, '') !== value) throw new Error('invalid-base64'); return bytes;
};
const canonicalProfileIdFormat = (value: string): string | undefined => /^[a-f0-9]{64}$/.test(value) ? value : undefined;
const verifyEd25519 = async (publicKey: string, signature: unknown, payload: Record<string, unknown>): Promise<boolean> => {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return false;
  try { const source = (bytes: Uint8Array): ArrayBuffer => Uint8Array.from(bytes).buffer as ArrayBuffer; const key = await subtle.importKey('raw', source(canonicalBase64(publicKey, 32)!), { name: 'Ed25519' }, false, ['verify']); return await subtle.verify({ name: 'Ed25519' }, key, source(canonicalBase64(signature, 64)!), source(signedBytes(payload))); } catch { return false; }
};
/** Internal test seam for the production signing-byte and Ed25519 verification path. */
export const verifySignedPayloadForTest = verifyEd25519;
/** Verify the complete raw response rather than accepting the Rust trust cache as proof. */
export const verifyAuthoritativeRawChain: RawChainVerifier = async (result, session) => {
  try {
    const publicState = classifyPublic(result, session.userId); if (publicState.state !== 'complete') return false;
    const devices = rawDevices(result, session, publicState.ids![1]); const current = devices?.find(device => device.id === session.deviceId); if (!current) return false;
    const master = exactUserMap(result.master_keys, session.userId)?.[session.userId]; const self = exactUserMap(result.self_signing_keys, session.userId)?.[session.userId]; const user = exactUserMap(result.user_signing_keys, session.userId)?.[session.userId];
    if (!object(master) || !object(self) || !object(user)) return false;
    const masterSignatures = exactUserMap(master.signatures, session.userId)?.[session.userId];
    if (!object(masterSignatures) || !await verifyEd25519(current.ed25519, masterSignatures[`ed25519:${current.id}`], master)) return false;
    const signatureFor = (value: Record<string, unknown>, id: string): unknown => { const userSignatures = exactUserMap(value.signatures, session.userId)?.[session.userId]; return object(userSignatures) ? userSignatures[`ed25519:${id}`] : undefined; };
    for (const key of [self, user]) if (!await verifyEd25519(publicState.ids![0], signatureFor(key, publicState.ids![0]), key)) return false;
    const raw = exactUserMap(result.device_keys, session.userId)?.[session.userId]; const value = object(raw) ? raw[current.id] : undefined;
    if (!object(value) || !await verifyEd25519(publicState.ids![1], signatureFor(value, publicState.ids![1]), value) || !await verifyEd25519(current.ed25519, signatureFor(value, current.id), value)) return false;
    return true;
  } catch { return false; }
};

/** Deliberately inert input for the stable-grant derivation test seam. */
export interface SasStableGrantDerivationInputForTest {
  readonly roomId: string;
  readonly peerUserId: string;
  readonly peerDeviceId: string;
  readonly raw: IDownloadKeyResult;
  readonly rustDevices: unknown;
  readonly rustCrossSigningKeys: unknown;
}
type StableKey = { readonly value: Record<string, unknown>; readonly id: string };
const exactNames = (value: unknown, names: readonly string[]): value is Record<string, unknown> => object(value) && Object.keys(value).length === names.length && names.every(name => Object.prototype.hasOwnProperty.call(value, name));
const stableKey = (value: unknown, user: string, usage: string): StableKey | undefined => {
  const parsed = rawKey(value, user, usage);
  return parsed && object(value) ? { value, id: parsed.id } : undefined;
};
const exactSignature = (value: Record<string, unknown>, user: string, ids: readonly string[]): Record<string, unknown> | undefined => {
  const signatures = value.signatures;
  if (!exactNames(signatures, [user])) return undefined;
  const signed = signatures[user];
  return exactNames(signed, ids.map(id => `ed25519:${id}`)) ? signed : undefined;
};
const stableDevice = (value: unknown, user: string, id: string): { readonly value: Record<string, unknown>; readonly ed25519: string; readonly curve25519: string } | undefined => {
  if (!object(value) || value.user_id !== user || value.device_id !== id || !exactStrings(value.algorithms, v42DeviceAlgorithms) || !exactNames(value.keys, [`ed25519:${id}`, `curve25519:${id}`])) return undefined;
  const ed25519 = value.keys[`ed25519:${id}`]; const curve25519 = value.keys[`curve25519:${id}`];
  return typeof ed25519 === 'string' && canonicalBase64(ed25519, 32) && typeof curve25519 === 'string' && canonicalBase64(curve25519, 32) ? { value, ed25519, curve25519 } : undefined;
};
const mapEntries = (value: unknown): readonly [string, unknown][] | undefined => value instanceof Map ? [...value.entries()].every((entry): entry is [string, unknown] => typeof entry[0] === 'string') ? [...value.entries()] as [string, unknown][] : undefined : object(value) ? Object.entries(value) : undefined;
const exactSnapshotUsers = (value: unknown, users: readonly string[]): Map<string, unknown> | undefined => {
  const entries = mapEntries(value); if (!entries || entries.length !== users.length || new Set(entries.map(([id]) => id)).size !== users.length || !users.every(id => entries.some(([actual]) => actual === id))) return undefined;
  return new Map(entries);
};
const canonicalHomeserver = (value: unknown): value is string => {
  if (typeof value !== 'string') return false;
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash && url.pathname === '/' && (value === url.origin || value === `${url.origin}/`); } catch { return false; }
};
const rustDevice = (value: unknown, id: string, expected: { value: Record<string, unknown>; ed25519: string; curve25519: string }): boolean => {
  if (!exactNames(value, ['deviceId', 'keys', 'signatures']) || value.deviceId !== id || !(value.keys instanceof Map) || value.keys.size !== 2 || [...value.keys.keys()].some(key => key !== `ed25519:${id}` && key !== `curve25519:${id}`)) return false;
  return value.keys.get(`ed25519:${id}`) === expected.ed25519 && value.keys.get(`curve25519:${id}`) === expected.curve25519 && canonicalEqual(value.signatures, expected.value.signatures);
};
const canonicalEqual = (left: unknown, right: unknown): boolean => {
  try { return canonicalJsonForTest(left) === canonicalJsonForTest(right); } catch { return false; }
};
const rustKeysMatch = (snapshot: unknown, user: string, expected: readonly [StableKey, StableKey, StableKey?]): boolean => {
  if (!exactNames(snapshot, expected[2] ? ['master_key', 'self_signing_key', 'user_signing_key'] : ['master_key', 'self_signing_key'])) return false;
  return expected.every((key, index) => key !== undefined && canonicalEqual(snapshot[['master_key', 'self_signing_key', 'user_signing_key'][index]!], key.value));
};
/**
 * Test-only, non-authoritative derivation.  It accepts snapshots rather than SDK
 * objects and is intentionally not called by bootstrap, SAS, or readiness paths.
 */
export const deriveSasStableGrantBindingForTest = async (session: MatrixSession, input: SasStableGrantDerivationInputForTest): Promise<SasStableGrantBinding | undefined> => {
  try {
    const local = session.userId; const peer = input.peerUserId;
    if (!canonicalProfileIdFormat(session.profileId) || !Number.isSafeInteger(session.generation) || session.generation <= 0 || session.homeserver !== MATRIX_HOMESERVER || !canonicalHomeserver(session.homeserver) || !parseMatrixUserId(local) || !parseMatrixDeviceId(session.deviceId) || !parseSupportedDomainRoomId(input.roomId) || !parseMatrixUserId(peer) || peer === local || !parseMatrixDeviceId(input.peerDeviceId) || session.profileId !== await canonicalProfileId({ homeserver: session.homeserver, userId: local, deviceId: session.deviceId })) return undefined;
    const users = [local, peer]; const raw = input.raw;
    if (!object(raw.failures) || Object.keys(raw.failures).length !== 0 || !exactNames(raw.device_keys, users) || !exactNames(raw.master_keys, users) || !exactNames(raw.self_signing_keys, users) || !exactNames(raw.user_signing_keys, [local])) return undefined;
    const localMaster = stableKey(raw.master_keys[local], local, 'master'); const localSelf = stableKey(raw.self_signing_keys[local], local, 'self_signing'); const localUser = stableKey(raw.user_signing_keys[local], local, 'user_signing'); const peerMaster = stableKey(raw.master_keys[peer], peer, 'master'); const peerSelf = stableKey(raw.self_signing_keys[peer], peer, 'self_signing');
    if (!localMaster || !localSelf || !localUser || !peerMaster || !peerSelf) return undefined;
    const localDevices = raw.device_keys[local]; const peerDevices = raw.device_keys[peer];
    if (!exactNames(localDevices, [session.deviceId]) || !exactNames(peerDevices, [input.peerDeviceId])) return undefined;
    const localDevice = stableDevice(localDevices[session.deviceId], local, session.deviceId); const peerDevice = stableDevice(peerDevices[input.peerDeviceId], peer, input.peerDeviceId);
    if (!localDevice || !peerDevice) return undefined;
    const verify = async (value: StableKey | { value: Record<string, unknown> }, signer: string, signatureUser: string, signatures: readonly string[]): Promise<boolean> => {
      const signed = exactSignature(value.value, signatureUser, signatures); return signed !== undefined && await verifyEd25519(signer, signed[`ed25519:${signatures[0]}`], value.value);
    };
    const peerMasterSignatures = peerMaster.value.signatures;
    if (!exactNames(peerMasterSignatures, [peer, local]) || !exactNames(peerMasterSignatures[peer], [`ed25519:${input.peerDeviceId}`]) || !exactNames(peerMasterSignatures[local], [`ed25519:${localUser.id}`])) return undefined;
    if (!await verify(localMaster, localDevice.ed25519, local, [session.deviceId]) || !await verify(localSelf, localMaster.id, local, [localMaster.id]) || !await verify(localUser, localMaster.id, local, [localMaster.id]) || !await verifyEd25519(peerDevice.ed25519, peerMasterSignatures[peer][`ed25519:${input.peerDeviceId}`], peerMaster.value) || !await verifyEd25519(localUser.id, peerMasterSignatures[local][`ed25519:${localUser.id}`], peerMaster.value) || !await verify(peerSelf, peerMaster.id, peer, [peerMaster.id])) return undefined;
    const localSigs = exactSignature(localDevice.value, local, [session.deviceId, localSelf.id]); const peerSigs = exactSignature(peerDevice.value, peer, [input.peerDeviceId, peerSelf.id]);
    if (!localSigs || !peerSigs || !await verifyEd25519(localDevice.ed25519, localSigs[`ed25519:${session.deviceId}`], localDevice.value) || !await verifyEd25519(localSelf.id, localSigs[`ed25519:${localSelf.id}`], localDevice.value) || !await verifyEd25519(peerDevice.ed25519, peerSigs[`ed25519:${input.peerDeviceId}`], peerDevice.value) || !await verifyEd25519(peerSelf.id, peerSigs[`ed25519:${peerSelf.id}`], peerDevice.value)) return undefined;
    const rustDevices = exactSnapshotUsers(input.rustDevices, users); const rustKeys = exactSnapshotUsers(input.rustCrossSigningKeys, users);
    if (!rustDevices || !rustKeys) return undefined;
    for (const [user, id, expected] of [[local, session.deviceId, localDevice], [peer, input.peerDeviceId, peerDevice]] as const) { const devices = mapEntries(rustDevices.get(user)); if (!devices || devices.length !== 1 || devices[0]![0] !== id || !rustDevice(devices[0]![1], id, expected)) return undefined; }
    if (!rustKeysMatch(rustKeys.get(local), local, [localMaster, localSelf, localUser]) || !rustKeysMatch(rustKeys.get(peer), peer, [peerMaster, peerSelf])) return undefined;
    return Object.freeze({ schemaVersion: 1, profileId: session.profileId, sessionGeneration: session.generation, homeserver: session.homeserver, localUserId: local, localDeviceId: session.deviceId, roomId: input.roomId, peerUserId: peer, localEd25519: localDevice.ed25519, localCurve25519: localDevice.curve25519, peerDeviceId: input.peerDeviceId, peerEd25519: peerDevice.ed25519, peerCurve25519: peerDevice.curve25519, localMasterRef: localMaster.id, peerMasterRef: peerMaster.id });
  } catch { return undefined; }
};
const trustedIdentity = async (crypto: CryptoApi, session: MatrixSession): Promise<boolean> => {
  const [user, device] = await Promise.all([crypto.getUserVerificationStatus(session.userId), crypto.getDeviceVerificationStatus(session.userId, session.deviceId)]);
  return user.known && user.isCrossSigningVerified() && !user.needsUserApproval && device?.signedByOwner === true && device.crossSigningVerified && device.isVerified();
};
/** No reset/retry path: an ambiguous durable attempt belongs to recovery. */
const resolveCrossSigningDisposition = async (raw: ReturnType<typeof createClient>, crypto: CryptoApi, session: MatrixSession, store: BootstrapStore, querySelf: (raw: ReturnType<typeof createClient>, userId: string) => Promise<IDownloadKeyResult>, verifyRawChain: RawChainVerifier): Promise<'published' | 'recovery-required'> => {
  const binding = bindingFor(session);
  let disposition = await store.getBootstrapDisposition({ profileId: session.profileId }); // Must precede Rust/network inspection.
  if (disposition.state === 'pending-uia') { await store.compareAndSetBootstrapDisposition(disposition, 'recovery-required', binding); return 'recovery-required'; }
  if (disposition.state === 'recovery-required') return 'recovery-required';
  try {
    const queried = await querySelf(raw, session.userId); const publicState = classifyPublic(queried, session.userId); const local = await localState(crypto); const status = await crypto.getCrossSigningStatus(); const ssss = await ssssState(raw, status.privateKeysInSecretStorage);
    const devices = rawDevices(queried, session, publicState.ids?.[1]); const current = devices?.find(device => device.id === session.deviceId);
    const own = await crypto.getOwnDeviceKeys(); const currentMatches = current !== undefined && current.ed25519 === own.ed25519 && current.curve25519 === own.curve25519;
    const completeProof = publicState.state === 'complete' && local.state === 'complete' && local.publicKeysOnDevice && sameKeys(publicState.ids, local.ids) && currentMatches && ssss === 'none' && await verifyRawChain(queried, session) && await trustedIdentity(crypto, session);
    if (completeProof) return 'published';
    const initialDevices = rawDevices(queried, session, undefined, true); const initialCurrent = initialDevices?.[0]; const initialOwn = initialCurrent !== undefined && initialCurrent.id === session.deviceId && initialCurrent.ed25519 === own.ed25519 && initialCurrent.curve25519 === own.curve25519;
    if (publicState.state !== 'absent' || local.state !== 'none' || ssss !== 'none' || local.publicKeysOnDevice || !initialOwn) { await store.compareAndSetBootstrapDisposition(disposition, 'recovery-required', binding); return 'recovery-required'; }
    disposition = (await store.compareAndSetBootstrapDisposition(disposition, 'pending-uia', binding)) ?? disposition; if (disposition.state !== 'pending-uia') return 'recovery-required';
    let madeRequest = false;
    await crypto.bootstrapCrossSigning({ setupNewCrossSigning: false, authUploadDeviceSigningKeys: async makeRequest => { if (madeRequest) throw new Error('uia-request-ambiguous'); madeRequest = true; await makeRequest(null); } });
    const postQuery = await querySelf(raw, session.userId); const published = classifyPublic(postQuery, session.userId); const postLocal = await localState(crypto); const postStatus = await crypto.getCrossSigningStatus(); const postSsss = await ssssState(raw, postStatus.privateKeysInSecretStorage); const postDevices = rawDevices(postQuery, session, published.ids?.[1]); const postCurrent = postDevices?.find(device => device.id === session.deviceId); const postOwn = await crypto.getOwnDeviceKeys(); const postMatches = postCurrent !== undefined && postCurrent.ed25519 === postOwn.ed25519 && postCurrent.curve25519 === postOwn.curve25519;
    if (!madeRequest || published.state !== 'complete' || postLocal.state !== 'complete' || !postLocal.publicKeysOnDevice || !sameKeys(published.ids, postLocal.ids) || postSsss !== 'none' || !postMatches || !await verifyRawChain(postQuery, session) || !await trustedIdentity(crypto, session)) throw new Error('cross-signing-publish-mismatch');
    return (await store.compareAndSetBootstrapDisposition(disposition, 'published', binding))?.state === 'published' ? 'published' : 'recovery-required';
  } catch { const current = await store.getBootstrapDisposition({ profileId: session.profileId }); if (current.state !== 'recovery-required') await store.compareAndSetBootstrapDisposition(current, 'recovery-required', binding); return 'recovery-required'; }
};
export function createSdkBootstrapPort(tokenRefreshFunction: (refreshToken: string) => Promise<{ accessToken: string; refreshToken?: string; expiry: Date }>, dependencies: BootstrapDependencies): ClientBootstrapPort {
  return { begin(session: MatrixSession, signal: AbortSignal): ClientBootstrapOperation {
    const raw = createClient({ baseUrl: session.homeserver, userId: session.userId, deviceId: session.deviceId, accessToken: session.accessToken, ...(session.refreshToken === undefined ? {} : { refreshToken: session.refreshToken }), disableVoip: true, logger: silentLogger, tokenRefreshFunction, verificationMethods: ['m.sas.v1'] });
    const roomClock = dependencies.roomClock ?? productionRoomClock; const sasScheduler = dependencies.sasScheduler ?? productionSasScheduler; const sasMonoStart = sasScheduler.now?.() ?? globalThis.performance.now(); const sasWallStart = roomClock.now(); const epoch = new EncryptionPolicyEpoch(); const listeners = new Set<MatrixSecurityStateListener>(); let security: MatrixSecurityState = 'starting';
    let transportStopped = signal.aborted;
    let runtimeGeneration = 0;
    /** Permanent runtime admission latch.  Presentation state is never authority. */
    let transportBlocked = false;
    let revokeTrust: (id?: string) => void = () => undefined;
    let closeSasIngress: () => void = () => undefined;
    let clearRetainedTimelineEvents: () => void = () => undefined;
    const stopped = (): boolean => transportStopped || signal.aborted;
    const unavailableTransport = (): boolean => stopped() || transportBlocked;
    const transition = (next: MatrixSecurityState): void => { if ((stopped() && next !== 'stopped') || (transportBlocked && next !== 'blocked' && next !== 'stopped')) return; security = next; listeners.forEach(listener => { try { listener(next); } catch { /* subscribers are not authority */ } }); };
    const poisonTransport = (): void => { transportBlocked = true; closeSasIngress(); revokeTrust(); if (!stopped()) transition('blocked'); };
    const abort = (): void => { if (transportStopped) return; runtimeGeneration += 1; transportStopped = true; transportBlocked = true; cancelOutgoingRequestWaiters(); clearRetainedTimelineEvents(); revokeTrust(); closeSasIngress(); transition('stopped'); };
    signal.addEventListener('abort', abort, { once: true });
    const crypto = (): CryptoApi => raw.getCrypto() ?? unavailable();
    // Keep raw MatrixEvents private.  The public verification request wrapper
    // deliberately does not expose these events in v42.
    const verificationEvents = new Map<string, Map<string, MatrixEvent>>();
    const MAX_VERIFICATION_EVENTS_PER_ROOM = 64;
    const MAX_VERIFICATION_EVENT_ROOMS = 32;
    const MAX_VERIFICATION_EVENTS = 256;
    let verificationEventCount = 0;
    const verificationEventOrder = new Map<string, { roomId: string; eventId: string }>();
    const verificationKey = (roomId: string, eventId: string): string => `${roomId}\u0000${eventId}`;
    // An SDK request wrapper is only a hint.  Outgoing requests are admitted
    // only after the self-authored raw event with this exact id is observed.
    // Keep this deliberately small: a peer cannot create unbounded pending
    // work, and every waiter owns and clears its scheduler handle.
    const outgoingRequestWaiters = new Map<string, { readonly resolve: (event: MatrixEvent | undefined) => void; readonly timer: unknown }>();
    const MAX_OUTGOING_REQUEST_WAITERS = 4;
    const cancelOutgoingRequestWaiters = (): void => {
      for (const [key, waiter] of outgoingRequestWaiters) {
        sasScheduler.clearTimeout(waiter.timer); outgoingRequestWaiters.delete(key); waiter.resolve(undefined);
      }
    };
    const dropVerificationEvent = (roomId: string, eventId: string): void => {
      const room = verificationEvents.get(roomId);
      if (!room?.delete(eventId)) return;
      verificationEventCount -= 1; verificationEventOrder.delete(verificationKey(roomId, eventId));
      if (room.size === 0) verificationEvents.delete(roomId);
    };
    const indexVerificationEvent = (event: MatrixEvent): void => {
      const envelope = ownedVerificationEnvelope(event); if (!envelope || typeof envelope.roomId !== 'string' || typeof envelope.eventId !== 'string') return;
      if (envelope.type !== 'm.room.message' && envelope.type !== 'm.key.verification.ready' && envelope.type !== 'm.key.verification.start') return;
      // Do not retain arbitrary timeline traffic: only an exact verification
      // shape is a candidate, and the later context check remains authoritative.
      const candidate = envelope.type === 'm.room.message'
        ? object(envelope.content) && envelope.content.msgtype === 'm.key.verification.request'
        : object(envelope.content) && typeof envelope.content.from_device === 'string' && object(envelope.content['m.relates_to']);
      if (!candidate) return;
      let room = verificationEvents.get(envelope.roomId);
      if (!room) {
        if (verificationEvents.size >= MAX_VERIFICATION_EVENT_ROOMS) {
          const oldest = verificationEvents.keys().next().value as string | undefined;
          if (oldest !== undefined) for (const eventId of verificationEvents.get(oldest)?.keys() ?? []) dropVerificationEvent(oldest, eventId);
        }
        room = new Map<string, MatrixEvent>(); verificationEvents.set(envelope.roomId, room);
      }
      if (!room.has(envelope.eventId) && room.size >= MAX_VERIFICATION_EVENTS_PER_ROOM) {
        const oldest = room.keys().next().value as string | undefined;
        if (oldest !== undefined) dropVerificationEvent(envelope.roomId, oldest);
      }
      if (!room.has(envelope.eventId) && verificationEventCount >= MAX_VERIFICATION_EVENTS) {
        const oldest = verificationEventOrder.values().next().value as { roomId: string; eventId: string } | undefined;
        if (oldest) dropVerificationEvent(oldest.roomId, oldest.eventId);
      }
      if (!room.has(envelope.eventId)) verificationEventCount += 1;
      room.set(envelope.eventId, event); verificationEventOrder.set(verificationKey(envelope.roomId, envelope.eventId), { roomId: envelope.roomId, eventId: envelope.eventId });
      const key = verificationKey(envelope.roomId, envelope.eventId);
      const waiter = outgoingRequestWaiters.get(key);
      if (waiter) { sasScheduler.clearTimeout(waiter.timer); outgoingRequestWaiters.delete(key); waiter.resolve(event); }
    };
    // These listeners deliberately exist before sync/start.  Their handlers are
    // assigned below once the SDK-free projection has been constructed.
    let receiveTimeline: (event: MatrixEvent, room?: Room, toStart?: boolean, removed?: boolean, data?: unknown) => void = () => {};
    let receiveLocalEcho: (event: MatrixEvent, room?: Room) => void = () => {};
    let receiveDecrypted: (event: MatrixEvent, error?: Error) => void = () => {};
    if (typeof RoomEvent.Timeline === 'string') raw.on(RoomEvent.Timeline, (event: MatrixEvent, room?: Room, toStart?: boolean, removed?: boolean, data?: unknown) => { if (unavailableTransport()) return; indexVerificationEvent(event); receiveTimeline(event, room, toStart, removed, data); });
    if (typeof RoomEvent.LocalEchoUpdated === 'string') raw.on(RoomEvent.LocalEchoUpdated, (event: MatrixEvent, room?: Room) => receiveLocalEcho(event, room));
    if (typeof MatrixEventEvent.Decrypted === 'string') raw.on(MatrixEventEvent.Decrypted, (event: MatrixEvent, error?: Error) => receiveDecrypted(event, error));
    const roomEvent = (id: string, eventId: string): MatrixEvent | undefined => {
      const room = raw.getRoom(id) as unknown as { findEventById?: (value: string) => MatrixEvent | undefined } | undefined;
      try { return room?.findEventById?.(eventId) ?? verificationEvents.get(id)?.get(eventId); } catch { return undefined; }
    };
    const waitForOutgoingRequestEvent = (id: string, eventId: string): Promise<MatrixEvent | undefined> => {
      const present = roomEvent(id, eventId);
      if (present) return Promise.resolve(present);
      if (outgoingRequestWaiters.size >= MAX_OUTGOING_REQUEST_WAITERS) return Promise.resolve(undefined);
      const key = verificationKey(id, eventId);
      return new Promise(resolve => {
        const timer = sasScheduler.setTimeout(() => {
          const waiter = outgoingRequestWaiters.get(key);
          if (waiter?.timer === timer) { outgoingRequestWaiters.delete(key); resolve(undefined); }
        }, 10 * 60_000);
        outgoingRequestWaiters.set(key, { resolve, timer });
        // Indexing can race between the initial lookup and registration.
        const raced = roomEvent(id, eventId);
        if (raced) { sasScheduler.clearTimeout(timer); outgoingRequestWaiters.delete(key); resolve(raced); }
      });
    };
    const relatedEvents = (id: string, context: Parameters<typeof validateVerificationEnvelope>[1], kind: 'ready' | 'start'): readonly MatrixEvent[] => {
      const values = [...(verificationEvents.get(id)?.values() ?? [])];
      return values.filter(event => validateVerificationEnvelope(ownedVerificationEnvelope(event) ?? {} as never, context)?.kind === kind);
    };
    /** Remove only one request's controls; another operation may share its room. */
    const clearVerificationEvents = (id: string, requestEventId: string | undefined): void => {
      if (!requestEventId) return;
      const room = verificationEvents.get(id); if (!room) return;
      for (const [eventId, event] of room) {
        const envelope = ownedVerificationEnvelope(event);
        const content = envelope?.content as { ['m.relates_to']?: { rel_type?: unknown; event_id?: unknown } } | undefined;
        const relation = content?.['m.relates_to'];
        if (eventId === requestEventId || (relation?.rel_type === 'm.reference' && relation.event_id === requestEventId)) dropVerificationEvent(id, eventId);
      }
      if (room.size === 0) verificationEvents.delete(id);
    };
    type ValidatedStart = { readonly event: MatrixEvent; readonly context: SasWireContext; readonly actor: 'peer' | 'self' };
    /** A Start may be remote, or locally authored after startVerification(). */
    const uniqueStart = (operation: SasOperation): ValidatedStart | undefined => {
      if (!operation.requestEventId) return undefined;
      const variants: readonly { readonly actor: ValidatedStart['actor']; readonly context: Parameters<typeof validateVerificationEnvelope>[1] }[] = [
        { actor: 'peer', context: { roomId: operation.roomId, expectedSender: operation.peerUserId, expectedSenderDeviceId: operation.peerDeviceId, requestEventId: operation.requestEventId, direction: operation.direction, now: roomClock.now() } },
        { actor: 'self', context: { roomId: operation.roomId, expectedSender: session.userId, expectedSenderDeviceId: session.deviceId, requestEventId: operation.requestEventId, direction: operation.direction, now: roomClock.now() } },
      ];
      const candidates = variants.flatMap(({ actor, context }) => relatedEvents(operation.roomId, context, 'start').flatMap(event => {
        const validated = wireContext(event, context, session.deviceId);
        return validated ? [{ event, context: validated, actor }] : [];
      }));
      return candidates.length === 1 ? candidates[0] : undefined;
    };
    const matchesRequestWireContext = (operation: SasOperation, context: SasWireContext): boolean => operation.direction === 'incoming'
      ? matchesSasWireContext(operation, context)
      : operation.roomId === context.roomId && operation.requestEventId === context.requestEventId && operation.localDeviceId === context.localDeviceId && context.sender === session.userId && context.peerDeviceId === session.deviceId;
    const matchesStartWireContext = (operation: SasOperation, start: ValidatedStart): boolean => start.actor === 'peer'
      ? matchesSasWireContext(operation, start.context)
      : operation.roomId === start.context.roomId && operation.requestEventId === start.context.requestEventId && operation.localDeviceId === start.context.localDeviceId && start.context.sender === session.userId && start.context.peerDeviceId === session.deviceId;
    // This listener deliberately precedes every bootstrap/sync listener.  Rust
    // emits request objects, not trusted application DTOs, so it is only a
    // wake-up edge; the handler below rechecks the room and every binding.
    let receiveVerification: (request: SdkVerificationRequest) => Promise<void> = async () => undefined;
    if (typeof CryptoEvent.VerificationRequestReceived === 'string') raw.on(CryptoEvent.VerificationRequestReceived, (request: SdkVerificationRequest) => { if (!unavailableTransport()) void receiveVerification(request).catch(() => undefined); });
    let bootstrapDisposition: 'published' | 'recovery-required' = 'recovery-required';
    const trustedDevice = async (): Promise<boolean> => { if (unavailableTransport()) return false; const status = await crypto().getDeviceVerificationStatus(session.userId, session.deviceId); return !unavailableTransport() && bootstrapDisposition === 'published' && status !== null && status.crossSigningVerified && status.isVerified(); };
    // Assigned after the SDK-free conversation projection is created.  The
    // bootstrap listeners are installed first, so no unsafe event can race it.
    let publishConversations: () => void = () => {};
    let emergencyTerminalizeSas = async (): Promise<void> => {};
    let reconcileSync = async (state: SyncState): Promise<void> => { void state; };
    const port: CryptoBootstrapPort = {
      installSyncListener: listener => { raw.on(ClientEvent.Sync, (current: SyncState, previous: SyncState | null, data) => { void previous; void data; if (unavailableTransport()) return; void reconcileSync(current).catch(() => undefined); try { listener(current as import('../../crypto/bootstrap-crypto').SyncState); } catch { /* subscriber */ } }); },
      installTerminalListener: listener => { raw.on(ClientEvent.Sync, (current: SyncState) => { if (current === SyncState.Stopped) listener(); }); raw.on(HttpApiEvent.SessionLoggedOut, listener); },
      installRoomListener: listener => { raw.on(RoomStateEvent.Events, () => { if (unavailableTransport()) return; try { listener(); } catch { /* subscriber */ } void cancelCurrentSas(); publishConversations(); trustListeners.forEach((entry, key) => { revokeTrust(key); publishTrust(entry.identity); }); }); }, installMembershipListener: listener => { raw.on(RoomMemberEvent.Membership, () => { if (unavailableTransport()) return; try { listener(); } catch { /* subscriber */ } void cancelCurrentSas(); publishConversations(); trustListeners.forEach((entry, key) => { revokeTrust(key); publishTrust(entry.identity); }); }); },
      // Key churn is expected while Rust SAS imports and signs keys.  It revokes
      // public readiness, but completion re-proves against the newest view.
      installCryptoListener: listener => { raw.on(CryptoEvent.KeysChanged, () => { if (unavailableTransport()) return; try { listener(); } catch { /* subscriber */ } markSasTrustChanged(); publishConversations(); trustListeners.forEach((entry, key) => { revokeTrust(key); publishTrust(entry.identity); }); publishVerification(); }); }, installTrustListener: listener => { raw.on(CryptoEvent.UserTrustStatusChanged, () => { if (unavailableTransport()) return; try { listener(); } catch { /* subscriber */ } markSasTrustChanged(); publishConversations(); trustListeners.forEach((entry, key) => { revokeTrust(key); publishTrust(entry.identity); }); publishVerification(); }); }, installDeviceListener: listener => { raw.on(CryptoEvent.DevicesUpdated, () => { if (unavailableTransport()) return; try { listener(); } catch { /* subscriber */ } markSasTrustChanged(); publishConversations(); trustListeners.forEach((entry, key) => { revokeTrust(key); publishTrust(entry.identity); }); publishVerification(); }); },
      initRustCrypto: options => raw.initRustCrypto(options), getCrypto: () => raw.getCrypto() ? { kind: 'rust-crypto' } : undefined,
      // Matrix JS SDK v42 directly performs authenticated /keys/query; no cache or force flag.
      configureSignedDeviceIsolation: async () => { if (stopped()) throw new Error('stopped'); bootstrapDisposition = await resolveCrossSigningDisposition(raw, crypto(), session, dependencies.store, dependencies.querySelf ?? ((client, user) => client.downloadKeysForUsers([user])), dependencies.verifyRawChain ?? verifyAuthoritativeRawChain); if (stopped() || bootstrapDisposition !== 'published') throw new Error('cross-signing-recovery-required'); crypto().setDeviceIsolationMode(new OnlySignedDevicesIsolationMode()); }, startClient: async () => { if (stopped()) return; await dependencies.store.rebaseUnresolvedOutbox({ profileId: session.profileId }); if (stopped()) return; const unresolved = await dependencies.store.listUnresolvedTextOutboxRecords({ profileId: session.profileId }, MAX_ATTEMPTS + 1); if (unresolved.length > MAX_ATTEMPTS) { poisonTransport(); throw new Error('recovered-outbox-over-capacity'); } for (const record of unresolved) { if (!allocateAttemptSlot(record.transactionId)) { poisonTransport(); throw new Error('recovered-outbox-over-capacity'); } recoveredOutbox.set(record.transactionId, record); } if (!stopped()) raw.startClient(); }, stopClient: async () => { abort(); await drainSasDurableWork(); await emergencyTerminalizeSas(); await drainSasDurableWork(); await drainQueues(); await raw.stopClient(); signal.removeEventListener('abort', abort); },
    };
    const operation = beginCryptoBootstrap(port, { cryptoDatabasePrefix: `dsa-signal:${session.profileId}`, syncReadyTimeoutMs: 30_000, policyEpoch: epoch, evaluatePostSyncPolicy: async () => await trustedDevice() ? 'ready' : 'unverified', onStateChange: value => transition(value) });
    const post = async (room: Room) => {
      const targetMembers = await room.getEncryptionTargetMembers(); const joined = new Map<string, RoomMember>();
      for (const member of targetMembers) { if (member.membership !== 'join' || joined.has(member.userId)) unavailable(); joined.set(member.userId, member); }
      const devices = await crypto().getUserDeviceInfo([...joined.keys()], true); const devicesByUser = new Map<string, DeviceEnumeration>();
      for (const userId of joined.keys()) { const entries = devices.get(userId); if (!entries) { devicesByUser.set(userId, { complete: false, devices: [] }); continue; }
        const trusted = await Promise.all([...entries.values()].map(async device => { const status = await crypto().getDeviceVerificationStatus(userId, device.deviceId); return { deviceId: device.deviceId, known: true, signed: status?.crossSigningVerified === true, verified: status?.isVerified() === true }; })); devicesByUser.set(userId, { complete: true, devices: trusted }); }
      return assessPostAdmission({ currentState: state(room), rustCryptoPersistent: await crypto().isEncryptionEnabledInRoom(room.roomId), encryptionTargetMembers: [...joined.values()].map(member => ({ userId: member.userId, membership: 'join' })), devicesByUser });
    };
    // Keep all SDK-shaped values in this closure.  In particular, listeners only
    // ever receive fresh application-owned DTOs, never Room/Event references.
    const conversationListeners = new Set<DirectConversationListener>();
    /** Once a room has been admitted to any direct surface, plaintext is fatal
     * even if later membership/policy drift makes `direct()` reject it. */
    const trackedDirectRooms = new Set<string>();
    /** Preserve the admitted peer even if current room state later becomes unsafe. */
    const trackedDirectPeers = new Map<string, string>();
    const identityKey = (identity: DirectConversationIdentity): string => `${identity.roomId}\u0000${identity.peerUserId}\u0000${identity.roomEpoch}`;
    const sameIdentity = (left: DirectConversationIdentity, right: DirectConversationIdentity): boolean => left.roomId === right.roomId && left.peerUserId === right.peerUserId && left.roomEpoch === right.roomEpoch;
    const timelineListeners = new Map<string, { readonly identity: DirectConversationIdentity; readonly listeners: Set<TimelineListener> }>();
    const trustListeners = new Map<string, { readonly identity: DirectConversationIdentity; readonly listeners: Set<DirectTrustListener> }>();
    /** The last owned DTO is sufficient to revoke readiness without exposing SDK data. */
    const lastTrust = new Map<string, import('../contract').DirectTrustState>();
    const verificationListeners = new Map<string, { readonly identity: DirectConversationIdentity; readonly listeners: Set<VerificationListener> }>();
    type Attempt = { readonly body: string; readonly bodyHash: string; readonly peer: string; readonly identity: DirectConversationIdentity; readonly timestamp: number; generation?: number; eventId?: string; localEvent?: MatrixEvent; indeterminate: boolean; synced: boolean };
    const attempts = new Map<string, Attempt>();
    const recoveredOutbox = new Map<string, Awaited<ReturnType<typeof dependencies.store.getTextOutboxRecord>>>();
    const MAX_ATTEMPTS = 256;
    const reservedTransactions = new Set<string>();
    /** The one capacity authority for reservations and every plaintext attempt. */
    const allocateAttemptSlot = (transactionId: string, reserve = false): boolean => {
      if (attempts.has(transactionId) || reservedTransactions.has(transactionId) || recoveredOutbox.has(transactionId)) return true;
      while (attempts.size + reservedTransactions.size + recoveredOutbox.size >= MAX_ATTEMPTS) {
        const terminal = [...attempts.entries()].find(([, value]) => value.synced);
        if (!terminal) return false;
        attempts.delete(terminal[0]);
      }
      if (reserve) reservedTransactions.add(transactionId);
      return true;
    };
    const messages = new Map<string, Map<string, TimelineTextMessage>>();
    const eventMessages = new Map<MatrixEvent, { roomId: string; localId: string; identity: DirectConversationIdentity }>();
    /** Self encrypted echoes remain private until authenticated plaintext proof. */
    const outgoingDecryptCandidates = new Map<MatrixEvent, { roomId: string; transactionId: string; eventId: string; peer: string; identity: DirectConversationIdentity }>();
    const MAX_PRIVATE_EVENTS = 256;
    const MAX_TIMELINE_MESSAGES = 256;
    clearRetainedTimelineEvents = (): void => {
      eventMessages.clear();
      outgoingDecryptCandidates.clear();
      verificationEvents.clear();
      verificationEventOrder.clear();
      verificationEventCount = 0;
    };
    let timelineQueue = Promise.resolve(); let timelineFailed = false; let syncQueue = Promise.resolve();
    // Network sends deliberately are not owner work: stop closes ingress and
    // drains only durable work, so a transport promise cannot retain ownership.
    const own = <T>(work: () => Promise<T>): Promise<T> => work();
    const enqueueTimeline = (work: () => Promise<void>): void => { timelineQueue = timelineQueue.then(work, work).catch(() => { timelineFailed = true; poisonTransport(); }); };
    /** Rust decrypt is intentionally detached: owner shutdown never waits on it. */
    const startDecrypt = (event: MatrixEvent): void => {
      void Promise.resolve().then(() => stopped() ? undefined : raw.decryptEventIfNeeded(event)).then(
        () => { if (!stopped()) receiveDecrypted(event); },
        () => { if (!stopped()) receiveDecrypted(event, new Error('decrypt')); },
      );
    };
    const transactionQueues = new Map<string, Promise<void>>();
    const enqueueTransaction = (transactionId: string, work: () => Promise<void>): Promise<void> => {
      const previous = transactionQueues.get(transactionId) ?? Promise.resolve();
      const queued = previous.then(work, work).catch(() => { poisonTransport(); });
      transactionQueues.set(transactionId, queued);
      void queued.finally(() => { if (transactionQueues.get(transactionId) === queued) transactionQueues.delete(transactionId); });
      return queued;
    };
    const drainQueues = async (): Promise<void> => {
      // Stop closes ingress synchronously first.  Repeat because settling owner
      // work can enqueue a per-transaction settlement.
      for (;;) {
        await timelineQueue; await Promise.all([...transactionQueues.values()]); await syncQueue;
        if (transactionQueues.size === 0) return;
      }
    };
    const publishTimeline = (id: string): void => {
      if (transportStopped) return;
      const list = [...(messages.get(id)?.values() ?? [])].sort((a, b) => a.timestamp - b.timestamp || a.localId.localeCompare(b.localId));
      for (const { identity, listeners: subscribers } of timelineListeners.values()) {
        if (identity.roomId !== id) continue;
        const exact = Object.freeze(list.filter(message => sameIdentity(message.identity, identity)));
        for (const listener of subscribers) { try { listener(exact); } catch { /* isolated subscriber */ } }
      }
    };
    const putTimeline = (id: string, bound: TimelineTextMessage): void => {
      const roomMessages = messages.get(id) ?? new Map<string, TimelineTextMessage>();
      if (!roomMessages.has(bound.localId)) {
        const total = [...messages.values()].reduce((count, values) => count + values.size, 0);
        if (total >= MAX_TIMELINE_MESSAGES) {
          const evictable = [...messages.entries()].flatMap(([roomIdValue, values]) => [...values.values()].map(value => ({ roomIdValue, value }))).filter(({ value }) => value.delivery === 'synced' || value.delivery === 'decryption-failed').sort((a, b) => a.value.timestamp - b.value.timestamp)[0];
          if (!evictable) { poisonTransport(); return; }
          messages.get(evictable.roomIdValue)?.delete(evictable.value.localId);
          if (evictable.value.direction === 'outgoing' && evictable.value.transactionId) attempts.delete(evictable.value.transactionId);
        }
      }
      roomMessages.set(bound.localId, Object.freeze(bound)); messages.set(id, roomMessages); publishTimeline(id);
    };
    const text = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 16_384;
    const bodyDigest = async (body: string): Promise<string> => Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))), value => value.toString(16).padStart(2, '0')).join('');
    const eventId = (event: MatrixEvent): string | undefined => { try { const id = event.getId(); return typeof id === 'string' && id.startsWith('$') ? id : undefined; } catch { return undefined; } };
    const txn = (event: MatrixEvent): string | undefined => { try { const id = event.getTxnId(); return typeof id === 'string' ? id : undefined; } catch { return undefined; } };
    const isDirectEvent = async (event: MatrixEvent, room: Room | undefined): Promise<DirectConversation | undefined> => {
      if (!room || event.getRoomId?.() !== room.roomId) return undefined;
      try { return await direct(room, undefined); } catch { return undefined; }
    };
    const retainEvent = (event: MatrixEvent, value: { roomId: string; localId: string; identity: DirectConversationIdentity }): void => {
      if (eventMessages.size >= MAX_PRIVATE_EVENTS && !eventMessages.has(event)) {
        const evicted = eventMessages.keys().next().value as MatrixEvent | undefined;
        const prior = evicted ? eventMessages.get(evicted) : undefined;
        const message = prior && messages.get(prior.roomId)?.get(prior.localId);
        if (prior && message?.direction === 'incoming' && message.delivery === 'decrypting') putTimeline(prior.roomId, { identity: message.identity, localId: prior.localId, peerUserId: message.peerUserId, timestamp: message.timestamp, direction: 'incoming', delivery: 'decryption-failed', eventId: message.eventId });
        if (evicted) eventMessages.delete(evicted);
      }
      eventMessages.set(event, value);
    };
    receiveTimeline = (event, room, toStart, removed) => enqueueTimeline(async () => {
      if (unavailableTransport()) return;
      // Verification requests share the outer message type but belong solely to
      // the verification index; they are never chat plaintext candidates.
      const eventRoomId = event.getRoomId?.();
      const trackedPeer = typeof eventRoomId === 'string' ? trackedDirectPeers.get(eventRoomId) : undefined;
      if (event.getType?.() === 'm.room.message' && event.getWireType?.() !== 'm.room.encrypted' && typeof eventRoomId === 'string' && trackedDirectRooms.has(eventRoomId)) {
        const sender = event.getSender?.();
        const context = trackedPeer === undefined || typeof sender !== 'string' ? undefined
          : sender === trackedPeer ? { roomId: eventRoomId, expectedSender: trackedPeer, expectedRecipient: session.userId, requestEventId: eventId(event), direction: 'incoming' as const, now: roomClock.now() }
            : sender === session.userId ? { roomId: eventRoomId, expectedSender: session.userId, expectedSenderDeviceId: session.deviceId, expectedRecipient: trackedPeer, requestEventId: eventId(event), direction: 'outgoing' as const, now: roomClock.now() }
              : undefined;
        const valid = context !== undefined && validateVerificationEnvelope(ownedVerificationEnvelope(event) ?? {} as never, context)?.kind === 'request';
        if (valid) return;
        poisonTransport(); return;
      }
      if (toStart || removed) return;
      const id = eventId(event);
      const trackedRoom = room !== undefined && trackedDirectRooms.has(room.roomId);
      const conversation = await isDirectEvent(event, room);
      if (!conversation || !id) { if (event.getType?.() === 'm.room.message' && trackedRoom) poisonTransport(); return; }
      if (unavailableTransport()) return;
      if (event.getWireType?.() !== 'm.room.encrypted') { if (event.getType() === 'm.room.message') poisonTransport(); return; }
      const localTransaction = txn(event); const remoteTransaction = event.getUnsigned?.()?.transaction_id;
      if (event.getSender?.() === session.userId && typeof (localTransaction ?? remoteTransaction) === 'string') {
        const transactionId = localTransaction ?? remoteTransaction as string;
        const durable = await dependencies.store.getTextOutboxRecord({ profileId: session.profileId }, transactionId);
        if (stopped()) return;
        if (!durable) return; // legitimate non-text / SAS echo
        if (durable.roomId !== room!.roomId) { poisonTransport(); return; }
        if (outgoingDecryptCandidates.size >= MAX_PRIVATE_EVENTS && !outgoingDecryptCandidates.has(event)) {
          // An unresolved self echo cannot safely be rendered after eviction.
          outgoingDecryptCandidates.delete(outgoingDecryptCandidates.keys().next().value!);
        }
        outgoingDecryptCandidates.set(event, { roomId: room!.roomId, transactionId, eventId: id, peer: conversation.peerUserId, identity: conversation });
        if (event.getType() === 'm.room.message') receiveDecrypted(event);
        else startDecrypt(event);
        return;
      }
      if (event.getSender?.() !== conversation.peerUserId) return;
      const localId = `in:${id}`; retainEvent(event, { roomId: room!.roomId, localId, identity: conversation });
      putTimeline(room!.roomId, { identity: conversation, localId, peerUserId: conversation.peerUserId, timestamp: event.getTs?.() ?? 0, direction: 'incoming', delivery: 'decrypting', eventId: id as import('../contract').MatrixEventId });
      if (event.getType() === 'm.room.message') receiveDecrypted(event);
      else startDecrypt(event);
    });
    receiveDecrypted = (event, error) => enqueueTimeline(async () => {
      const decryptEpoch = epoch.value; if (unavailableTransport()) return;
      const outgoing = outgoingDecryptCandidates.get(event);
      if (outgoing) {
        outgoingDecryptCandidates.delete(event);
        const durable = await dependencies.store.getTextOutboxRecord({ profileId: session.profileId }, outgoing.transactionId);
        if (stopped()) return;
        const content = event.getContent();
        if (error || !durable || durable.roomId !== outgoing.roomId || event.getWireType?.() !== 'm.room.encrypted' || event.getType() !== 'm.room.message' || !object(content) || content.msgtype !== 'm.text' || !text(content.body) || Object.prototype.hasOwnProperty.call(content, 'm.relates_to') || await bodyDigest(content.body) !== durable.bodyHash) { poisonTransport(); return; }
        if (stopped() || epoch.value !== decryptEpoch) return;
        await enqueueTransaction(outgoing.transactionId, async () => {
          const outcome = await dependencies.store.reconcileOutboxRemoteEcho({ profileId: session.profileId }, outgoing.transactionId, outgoing.eventId);
          if (unavailableTransport() || (outcome.kind !== 'updated' && outcome.kind !== 'unchanged')) { poisonTransport(); return; }
          let attempt = attempts.get(outgoing.transactionId);
          if (!attempt) {
            if (!allocateAttemptSlot(outgoing.transactionId)) return;
            attempt = { body: content.body, bodyHash: durable.bodyHash, peer: outgoing.peer, identity: outgoing.identity, timestamp: event.getTs?.() ?? 0, generation: outcome.record.generation, indeterminate: false, synced: false };
            attempts.set(outgoing.transactionId, attempt);
          }
          // Echo settlement is authoritative even when plaintext was not supplied.
          recoveredOutbox.delete(outgoing.transactionId);
          if (attempt.body !== content.body) return;
          if (outcome.record.state !== 'synced' && outcome.record.state !== 'homeserver-accepted') { poisonTransport(); return; }
          attempt.localEvent = event; attempt.eventId = outcome.record.eventId; attempt.synced = outcome.record.state === 'synced';
          putTimeline(outgoing.roomId, { identity: outgoing.identity, localId: outgoing.transactionId, peerUserId: userId(attempt.peer), timestamp: attempt.timestamp, direction: 'outgoing', transactionId: outgoing.transactionId as import('../contract').MatrixTransactionId, delivery: outcome.record.state, eventId: outcome.record.eventId as import('../contract').MatrixEventId, plaintext: attempt.body });
        });
        return;
      }
      const indexed = eventMessages.get(event); if (!indexed) return;
      const id = eventId(event); if (!id) return;
      const sender = event.getSender();
      const current = messages.get(indexed.roomId)?.get(indexed.localId);
      const stillDecrypting = current?.direction === 'incoming' && current.delivery === 'decrypting' && current.eventId === id;
      const terminalize = (): void => { const existing = messages.get(indexed.roomId)?.get(indexed.localId); if (existing?.direction === 'incoming' && existing.delivery === 'decrypting') putTimeline(indexed.roomId, { identity: existing.identity, localId: indexed.localId, peerUserId: existing.peerUserId, timestamp: existing.timestamp, direction: 'incoming', delivery: 'decryption-failed', eventId: existing.eventId }); };
      if (!sender || !stillDecrypting) return;
      const room = raw.getRoom(indexed.roomId); let conversation: DirectConversation | undefined;
      try { if (room) conversation = await direct(room, undefined); } catch { terminalize(); poisonTransport(); return; }
      if (stopped()) return;
      if (epoch.value !== decryptEpoch || !conversation || conversation.membership !== 'joined' || conversation.peerUserId !== sender || event.getWireType?.() !== 'm.room.encrypted') { terminalize(); poisonTransport(); return; }
      const update = (plaintext: string | undefined): void => { const existing = messages.get(indexed.roomId)?.get(indexed.localId); if (!existing || existing.direction !== 'incoming') return; const reduced = reduceIncoming({ eventId: existing.eventId, delivery: existing.delivery === 'decrypting' ? 'decrypting' : existing.delivery === 'synced' ? 'synced' : 'decryption-failed', ...(existing.delivery === 'synced' ? { plaintext: existing.plaintext } : {}) } as never, { eventId: id, plaintext }); if (reduced.delivery === 'synced') putTimeline(indexed.roomId, { identity: existing.identity, localId: indexed.localId, peerUserId: userId(sender), timestamp: event.getTs?.() ?? 0, direction: 'incoming', delivery: 'synced', eventId: id as import('../contract').MatrixEventId, plaintext: reduced.plaintext }); else if (reduced.delivery === 'decryption-failed') putTimeline(indexed.roomId, { identity: existing.identity, localId: indexed.localId, peerUserId: userId(sender), timestamp: event.getTs?.() ?? 0, direction: 'incoming', delivery: 'decryption-failed', eventId: id as import('../contract').MatrixEventId }); };
      if (error) { update(undefined); poisonTransport(); return; }
      const content = event.getContent();
      if (event.getType() !== 'm.room.message' || !object(content) || content.msgtype !== 'm.text' || !text(content.body) || Object.prototype.hasOwnProperty.call(content, 'm.relates_to')) { update(undefined); poisonTransport(); return; }
      update(content.body);
    });
    receiveLocalEcho = (event, room) => { if (unavailableTransport() || !room || event.getRoomId?.() !== room.roomId || event.getSender?.() !== session.userId) return; const transactionId = txn(event) ?? event.getUnsigned?.()?.transaction_id; if (typeof transactionId !== 'string') return; const type = event.getType?.(); if (type !== 'm.room.message' && type !== 'm.room.encrypted') return; void enqueueTransaction(transactionId, async () => { const attempt = attempts.get(transactionId); if (attempt) attempt.localEvent = event; }); };
    reconcileSync = async current => { if (current !== SyncState.Syncing || unavailableTransport()) return; syncQueue = syncQueue.then(async () => { await timelineQueue; if (unavailableTransport() || timelineFailed) return; try { await dependencies.store.incrementSyncGeneration({ profileId: session.profileId }); } catch { timelineFailed = true; poisonTransport(); } }); await syncQueue; };
    const activeMembers = (room: Room): readonly { userId: string; membership: string }[] => {
      const candidate = room as unknown as { getMembers?: () => readonly { userId: string; membership: string }[] };
      return candidate.getMembers?.() ?? [];
    };
    const rememberTrackedDirectRoom = (id: string): void => {
      trackedDirectRooms.add(id);
      const members = raw.getRoom(id) ? activeMembers(raw.getRoom(id)!) : [];
      const users = [...new Set(members.filter(member => member.membership === 'join' || member.membership === 'invite' || member.membership === 'knock').map(member => member.userId))];
      const peer = users.length === 2 && users.includes(session.userId) ? users.find(value => value !== session.userId) : undefined;
      if (peer) trackedDirectPeers.set(id, peer);
    };
    const direct = async (room: Room, peer: string | undefined): Promise<DirectConversation> => {
      const projectionEpoch = epoch.value;
      const active = activeMembers(room).filter(member => member.membership === 'join' || member.membership === 'invite' || member.membership === 'knock');
      const users = new Set(active.map(member => member.userId));
      const inferredPeer = peer ?? [...users].find(value => value !== session.userId);
      if (!inferredPeer || inferredPeer === session.userId || users.size !== 2 || !users.has(session.userId) || !users.has(inferredPeer) || !active.some(member => member.userId === session.userId && member.membership === 'join') || !hasRequiredRoomState(room) || !await crypto().isEncryptionEnabledInRoom(room.roomId) || epoch.value !== projectionEpoch) unavailable();
      const safePeer: string = inferredPeer ?? unavailable();
      const bothJoined = active.every(member => member.membership === 'join');
      rememberTrackedDirectRoom(room.roomId); trackedDirectPeers.set(room.roomId, safePeer);
      return Object.freeze({ roomId: roomId(room.roomId), peerUserId: userId(safePeer), membership: bothJoined ? 'joined' : 'verification-only', roomEpoch: projectionEpoch });
    };
    type SasDisplay = Readonly<{ emojis: readonly Readonly<{ emoji: string; label: string }>[]; decimals: readonly number[] }>;
    type ActiveSas = { operation: SasOperation; request: VerificationWireRequest; verifier?: Verifier; callbacks?: ShowSasCallbacks; pendingCallbacks?: ShowSasCallbacks; sas?: SasDisplay; timer?: unknown; consumed: boolean; publicationRoomEpoch: number; trustRevision: number; localStartRequested: boolean; startFlight?: Promise<void>; identity: symbol; verifierResolved: boolean; verifierStarted: boolean; requestDone: boolean; confirmFulfilled: boolean; terminalRequested: boolean; queue: Promise<void>; completion: Promise<void>; resolveCompletion: () => void; rejectCompletion: () => void; completionSettled: boolean; completionFlight?: Promise<void>; terminalFlight?: Promise<void> };
    let activeSas: ActiveSas | undefined;
    /** Store work, unlike Rust/network work, is ownership work and must drain at stop. */
    const sasDurableWork = new Set<Promise<unknown>>();
    const sasMutation = <T>(work: () => Promise<T>): Promise<T> => {
      const pending = Promise.resolve().then(work);
      sasDurableWork.add(pending);
      void pending.finally(() => sasDurableWork.delete(pending)).catch(() => undefined);
      return pending;
    };
    const drainSasDurableWork = async (): Promise<void> => {
      while (sasDurableWork.size !== 0) await Promise.all([...sasDurableWork]);
    };
    // A persisted operation has one in-process owner even before it has an
    // ActiveSas.  In particular, recovery must not dispose it while a received
    // callback is awaiting room admission.
    let sasOperationAuthority: Promise<void> = Promise.resolve();
    const withSasOperationAuthority = async <T>(work: () => Promise<T>): Promise<T> => {
      const previous = sasOperationAuthority;
      let release!: () => void;
      sasOperationAuthority = new Promise<void>(resolve => { release = resolve; });
      await previous;
      try { return await work(); } finally { release(); }
    };
    const sameSasOperation = (expected: SasOperation, current: SasOperation | undefined): current is SasOperation => current !== undefined
      && !current.disposed
      && current.profileId === expected.profileId
      && current.generation === expected.generation
      && current.roomId === expected.roomId
      && current.peerUserId === expected.peerUserId
      && current.localDeviceId === expected.localDeviceId
      && current.direction === expected.direction
      && current.phase === expected.phase
      && current.transactionId === expected.transactionId
      && current.peerDeviceId === expected.peerDeviceId
      && current.expiresAt === expected.expiresAt
      && current.requestEventId === expected.requestEventId
      && current.startEventId === expected.startEventId;
    /** Claim only the exact durable generation immediately before publication. */
    const claimPersistedSas = async (expected: SasOperation, request: VerificationWireRequest): Promise<ActiveSas | undefined> => {
      const current = await dependencies.store.getSasOperation({ profileId: session.profileId });
      if (!sameSasOperation(expected, current) || activeSas) return undefined;
      // Never install a live authority after shutdown/block.  Retire exactly the
      // generation we observed; this path intentionally has no publication.
      if (unavailableTransport()) {
        const terminal = current.phase === 'done' || current.phase === 'failed' || current.phase === 'cancelled'
          ? current : await dependencies.store.advanceSasPhase({ profileId: session.profileId }, current.generation, 'failed');
        if (terminal) await dependencies.store.disposeSasOperation({ profileId: session.profileId }, terminal.generation);
        return undefined;
      }
      const active = newActiveSas(current, request); activeSas = active;
      return active;
    };
    const newActiveSas = (operation: SasOperation, request: VerificationWireRequest): ActiveSas => {
      let resolveCompletion!: () => void; let rejectCompletion!: () => void;
      const completion = new Promise<void>((resolve, reject) => { resolveCompletion = resolve; rejectCompletion = () => reject(new Error('sas-completion-failed')); });
      // A flow may never be confirmed; retain a handled branch while still
      // exposing the original promise to confirmSas.
      void completion.catch(() => undefined);
      return { operation, request, consumed: false, publicationRoomEpoch: epoch.value, trustRevision: 0, localStartRequested: false, identity: Symbol('sas'), verifierResolved: false, verifierStarted: false, requestDone: false, confirmFulfilled: false, terminalRequested: false, queue: Promise.resolve(), completion, resolveCompletion, rejectCompletion, completionSettled: false };
    };
    /** The sole serialization gate for all SDK callbacks and terminal commands. */
    const queueSas = <T>(active: ActiveSas | undefined, work: () => Promise<T>, terminalWork = false): Promise<T | undefined> => {
      if (!active) return Promise.resolve(undefined);
      const identity = active.identity;
      const run = async (): Promise<T | undefined> => {
        if (activeSas !== active || active.identity !== identity || (active.terminalRequested && !terminalWork)) return undefined;
        return await work();
      };
      const result = active.queue.then(run, run);
      active.queue = result.then(() => undefined, () => undefined);
      return result;
    };
    /** Protocol calls are intentionally detached from the durable SAS queue. */
    const scheduleStartVerification = (active: ActiveSas): void => {
      if (active.startFlight) return;
      active.localStartRequested = true;
      active.startFlight = active.request.startVerification('m.sas.v1').then(verifier => {
        void queueSas(active, async () => {
          if (activeSas !== active || active.terminalRequested || active.operation.phase === 'failed' || active.operation.phase === 'cancelled' || active.operation.phase === 'done') return;
          attachVerifier(active, verifier);
        });
      }, () => { void queueSas(active, async () => { if (activeSas === active && !active.terminalRequested) await failSas(active); }); }).then(() => undefined);
    };
    const markSasTrustChanged = (): void => { const active = activeSas; if (active) { active.publicationRoomEpoch = epoch.value; active.trustRevision += 1; } };
    const settleSasCompletion = (active: ActiveSas, success: boolean): void => {
      if (active.completionSettled) return;
      active.completionSettled = true;
      if (success) active.resolveCompletion(); else active.rejectCompletion();
    };
    /** SDK callbacks and transport cancellation are advisory after terminal intent. */
    const bestEffortSasEffect = (effect: () => unknown): void => {
      try { void Promise.resolve(effect()).catch(() => undefined); } catch { /* best effort only */ }
    };
    /** Revoke completion synchronously; durable terminal work remains queued. */
    const requestSasTerminal = (active: ActiveSas | undefined): boolean => {
      if (!active || activeSas !== active || active.terminalRequested) return false;
      active.terminalRequested = true; active.callbacks = undefined; active.pendingCallbacks = undefined; active.sas = undefined;
      epoch.verificationChanged(); revokeTrust();
      settleSasCompletion(active, false);
      return true;
    };
    type TrustSnapshot = Readonly<{ identity: symbol; generation: number; epoch: number; trustRevision: number }>;
    const trustSnapshot = (active: ActiveSas): TrustSnapshot => Object.freeze({ identity: active.identity, generation: active.operation.generation, epoch: epoch.value, trustRevision: active.trustRevision });
    const stableTrustSnapshot = (active: ActiveSas, snapshot: TrustSnapshot): boolean => !active.terminalRequested && !active.completionSettled && activeSas === active && active.identity === snapshot.identity && active.operation.generation === snapshot.generation && epoch.value === snapshot.epoch && active.trustRevision === snapshot.trustRevision;
    const verificationDto = (active: ActiveSas): import('../contract').VerificationState | undefined => {
      const phase = active.operation.phase === 'intent' ? 'requested' : active.operation.phase;
      if (phase === 'sas-shown' && (!active.callbacks || !active.sas)) return undefined;
      return Object.freeze({ roomId: roomId(active.operation.roomId), peerUserId: userId(active.operation.peerUserId), roomEpoch: active.publicationRoomEpoch, direction: active.operation.direction, phase, ...(phase === 'sas-shown' ? { sas: active.sas } : {}) } as import('../contract').VerificationState);
    };
    const publishVerification = (): void => {
      if (unavailableTransport()) return;
      const active = activeSas;
      if (!active) return;
      const dto = verificationDto(active); if (!dto) return;
      for (const { identity, listeners: subscribers } of verificationListeners.values()) {
        if (!sameIdentity(identity, dto)) continue;
        for (const listener of subscribers) { try { listener(dto); } catch { /* subscriber */ } }
      }
    };
    const safeRoom = async (id: string, peer: string): Promise<boolean> => {
      const candidate = raw.getRoom(id);
      if (!candidate) return false;
      try { const conversation = await direct(candidate, peer); return conversation.membership === 'joined' && conversation.roomEpoch === epoch.value; } catch { return false; }
    };
    /** Commands and subscriptions use the caller's captured admission epoch. */
    const exactCurrentIdentity = async (identity: DirectConversationIdentity): Promise<boolean> => {
      if (identity.roomEpoch !== epoch.value) return false;
      const room = raw.getRoom(identity.roomId);
      if (!room) return false;
      try { return sameIdentity(await direct(room, identity.peerUserId), identity) && identity.roomEpoch === epoch.value; } catch { return false; }
    };
    /** Completion requires a new authoritative key response, never just Rust's
     * cache.  Bind both device fingerprints to the same cached Device object. */
    const cachedDeviceKeys = (device: unknown, deviceId: string): { ed25519: string; curve25519: string } | undefined => {
      const keys = (device as { keys?: unknown }).keys;
      if (!(keys instanceof Map) || keys.size !== 2) return undefined;
      const ed25519 = keys.get(`ed25519:${deviceId}`); const curve25519 = keys.get(`curve25519:${deviceId}`);
      return typeof ed25519 === 'string' && typeof curve25519 === 'string' ? { ed25519, curve25519 } : undefined;
    };
    /** A fresh, owned trust proof shared by SAS, send admission, and public readiness. */
    const freshDirectTrust = async (id: string, peer: string, requiredPeerDeviceId?: string): Promise<{ readonly allowed: boolean; readonly state?: import('../contract').DirectTrustState; readonly epoch: number }> => {
      const proofEpoch = epoch.value;
      try {
        if (unavailableTransport()) return { allowed: false, epoch: proofEpoch };
        const room = raw.getRoom(id); if (!room || !await safeRoom(id, peer) || unavailableTransport() || epoch.value !== proofEpoch) return { allowed: false, epoch: proofEpoch };
        const rawKeys = await raw.downloadKeysForUsers([session.userId, peer]);
        if (!object(rawKeys.failures) || Object.keys(rawKeys.failures).length !== 0 || unavailableTransport() || epoch.value !== proofEpoch) return { allowed: false, epoch: proofEpoch };
        const users = [session.userId, peer]; const cached = await crypto().getUserDeviceInfo(users, true);
        const rawDeviceUsers = rawKeys.device_keys;
        if (!object(rawDeviceUsers) || Object.keys(rawDeviceUsers).length !== 2 || !users.every(id => Object.prototype.hasOwnProperty.call(rawDeviceUsers, id))) return { allowed: false, epoch: proofEpoch };
        const authoritative = new Map<string, readonly AuthoritativeDeviceKey[]>(); const rust = new Map<string, readonly AuthoritativeDeviceKey[]>(); const trust = new Map<string, DeviceEnumeration>(); const identities = new Map<string, { known: boolean; crossSigningVerified: boolean; awaitingApproval: boolean }>();
        for (const id of users) {
          const rawDevicesForUser = rawDeviceUsers[id]; if (!object(rawDevicesForUser)) return { allowed: false, epoch: proofEpoch };
          const listed: AuthoritativeDeviceKey[] = [];
          for (const [id, value] of Object.entries(rawDevicesForUser)) { if (!object(value) || !object(value.keys) || typeof value.keys[`ed25519:${id}`] !== 'string' || typeof value.keys[`curve25519:${id}`] !== 'string') return { allowed: false, epoch: proofEpoch }; listed.push({ deviceId: id, ed25519Fingerprint: value.keys[`ed25519:${id}`] as string, curve25519Fingerprint: value.keys[`curve25519:${id}`] as string }); }
          authoritative.set(id, listed);
          const devices = cached.get(id); if (!devices) return { allowed: false, epoch: proofEpoch };
          const rustListed: AuthoritativeDeviceKey[] = []; const trusted = await Promise.all([...devices.values()].map(async device => { const keys = cachedDeviceKeys(device, device.deviceId); if (!keys) throw new Error('malformed-cached-device-keys'); rustListed.push({ deviceId: device.deviceId, ed25519Fingerprint: keys.ed25519, curve25519Fingerprint: keys.curve25519 }); const status = await crypto().getDeviceVerificationStatus(id, device.deviceId); return { deviceId: device.deviceId, known: status !== null, signed: status?.signedByOwner === true && status.crossSigningVerified === true, verified: status?.isVerified() === true }; }));
          rust.set(id, rustListed); trust.set(id, { complete: true, devices: trusted }); const identity = await crypto().getUserVerificationStatus(id); identities.set(id, { known: identity.known, crossSigningVerified: identity.isCrossSigningVerified(), awaitingApproval: identity.needsUserApproval });
        }
        const own = await crypto().getDeviceVerificationStatus(session.userId, session.deviceId);
        const encrypted = await crypto().isEncryptionEnabledInRoom(room.roomId); const targets = await room.getEncryptionTargetMembers();
        if (unavailableTransport() || epoch.value !== proofEpoch || (requiredPeerDeviceId !== undefined && !authoritative.get(peer)?.some(device => device.deviceId === requiredPeerDeviceId))) return { allowed: false, epoch: proofEpoch };
        const allowed = assessDirectSendReadiness({ currentState: state(room), rustCryptoPersistent: encrypted, encryptionTargetMembers: targets.map(member => ({ userId: member.userId, membership: member.membership })) as never, devicesByUser: trust, selfUserId: session.userId, peerUserId: peer, activeMembers: activeMembers(room) as never, ownCurrentDeviceReady: own?.signedByOwner === true && own.crossSigningVerified && own.isVerified(), identities, keysQueryFailures: [], authoritativeDevicesByUser: authoritative, rustDevicesByUser: rust }).allowed;
        const project = (value: string): import('../contract').UserTrustState => Object.freeze({ userId: userId(value), identityKnown: identities.get(value)?.known === true, crossSigningVerified: identities.get(value)?.crossSigningVerified === true, awaitingApproval: identities.get(value)?.awaitingApproval === true, devices: Object.freeze((rust.get(value) ?? []).map(device => { const trusted = trust.get(value)?.devices.find(candidate => candidate.deviceId === device.deviceId); return Object.freeze({ deviceId: device.deviceId as import('../contract').MatrixDeviceId, known: trusted?.known === true, ownerSigned: trusted?.signed === true, verified: trusted?.verified === true, ed25519Fingerprint: device.ed25519Fingerprint, curve25519Fingerprint: device.curve25519Fingerprint }); })) });
        return { allowed, epoch: proofEpoch, state: Object.freeze({ roomId: roomId(id), peerUserId: userId(peer), peer: project(peer), self: project(session.userId), sendReady: allowed, roomEpoch: proofEpoch }) };
      } catch { return { allowed: false, epoch: proofEpoch }; }
    };
    const freshPeerTrust = async (active: ActiveSas): Promise<boolean> => (await freshDirectTrust(active.operation.roomId, active.operation.peerUserId, active.operation.peerDeviceId)).allowed;
    const clearDisposedSas = (active: ActiveSas | undefined, terminal: SasOperation, phase: 'done' | 'failed' | 'cancelled'): void => {
      // Disposal is generation-specific.  It must not evict a replacement
      // authority, but its indexed wire events are never reusable.
      clearVerificationEvents(terminal.roomId, terminal.requestEventId);
      if (!active || activeSas !== active || active.operation.generation !== terminal.generation) return;
      activeSas = undefined;
      if (active.timer !== undefined) sasScheduler.clearTimeout(active.timer);
      active.callbacks = undefined; active.pendingCallbacks = undefined; active.sas = undefined;
      if (!stopped()) for (const { identity, listeners: subscribers } of verificationListeners.values()) { if (identity.roomId !== terminal.roomId || identity.peerUserId !== terminal.peerUserId || identity.roomEpoch !== active.publicationRoomEpoch) continue; for (const listener of subscribers) { try { listener(Object.freeze({ roomId: roomId(terminal.roomId), peerUserId: userId(terminal.peerUserId), roomEpoch: active.publicationRoomEpoch, direction: terminal.direction, phase } as import('../contract').VerificationState)); } catch { /* subscriber */ } } }
      publishConversations();
    };
    const clearStaleSasAfterFailedTerminalCas = async (active: ActiveSas): Promise<void> => {
      const current = await dependencies.store.getSasOperation({ profileId: session.profileId });
      // Retain this authority only while its exact durable generation remains
      // live.  A tombstone, absence, or successor cannot own this closure.
      if (sameSasOperation(active.operation, current)) return;
      if (activeSas !== active) return;
      activeSas = undefined;
      if (active.timer !== undefined) sasScheduler.clearTimeout(active.timer);
      active.callbacks = undefined; active.pendingCallbacks = undefined; active.sas = undefined;
      clearVerificationEvents(active.operation.roomId, active.operation.requestEventId);
      publishConversations();
    };
    const sameSasLineage = (expected: SasOperation, current: SasOperation | undefined): current is SasOperation => current !== undefined
      && current.profileId === expected.profileId && current.roomId === expected.roomId
      && current.peerUserId === expected.peerUserId && current.localDeviceId === expected.localDeviceId
      && current.direction === expected.direction && current.expiresAt === expected.expiresAt
      && current.transactionId === expected.transactionId && current.requestEventId === expected.requestEventId
      && current.peerDeviceId === expected.peerDeviceId && current.startEventId === expected.startEventId;
    /** Shutdown-only terminalizer.  It deliberately never joins active.queue or
     * calls an SDK object: a hung Rust callback must not retain the owner. */
    emergencyTerminalizeSas = async (): Promise<void> => {
      const active = activeSas;
      const expected = active?.operation;
      if (active) requestSasTerminal(active); // synchronous ingress/transient revocation
      for (let retry = 0; retry !== 3; retry += 1) {
        const current = await sasMutation(() => dependencies.store.getSasOperation({ profileId: session.profileId }));
        if (!current) return;
        if (expected && current.generation > expected.generation && (current.roomId !== expected.roomId || current.transactionId !== expected.transactionId || current.requestEventId !== expected.requestEventId || current.direction !== expected.direction)) return;
        if (current.profileId !== session.profileId || current.localDeviceId !== session.deviceId) throw new Error('sas-cleanup-foreign-record');
        if (current.disposed) {
          if (!expected || sameSasLineage(expected, current)) return;
          throw new Error('sas-cleanup-unproven-tombstone');
        }
        let terminal: SasOperation | undefined = current;
        if (terminal.phase !== 'done' && terminal.phase !== 'cancelled' && terminal.phase !== 'failed') {
          terminal = await sasMutation(() => dependencies.store.advanceSasPhase({ profileId: session.profileId }, terminal!.generation, 'cancelled'));
          if (!terminal) continue;
        }
        if (!await sasMutation(() => dependencies.store.disposeSasOperation({ profileId: session.profileId }, terminal.generation))) continue;
        const proof = await sasMutation(() => dependencies.store.getSasOperation({ profileId: session.profileId }));
        if (!proof) return;
        if (sameSasLineage(terminal, proof) && proof.disposed) {
          if (active) clearDisposedSas(active, terminal, terminal.phase === 'done' ? 'done' : terminal.phase === 'failed' ? 'failed' : 'cancelled');
          return;
        }
        if (proof.generation > terminal.generation && (proof.roomId !== terminal.roomId || proof.transactionId !== terminal.transactionId || proof.requestEventId !== terminal.requestEventId || proof.direction !== terminal.direction)) return;
      }
      throw new Error('sas-cleanup-retry-exhausted');
    };
    const finishSas = async (phase: 'failed' | 'cancelled', cancel: boolean, captured: ActiveSas | undefined): Promise<void> => {
      const active = captured; if (!active || activeSas !== active) return;
      requestSasTerminal(active);
      // Transport cancellation is deliberately detached: Rust may leave it
      // pending forever and it must not hold the durable mutation owner.
      if (cancel) bestEffortSasEffect(() => active.request.cancel());
      if (active.terminalFlight) { await active.terminalFlight; return; }
      active.terminalFlight = queueSas(active, async () => {
      try {
        const current = active.operation;
        const terminal = current.phase === 'done' || current.phase === 'failed' || current.phase === 'cancelled'
          ? current
          : await dependencies.store.advanceSasPhase({ profileId: session.profileId }, current.generation, phase);
        if (terminal) active.operation = terminal;
        if (!terminal) { await clearStaleSasAfterFailedTerminalCas(active); return; }
        if (!await dependencies.store.disposeSasOperation({ profileId: session.profileId }, terminal.generation)) return;
        clearDisposedSas(active, terminal, phase);
      } catch { /* fail closed: retain activeSas */ }
      }, true).then(() => undefined);
      await active.terminalFlight;
    };
    const failSas = async (active: ActiveSas | undefined): Promise<void> => await finishSas('failed', true, active);
    const cancelledSas = async (active: ActiveSas | undefined): Promise<void> => await finishSas('cancelled', false, active);
    const cancelCurrentSas = async (): Promise<void> => { const captured = activeSas; requestSasTerminal(captured); await finishSas('cancelled', true, captured); };
    // Abort/poison closes synchronous ingress before detached durable cleanup.
    // Capture the owner so a later flow cannot be terminalized by this flight.
    closeSasIngress = (): void => { cancelOutgoingRequestWaiters(); const captured = activeSas; requestSasTerminal(captured); void finishSas(stopped() ? 'cancelled' : 'failed', true, captured); };
    const scheduleExpiry = (active: ActiveSas): void => {
      const elapsed = (sasScheduler.now?.() ?? globalThis.performance.now()) - sasMonoStart;
      active.timer = sasScheduler.setTimeout(() => { requestSasTerminal(active); void finishSas('cancelled', true, active); }, Math.max(0, active.operation.expiresAt - (sasWallStart + elapsed)));
    };
    const showPendingSas = async (active: ActiveSas): Promise<void> => {
      const value = active.pendingCallbacks; if (!value || active.operation.phase !== 'started') return;
      active.pendingCallbacks = undefined; active.callbacks = value;
      const emoji = value.sas.emoji!; const decimal = value.sas.decimal!;
      try { const next = await dependencies.store.advanceSasPhase({ profileId: session.profileId }, active.operation.generation, 'sas-shown');
        if (next) active.operation = next;
        if (!next || unavailableTransport() || active.terminalRequested || activeSas !== active) { void failSas(active); return; }
        active.sas = Object.freeze({ emojis: Object.freeze(emoji.map(([emoji, label]) => Object.freeze({ emoji, label }))), decimals: Object.freeze([...decimal]) });
        publishVerification();
      } catch { void failSas(active); }
    };
    const maybeComplete = async (active: ActiveSas): Promise<void> => {
      if (active.terminalRequested || activeSas !== active || !active.verifierResolved || !active.requestDone || !active.confirmFulfilled) return;
      if (active.completionFlight) return active.completionFlight;
      active.completionFlight = (async () => {
        try {
          // A policy listener changes trustRevision synchronously.  Proof may be
          // retried once against that new view, but is never reused across it.
          let proof: TrustSnapshot | undefined;
          for (let attempt = 0; attempt !== 2; attempt += 1) {
            if (active.terminalRequested) return;
            const snapshot = trustSnapshot(active);
            const trusted = await freshPeerTrust(active);
            if (active.terminalRequested) return;
            if (stableTrustSnapshot(active, snapshot) && trusted) { proof = snapshot; break; }
            if (!stableTrustSnapshot(active, snapshot) && attempt === 0) continue;
            requestSasTerminal(active); void finishSas('failed', true, active); return;
          }
          if (active.terminalRequested) return;
          if (!proof || !stableTrustSnapshot(active, proof)) { requestSasTerminal(active); void finishSas('failed', true, active); return; }
          const done = await dependencies.store.advanceSasPhase({ profileId: session.profileId }, active.operation.generation, 'done');
          if (done) active.operation = done;
          if (active.terminalRequested) return;
          if (!done || activeSas !== active) { requestSasTerminal(active); void finishSas('failed', true, active); return; }
          // Done cannot be reverted.  Drop all transient SAS material before
          // re-proving and fail completion closed if the terminal proof races.
          active.callbacks = undefined; active.pendingCallbacks = undefined; active.sas = undefined;
          const terminalSnapshot = trustSnapshot(active);
          // `done` legitimately advances the durable operation generation. The
          // terminal snapshot is therefore the authority for this second proof;
          // policy epoch/trust revision stability is still checked below.
          const terminalTrusted = await freshPeerTrust(active);
          if (active.terminalRequested) return;
          if (!terminalTrusted || !stableTrustSnapshot(active, terminalSnapshot)) {
            if (activeSas === active && await dependencies.store.disposeSasOperation({ profileId: session.profileId }, done.generation)) { epoch.verificationChanged(); clearDisposedSas(active, done, 'failed'); }
            settleSasCompletion(active, false); return;
          }
          if (active.terminalRequested) return;
          const disposed = await dependencies.store.disposeSasOperation({ profileId: session.profileId }, done.generation);
          if (!disposed) { settleSasCompletion(active, false); return; }
          if (active.terminalRequested || !stableTrustSnapshot(active, terminalSnapshot)) { clearDisposedSas(active, done, 'failed'); settleSasCompletion(active, false); return; }
          // The durable terminal state is committed before the public security
          // state is restored.  A failed dispose therefore cannot expose ready.
          if (active.terminalRequested) { settleSasCompletion(active, false); return; }
          // Completion is a terminal verification transition: subsequent room
          // operations must use a newly captured identity.
          epoch.verificationChanged();
          clearDisposedSas(active, done, 'done'); settleSasCompletion(active, true);
          transition('ready'); publishConversations(); trustListeners.forEach(entry => publishTrust(entry.identity));
        } catch { requestSasTerminal(active); void finishSas('failed', true, active); }
      })();
      return active.completionFlight;
    };
    const attachVerifier = (active: ActiveSas, verifier: Verifier): void => {
      if (active.verifier || verifier.userId !== active.operation.peerUserId) { void failSas(active); return; }
      active.verifier = verifier;
      onVerifier(verifier, VerifierEvent.Cancel, () => { requestSasTerminal(active); void finishSas('cancelled', true, active); });
      onVerifier(verifier, VerifierEvent.ShowSas, callbacks => {
        void queueSas(active, async () => {
        // The SDK callbacks remain private.  Copy only display primitives and
        // never place them in IndexedDB or a log.
        const value = callbacks as ShowSasCallbacks;
        if (activeSas !== active || active.consumed || !value.sas) { void failSas(active); return; }
        const emoji = value.sas.emoji; const decimal = value.sas.decimal;
        if (!Array.isArray(emoji) || emoji.length !== 7 || !Array.isArray(decimal) || decimal.length !== 3 || emoji.some(pair => !Array.isArray(pair) || pair.length !== 2 || pair.some(item => typeof item !== 'string')) || decimal.some(item => !Number.isSafeInteger(item))) { void failSas(active); return; }
        // Rust can emit ShowSas while Start's room event is still reaching the
        // timeline.  Retain the callback only in this closure until Start CASes.
        if (active.operation.phase !== 'started') { active.pendingCallbacks = value; return; }
        active.pendingCallbacks = value;
        await showPendingSas(active);
        });
      });
      const late = verifier.getShowSasCallbacks?.();
      if (late) { active.pendingCallbacks = late; void queueSas(active, async () => await showPendingSas(active)); }
      if (!active.verifierStarted) { active.verifierStarted = true; verifier.verify().then(() => { void queueSas(active, async () => { active.verifierResolved = true; await maybeComplete(active); }); }).catch(() => { requestSasTerminal(active); void queueSas(active, async () => { void failSas(active); }); }); }
    };
    // Kept as the single verifier attachment path; transitions only invoke it
    // after a raw start event has been durably bound.
    void attachVerifier;
    /** Called only while sasOperationAuthority is held. */
    const receiveVerificationCore = async (request: SdkVerificationRequest): Promise<void> => {
      if (unavailableTransport()) return;
      // Do not use request.methods: the v42 Rust wrapper leaves that getter
      // unimplemented.  The only accepted method is enforced when starting.
      // The SDK may deliver the same object after recovery has claimed it. It
      // is the legitimate owner, not a duplicate to cancel.
      if (activeSas?.request === request) return;
      const wired = request as VerificationWireRequest;
      const persisted = await sasMutation(() => dependencies.store.getSasOperation({ profileId: session.profileId }));
      if (stopped()) return;
      const recovering = persisted !== undefined && !persisted.disposed;
      const rawRequest = request.roomId && request.transactionId ? roomEvent(request.roomId, request.transactionId) : undefined;
      const requestSender = request.initiatedByMe ? session.userId : request.otherUserId;
      const context = request.roomId ? wireContext(rawRequest, { roomId: request.roomId, expectedSender: requestSender, expectedSenderDeviceId: request.initiatedByMe ? session.deviceId : request.otherDeviceId, expectedRecipient: request.initiatedByMe ? request.otherUserId : session.userId, requestEventId: request.transactionId, direction: request.initiatedByMe ? 'outgoing' : 'incoming', now: roomClock.now() }, session.deviceId) : undefined;
      const validRequest = !activeSas && (recovering || !request.initiatedByMe) && !request.isSelfVerification && request.roomId !== undefined && request.otherUserId !== session.userId && request.transactionId !== undefined && context !== undefined && context.roomId === request.roomId && context.sender === requestSender && context.requestEventId === request.transactionId && (request.otherDeviceId === undefined || request.initiatedByMe || context.peerDeviceId === request.otherDeviceId);
      if (!validRequest || !await safeRoom(request.roomId!, request.otherUserId) || unavailableTransport()) { if (!unavailableTransport() && recovering && persisted && !activeSas) { const active = await claimPersistedSas(persisted, request as VerificationWireRequest); if (active) { await failSas(active); return; } } if (!unavailableTransport()) bestEffortSasEffect(() => request.cancel()); return; }
      if (persisted && !persisted.disposed) {
        // Reload recovery is deliberately exact: a new request never replaces a
        // durable operation, and only the same live in-room flow can resume.
        const start = uniqueStart(persisted);
        if (persisted.expiresAt <= roomClock.now() || persisted.transactionId !== persisted.requestEventId || persisted.transactionId !== request.transactionId || persisted.roomId !== request.roomId || persisted.peerUserId !== request.otherUserId || persisted.localDeviceId !== session.deviceId || persisted.direction !== (request.initiatedByMe ? 'outgoing' : 'incoming') || !matchesRequestWireContext(persisted, context) || persisted.phase !== 'started' || request.phase !== VerificationPhase.Started || request.chosenMethod !== 'm.sas.v1' || !request.verifier || !start || !matchesStartWireContext(persisted, start) || start.event.getId() !== persisted.startEventId) { const active = await claimPersistedSas(persisted, wired); if (active) await failSas(active); return; }
        const active = await claimPersistedSas(persisted, wired); if (!active) return;
        onRequest(request, () => { const callbackEpoch = epoch.value; if (request.phase === VerificationPhase.Cancelled) requestSasTerminal(active); void queueSas(active, async () => { if (callbackEpoch === epoch.value) await onRequestChange(active); }); });
        attachVerifier(active, request.verifier); scheduleExpiry(active); publishVerification(); return;
      }
      const incomingRoom = request.roomId!; const incomingTransaction = request.transactionId!; const incomingContext = context!;
      const operation: SasOperation = { profileId: session.profileId, roomId: incomingRoom, peerUserId: request.otherUserId, localDeviceId: session.deviceId, direction: 'incoming', phase: 'intent', expiresAt: roomClock.now() + 10 * 60_000, generation: persisted ? persisted.generation + 1 : 1 };
      if (unavailableTransport()) return;
      if (!await sasMutation(() => dependencies.store.createIncomingSasOperation(operation, incomingTransaction, incomingTransaction, incomingContext.peerDeviceId))) return;
      const created = await sasMutation(() => dependencies.store.getSasOperation({ profileId: session.profileId }));
      if (!created || !sameSasOperation({ ...operation, phase: 'requested', requestEventId: incomingTransaction, transactionId: incomingTransaction, peerDeviceId: incomingContext.peerDeviceId }, created)) return;
      if (unavailableTransport()) { await claimPersistedSas(created, wired); return; }
      activeSas = newActiveSas(created, wired);
      const active = activeSas; onRequest(request, () => { const callbackEpoch = epoch.value; if (request.phase === VerificationPhase.Cancelled) requestSasTerminal(active); void queueSas(active, async () => { if (callbackEpoch === epoch.value) await onRequestChange(active); }); }); scheduleExpiry(active); publishVerification();
    };
    /** Listener boundary: serialize every externally delivered SDK request. */
    receiveVerification = request => withSasOperationAuthority(async () => await receiveVerificationCore(request));
    const recoverPersistedSas = async (): Promise<void> => {
      await withSasOperationAuthority(async () => {
      if (activeSas) return;
      // Compatibility for minimal bootstrap ports that intentionally do not
      // install SAS persistence; production's IndexedDB store always has it.
      if (typeof dependencies.store.getSasOperation !== 'function') return;
      const persisted = await dependencies.store.getSasOperation({ profileId: session.profileId });
      // A verification callback may have claimed authority while the recovery
      // read was in flight; never overwrite that live owner.
      if (activeSas) return;
      if (!persisted || persisted.disposed) return;
      const found = (crypto() as unknown as { findVerificationRequestDMInProgress?: (roomId: string, userId: string) => SdkVerificationRequest | undefined }).findVerificationRequestDMInProgress?.(persisted.roomId, persisted.peerUserId);
      // Do not release and reacquire authority around the exact SDK object.
      if (found) { await receiveVerificationCore(found); return; }
      // No SDK request is not an empty slot: durably fail and dispose this exact
      // generation.  The stub is never published and only supplies best-effort
      // cancellation to the common terminal path.
      const rejected: SdkVerificationRequest = { transactionId: undefined, roomId: undefined, initiatedByMe: persisted.direction === 'outgoing', otherUserId: persisted.peerUserId, otherDeviceId: undefined, isSelfVerification: false, phase: VerificationPhase.Cancelled, chosenMethod: null, verifier: undefined, accept: async () => undefined, cancel: async () => undefined, startVerification: async () => { throw new Error('recovery-missing-request'); }, on: () => undefined };
      if (persisted.phase === 'done' || persisted.phase === 'cancelled' || persisted.phase === 'failed') {
        // Claim recovery authority before disposal so an incoming callback cannot
        // install a successor while this generation is being retired.
        const active = await claimPersistedSas(persisted, rejected);
        if (active) await finishSas('failed', false, active);
        return;
      }
      const active = await claimPersistedSas(persisted, rejected);
      if (active) await failSas(active);
      });
    };
    const onRequestChange = async (active: ActiveSas | undefined): Promise<void> => {
      if (!active || activeSas !== active) return;
      if (!await safeRoom(active.operation.roomId, active.operation.peerUserId)) return void failSas(active);
      // safeRoom yields.  A synchronous SDK cancellation can revoke this
      // authority while it is pending, so no durable Ready mutation may follow
      // that await unless this exact closure is still its owner.
      if (active.terminalRequested || activeSas !== active) return;
      if (active.request.phase === VerificationPhase.Cancelled) return void cancelledSas(active);
      // Done is an independent SDK latch, not an error.  It may arrive before
      // verify() resolves, and completion checks all latches later.
      if (active.request.phase === VerificationPhase.Done) { active.requestDone = true; await maybeComplete(active); return; }
      const readyAllowed = active.operation.direction === 'outgoing' ? active.operation.phase === 'requested' : active.operation.phase === 'accepted';
      if (active.request.phase === VerificationPhase.Ready && readyAllowed) {
        const readies = relatedEvents(active.operation.roomId, { roomId: active.operation.roomId, expectedSender: active.operation.peerUserId, expectedSenderDeviceId: active.operation.peerDeviceId, requestEventId: active.operation.requestEventId, direction: active.operation.direction, now: roomClock.now() }, 'ready');
        const ready = readies.length === 1 ? wireContext(readies[0], { roomId: active.operation.roomId, expectedSender: active.operation.peerUserId, expectedSenderDeviceId: active.operation.peerDeviceId, requestEventId: active.operation.requestEventId, direction: active.operation.direction, now: roomClock.now() }, session.deviceId) : undefined;
        if (!ready) return void failSas(active);
        if (!active.operation.peerDeviceId) {
          const bound = await dependencies.store.bindSasPeerDevice({ profileId: session.profileId }, active.operation.generation, ready.peerDeviceId);
          if (bound) active.operation = bound;
          if (!bound || activeSas !== active) return void failSas(active);
          if (active.terminalRequested || activeSas !== active) return;
        }
        const next = await dependencies.store.advanceSasPhase({ profileId: session.profileId }, active.operation.generation, 'ready');
        if (next) active.operation = next;
        if (!next || activeSas !== active) return void failSas(active);
        if (active.terminalRequested || activeSas !== active) return;
        publishVerification();
        if (active.operation.direction === 'outgoing') scheduleStartVerification(active);
        return;
      }
      const startedAllowed = active.operation.direction === 'outgoing'
        ? active.operation.phase === 'requested' || active.operation.phase === 'ready'
        : active.operation.phase === 'ready';
      if (active.request.phase === VerificationPhase.Started && active.request.chosenMethod === 'm.sas.v1' && active.request.verifier && active.operation.startEventId === undefined && startedAllowed) {
        const start = uniqueStart(active.operation);
        if (!start || start.event.getId() === undefined || (active.localStartRequested && start.actor !== 'self')) return void failSas(active);
        // A remote Start can race Ready, and is the only Start that establishes
        // the peer device.  A local Start must retain Ready's peer binding.
        if (start.actor === 'peer' && !active.operation.peerDeviceId) { const peer = await dependencies.store.bindSasPeerDevice({ profileId: session.profileId }, active.operation.generation, start.context.peerDeviceId); if (!peer || activeSas !== active) return void failSas(active); active.operation = peer; }
        if (!matchesStartWireContext(active.operation, start)) return void failSas(active);
        const prior = active.operation;
        const bound = await dependencies.store.bindSasStartEvent({ profileId: session.profileId }, prior.generation, start.event.getId()!);
        if (!bound || bound.generation !== prior.generation + 1 || bound.phase !== 'started' || bound.roomId !== prior.roomId || bound.peerUserId !== prior.peerUserId || bound.direction !== prior.direction || bound.requestEventId !== prior.requestEventId || bound.startEventId !== start.event.getId()) return void failSas(active);
        active.operation = bound;
        if (active.terminalRequested || activeSas !== active) return void failSas(active);
        // A returned verifier can have emitted ShowSas before the raw Start was
        // indexed.  Binding Start is the publication barrier.
        if (!active.verifier) attachVerifier(active, active.request.verifier);
        await showPendingSas(active);
      } else if (active.request.phase === VerificationPhase.Started && active.operation.direction === 'incoming') {
        // An incoming Start before explicit consent/Ready is terminal, including
        // a forged SDK phase transition with no usable raw event.
        void failSas(active);
      }
    };
    const publishTrust = (identity: DirectConversationIdentity): void => {
      const key = identityKey(identity);
      if (unavailableTransport()) { revokeTrust(key); return; }
      const entry = trustListeners.get(key); const room = raw.getRoom(identity.roomId); if (!entry || !room) { revokeTrust(key); return; }
      const publicationEpoch = epoch.value;
      void direct(room, undefined).then(async conversation => {
        const proof = await freshDirectTrust(identity.roomId, conversation.peerUserId);
        if (unavailableTransport() || epoch.value !== publicationEpoch || !proof.state || !sameIdentity(proof.state, identity)) { revokeTrust(key); return; }
        const dto = Object.freeze({ ...proof.state, sendReady: !transportBlocked && bootstrapDisposition === 'published' && proof.allowed });
        lastTrust.set(key, dto);
        for (const listener of entry.listeners) { try { listener(dto); } catch { /* subscribers are not authority */ } }
      }).catch(() => revokeTrust(key));
    };
    revokeTrust = (id?: string): void => {
      const ids = id === undefined ? [...trustListeners.keys()] : [id];
      for (const value of ids) {
        const prior = lastTrust.get(value);
        if (!prior) continue;
        const dto = Object.freeze({ ...prior, sendReady: false });
        lastTrust.set(value, dto);
        for (const listener of trustListeners.get(value)?.listeners ?? []) { try { listener(dto); } catch { /* subscriber */ } }
      }
    };
    let conversationPublication = 0;
    publishConversations = (): void => {
      if (unavailableTransport()) return;
      const publication = ++conversationPublication;
      const publicationEpoch = epoch.value;
      const rooms = (raw as unknown as { getRooms?: () => readonly Room[] }).getRooms?.() ?? [];
      void Promise.all(rooms.map(value => direct(value, undefined).catch(() => undefined))).then(values => {
        const safe = values.filter((value): value is DirectConversation => value !== undefined);
        if (unavailableTransport() || publication !== conversationPublication || publicationEpoch !== epoch.value) return; for (const listener of conversationListeners) { try { listener(Object.freeze([...safe])); } catch { /* isolated */ } }
      });
    };
    const readiness = operation.readiness.then(async result => { await recoverPersistedSas(); return result; });
    const gateway: MatrixGateway = { start: async () => { await readiness; }, stop: () => operation.stop(), subscribeSecurityState: listener => { listeners.add(listener); listener(security); return () => listeners.delete(listener); },
      observeLocalIdentity: async () => {
        try {
          const profileId = canonicalProfileIdFormat(session.profileId);
          const localUserId = userId(session.userId);
          const localDeviceId = deviceId(session.deviceId);
          if (!profileId || unavailableTransport() || security !== 'ready' || bootstrapDisposition !== 'published') unavailable();
          const initialEpoch = epoch.value;
          const initialRuntime = runtimeGeneration;
          const initial = await localState(crypto());
          const master = initial.state === 'complete' && initial.publicKeysOnDevice ? initial.ids?.[0] : undefined;
          if (!master || !canonicalBase64(master, 32)) unavailable();
          const profileRef = Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(`dsa-g2-profile-ref-v1\u0000${profileId}`))), value => value.toString(16).padStart(2, '0')).join('');
          if (unavailableTransport() || security !== 'ready' || bootstrapDisposition !== 'published' || epoch.value !== initialEpoch || runtimeGeneration !== initialRuntime || !await trustedIdentity(crypto(), session)) unavailable();
          const current = await localState(crypto()); const masterRef = current.ids?.[0];
          if (current.state !== 'complete' || !current.publicKeysOnDevice || masterRef === undefined || masterRef !== master || !canonicalBase64(masterRef, 32) || unavailableTransport() || security !== 'ready' || bootstrapDisposition !== 'published' || epoch.value !== initialEpoch || runtimeGeneration !== initialRuntime) unavailable();
          const stableMasterRef = masterRef as string;
          return Object.freeze({ userId: localUserId, deviceId: localDeviceId, profileRef, crossSigningMasterRef: stableMasterRef });
        } catch { return unavailable(); }
      },
      createEncryptedRoom: async request => { if (unavailableTransport() || !request.name.trim()) unavailable(); const dto = buildEncryptedRoomCreateRequest(request.invitees); const guarded = await epoch.runGuarded(async () => !unavailableTransport() && security === 'ready' && await trustedDevice() ? { allowed: true } : { allowed: false, reason: 'unverified-device', unverified: true }, () => raw.createRoom({ name: request.name, visibility: dto.visibility as never, preset: dto.preset as never, invite: [...dto.invite], initial_state: [...dto.initial_state] })); if (unavailableTransport() || guarded.admitted === false) return unavailable(); const id = roomId(guarded.value.room_id); const room = await waitForJoinedRoom(raw, id, roomClock); if (!room || unavailableTransport()) return unavailable(); const postEpoch = epoch.value; if (!(await post(room)).allowed || unavailableTransport() || !(await trustedDevice()) || epoch.value !== postEpoch) unavailable(); transition('ready'); return id; },
      joinEncryptedRoom: async request => { if (unavailableTransport()) unavailable(); const requestedRoomId = roomId(request.roomId); const invited = raw.getRoom(requestedRoomId); const membership = invited?.getMyMembership(); if (!invited || membership !== 'invite' || !assessPreJoinAdmission({ membership: { userId: session.userId, membership }, strippedState: state(invited) }).allowed) unavailable(); const guarded = await epoch.runGuarded(async () => !unavailableTransport() && security === 'ready' && await trustedDevice() ? { allowed: true } : { allowed: false, reason: 'unverified-device', unverified: true }, () => raw.joinRoom(requestedRoomId)); if (unavailableTransport() || guarded.admitted === false) return unavailable(); const id = roomId(guarded.value.roomId); if (id !== requestedRoomId) unavailable(); const room = await waitForJoinedRoom(raw, id, roomClock); if (!room || unavailableTransport()) return unavailable(); const postEpoch = epoch.value; if (!(await post(room)).allowed || unavailableTransport() || !(await trustedDevice()) || epoch.value !== postEpoch) unavailable(); transition('ready'); return id; },
      subscribeDirectConversations: listener => { conversationListeners.add(listener); publishConversations(); return () => conversationListeners.delete(listener); },
      createDirectConversation: async request => {
        if (request.peerUserId === userId(session.userId)) unavailable();
        const id = await gateway.createEncryptedRoom({ name: 'Private conversation', invitees: [request.peerUserId] });
        const room = await waitForJoinedRoom(raw, id, roomClock); if (!room) unavailable();
        return direct(room as Room, request.peerUserId);
      },
      joinDirectConversation: async request => { const id = await gateway.joinEncryptedRoom(request); const room = raw.getRoom(id); if (!room) unavailable(); return direct(room as Room, undefined); },
      subscribeTimeline: (identity, listener) => { if (stopped()) return () => undefined; rememberTrackedDirectRoom(identity.roomId); const key = identityKey(identity); const entry = timelineListeners.get(key) ?? { identity: Object.freeze({ ...identity }), listeners: new Set<TimelineListener>() }; entry.listeners.add(listener); timelineListeners.set(key, entry); try { listener(Object.freeze([...(messages.get(identity.roomId)?.values() ?? [])].filter(message => sameIdentity(message.identity, identity)).sort((a, b) => a.timestamp - b.timestamp || a.localId.localeCompare(b.localId)))); } catch { /* isolated subscriber */ } return () => { entry.listeners.delete(listener); if (entry.listeners.size === 0) timelineListeners.delete(key); }; },
      sendDirectText: request => own(async () => {
        // Reject a stale identity before reserving an outbox slot or touching
        // durable/SDK state.  Later proofs bind the room and peer as well.
        if (request.roomEpoch !== epoch.value) return unavailable();
        // Reserve before this invocation can yield. Existing retries do not need
        // a slot; unknown transactions reserve conservatively until the store
        // proves otherwise.
        const known = attempts.has(request.transactionId) || recoveredOutbox.has(request.transactionId);
        let reserved = false;
        if (!known) {
          if (!allocateAttemptSlot(request.transactionId, true)) return unavailable();
          reserved = true;
        }
        try {
        if (unavailableTransport() || !text(request.body) || (attempts.has(request.transactionId) && !attempts.get(request.transactionId)!.indeterminate)) return unavailable();
        const bytes = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(request.body)));
        const bodyHash = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
        const room = raw.getRoom(request.roomId); if (!room) return unavailable();
        let conversation: DirectConversation;
        try { conversation = await direct(room, request.peerUserId); } catch { return unavailable(); }
        const admissionEpoch = epoch.value;
        const proof = await freshDirectTrust(request.roomId, request.peerUserId);
        if (conversation.membership !== 'joined' || conversation.peerUserId !== request.peerUserId || conversation.roomEpoch !== request.roomEpoch || !proof.allowed || unavailableTransport() || epoch.value !== admissionEpoch || proof.epoch !== admissionEpoch) return unavailable();
        const existing = await dependencies.store.getTextOutboxRecord({ profileId: session.profileId }, request.transactionId);
        if (stopped() || epoch.value !== admissionEpoch) return unavailable();
        const oldAttempt = attempts.get(request.transactionId); let generation: number; let retry = false; let retryEvent: MatrixEvent | undefined;
        if (existing) {
          if (existing.roomId !== request.roomId || existing.bodyHash !== bodyHash) return unavailable();
          if ((existing.state === 'homeserver-accepted' || existing.state === 'synced') && existing.eventId) {
            // A reload has only hashes.  Exact user body resupply may restore the
            // owned projection, but never reopens a transport/retry path.
            if (!attempts.has(request.transactionId) && !allocateAttemptSlot(request.transactionId)) return unavailable();
            const hydrated: Attempt = { body: request.body, bodyHash, peer: request.peerUserId, identity: conversation, timestamp: Date.now(), generation: existing.generation, eventId: existing.eventId, indeterminate: false, synced: existing.state === 'synced' };
            attempts.set(request.transactionId, hydrated);
            putTimeline(request.roomId, { identity: hydrated.identity, localId: request.transactionId, peerUserId: request.peerUserId, timestamp: hydrated.timestamp, direction: 'outgoing', transactionId: request.transactionId, delivery: existing.state, eventId: existing.eventId as import('../contract').MatrixEventId, plaintext: request.body });
            recoveredOutbox.delete(request.transactionId);
            return;
          }
          // Re-prove before consuming the one retry.  Consumption is the final
          // durable await before the raw call below.
          if (oldAttempt && !oldAttempt.localEvent) return unavailable();
          if (!oldAttempt && !recoveredOutbox.has(request.transactionId)) return unavailable();
          const secondProof = await freshDirectTrust(request.roomId, request.peerUserId);
          if (stopped() || !secondProof.allowed || secondProof.epoch !== admissionEpoch || epoch.value !== admissionEpoch || !hasRequiredRoomState(room) || room.getMyMembership() !== 'join') return unavailable();
          const authorized = await dependencies.store.consumeOutboxRetry({ profileId: session.profileId }, request.transactionId, bodyHash, existing.generation);
          if (!authorized) return unavailable(); generation = authorized.record.generation; retry = true;
          retryEvent = oldAttempt?.localEvent;
          // The CAS is deliberately the last await before raw transport.  Only
          // synchronous, exact-current authority checks may follow it.
          const members = activeMembers(room);
          const exactMembers = members.length === 2 && members.some(member => member.userId === session.userId && member.membership === 'join') && members.some(member => member.userId === request.peerUserId && member.membership === 'join');
          if (unavailableTransport() || epoch.value !== admissionEpoch || !hasRequiredRoomState(room) || room.getMyMembership() !== 'join' || !exactMembers || (oldAttempt !== undefined && (attempts.get(request.transactionId) !== oldAttempt || oldAttempt.localEvent !== retryEvent))) {
            let rolledBack: TextOutboxRecord | undefined;
            try { await enqueueTransaction(request.transactionId, async () => { rolledBack = await dependencies.store.rollbackOutboxRetry({ profileId: session.profileId }, request.transactionId, bodyHash, generation); }); } catch { poisonTransport(); }
            if (!rolledBack) {
              const current = await dependencies.store.getTextOutboxRecord({ profileId: session.profileId }, request.transactionId);
              if (!(current && current.roomId === request.roomId && current.bodyHash === bodyHash && current.eventId && (current.state === 'synced' || current.state === 'homeserver-accepted'))) poisonTransport();
            }
            return unavailable();
          }
        } else {
          if (stopped() || epoch.value !== admissionEpoch) return unavailable();
          const initial = { profileId: session.profileId, transactionId: request.transactionId, roomId: request.roomId, bodyHash, retryConsumed: false, state: 'local-pending' as const, indeterminate: false };
          const created = await dependencies.store.createInitialTextOutboxRecord(initial);
          if (!created || stopped() || epoch.value !== admissionEpoch) {
            if (created) try { await enqueueTransaction(request.transactionId, async () => { await dependencies.store.markOutboxIndeterminate({ profileId: session.profileId }, request.transactionId, created.generation); }); } catch { poisonTransport(); }
            return unavailable();
          }
          generation = created.generation;
        }
        const attempt: Attempt = { body: request.body, bodyHash, peer: request.peerUserId, identity: oldAttempt?.identity ?? conversation, timestamp: oldAttempt?.timestamp ?? Date.now(), generation, indeterminate: false, synced: false, ...(retryEvent ? { localEvent: retryEvent } : {}) };
        attempts.set(request.transactionId, attempt);
        // A recovered row transfers to the plaintext attempt only after that
        // attempt has a slot and is installed; earlier failures retain recovery.
        recoveredOutbox.delete(request.transactionId);
        putTimeline(request.roomId, { identity: attempt.identity, localId: request.transactionId, peerUserId: request.peerUserId, timestamp: attempt.timestamp, direction: 'outgoing', transactionId: request.transactionId, delivery: 'local-pending', plaintext: request.body, indeterminate: false });
        const api = raw as unknown as { sendMessage(roomId: string, content: { msgtype: 'm.text'; body: string }, transactionId: string): Promise<{ event_id?: unknown }>; resendEvent?(event: MatrixEvent, room: Room): Promise<{ event_id?: unknown }> };
        let contractBreach = false;
        try {
          // Initial rows need a second proof after durable creation. Retries
          // already completed that proof before their consume CAS.
          if (!retry) {
            const secondProof = await freshDirectTrust(request.roomId, request.peerUserId);
            if (stopped() || !secondProof.allowed || secondProof.epoch !== admissionEpoch || epoch.value !== admissionEpoch || !hasRequiredRoomState(room) || room.getMyMembership() !== 'join') {
              try {
                let marked: TextOutboxRecord | undefined; if (!stopped()) await enqueueTransaction(request.transactionId, async () => { marked = await dependencies.store.markOutboxIndeterminate({ profileId: session.profileId }, request.transactionId, generation); });
                if (!marked) throw new Error('outbox-mark-unavailable');
                attempt.indeterminate = true;
                putTimeline(request.roomId, { identity: attempt.identity, localId: request.transactionId, peerUserId: request.peerUserId, timestamp: attempt.timestamp, direction: 'outgoing', transactionId: request.transactionId, delivery: 'local-pending', plaintext: request.body, indeterminate: true });
              } catch { poisonTransport(); }
              return unavailable();
            }
          }
          if (stopped() || epoch.value !== admissionEpoch || !hasRequiredRoomState(room) || room.getMyMembership() !== 'join') {
            if (retry) {
              let rolledBack: TextOutboxRecord | undefined;
              try { await enqueueTransaction(request.transactionId, async () => { rolledBack = await dependencies.store.rollbackOutboxRetry({ profileId: session.profileId }, request.transactionId, bodyHash, generation); }); } catch { poisonTransport(); }
              if (!rolledBack) {
                const current = await dependencies.store.getTextOutboxRecord({ profileId: session.profileId }, request.transactionId);
                if (!(current && current.roomId === request.roomId && current.bodyHash === bodyHash && current.eventId && (current.state === 'synced' || current.state === 'homeserver-accepted'))) poisonTransport();
              }
              if (rolledBack) {
                if (oldAttempt) attempts.set(request.transactionId, oldAttempt); else attempts.delete(request.transactionId);
                if (oldAttempt) putTimeline(request.roomId, { identity: oldAttempt.identity, localId: request.transactionId, peerUserId: userId(oldAttempt.peer), timestamp: oldAttempt.timestamp, direction: 'outgoing', transactionId: request.transactionId as import('../contract').MatrixTransactionId, delivery: 'local-pending', plaintext: oldAttempt.body, indeterminate: true });
                else { messages.get(request.roomId)?.delete(request.transactionId); publishTimeline(request.roomId); }
              }
            }
            return unavailable();
          }
          // No await may intervene between retry CAS and raw transport.
          const send = retry && attempt.localEvent ? api.resendEvent!(attempt.localEvent, room) : api.sendMessage(request.roomId, { msgtype: 'm.text', body: request.body }, request.transactionId);
          const response = await send;
          if (typeof response?.event_id !== 'string' || !response.event_id.startsWith('$')) { contractBreach = true; throw new Error('invalid-send-response'); }
          const acceptedEventId = response.event_id;
          if (stopped()) return unavailable();
          await enqueueTransaction(request.transactionId, async () => {
            const outcome = await dependencies.store.recordOutboxAcceptance({ profileId: session.profileId }, request.transactionId, generation, acceptedEventId);
            if (unavailableTransport() || (outcome.kind !== 'updated' && outcome.kind !== 'unchanged')) { poisonTransport(); return; }
            if (outcome.record.state !== 'synced' && outcome.record.state !== 'homeserver-accepted') { poisonTransport(); return; }
            attempt.eventId = outcome.record.eventId; attempt.synced = outcome.record.state === 'synced';
            putTimeline(request.roomId, { identity: attempt.identity, localId: request.transactionId, peerUserId: request.peerUserId, timestamp: attempt.timestamp, direction: 'outgoing', transactionId: request.transactionId, delivery: outcome.record.state, eventId: outcome.record.eventId as import('../contract').MatrixEventId, plaintext: request.body });
          });
        } catch {
          // A cryptographically reconciled remote echo is authoritative over a
          // late SDK rejection.  Never regress its terminal projection.
          await enqueueTransaction(request.transactionId, async () => {
            const marked = stopped() ? undefined : await dependencies.store.markOutboxIndeterminate({ profileId: session.profileId }, request.transactionId, generation);
            // A queued echo/acceptance may have won the CAS.  Its durable state is authoritative.
            if (!marked) {
              const current = await dependencies.store.getTextOutboxRecord({ profileId: session.profileId }, request.transactionId);
              if (current && current.roomId === request.roomId && current.bodyHash === bodyHash && current.eventId && (current.state === 'synced' || current.state === 'homeserver-accepted')) return;
              poisonTransport(); return;
            }
            attempt.indeterminate = true;
            putTimeline(request.roomId, { identity: attempt.identity, localId: request.transactionId, peerUserId: request.peerUserId, timestamp: attempt.timestamp, direction: 'outgoing', transactionId: request.transactionId, delivery: 'local-pending', plaintext: request.body, indeterminate: true });
            if (contractBreach) poisonTransport();
          });
          return unavailable();
        }
        } finally { if (reserved) reservedTransactions.delete(request.transactionId); }
      }),
      subscribeDirectTrust: (identity, listener) => { rememberTrackedDirectRoom(identity.roomId); const key = identityKey(identity); const entry = trustListeners.get(key) ?? { identity: Object.freeze({ ...identity }), listeners: new Set<DirectTrustListener>() }; entry.listeners.add(listener); trustListeners.set(key, entry); publishTrust(identity); return () => { entry.listeners.delete(listener); if (entry.listeners.size === 0) trustListeners.delete(key); }; },
      subscribeVerification: (identity, listener) => { rememberTrackedDirectRoom(identity.roomId); const key = identityKey(identity); const entry = verificationListeners.get(key) ?? { identity: Object.freeze({ ...identity }), listeners: new Set<VerificationListener>() }; entry.listeners.add(listener); verificationListeners.set(key, entry); publishVerification(); return () => { entry.listeners.delete(listener); if (entry.listeners.size === 0) verificationListeners.delete(key); }; },
      initiateSas: async request => await withSasOperationAuthority(async () => {
        if (unavailableTransport() || activeSas || request.peerUserId === userId(session.userId) || !await exactCurrentIdentity(request) || unavailableTransport()) unavailable();
        const prior = await dependencies.store.getSasOperation({ profileId: session.profileId });
        if (unavailableTransport() || (prior && !prior.disposed)) unavailable();
        const intent: SasOperation = { profileId: session.profileId, roomId: request.roomId, peerUserId: request.peerUserId, localDeviceId: session.deviceId, direction: 'outgoing', phase: 'intent', expiresAt: roomClock.now() + 10 * 60_000, generation: prior ? prior.generation + 1 : 1 };
        if (!await exactCurrentIdentity(request) || !await sasMutation(() => dependencies.store.createSasIntent(intent)) || unavailableTransport()) unavailable();
        // Before an SDK request is bound there is no active closure to own the
        // slot.  Still terminally advance *and dispose this exact generation*;
        // if either CAS fails the durable slot deliberately remains fail-closed.
        const failIntent = async (expected: SasOperation, sdkRequest?: SdkVerificationRequest): Promise<void> => {
          if (sdkRequest) bestEffortSasEffect(() => sdkRequest.cancel());
          try {
            const failed = await sasMutation(() => dependencies.store.advanceSasPhase({ profileId: session.profileId }, expected.generation, 'failed'));
            if (failed && await sasMutation(() => dependencies.store.disposeSasOperation({ profileId: session.profileId }, failed.generation))) { epoch.verificationChanged(); clearDisposedSas(undefined, failed, 'failed'); publishConversations(); }
            else clearVerificationEvents(expected.roomId, expected.requestEventId);
          } catch { clearVerificationEvents(expected.roomId, expected.requestEventId); }
        };
        let sdkRequest: SdkVerificationRequest | undefined;
        try { if (!await exactCurrentIdentity(request)) unavailable(); sdkRequest = await crypto().requestVerificationDM(request.peerUserId, request.roomId); } catch { if (!stopped()) await failIntent(intent); unavailable(); }
        // Stop can win while Rust is obtaining the request wrapper.  It owns no
        // durable mutation here, but the late wrapper must not remain live.
        if (unavailableTransport()) { if (sdkRequest) bestEffortSasEffect(() => sdkRequest!.cancel()); return unavailable(); }
        if (!sdkRequest) unavailable();
        if (!sdkRequest!.transactionId || sdkRequest!.roomId !== request.roomId || sdkRequest!.otherUserId !== request.peerUserId || !sdkRequest!.initiatedByMe) { await failIntent({ ...intent, requestEventId: sdkRequest!.transactionId, transactionId: sdkRequest!.transactionId }, sdkRequest); unavailable(); }
        const requestEventId = sdkRequest!.transactionId!;
        const rawRequest = await waitForOutgoingRequestEvent(request.roomId, requestEventId);
        const rawRequestContext = rawRequest === undefined ? undefined : wireContext(rawRequest, {
          roomId: request.roomId,
          expectedSender: session.userId,
          expectedSenderDeviceId: session.deviceId,
          expectedRecipient: request.peerUserId,
          requestEventId,
          direction: 'outgoing',
          now: roomClock.now(),
        }, session.deviceId);
        // Do not bind or publish an SDK-only request.  A stopped operation is
        // left for emergency terminalization, which deliberately does not join
        // this waiter or call into Rust.
        if (unavailableTransport()) { await failIntent({ ...intent, requestEventId, transactionId: requestEventId }, sdkRequest); return unavailable(); }
        if (!rawRequestContext || rawRequestContext.requestEventId !== requestEventId) {
          await failIntent({ ...intent, requestEventId, transactionId: requestEventId }, sdkRequest);
          unavailable();
        }
        // Rust may synchronously report cancellation before its request is bound
        // durably.  This witness covers the whole bind/claim interval; it is
        // intentionally not a second long-lived listener.
        let cancelledDuringBinding = sdkRequest!.phase === VerificationPhase.Cancelled;
        onRequest(sdkRequest!, () => { if (sdkRequest!.phase === VerificationPhase.Cancelled) cancelledDuringBinding = true; });
        const bound = await sasMutation(() => dependencies.store.bindSasRequest({ profileId: session.profileId }, intent.generation, requestEventId, requestEventId));
        if (stopped()) return unavailable();
        if (!bound) { await failIntent({ ...intent, requestEventId: sdkRequest!.transactionId, transactionId: sdkRequest!.transactionId }, sdkRequest); unavailable(); }
        const active = await claimPersistedSas(bound!, sdkRequest! as VerificationWireRequest);
        if (!active) { await failIntent(bound!, sdkRequest); unavailable(); }
        if (cancelledDuringBinding || sdkRequest!.phase === VerificationPhase.Cancelled) {
          requestSasTerminal(active!);
          await cancelledSas(active!);
          return unavailable();
        }
        onRequest(sdkRequest!, () => { const callbackEpoch = epoch.value; if (sdkRequest!.phase === VerificationPhase.Cancelled) requestSasTerminal(active!); void queueSas(active!, async () => { if (callbackEpoch === epoch.value) await onRequestChange(active!); }); }); scheduleExpiry(active!); publishVerification();
      }),
      acceptSas: async request => {
        if (unavailableTransport()) return unavailable();
        const active = activeSas;
        if (!active) return unavailable();
        const accepted = await queueSas(active, async () => {
        if (active.consumed || active.publicationRoomEpoch !== request.roomEpoch || active.operation.direction !== 'incoming' || active.operation.phase !== 'requested' || active.operation.roomId !== request.roomId || active.operation.peerUserId !== request.peerUserId || !await exactCurrentIdentity(request) || unavailableTransport() || active.terminalRequested || activeSas !== active) return false;
        active.consumed = true;
        // Persist consent first: accept() may synchronously emit Ready.
        const next = await dependencies.store.advanceSasPhase({ profileId: session.profileId }, active.operation.generation, 'accepted'); if (!next || unavailableTransport() || active.terminalRequested || activeSas !== active) { void failSas(active); return false; } active.operation = next;
        return true;
        });
        if (!accepted) return unavailable();
        try { await active.request.accept(); } catch { await failSas(active); return unavailable(); }
        await queueSas(active, async () => { if (activeSas === active) { active.consumed = false; if (!active.terminalRequested) publishVerification(); } });
      },
      confirmSas: async request => {
        if (unavailableTransport()) return unavailable();
        const active = activeSas;
        if (!active) return unavailable();
        const confirm = await queueSas(active, async () => {
        if (active.consumed || active.publicationRoomEpoch !== request.roomEpoch || !active.verifier || active.operation.roomId !== request.roomId || active.operation.peerUserId !== request.peerUserId) return unavailable();
        active.consumed = true;
        // Confirmation is intentionally unavailable until a start event has
        // been durably bound; this prevents callback-only completion.
        if (active.operation.phase !== 'sas-shown' || !active.callbacks || active.publicationRoomEpoch !== epoch.value || !await exactCurrentIdentity(request) || unavailableTransport() || active.terminalRequested || activeSas !== active) { void failSas(active); return unavailable(); }
        const callback = active.callbacks.confirm.bind(active.callbacks);
        try {
          const confirming = await dependencies.store.advanceSasPhase({ profileId: session.profileId }, active.operation.generation, 'confirming');
          if (!confirming || unavailableTransport() || active.terminalRequested || activeSas !== active) throw new Error('confirm-store');
          active.operation = confirming;
          active.callbacks = undefined; active.pendingCallbacks = undefined; active.sas = undefined;
          publishVerification();
          return callback;
        } catch { void failSas(active); return undefined; }
        });
        if (!confirm) return unavailable();
        try { await confirm(); } catch { await failSas(active); return unavailable(); }
        await queueSas(active, async () => { if (activeSas === active && !active.terminalRequested && !unavailableTransport()) { active.confirmFulfilled = true; await maybeComplete(active); } });
        // Completion callbacks are also serialized through the operation queue;
        // wait only after releasing this command's queue turn.
        try { await active.completion; } catch { await failSas(active); return unavailable(); }
      },
      mismatchSas: async request => { if (unavailableTransport()) return unavailable(); const active = activeSas; if (!active || request.roomEpoch !== epoch.value || active.publicationRoomEpoch !== request.roomEpoch || active.consumed || !active.callbacks || active.operation.roomId !== request.roomId || active.operation.peerUserId !== request.peerUserId) return unavailable(); const mismatch = active.callbacks.mismatch.bind(active.callbacks); requestSasTerminal(active); active.consumed = true; bestEffortSasEffect(mismatch); await cancelledSas(active); },
      cancelSas: async request => { if (unavailableTransport()) return unavailable(); const active = activeSas; if (!active || request.roomEpoch !== epoch.value || active.publicationRoomEpoch !== request.roomEpoch || active.consumed || active.operation.roomId !== request.roomId || active.operation.peerUserId !== request.peerUserId) return unavailable(); const cancel = active.callbacks?.cancel.bind(active.callbacks); requestSasTerminal(active); active.consumed = true; if (cancel) bestEffortSasEffect(cancel); bestEffortSasEffect(() => active.request.cancel()); await cancelledSas(active); },
    };
    return { ...operation, readiness, gateway };
  } };
}

/** OAuth operations use metadata established by explicit discovery, keyed by its immutable endpoints. */
export function createSdkOAuthPort(): MatrixOAuthPort {
  const metadataByEndpoint = new Map<string, ValidatedAuthMetadata>();
  const remember = (metadata: ValidatedAuthMetadata): ValidatedAuthMetadata => { for (const endpoint of [metadata.registration_endpoint, metadata.authorization_endpoint, metadata.token_endpoint, metadata.revocation_endpoint]) metadataByEndpoint.set(endpoint, metadata); return metadata; };
  const required = (endpoint: string): ValidatedAuthMetadata => { const metadata = metadataByEndpoint.get(endpoint); if (!metadata) throw new Error('oauth_metadata_not_discovered'); return metadata; };
  const flow = (endpoint: string, clientId: string, redirectUri: string, codeVerifier?: string, deviceId?: string): OAuth2 => new OAuth2(required(endpoint), { clientId, redirectUri, ...(codeVerifier === undefined ? {} : { codeVerifier }), ...(deviceId === undefined ? {} : { deviceId }) });
  return { discoverAuthMetadata: async homeserver => remember(await createClient({ baseUrl: homeserver, disableVoip: true, logger: silentLogger }).getAuthMetadata()), registerClient: (endpoint, request) => OAuth2.registerClient(required(endpoint), { ...request, redirect_uris: [...request.redirect_uris], grant_types: [...request.grant_types] as [string, ...string[]], response_types: [...request.response_types] as [string, ...string[]] }), authorizationUrl: request => flow(request.authorizationEndpoint, request.clientId, request.redirectUri, request.codeVerifier, request.deviceId).generateAuthorizationCodeGrantUrl(request.state, request.responseMode, undefined, request.scope), exchange: request => flow(request.tokenEndpoint, request.clientId, request.redirectUri, request.codeVerifier).completeAuthorizationCodeGrant(request.code), whoami: (homeserver, accessToken) => createClient({ baseUrl: homeserver, accessToken, disableVoip: true, logger: silentLogger }).whoami(), revoke: (endpoint, token, clientId, hint) => flow(endpoint, clientId, 'https://chat.localhost:8443/').revokeToken(token, hint), refresh: (session, token) => refreshSdkOAuth(session, token, required(session.metadata.tokenEndpoint)) };
}

export async function refreshSdkOAuth(session: MatrixSession, refreshToken: string, metadata?: ValidatedAuthMetadata): Promise<unknown> {
  if (!metadata) throw new Error('oauth_metadata_not_discovered');
  try { return await new OAuth2(metadata, { clientId: session.clientId, redirectUri: session.redirectUri }).performRefreshTokenGrant(refreshToken); } catch (error) { if (typeof error === 'object' && error !== null && 'httpStatus' in error && typeof error.httpStatus === 'number' && error.httpStatus >= 400 && error.httpStatus < 500) throw new Error('invalid_grant'); throw error; }
}
