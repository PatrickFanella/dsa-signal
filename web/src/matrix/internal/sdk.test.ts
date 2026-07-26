import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const sdk = vi.hoisted(() => {
  const clients: unknown[] = [];
  const oauth = { register: vi.fn(), refresh: vi.fn(async () => ({ access_token: 'a' })), instances: [] as { metadata: unknown; options: unknown }[] };
  class OAuth2 {
    public constructor(metadata: unknown, options: unknown) { oauth.instances.push({ metadata, options }); }
    public static registerClient = oauth.register;
    public generateAuthorizationCodeGrantUrl = vi.fn(() => 'https://auth.localhost:8443/authorize');
    public completeAuthorizationCodeGrant = vi.fn(async () => ({ access_token: 'a' }));
    public revokeToken = vi.fn(async () => undefined);
    public performRefreshTokenGrant = oauth.refresh;
  }
  return { clients, oauth, createClient: vi.fn((options: unknown): unknown => { const client = { options }; clients.push(client); return client; }), OAuth2 };
});
vi.mock('matrix-js-sdk', () => ({
  createClient: sdk.createClient, OAuth2: sdk.OAuth2,
  ClientEvent: { Sync: 'sync' }, HttpApiEvent: { SessionLoggedOut: 'logout' }, MatrixEventEvent: { Decrypted: 'decrypted' }, RoomEvent: { Timeline: 'timeline', LocalEchoUpdated: 'localEcho' }, RoomStateEvent: { Events: 'room' }, RoomMemberEvent: { Membership: 'member' }, SyncState: { Stopped: 'STOPPED', Syncing: 'SYNCING' }, VerificationPhase: { Ready: 3, Started: 4, Cancelled: 5, Done: 6 }, VerificationRequestEvent: { Change: 'change' }, VerifierEvent: { Cancel: 'cancel', ShowSas: 'show_sas' },
}));
vi.mock('matrix-js-sdk/lib/crypto-api', () => ({ CryptoEvent: { VerificationRequestReceived: 'verification', KeysChanged: 'keys', UserTrustStatusChanged: 'trust', DevicesUpdated: 'devices' }, CrossSigningKey: { Master: 'master_key', SelfSigning: 'self_signing_key', UserSigning: 'user_signing_key' }, OnlySignedDevicesIsolationMode: class OnlySignedDevicesIsolationMode {} }));
vi.mock('matrix-js-sdk/lib/crypto-api/verification', () => ({ VerificationPhase: { Ready: 3, Started: 4, Cancelled: 5, Done: 6 }, VerificationRequestEvent: { Change: 'change' }, VerifierEvent: { Cancel: 'cancel', ShowSas: 'show_sas' } }));

import { canonicalJsonForTest, createSdkBootstrapPort, createSdkOAuthPort, deriveSasStableGrantBindingForTest, refreshSdkOAuth, verifyAuthoritativeRawChain, verifySignedPayloadForTest } from './sdk';
import type { MatrixSession } from '../../auth/session-store';
import { createTokenRefreshCoordinator } from '../../auth/matrix-oauth';
import { MATRIX_AUTHORIZATION_ENDPOINT, MATRIX_HOMESERVER, MATRIX_ISSUER, MATRIX_REDIRECT_URI, MATRIX_REGISTRATION_ENDPOINT, MATRIX_REVOCATION_ENDPOINT, MATRIX_TOKEN_ENDPOINT } from '../../auth/matrix-topology';
import { canonicalProfileId } from '../../auth/canonical-profile';
import { CryptoOwnerCoordinator, type CryptoBroadcastChannel, type WebLockManager } from '../../crypto/crypto-owner';

const metadata = { registration_endpoint: 'register', authorization_endpoint: 'authorize', token_endpoint: 'token', revocation_endpoint: 'revoke' } as unknown as import('matrix-js-sdk').ValidatedAuthMetadata;
const session = { profileId: 'p', generation: 1, homeserver: 'https://matrix.localhost:8443', userId: '@me:test', deviceId: 'd'.repeat(43), accessToken: 'secret', clientId: 'client', redirectUri: 'https://chat.localhost:8443/', metadata: {}, issuer: 'https://auth.localhost:8443/', expiresAt: 1 } as MatrixSession;
const fingerprint = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const events = [
  { getType: () => 'm.room.join_rules', getStateKey: () => '', getContent: () => ({ join_rule: 'invite' }) },
  { getType: () => 'm.room.encryption', getStateKey: () => '', getContent: () => ({ algorithm: 'm.megolm.v1.aes-sha2' }) },
  { getType: () => 'm.room.history_visibility', getStateKey: () => '', getContent: () => ({ history_visibility: 'joined' }) },
];
const room = (membership = 'join', targets = [{ userId: '@me:test', membership: 'join' }]) => ({ roomId: '!r:test', getMyMembership: () => membership, currentState: { getStateEvents: (type: string) => events.filter(event => event.getType() === type) }, getEncryptionTargetMembers: async () => targets });
const deterministicRoomClock = (): { now(): number; sleep(milliseconds: number): Promise<void> } => { let now = 0; return { now: () => now, sleep: async milliseconds => { now += milliseconds; } }; };
/** All adapter fixtures use an active-session-bound, already-published record. */
const strictStore = () => ({ getBootstrapDisposition: async (locator: { profileId: string }) => { expect(locator).toEqual({ profileId: session.profileId }); return { profileId: session.profileId, state: 'published' as const, generation: 1 }; }, compareAndSetBootstrapDisposition: async () => { throw new Error('published fixture must not mutate'); }, rebaseUnresolvedOutbox: async () => 0, listUnresolvedTextOutboxRecords: async () => [], getSyncGeneration: async () => ({ profileId: session.profileId, syncGeneration: 0 }), incrementSyncGeneration: async () => ({ profileId: session.profileId, syncGeneration: 1 }), getTextOutboxRecord: async () => undefined, createTextOutboxRecord: async () => true, consumeOutboxRetry: async () => undefined, markOutboxIndeterminate: async () => undefined, recordOutboxAcceptance: async () => ({ kind: 'missing' as const }), reconcileOutboxRemoteEcho: async () => ({ kind: 'missing' as const }) });
const outboxMethods = () => { const { getBootstrapDisposition: ignored, compareAndSetBootstrapDisposition: ignoredCas, ...methods } = strictStore(); void ignored; void ignoredCas; return methods; };
const publicKeys = (signature = 'signature') => ({
  master_key: { user_id: session.userId, usage: ['master'], keys: { [`ed25519:${fingerprint}`]: fingerprint }, signatures: { [session.userId]: { [`ed25519:${session.deviceId}`]: 'signature' } } },
  self_signing_key: { user_id: session.userId, usage: ['self_signing'], keys: { [`ed25519:${fingerprint}`]: fingerprint }, signatures: { [session.userId]: { [`ed25519:${fingerprint}`]: signature } } },
  user_signing_key: { user_id: session.userId, usage: ['user_signing'], keys: { [`ed25519:${fingerprint}`]: fingerprint }, signatures: { [session.userId]: { [`ed25519:${fingerprint}`]: signature } } },
});
/** Rust's cached Device uses a Map; only /keys/query fixtures use wire objects. */
const cachedDeviceKeys = (id: string, ed25519 = fingerprint, curve25519 = fingerprint) => new Map([[`ed25519:${id}`, ed25519], [`curve25519:${id}`, curve25519]]);
const currentDevice = (signature = 'signature') => ({ deviceId: session.deviceId, keys: cachedDeviceKeys(session.deviceId), signatures: { [session.userId]: { 'ed25519:self': signature } } });
/** Exact v42 wire proofs; no SDK-derived identity objects are used for bootstrap. */
const deviceAlgorithms = ['m.olm.v1.curve25519-aes-sha2', 'm.megolm.v1.aes-sha2'];
/** Matrix SDK v42 does not root-export OwnDeviceKeys; assert its documented structural result. */
const ownDeviceKeys = { ed25519: fingerprint, curve25519: fingerprint } satisfies { ed25519: string; curve25519: string };
const firstDeviceResponse = () => ({ failures: {}, device_keys: { [session.userId]: { [session.deviceId]: { user_id: session.userId, device_id: session.deviceId, algorithms: deviceAlgorithms, keys: { [`ed25519:${session.deviceId}`]: fingerprint, [`curve25519:${session.deviceId}`]: fingerprint }, signatures: { [session.userId]: { [`ed25519:${session.deviceId}`]: 'own' } } } } } });
const publishedResponse = () => {
  const keys = publicKeys();
  return { failures: {}, master_keys: { [session.userId]: keys.master_key }, self_signing_keys: { [session.userId]: keys.self_signing_key }, user_signing_keys: { [session.userId]: keys.user_signing_key }, device_keys: { [session.userId]: { [session.deviceId]: { user_id: session.userId, device_id: session.deviceId, algorithms: deviceAlgorithms, keys: { [`ed25519:${session.deviceId}`]: fingerprint, [`curve25519:${session.deviceId}`]: fingerprint }, signatures: { [session.userId]: { [`ed25519:${session.deviceId}`]: 'own', [`ed25519:${fingerprint}`]: 'self' } } } } } };
};
const ssss = (state: 'none' | 'partial' | 'complete') => ({ isStored: async (name: string) => state === 'none' ? null : state === 'complete' || name === 'm.cross_signing.master' ? {} : null });
const validCrypto = (overrides: Record<string, unknown> = {}) => ({ getDeviceVerificationStatus: async () => ({ signedByOwner: true, crossSigningVerified: true, isVerified: () => true }), getUserVerificationStatus: async () => ({ known: true, needsUserApproval: false, isCrossSigningVerified: () => true }), getCrossSigningKeyId: async () => fingerprint, getCrossSigningStatus: async () => ({ publicKeysOnDevice: true, privateKeysCachedLocally: { masterKey: true, selfSigningKey: true, userSigningKey: true }, privateKeysInSecretStorage: false }), getOwnDeviceKeys: async () => ownDeviceKeys, getUserCrossSigningKeys: async () => publicKeys(), getUserDeviceInfo: async () => new Map([[session.userId, new Map([[session.deviceId, currentDevice()]])]]), setDeviceIsolationMode: () => {}, isEncryptionEnabledInRoom: async () => true, ...overrides });
type AdapterFixture = Awaited<ReturnType<typeof startAdapterFixture>>;
const startAdapterFixture = async (overrides: Partial<{ create: () => Promise<unknown>; join: () => Promise<unknown>; preRoom: unknown; postRoom: unknown; getRoom: (id: string) => unknown; devices: unknown; postStatus: () => Promise<unknown>; encryption: boolean; store: unknown; crypto: Record<string, unknown>; download: (users: string[]) => Promise<unknown>; timeline: unknown[]; sasScheduler: { setTimeout(callback: () => void, milliseconds: number): unknown; clearTimeout(handle: unknown): void } }> = {}) => {
  const listeners = new Map<string, Set<(...values: never[]) => void>>(); const on = (event: string, listener: (...values: never[]) => void): void => { const set = listeners.get(event) ?? new Set(); set.add(listener); listeners.set(event, set); };
  let fixtureEpoch = 0; let terminalIngress = false;
  const suppliedStore = (overrides.store ?? strictStore()) as Record<string, unknown>;
  const advanceSasPhase = suppliedStore.advanceSasPhase as ((...values: never[]) => Promise<unknown>) | undefined;
  // Mirror verificationChanged(): commands advance at ingress, while SDK and
  // verifier terminal paths advance when their durable transition succeeds.
  // This never changes an identity supplied explicitly by a race test.
  const store = advanceSasPhase === undefined ? suppliedStore : new Proxy(suppliedStore, {
    get(target, property, receiver) {
      if (property !== 'advanceSasPhase') return Reflect.get(target, property, receiver);
      return async (...values: never[]) => {
        const current = Reflect.get(target, 'advanceSasPhase', receiver) as (...args: never[]) => Promise<unknown>;
        const result = await current(...values);
        if (result && ['done', 'failed', 'cancelled'].includes(values[2] as string) && !terminalIngress) fixtureEpoch += 1;
        return result;
      };
    },
  });
  const emit = (event: string, ...values: never[]): void => { if (['room', 'member', 'trust', 'keys', 'devices'].includes(event)) fixtureEpoch += 1; for (const listener of listeners.get(event) ?? []) listener(...values); };
  const exact = (membership = 'join', id = '!r:test', targets = [{ userId: '@me:test', membership: 'join' }]) => ({ roomId: id, getMyMembership: () => membership, currentState: { getStateEvents: (type: string) => events.filter(value => value.getType() === type) }, getEncryptionTargetMembers: async () => targets });
  const hasPreRoom = 'preRoom' in overrides; let preRoom: unknown = hasPreRoom ? overrides.preRoom : exact('invite'); let postRoom: unknown = 'postRoom' in overrides ? overrides.postRoom : exact(); let joined = false;
  const trusted = async () => ({ signedByOwner: true, crossSigningVerified: true, isVerified: () => true }); let booted = false; let postStatusChecks = 0;
  const crypto = validCrypto({ getDeviceVerificationStatus: async (_userId: string, deviceId: string) => booted && overrides.postStatus !== undefined && postStatusChecks++ > 0 ? overrides.postStatus() : deviceId === session.deviceId ? trusted() : (overrides.postStatus ?? trusted)(), getUserDeviceInfo: async () => booted && overrides.devices !== undefined ? overrides.devices : new Map([[session.userId, new Map([[session.deviceId, currentDevice()]])]]), isEncryptionEnabledInRoom: async () => 'encryption' in overrides ? overrides.encryption : true, ...overrides.crypto });
  const join = overrides.join ?? (async () => ({ roomId: '!r:test' })); const raw = { on, initRustCrypto: async () => {}, getCrypto: () => crypto, downloadKeysForUsers: async (users: string[]) => 'download' in overrides ? overrides.download!(users) : publishedResponse(), startClient: () => {}, stopClient: async () => {}, createRoom: vi.fn(overrides.create ?? (async () => ({ room_id: '!r:test' }))), joinRoom: vi.fn(async () => { const result = await join(); joined = true; return result; }), getRoom: (id: string) => 'getRoom' in overrides ? overrides.getRoom!(id) : (hasPreRoom && !joined ? preRoom : postRoom), getRooms: () => [postRoom] };
  const controller = new AbortController(); sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: store as never, roomClock: deterministicRoomClock(), ...(overrides.sasScheduler === undefined ? {} : { sasScheduler: overrides.sasScheduler }), verifyRawChain: async () => true }).begin(session, controller.signal);
  // Recovery consumes raw wire history during readiness, so index it before sync.
  for (const event of overrides.timeline ?? []) emit('timeline', event as never);
  await vi.waitFor(() => expect(listeners.get('sync')).toBeDefined()); emit('sync', 'PREPARED' as never); await operation.readiness; booted = true;
  // Older fixture calls intentionally exercise the adapter through a current
  // identity.  Production callers cannot use this convenience wrapper.
  const gateway = operation.gateway!;
  const currentIdentity = (identity: unknown) => typeof identity === 'string' ? { roomId: identity as never, peerUserId: '@peer:test' as never, roomEpoch: fixtureEpoch } : identity;
  const fixtureGateway = {
    ...gateway,
    subscribeTimeline: (identity: unknown, listener: never) => gateway.subscribeTimeline(currentIdentity(identity) as never, listener),
    subscribeVerification: (identity: unknown, listener: never) => gateway.subscribeVerification(currentIdentity(identity) as never, listener),
    sendDirectText: (request: Record<string, unknown>) => gateway.sendDirectText({ roomEpoch: fixtureEpoch, ...request } as never),
    initiateSas: (request: Record<string, unknown>) => gateway.initiateSas({ roomEpoch: fixtureEpoch, ...request } as never),
    acceptSas: (request: Record<string, unknown>) => gateway.acceptSas({ roomEpoch: fixtureEpoch, ...request } as never),
    confirmSas: async (request: Record<string, unknown>) => await gateway.confirmSas({ roomEpoch: fixtureEpoch, ...request } as never),
    mismatchSas: async (request: Record<string, unknown>) => { const captured = fixtureEpoch; terminalIngress = true; fixtureEpoch += 1; try { await gateway.mismatchSas({ roomEpoch: captured, ...request } as never); } finally { terminalIngress = false; } },
    cancelSas: async (request: Record<string, unknown>) => { const captured = fixtureEpoch; terminalIngress = true; fixtureEpoch += 1; try { await gateway.cancelSas({ roomEpoch: captured, ...request } as never); } finally { terminalIngress = false; } },
  };
  type LegacyFixtureGateway = import('../contract').MatrixGateway & {
    subscribeTimeline(identity: string, listener: import('../contract').TimelineListener): () => void;
    subscribeVerification(identity: string, listener: import('../contract').VerificationListener): () => void;
    sendDirectText(request: Omit<import('../contract').SendDirectTextRequest, 'roomEpoch'>): Promise<void>;
    initiateSas(request: Omit<import('../contract').VerificationRequest, 'roomEpoch'>): Promise<void>;
    acceptSas(request: Omit<import('../contract').VerificationRequest, 'roomEpoch'>): Promise<void>;
    confirmSas(request: Omit<import('../contract').VerificationRequest, 'roomEpoch'>): Promise<void>;
    mismatchSas(request: Omit<import('../contract').VerificationRequest, 'roomEpoch'>): Promise<void>;
    cancelSas(request: Omit<import('../contract').VerificationRequest, 'roomEpoch'>): Promise<void>;
  };
  return { raw, operation: { ...operation, gateway: fixtureGateway as unknown as LegacyFixtureGateway }, abort: () => controller.abort(), get roomEpoch() { return fixtureEpoch; }, exact, emit, setPre: (value: unknown) => { preRoom = value; }, setPost: (value: unknown) => { postRoom = value; } };
};

describe('Matrix SDK adapter', () => {
  beforeEach(() => { vi.clearAllMocks(); sdk.clients.length = 0; sdk.oauth.instances.length = 0; Object.defineProperty(Object.prototype, 'secretStorage', { configurable: true, value: ssss('none') }); });
  afterEach(() => { delete (Object.prototype as { secretStorage?: unknown }).secretStorage; });
  it('fails bootstrap immediately before start when recovered outbox exceeds its exact cap', async () => {
    const listeners = new Map<string, (...values: never[]) => void>(); const order: string[] = []; const startClient = vi.fn();
    const raw = { on: (event: string, listener: (...values: never[]) => void) => listeners.set(event, listener), initRustCrypto: async () => {}, getCrypto: () => validCrypto(), downloadKeysForUsers: async () => publishedResponse(), startClient, stopClient: async () => { order.push('stop'); } };
    sdk.createClient.mockReturnValue(raw);
    const record = { profileId: session.profileId, transactionId: 'over-cap', roomId: '!r:test', bodyHash: 'a'.repeat(64), state: 'local-pending' as const, indeterminate: true, baselineGeneration: 0, requiredGeneration: 0, retryConsumed: false, generation: 1 };
    const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: { ...strictStore(), rebaseUnresolvedOutbox: async () => { order.push('rebase'); return 257; }, listUnresolvedTextOutboxRecords: async () => { order.push('list'); return Array.from({ length: 257 }, (_, index) => ({ ...record, transactionId: `over-cap-${index}` })); } } as never, verifyRawChain: async () => true }).begin(session, new AbortController().signal);
    await expect(operation.readiness).rejects.toThrow('bootstrap_blocked'); expect(order).toEqual(['rebase', 'list']); expect(startClient).not.toHaveBeenCalled();
  });
  it('admits only a valid incoming request through the owned verification wire boundary', async () => {
    const createIncomingSasOperation = vi.fn(async () => true);
    const members = [{ userId: session.userId, membership: 'join' }, { userId: '@peer:test', membership: 'join' }];
    const fixture = await startAdapterFixture({ postRoom: { ...room('join', members), getMembers: () => members }, store: { ...strictStore(), getSasOperation: async () => undefined, createIncomingSasOperation, bindSasRequest: async () => undefined, bindSasPeerDevice: async () => undefined, bindSasStartEvent: async () => undefined, advanceSasPhase: async () => undefined, disposeSasOperation: async () => undefined } });
    const event = (body: string) => ({ getType: () => 'm.room.message', getContent: () => ({ msgtype: 'm.key.verification.request', to: session.userId, from_device: 'PEER', methods: ['m.sas.v1'], body }), getSender: () => '@peer:test', getId: () => '$request', getTs: () => 0, getRoomId: () => '!r:test', getUnsigned: () => undefined });
    const request = (wire: unknown) => ({ initiatedByMe: false, isSelfVerification: false, roomId: '!r:test', otherUserId: '@peer:test', otherDeviceId: 'PEER', transactionId: '$request', requestEvent: wire, phase: 0, chosenMethod: null, verifier: undefined, accept: async () => undefined, cancel: vi.fn(async () => undefined), startVerification: async () => { throw new Error('not reached'); }, on: () => undefined });
    const malformed = request(event('forged'));
    fixture.emit('timeline', event('forged') as never);
    fixture.emit('verification', malformed as never);
    await vi.waitFor(() => expect(malformed.cancel).toHaveBeenCalledOnce());
    expect(createIncomingSasOperation).not.toHaveBeenCalled();
    const accepted = event('@peer:test is requesting to verify your key, but your client does not support in-chat key verification. You will need to use legacy key verification to verify keys.'); fixture.emit('timeline', accepted as never);
    fixture.emit('verification', request(accepted) as never);
    await vi.waitFor(() => expect(createIncomingSasOperation).toHaveBeenCalledOnce());
  });
  it('permanently poisons transport on self-authored plaintext and admits no later raw send', async () => {
    const members = [{ userId: session.userId, membership: 'join' }, { userId: '@peer:test', membership: 'join' }];
    const fixture = await startAdapterFixture({ postRoom: { ...room('join', members), getMembers: () => members } });
    const raw = fixture.raw as unknown as { sendMessage?: ReturnType<typeof vi.fn> };
    raw.sendMessage = vi.fn(async () => ({ event_id: '$must-not-send' }));
    const states: string[] = []; fixture.operation.gateway!.subscribeSecurityState(state => states.push(state));
    fixture.emit('timeline', { getType: () => 'm.room.message', getWireType: () => 'm.room.message', getContent: () => ({ msgtype: 'm.text', body: 'plaintext' }), getSender: () => session.userId, getId: () => '$plain', getRoomId: () => '!r:test', getTs: () => 0 } as never, { ...room('join', members), getMembers: () => members } as never);
    await vi.waitFor(() => expect(states).toContain('blocked'));
    await expect(fixture.operation.gateway!.sendDirectText({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never, body: 'blocked', transactionId: 't' as never })).rejects.toThrow('unavailable');
    expect(raw.sendMessage).not.toHaveBeenCalled();
  });
  it('admits an exact self-to-peer plaintext verification request without a room callback', async () => {
    const members = [{ userId: session.userId, membership: 'join' }, { userId: '@peer:test', membership: 'join' }];
    const fixture = await startAdapterFixture({ postRoom: { ...room('join', members), getMembers: () => members } });
    const states: string[] = []; fixture.operation.gateway!.subscribeSecurityState(state => states.push(state));
    fixture.operation.gateway!.subscribeTimeline('!r:test' as never, () => undefined);
    fixture.emit('timeline', { getType: () => 'm.room.message', getWireType: () => 'm.room.message', getContent: () => ({ msgtype: 'm.key.verification.request', to: '@peer:test', from_device: session.deviceId, methods: ['m.sas.v1'], body: '@me:test is requesting to verify your key, but your client does not support in-chat key verification. You will need to use legacy key verification to verify keys.' }), getSender: () => session.userId, getId: () => '$outgoing-request', getRoomId: () => '!r:test', getTs: () => 0, getUnsigned: () => undefined } as never);
    await new Promise(resolve => setTimeout(resolve));
    expect(states).not.toContain('blocked');
  });
  it('cryptographically accepts a real canonical current-device chain despite a valid stale device and signature, and rejects tampering', async () => {
    const bytes = (value: ArrayBuffer): string => globalThis.btoa(String.fromCharCode(...new Uint8Array(value))).replace(/=+$/, '');
    const signing = async () => await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const [device, staleDevice, master, self, user] = await Promise.all([signing(), signing(), signing(), signing(), signing()]);
    const publicKey = async (key: CryptoKeyPair): Promise<string> => bytes(await globalThis.crypto.subtle.exportKey('raw', key.publicKey));
    const [deviceIdKey, staleDeviceIdKey, masterId, selfId, userId] = await Promise.all([publicKey(device), publicKey(staleDevice), publicKey(master), publicKey(self), publicKey(user)]);
    const sign = async (key: CryptoKeyPair, value: Record<string, unknown>): Promise<string> => {
      const payload = Object.fromEntries(Object.entries(value).filter(([name]) => name !== 'signatures' && name !== 'unsigned'));
      const canonical = (candidate: unknown): string => candidate === null || typeof candidate === 'string' || typeof candidate === 'boolean' || typeof candidate === 'number' ? JSON.stringify(candidate) : Array.isArray(candidate) ? `[${candidate.map(canonical).join(',')}]` : `{${Object.keys(candidate as Record<string, unknown>).sort().map(name => `${JSON.stringify(name)}:${canonical((candidate as Record<string, unknown>)[name])}`).join(',')}}`;
      return bytes(await globalThis.crypto.subtle.sign({ name: 'Ed25519' }, key.privateKey, new TextEncoder().encode(canonical(payload))));
    };
    const masterKey: Record<string, unknown> = { user_id: session.userId, usage: ['master'], keys: { [`ed25519:${masterId}`]: masterId }, signatures: {} };
    const selfKey: Record<string, unknown> = { user_id: session.userId, usage: ['self_signing'], keys: { [`ed25519:${selfId}`]: selfId }, signatures: {} };
    const userKey: Record<string, unknown> = { user_id: session.userId, usage: ['user_signing'], keys: { [`ed25519:${userId}`]: userId }, signatures: {} };
    const curve = bytes(globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer);
    const deviceKey: Record<string, unknown> = { user_id: session.userId, device_id: session.deviceId, algorithms: deviceAlgorithms, keys: { [`ed25519:${session.deviceId}`]: deviceIdKey, [`curve25519:${session.deviceId}`]: curve }, signatures: {} };
    masterKey.signatures = { [session.userId]: { [`ed25519:${session.deviceId}`]: await sign(device, masterKey) } }; selfKey.signatures = { [session.userId]: { [`ed25519:${masterId}`]: await sign(master, selfKey) } }; userKey.signatures = { [session.userId]: { [`ed25519:${masterId}`]: await sign(master, userKey) } }; deviceKey.signatures = { [session.userId]: { [`ed25519:${session.deviceId}`]: await sign(device, deviceKey), [`ed25519:${selfId}`]: await sign(self, deviceKey) } };
    const result = { failures: {}, master_keys: { [session.userId]: masterKey }, self_signing_keys: { [session.userId]: selfKey }, user_signing_keys: { [session.userId]: userKey }, device_keys: { [session.userId]: { [session.deviceId]: deviceKey } } };
    await expect(verifyAuthoritativeRawChain(result as never, session)).resolves.toBe(true);
    const staleId = 'stale'; const staleKey = bytes(globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer);
    const stale = { user_id: session.userId, device_id: staleId, algorithms: deviceAlgorithms, keys: { [`ed25519:${staleId}`]: staleDeviceIdKey, [`curve25519:${staleId}`]: staleKey }, signatures: {} as Record<string, unknown> };
    stale.signatures = { [session.userId]: { [`ed25519:${staleId}`]: await sign(staleDevice, stale), [`ed25519:${selfId}`]: await sign(self, stale) } };
    (masterKey.signatures as Record<string, Record<string, string>>)[session.userId]![`ed25519:${staleId}`] = await sign(staleDevice, masterKey);
    result.device_keys[session.userId][staleId] = stale;
    await expect(verifyAuthoritativeRawChain(result as never, session)).resolves.toBe(true);
    // The valid stale proof is deliberately not an authority for this session.
    (masterKey.signatures as Record<string, Record<string, string>>)[session.userId]![`ed25519:${staleId}`] = bytes(globalThis.crypto.getRandomValues(new Uint8Array(64)).buffer);
    await expect(verifyAuthoritativeRawChain(result as never, session)).resolves.toBe(true);
    const corrupt = async (container: Record<string, string>, name: string): Promise<void> => { const original = container[name]!; container[name] = bytes(globalThis.crypto.getRandomValues(new Uint8Array(64)).buffer); await expect(verifyAuthoritativeRawChain(result as never, session)).resolves.toBe(false); container[name] = original; };
    await corrupt((masterKey.signatures as Record<string, Record<string, string>>)[session.userId]!, `ed25519:${session.deviceId}`);
    await corrupt((selfKey.signatures as Record<string, Record<string, string>>)[session.userId]!, `ed25519:${masterId}`);
    await corrupt((userKey.signatures as Record<string, Record<string, string>>)[session.userId]!, `ed25519:${masterId}`);
    await corrupt((deviceKey.signatures as Record<string, Record<string, string>>)[session.userId]!, `ed25519:${selfId}`);
    await corrupt((deviceKey.signatures as Record<string, Record<string, string>>)[session.userId]!, `ed25519:${session.deviceId}`);
    (deviceKey.keys as Record<string, string>)[`curve25519:${session.deviceId}`] = 'tampered';
    await expect(verifyAuthoritativeRawChain(result as never, session)).resolves.toBe(false);
    (deviceKey.keys as Record<string, string>)[`curve25519:${session.deviceId}`] = curve;
    for (const malformed of [`${deviceIdKey}=`, ` ${deviceIdKey}`, `${deviceIdKey.slice(0, -1)}B`]) { (masterKey.keys as Record<string, string>)[`ed25519:${masterId}`] = malformed; await expect(verifyAuthoritativeRawChain(result as never, session)).resolves.toBe(false); }
  });
  it('derives an exact frozen, non-authoritative two-user stable binding from signed snapshots', async () => {
    const bytes = (value: ArrayBuffer): string => globalThis.btoa(String.fromCharCode(...new Uint8Array(value))).replace(/=+$/, '');
    const signing = async () => await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const [localDeviceKey, peerDeviceKey, localMasterKey, localSelfKey, localUserKey, peerMasterKey, peerSelfKey] = await Promise.all(Array.from({ length: 7 }, signing));
    const id = async (key: CryptoKeyPair): Promise<string> => bytes(await globalThis.crypto.subtle.exportKey('raw', key.publicKey));
    const [localDevice, peerDevice, localMaster, localSelf, localUser, peerMaster, peerSelf] = await Promise.all([localDeviceKey, peerDeviceKey, localMasterKey, localSelfKey, localUserKey, peerMasterKey, peerSelfKey].map(id));
    const peer = '@peer:test'; const peerId = 'PEER';
    const sign = async (key: CryptoKeyPair, value: Record<string, unknown>): Promise<string> => bytes(await globalThis.crypto.subtle.sign({ name: 'Ed25519' }, key.privateKey, new TextEncoder().encode(canonicalJsonForTest(Object.fromEntries(Object.entries(value).filter(([name]) => name !== 'signatures' && name !== 'unsigned'))))));
    const cross = (user: string, usage: string, value: string): Record<string, unknown> => ({ user_id: user, usage: [usage], keys: { [`ed25519:${value}`]: value }, signatures: {} });
    const lm = cross(session.userId, 'master', localMaster); const ls = cross(session.userId, 'self_signing', localSelf); const lu = cross(session.userId, 'user_signing', localUser); const pm = cross(peer, 'master', peerMaster); const ps = cross(peer, 'self_signing', peerSelf);
    const device = (user: string, deviceId: string, ed: string): Record<string, unknown> => ({ user_id: user, device_id: deviceId, algorithms: deviceAlgorithms, keys: { [`ed25519:${deviceId}`]: ed, [`curve25519:${deviceId}`]: bytes(globalThis.crypto.getRandomValues(new Uint8Array(32)).buffer) }, signatures: {} });
    const ld = device(session.userId, session.deviceId, localDevice); const pd = device(peer, peerId, peerDevice);
    lm.signatures = { [session.userId]: { [`ed25519:${session.deviceId}`]: await sign(localDeviceKey, lm) } }; ls.signatures = { [session.userId]: { [`ed25519:${localMaster}`]: await sign(localMasterKey, ls) } }; lu.signatures = { [session.userId]: { [`ed25519:${localMaster}`]: await sign(localMasterKey, lu) } }; pm.signatures = { [peer]: { [`ed25519:${peerId}`]: await sign(peerDeviceKey, pm) }, [session.userId]: { [`ed25519:${localUser}`]: await sign(localUserKey, pm) } }; ps.signatures = { [peer]: { [`ed25519:${peerMaster}`]: await sign(peerMasterKey, ps) } };
    ld.signatures = { [session.userId]: { [`ed25519:${session.deviceId}`]: await sign(localDeviceKey, ld), [`ed25519:${localSelf}`]: await sign(localSelfKey, ld) } }; pd.signatures = { [peer]: { [`ed25519:${peerId}`]: await sign(peerDeviceKey, pd), [`ed25519:${peerSelf}`]: await sign(peerSelfKey, pd) } };
    const raw = { failures: {}, device_keys: { [session.userId]: { [session.deviceId]: ld }, [peer]: { [peerId]: pd } }, master_keys: { [session.userId]: lm, [peer]: pm }, self_signing_keys: { [session.userId]: ls, [peer]: ps }, user_signing_keys: { [session.userId]: lu } };
    const rustDevices = new Map([[session.userId, new Map([[session.deviceId, { deviceId: session.deviceId, keys: new Map(Object.entries(ld.keys as Record<string, string>)), signatures: ld.signatures }]])], [peer, new Map([[peerId, { deviceId: peerId, keys: new Map(Object.entries(pd.keys as Record<string, string>)), signatures: pd.signatures }]])]]);
    const rustKeys = new Map([[session.userId, { master_key: lm, self_signing_key: ls, user_signing_key: lu }], [peer, { master_key: pm, self_signing_key: ps }]]);
    const input = { roomId: '!room:test', peerUserId: peer, peerDeviceId: peerId, raw, rustDevices, rustCrossSigningKeys: rustKeys };
    const profileId = await canonicalProfileId({ homeserver: session.homeserver, userId: session.userId, deviceId: session.deviceId });
    const binding = await deriveSasStableGrantBindingForTest({ ...session, profileId }, input as never);
    expect(binding).toEqual({ schemaVersion: 1, profileId, sessionGeneration: 1, homeserver: session.homeserver, localUserId: session.userId, localDeviceId: session.deviceId, roomId: '!room:test', peerUserId: peer, peerDeviceId: peerId, localEd25519: localDevice, localCurve25519: (ld.keys as Record<string, string>)[`curve25519:${session.deviceId}`], peerEd25519: peerDevice, peerCurve25519: (pd.keys as Record<string, string>)[`curve25519:${peerId}`], localMasterRef: localMaster, peerMasterRef: peerMaster });
    expect(Object.isFrozen(binding)).toBe(true); expect(Object.keys(binding ?? {}).sort()).toEqual(['homeserver', 'localCurve25519', 'localDeviceId', 'localEd25519', 'localMasterRef', 'localUserId', 'peerCurve25519', 'peerDeviceId', 'peerEd25519', 'peerMasterRef', 'peerUserId', 'profileId', 'roomId', 'schemaVersion', 'sessionGeneration']);
    const failed = { ...raw, failures: { x: {} } };
    await expect(deriveSasStableGrantBindingForTest({ ...session, profileId }, { ...input, raw: failed } as never)).resolves.toBeUndefined();
    const padded = structuredClone(raw); (padded.master_keys[session.userId].keys as Record<string, string>)[`ed25519:${localMaster}`] += '=';
    await expect(deriveSasStableGrantBindingForTest({ ...session, profileId }, { ...input, raw: padded } as never)).resolves.toBeUndefined();
    const extraRust = new Map(rustDevices); extraRust.set('@extra:test', new Map());
    await expect(deriveSasStableGrantBindingForTest({ ...session, profileId }, { ...input, rustDevices: extraRust } as never)).resolves.toBeUndefined();
    // Keep every mutation isolated so signature-envelope failures reach their
    // own guard rather than a previous malformed fixture.
    type MutableRaw = { master_keys: Record<string, { signatures: Record<string, Record<string, string>>; keys: Record<string, string> }>; device_keys: Record<string, Record<string, { signatures: Record<string, Record<string, string>> }>>; user_signing_keys: Record<string, unknown> };
    const reject = async (change: (candidate: { raw: MutableRaw }) => void): Promise<void> => { const candidate = { raw: structuredClone(raw) as unknown as MutableRaw }; change(candidate); await expect(deriveSasStableGrantBindingForTest({ ...session, profileId }, { ...input, ...candidate } as never)).resolves.toBeUndefined(); };
    await reject(candidate => { delete candidate.raw.master_keys[peer].signatures[peer]; });
    await reject(candidate => { candidate.raw.master_keys[peer].signatures[peer]['ed25519:wrong'] = candidate.raw.master_keys[peer].signatures[peer][`ed25519:${peerId}`]; delete candidate.raw.master_keys[peer].signatures[peer][`ed25519:${peerId}`]; });
    await reject(candidate => { candidate.raw.master_keys[peer].signatures['@extra:test'] = {}; });
    await reject(candidate => { candidate.raw.device_keys[peer][peerId].signatures[peer]['ed25519:extra'] = 'extra'; });
    await reject(candidate => { candidate.raw.user_signing_keys[peer] = structuredClone(candidate.raw.user_signing_keys[session.userId]); });
    await reject(candidate => { candidate.raw.device_keys[peer]!['EXTRA'] = structuredClone(candidate.raw.device_keys[peer]![peerId]); });
    await reject(candidate => { candidate.raw.master_keys[peer].keys[`ed25519:${peerMaster}`] = `${peerMaster}=`; });
    const rustSignatureMismatch = new Map(rustDevices); const peerSnapshots = new Map(rustSignatureMismatch.get(peer)!); peerSnapshots.set(peerId, Object.assign({}, peerSnapshots.get(peerId) as object, { signatures: {} }) as never); rustSignatureMismatch.set(peer, peerSnapshots);
    await expect(deriveSasStableGrantBindingForTest({ ...session, profileId }, { ...input, rustDevices: rustSignatureMismatch } as never)).resolves.toBeUndefined();
    const rustCrossMismatch = new Map(rustKeys); rustCrossMismatch.set(peer, Object.assign({}, rustCrossMismatch.get(peer) as object, { master_key: { ...pm, signatures: {} } }) as never);
    await expect(deriveSasStableGrantBindingForTest({ ...session, profileId }, { ...input, rustCrossSigningKeys: rustCrossMismatch } as never)).resolves.toBeUndefined();
    for (const invalid of [{ generation: 0 }, { generation: 1.5 }, { homeserver: 'https://wrong.localhost' }, { profileId: 'b'.repeat(64) }, { userId: '@bad:test' }, { deviceId: 'bad' }]) await expect(deriveSasStableGrantBindingForTest({ ...session, profileId, ...invalid }, input as never)).resolves.toBeUndefined();
    for (const invalid of [{ roomId: 'bad' }, { peerUserId: session.userId }, { peerUserId: 'bad' }, { peerDeviceId: 'bad' }]) await expect(deriveSasStableGrantBindingForTest({ ...session, profileId }, { ...input, ...invalid } as never)).resolves.toBeUndefined();
  });
  it('uses Matrix canonical JSON fixed Unicode, ordinary, and control vectors', () => {
    expect(canonicalJsonForTest({ z: [true, null, 'a\\b\n\u0000'], a: { 'Ω': '😀' } })).toBe('{"a":{"Ω":"😀"},"z":[true,null,"a\\\\b\\n\\u0000"]}');
    expect(canonicalJsonForTest({ unsigned: { remains: true }, signatures: { remains: true } })).toBe('{"signatures":{"remains":true},"unsigned":{"remains":true}}');
    expect(canonicalJsonForTest({ '😀': 1, '\ue000': 2, z: 3, A: 4, '\u0001': 5 })).toBe('{"\\u0001":5,"A":4,"z":3,"":2,"😀":1}');
    for (const value of [1.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, new Date(), Object.create(null), '\ud800', { '\udc00': 1 }]) expect(() => canonicalJsonForTest(value)).toThrow();
  });
  it('verifies literal canonical bytes through the production signing path', async () => {
    const pair = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const literal = '{"a":{"nested":"signed"},"z":1}';
    const signature = globalThis.btoa(String.fromCharCode(...new Uint8Array(await globalThis.crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, new TextEncoder().encode(literal))))).replace(/=+$/, '');
    const key = globalThis.btoa(String.fromCharCode(...new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', pair.publicKey)))).replace(/=+$/, '');
    const payload = { z: 1, a: { nested: 'signed' }, signatures: { ignored: true }, unsigned: { ignored: true } };
    await expect(verifySignedPayloadForTest(key, signature, payload)).resolves.toBe(true);
    await expect(verifySignedPayloadForTest(key, signature, { ...payload, signatures: { changed: true }, unsigned: { changed: true } })).resolves.toBe(true);
    await expect(verifySignedPayloadForTest(key, signature, { ...payload, a: { nested: 'changed' } })).resolves.toBe(false);
  });
  it('uses one discovered OAuth metadata object for string registration and all OAuth operations', async () => {
    const discovery = { getAuthMetadata: vi.fn(async () => metadata) }; sdk.createClient.mockReturnValueOnce(discovery); sdk.oauth.register.mockResolvedValue('client-id');
    const port = createSdkOAuthPort(); await expect(port.discoverAuthMetadata(session.homeserver)).resolves.toBe(metadata);
    await expect(port.registerClient('register', { application_type: 'web', client_name: 'DSA Signal', client_uri: session.redirectUri, redirect_uris: [session.redirectUri], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' })).resolves.toBe('client-id');
    await port.authorizationUrl({ authorizationEndpoint: 'authorize', clientId: 'client-id', redirectUri: session.redirectUri, state: 'state', codeVerifier: 'verifier', deviceId: 'device', codeChallenge: 'challenge', scope: 'scope', responseMode: 'fragment' });
    await port.exchange({ tokenEndpoint: 'token', clientId: 'client-id', redirectUri: session.redirectUri, codeVerifier: 'verifier', code: 'code' }); await port.revoke('revoke', 'refresh', 'client-id', 'refresh_token');
    expect(discovery.getAuthMetadata).toHaveBeenCalledOnce(); expect(sdk.oauth.register).toHaveBeenCalledWith(metadata, expect.any(Object)); expect(sdk.oauth.instances.every(instance => instance.metadata === metadata)).toBe(true);
    expect(sdk.oauth.instances[0].options).toMatchObject({ clientId: 'client-id', redirectUri: session.redirectUri, codeVerifier: 'verifier', deviceId: 'device' }); expect(sdk.oauth.instances.at(-1)?.options).toMatchObject({ clientId: 'client-id' });
  });
  it('requires explicit discovery and the exact discovered endpoint for refresh without rediscovering', async () => {
    const discovery = { getAuthMetadata: vi.fn(async () => metadata) }; sdk.createClient.mockReturnValue(discovery); const discoveredSession = { ...session, metadata: { ...session.metadata, tokenEndpoint: 'token' } };
    const port = createSdkOAuthPort();
    expect(() => port.refresh!(session, 'refresh')).toThrow('oauth_metadata_not_discovered');
    await port.discoverAuthMetadata(session.homeserver);
    expect(() => port.refresh!({ ...session, metadata: { ...session.metadata, tokenEndpoint: 'wrong' } }, 'refresh')).toThrow('oauth_metadata_not_discovered');
    await expect(port.refresh!(discoveredSession, 'refresh')).resolves.toEqual({ access_token: 'a' });
    expect(discovery.getAuthMetadata).toHaveBeenCalledOnce();
  });
  it('maps SDK-shaped 400 refresh failures to terminal invalid_grant but leaves transport/server failures', async () => {
    sdk.oauth.refresh.mockRejectedValueOnce({ httpStatus: 400 }).mockRejectedValueOnce({ httpStatus: 500 }).mockRejectedValueOnce(new Error('transport'));
    await expect(refreshSdkOAuth(session, 'r', metadata)).rejects.toThrow('invalid_grant'); await expect(refreshSdkOAuth(session, 'r', metadata)).rejects.toEqual({ httpStatus: 500 }); await expect(refreshSdkOAuth(session, 'r', metadata)).rejects.toThrow('transport'); expect(sdk.oauth.refresh).toHaveBeenCalledTimes(3);
  });
  it('runs a real OAuth refresh terminal shutdown through owner release before clearing its exact locator', async () => {
    const calls: string[] = []; const profileId = 'a'.repeat(64); const active = { profileId, generation: 1 };
    const endpointMetadata = { issuer: MATRIX_ISSUER, authorization_endpoint: MATRIX_AUTHORIZATION_ENDPOINT, token_endpoint: MATRIX_TOKEN_ENDPOINT, registration_endpoint: MATRIX_REGISTRATION_ENDPOINT, revocation_endpoint: MATRIX_REVOCATION_ENDPOINT, response_types_supported: ['code'], response_modes_supported: ['fragment'], grant_types_supported: ['authorization_code', 'refresh_token'], code_challenge_methods_supported: ['S256'] };
    const durableMetadata = { key: MATRIX_ISSUER, issuer: MATRIX_ISSUER, authorizationEndpoint: MATRIX_AUTHORIZATION_ENDPOINT, tokenEndpoint: MATRIX_TOKEN_ENDPOINT, registrationEndpoint: MATRIX_REGISTRATION_ENDPOINT, revocationEndpoint: MATRIX_REVOCATION_ENDPOINT, issuerParameterSupported: false };
    const durable = { ...session, ...active, homeserver: MATRIX_HOMESERVER, issuer: MATRIX_ISSUER, redirectUri: MATRIX_REDIRECT_URI, metadata: durableMetadata, refreshToken: 'refresh' };
    const locks: WebLockManager = { request: async <T>(_name: string, _options: { ifAvailable?: boolean; signal?: AbortSignal }, callback: (lock: unknown | null) => Promise<T> | T) => { await callback({}); calls.push('lockReleased'); return undefined as T; } };
    const channel: CryptoBroadcastChannel = { postMessage: () => {}, addEventListener: () => {}, removeEventListener: () => {}, close: () => {} };
    const owner = new CryptoOwnerCoordinator({ locks, createChannel: () => channel }); const handle = await owner.acquire({ profileId, stop: async () => { calls.push('stopClient'); } });
    const store = { getActiveProfile: async () => active, loadSession: async () => durable, clearSessionForLocator: async (value: typeof active) => { expect(value).toEqual(active); calls.push('clearRecords'); } };
    sdk.createClient.mockReturnValue({ getAuthMetadata: async () => endpointMetadata }); const port = createSdkOAuthPort(); await port.discoverAuthMetadata(MATRIX_HOMESERVER);
    sdk.oauth.refresh.mockImplementationOnce(async () => { calls.push('refresh400'); throw { httpStatus: 400 }; });
    const refresh = createTokenRefreshCoordinator({ store: store as never, locator: active, discoverAuthMetadata: port.discoverAuthMetadata, refresh: port.refresh!, terminalShutdown: () => handle.close() });
    await expect(refresh('refresh')).rejects.toThrow('reauthentication'); expect(calls).toEqual(['refresh400', 'stopClient', 'lockReleased', 'clearRecords']);
  });
  it('retains runtime authority and records when an SDK 400 terminal listener cannot stop', async () => {
    const calls: string[] = []; const profileId = 'b'.repeat(64); const active = { profileId, generation: 1 };
    const endpointMetadata = { issuer: MATRIX_ISSUER, authorization_endpoint: MATRIX_AUTHORIZATION_ENDPOINT, token_endpoint: MATRIX_TOKEN_ENDPOINT, registration_endpoint: MATRIX_REGISTRATION_ENDPOINT, revocation_endpoint: MATRIX_REVOCATION_ENDPOINT, response_types_supported: ['code'], response_modes_supported: ['fragment'], grant_types_supported: ['authorization_code', 'refresh_token'], code_challenge_methods_supported: ['S256'] };
    const durable = { ...session, ...active, homeserver: MATRIX_HOMESERVER, issuer: MATRIX_ISSUER, redirectUri: MATRIX_REDIRECT_URI, metadata: { key: MATRIX_ISSUER, issuer: MATRIX_ISSUER, authorizationEndpoint: MATRIX_AUTHORIZATION_ENDPOINT, tokenEndpoint: MATRIX_TOKEN_ENDPOINT, registrationEndpoint: MATRIX_REGISTRATION_ENDPOINT, revocationEndpoint: MATRIX_REVOCATION_ENDPOINT, issuerParameterSupported: false }, refreshToken: 'refresh' };
    const locks: WebLockManager = { request: async <T>(_name: string, _options: { ifAvailable?: boolean; signal?: AbortSignal }, callback: (lock: unknown | null) => Promise<T> | T) => { await callback({}); calls.push('lockReleased'); return undefined as T; } };
    const channel: CryptoBroadcastChannel = { postMessage: () => {}, addEventListener: () => {}, removeEventListener: () => {}, close: () => {} };
    const owner = new CryptoOwnerCoordinator({ locks, createChannel: () => channel }); const handle = await owner.acquire({ profileId, stop: async () => { calls.push('stopClient'); throw new Error('stop'); } });
    const store = { getActiveProfile: async () => active, loadSession: async () => durable, clearSessionForLocator: async () => { calls.push('clearRecords'); return true; } };
    sdk.createClient.mockReturnValue({ getAuthMetadata: async () => endpointMetadata }); const port = createSdkOAuthPort(); await port.discoverAuthMetadata(MATRIX_HOMESERVER);
    sdk.oauth.refresh.mockImplementationOnce(async () => { calls.push('refresh400'); throw { httpStatus: 400 }; });
    const runtimeTerminal = (): Promise<void> => handle.close();
    const refresh = createTokenRefreshCoordinator({ store: store as never, locator: active, discoverAuthMetadata: port.discoverAuthMetadata, refresh: port.refresh!, terminalShutdown: async () => { await runtimeTerminal!(); } });
    await expect(refresh('refresh')).rejects.toThrow('reauthentication'); expect(calls).toEqual(['refresh400', 'stopClient']);
    expect((await owner.acquire({ profileId, stop: async () => {} })).ownership).toBe('blocked');
  });
  it('installs exact listeners before persistent Rust OnlySigned bootstrap without legacy crypto or logging', async () => {
    const calls: string[] = []; const listeners = new Map<string, ((state: string) => void)[]>();
    const raw = new Proxy({ on: (event: string, listener: (state: string) => void) => { if (!event) throw new Error('undefined event'); calls.push(`on:${event}`); listeners.set(event, [...(listeners.get(event) ?? []), listener]); }, initRustCrypto: async (options: unknown) => { calls.push(`init:${JSON.stringify(options)}`); }, getCrypto: () => validCrypto({ setDeviceIsolationMode: () => { calls.push('isolation'); } }), downloadKeysForUsers: async () => publishedResponse(), startClient: () => calls.push('start'), stopClient: async () => calls.push('stop') }, { get(target, key) { if (key === 'initCrypto' || key === 'initLegacyCrypto') throw new Error('legacy'); return Reflect.get(target, key); } });
    sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: strictStore() as never, verifyRawChain: async () => true }).begin(session, new AbortController().signal); await vi.waitFor(() => expect(listeners.get('devices')).toHaveLength(1));
    expect(calls).toEqual(['on:timeline', 'on:localEcho', 'on:decrypted', 'on:verification', 'on:sync', 'on:sync', 'on:logout', 'on:room', 'on:member', 'on:keys', 'on:trust', 'on:devices', 'init:{"useIndexedDB":true,"cryptoDatabasePrefix":"dsa-signal:p"}', 'isolation', 'start']);
    for (const listener of listeners.get('sync') ?? []) listener('PREPARED'); await operation.readiness;
    expect(calls.indexOf('init:{"useIndexedDB":true,"cryptoDatabasePrefix":"dsa-signal:p"}')).toBeGreaterThan(calls.indexOf('on:devices'));
    const output = vi.spyOn(console, 'error'); const logger = sdk.createClient.mock.calls[0]?.[0] as { logger: { error(...values: unknown[]): void; getChild(name: string): unknown } }; logger.logger.error('canary-token'); expect(logger.logger.getChild('x')).toBe(logger.logger); expect(output).not.toHaveBeenCalled(); output.mockRestore();
  });
  it('reads the durable disposition before inspection and reuses a matching multi-device published identity from never-attempted without bootstrap', async () => {
    const calls: string[] = []; let sync: ((state: string) => void) | undefined;
    const crypto = validCrypto({ bootstrapCrossSigning: vi.fn(), setDeviceIsolationMode: () => calls.push('isolation') });
    const query = vi.fn(async () => { calls.push('query'); const response = publishedResponse(); const oldId = 'old-device'; response.device_keys[session.userId][oldId] = { user_id: session.userId, device_id: oldId, algorithms: deviceAlgorithms, keys: { [`ed25519:${oldId}`]: fingerprint, [`curve25519:${oldId}`]: fingerprint }, signatures: { [session.userId]: { [`ed25519:${oldId}`]: 'own', [`ed25519:${fingerprint}`]: 'self' } } }; return response; }); const raw = { on: (event: string, listener: (state: string) => void) => { if (event === 'sync') sync = listener; }, initRustCrypto: async () => {}, getCrypto: () => crypto, downloadKeysForUsers: query, startClient: () => calls.push('start'), stopClient: async () => {} };
    const disposition = { profileId: session.profileId, state: 'never-attempted' as const, generation: 2 }; const store = { ...outboxMethods(), getActiveProfile: async () => ({ profileId: session.profileId, generation: session.generation }), loadSession: async () => session, getBootstrapDisposition: async () => { calls.push('disposition'); return disposition; }, compareAndSetBootstrapDisposition: vi.fn() };
    sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: store as never, verifyRawChain: async () => true }).begin(session, new AbortController().signal);
    await vi.waitFor(() => expect(sync).toBeTypeOf('function')); sync?.('PREPARED'); await operation.readiness;
    expect(calls).toEqual(['disposition', 'query', 'isolation', 'start']); expect(query.mock.calls).toEqual([[[session.userId]]]); expect((crypto as unknown as { bootstrapCrossSigning: ReturnType<typeof vi.fn> }).bootstrapCrossSigning).not.toHaveBeenCalled(); expect(store.compareAndSetBootstrapDisposition).not.toHaveBeenCalled();
  });
  it('converts a reloaded pending UIA operation to recovery before any key query', async () => {
    const calls: string[] = []; const raw = { on: () => {}, initRustCrypto: async () => {}, getCrypto: () => ({}), stopClient: async () => {} }; const pending = { profileId: session.profileId, state: 'pending-uia' as const, generation: 1 }; const store = { getActiveProfile: async () => ({ profileId: session.profileId, generation: session.generation }), loadSession: async () => session, getBootstrapDisposition: async () => { calls.push('disposition'); return pending; }, compareAndSetBootstrapDisposition: async () => { calls.push('recovery'); return { ...pending, state: 'recovery-required' as const, generation: 2 }; } };
    sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: store as never, verifyRawChain: async () => true }).begin(session, new AbortController().signal);
    await expect(operation.readiness).rejects.toThrow('bootstrap_blocked'); expect(calls).toEqual(['disposition', 'recovery']);
  });
  it('bootstraps a never-attempted first device exactly once and publishes only the exact v42 proof', async () => {
    const calls: string[] = []; let published = false; let sync: ((state: string) => void) | undefined;
    const store = { ...outboxMethods(), getBootstrapDisposition: async () => { calls.push('disposition'); return { profileId: session.profileId, state: 'never-attempted' as const, generation: 0 }; }, compareAndSetBootstrapDisposition: async (expected: { state: string }, next: string) => { calls.push(`cas:${expected.state}->${next}`); return { profileId: session.profileId, state: next, generation: next === 'pending-uia' ? 1 : 2 }; } };
    const crypto = validCrypto({ getCrossSigningStatus: async () => published ? { publicKeysOnDevice: true, privateKeysCachedLocally: { masterKey: true, selfSigningKey: true, userSigningKey: true }, privateKeysInSecretStorage: false } : { publicKeysOnDevice: false, privateKeysCachedLocally: { masterKey: false, selfSigningKey: false, userSigningKey: false }, privateKeysInSecretStorage: false }, getCrossSigningKeyId: async () => published ? fingerprint : undefined, bootstrapCrossSigning: vi.fn(async options => { calls.push('bootstrap'); expect(options.setupNewCrossSigning).toBe(false); await options.authUploadDeviceSigningKeys(vi.fn(async request => { calls.push('makeRequest'); expect(request).toBeNull(); })); published = true; }), setDeviceIsolationMode: () => calls.push('isolation') });
    const query = vi.fn(async () => { calls.push('query'); return published ? publishedResponse() : firstDeviceResponse(); }); const raw = { on: (event: string, listener: (state: string) => void) => { if (event === 'sync') sync = listener; }, initRustCrypto: async () => {}, getCrypto: () => crypto, secretStorage: ssss('none'), downloadKeysForUsers: query, startClient: () => calls.push('start'), stopClient: async () => {} };
    sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: store as never, verifyRawChain: async () => true }).begin(session, new AbortController().signal);
    await vi.waitFor(() => expect(sync).toBeTypeOf('function')); sync?.('PREPARED');
    await operation.readiness;
    expect(calls).toEqual(['disposition', 'query', 'cas:never-attempted->pending-uia', 'bootstrap', 'makeRequest', 'query', 'cas:pending-uia->published', 'isolation', 'start']);
    expect(query.mock.calls).toEqual([[[session.userId]], [[session.userId]]]); expect((crypto as unknown as { bootstrapCrossSigning: ReturnType<typeof vi.fn> }).bootstrapCrossSigning).toHaveBeenCalledOnce();
  });
  it('durably quarantines missing, repeated, rejected, or failed UIA bootstrap attempts', async () => {
    for (const failure of ['missing', 'double', 'rejected', 'bootstrap'] as const) {
      let disposition: { profileId: string; state: 'never-attempted' | 'pending-uia' | 'published' | 'recovery-required'; generation: number } = { profileId: session.profileId, state: 'never-attempted', generation: 0 };
      // This fake models the active session binding and terminal durable state,
      // rather than returning independent canned CAS responses.
      const store = {
        getBootstrapDisposition: async (profile: { profileId: string }) => { expect(profile.profileId).toBe(session.profileId); return disposition; },
        compareAndSetBootstrapDisposition: async (expected: typeof disposition, next: typeof disposition.state, binding: { profileId: string; locatorGeneration: number; sessionGeneration: number; localDeviceId: string }) => {
          expect(binding).toEqual({ profileId: session.profileId, locatorGeneration: session.generation, sessionGeneration: session.generation, localDeviceId: session.deviceId });
          if (expected !== disposition || (next !== 'pending-uia' && next !== 'recovery-required')) return undefined;
          disposition = { profileId: session.profileId, state: next, generation: disposition.generation + 1 }; return disposition;
        },
      };
      const crypto = validCrypto({ getCrossSigningStatus: async () => ({ publicKeysOnDevice: false, privateKeysCachedLocally: { masterKey: false, selfSigningKey: false, userSigningKey: false }, privateKeysInSecretStorage: false }), getCrossSigningKeyId: async () => undefined, bootstrapCrossSigning: async (options: { authUploadDeviceSigningKeys: (request: (body: null) => Promise<void>) => Promise<void> }) => {
        if (failure === 'bootstrap') throw new Error('bootstrap');
        if (failure === 'missing') return;
        if (failure === 'rejected') await options.authUploadDeviceSigningKeys(async () => { throw new Error('rejected'); });
        else { await options.authUploadDeviceSigningKeys(async () => undefined); await options.authUploadDeviceSigningKeys(async () => undefined); }
      } });
      const raw = { on: () => {}, initRustCrypto: async () => {}, getCrypto: () => crypto, secretStorage: ssss('none'), downloadKeysForUsers: async () => firstDeviceResponse(), startClient: () => { throw new Error('must not publish'); }, stopClient: async () => {} };
      sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: store as never, verifyRawChain: async () => true }).begin(session, new AbortController().signal);
      await expect(operation.readiness, failure).rejects.toThrow('bootstrap_blocked');
      expect(disposition).toMatchObject({ state: 'recovery-required' });
      expect(disposition.state).not.toBe('pending-uia'); expect(disposition.state).not.toBe('published');
    }
  });
  it('fails closed for every invalid raw proof or durable bootstrap branch', async () => {
    const mutate = (result: ReturnType<typeof publishedResponse>, name: string): ReturnType<typeof publishedResponse> => {
      if (name === 'failures') return { ...result, failures: { test: {} } };
      if (name === 'missing device') return { ...result, device_keys: { [session.userId]: {} } };
      if (name === 'extra device') return { ...result, device_keys: { [session.userId]: { ...result.device_keys[session.userId], old: result.device_keys[session.userId][session.deviceId] } } };
      if (name === 'partial public') return { ...result, user_signing_keys: undefined } as unknown as ReturnType<typeof publishedResponse>;
      if (name === 'bad usage') return { ...result, self_signing_keys: { [session.userId]: { ...result.self_signing_keys![session.userId], usage: ['wrong'] } } };
      if (name === 'bad key id') return { ...result, master_keys: { [session.userId]: { ...result.master_keys![session.userId], keys: { 'ed25519:not-master': 'master' } } } } as unknown as ReturnType<typeof publishedResponse>;
      if (name === 'bad signature') return { ...result, self_signing_keys: { [session.userId]: { ...result.self_signing_keys![session.userId], signatures: {} } } };
      return result;
    };
    const cases = ['query throw', 'failures', 'missing device', 'extra device', 'partial public', 'bad usage', 'bad key id', 'bad signature', 'local partial', 'local mismatch', 'SSSS partial', 'SSSS complete', 'wrong sole device ID', 'callback absent', 'callback twice', 'UIA rejection', 'bootstrap rejection', 'publicKeysOnDevice', 'current trust false', 'post incomplete', 'CAS drift', 'published mismatch'] as const;
    for (const name of cases) {
      let booted = false; const calls: string[] = []; const store = { getBootstrapDisposition: async () => ({ profileId: session.profileId, state: name === 'published mismatch' ? 'published' as const : 'never-attempted' as const, generation: 1 }), compareAndSetBootstrapDisposition: async (expected: { state: string }, next: string) => { calls.push(`cas:${expected.state}->${next}`); if (name === 'CAS drift' && next === 'pending-uia') return { profileId: session.profileId, state: 'never-attempted', generation: 2 }; return { profileId: session.profileId, state: next, generation: 2 }; } };
      const crypto = validCrypto({ getCrossSigningStatus: async () => name === 'local partial' ? { publicKeysOnDevice: false, privateKeysCachedLocally: { masterKey: true, selfSigningKey: false, userSigningKey: true }, privateKeysInSecretStorage: false } : name === 'local mismatch' ? { publicKeysOnDevice: true, privateKeysCachedLocally: { masterKey: true, selfSigningKey: true, userSigningKey: true }, privateKeysInSecretStorage: false } : { publicKeysOnDevice: name === 'publicKeysOnDevice', privateKeysCachedLocally: { masterKey: false, selfSigningKey: false, userSigningKey: false }, privateKeysInSecretStorage: false }, getCrossSigningKeyId: async () => name === 'local mismatch' ? 'wrong' : undefined, getUserVerificationStatus: async () => ({ known: name !== 'current trust false', needsUserApproval: false, isCrossSigningVerified: () => name !== 'current trust false' }), bootstrapCrossSigning: vi.fn(async options => { if (name === 'bootstrap rejection') throw new Error('bootstrap'); if (name === 'callback absent') return; booted = true; if (name === 'UIA rejection') await options.authUploadDeviceSigningKeys(async () => { throw new Error('uia'); }); else { await options.authUploadDeviceSigningKeys(async () => undefined); if (name === 'callback twice') await options.authUploadDeviceSigningKeys(async () => undefined); } }) });
      const raw = { on: () => {}, initRustCrypto: async () => {}, getCrypto: () => crypto, secretStorage: ssss(name === 'SSSS partial' ? 'partial' : name === 'SSSS complete' ? 'complete' : 'none'), downloadKeysForUsers: async () => { calls.push('query'); if (name === 'query throw') throw new Error('query'); const result = booted && name !== 'post incomplete' ? publishedResponse() : firstDeviceResponse() as unknown as ReturnType<typeof publishedResponse>; if (name === 'wrong sole device ID' && !booted) result.device_keys[session.userId][session.deviceId].device_id = 'wrong'; return mutate(result, name); }, startClient: () => calls.push('start'), stopClient: async () => {} };
      sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: store as never, verifyRawChain: async () => true }).begin(session, new AbortController().signal);
      await expect(operation.readiness, name).rejects.toThrow('bootstrap_blocked'); expect(calls).not.toContain('start');
      if (name === 'published mismatch') expect(calls).toContain('cas:published->recovery-required');
    }
  });
  it('returns only a frozen current-local identity observation with fixed references', async () => {
    const original = session.profileId; (session as { profileId: string }).profileId = '4421c6877a6168a50fc657194c2cb7c665e0e570aa84b2cc5ef7d5bfe6f2a991';
    try {
      const fixture = await startAdapterFixture(); const observation = await fixture.operation.gateway!.observeLocalIdentity();
      expect(Object.keys(observation)).toEqual(['userId', 'deviceId', 'profileRef', 'crossSigningMasterRef']);
      expect(Object.isFrozen(observation)).toBe(true);
      expect(observation).toEqual({ userId: '@me:test', deviceId: session.deviceId, profileRef: '13c60e0ddb0c298c41a4aafe36f5fcc4cbf6d1edf64b849a783f419d93e6d43a', crossSigningMasterRef: fingerprint });
      expect(observation.profileRef).toMatch(/^[a-f0-9]{64}$/); expect(observation.crossSigningMasterRef).toMatch(/^[A-Za-z0-9+/]{43}$/);
      expect(JSON.stringify(observation)).not.toContain(session.accessToken); expect(JSON.stringify(observation)).not.toContain(session.profileId);
    } finally { (session as { profileId: string }).profileId = original; }
  });
  it('fails observation closed for malformed local anchors, trust loss, master drift, epoch drift, and runtime replacement', async () => {
    const original = session.profileId; (session as { profileId: string }).profileId = '4421c6877a6168a50fc657194c2cb7c665e0e570aa84b2cc5ef7d5bfe6f2a991';
    try {
      let trusted = true; let master = fingerprint; let armMasterDrift = false;
      const fixture = await startAdapterFixture({ crypto: {
        getCrossSigningKeyId: async () => master,
        getUserVerificationStatus: async () => { if (armMasterDrift) master = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'; return { known: trusted, needsUserApproval: false, isCrossSigningVerified: () => trusted }; },
      } });
      (session as { profileId: string }).profileId = 'not-a-profile'; await expect(fixture.operation.gateway!.observeLocalIdentity()).rejects.toThrow('unavailable');
      (session as { profileId: string }).profileId = '4421c6877a6168a50fc657194c2cb7c665e0e570aa84b2cc5ef7d5bfe6f2a991';
      master = 'bad'; await expect(fixture.operation.gateway!.observeLocalIdentity()).rejects.toThrow('unavailable');
      master = fingerprint; trusted = false; await expect(fixture.operation.gateway!.observeLocalIdentity()).rejects.toThrow('unavailable');
      trusted = true; armMasterDrift = true; await expect(fixture.operation.gateway!.observeLocalIdentity()).rejects.toThrow('unavailable');
      armMasterDrift = false; master = fingerprint; const epochRace = fixture.operation.gateway!.observeLocalIdentity(); fixture.emit('keys'); await expect(epochRace).rejects.toThrow('unavailable');
      const runtimeFixture = await startAdapterFixture(); const runtimeRace = runtimeFixture.operation.gateway!.observeLocalIdentity(); runtimeFixture.abort(); await expect(runtimeRace).rejects.toThrow('unavailable');
    } finally { (session as { profileId: string }).profileId = original; }
  });
  it('rejects aliases and malformed room identifiers before raw join mutation', async () => {
    const fixture = await startAdapterFixture({ preRoom: room('invite') });
    for (const roomId of ['#alias:test', '!missing-server', ' !r:test', '!r:test ']) await expect(fixture.operation.gateway!.joinEncryptedRoom({ roomId: roomId as never })).rejects.toThrow('unavailable');
    expect(fixture.raw.joinRoom).not.toHaveBeenCalled();
  });
  it('creates only after cache stabilization and rejects nonjoined encryption targets', async () => {
    let sync: ((state: string) => void) | undefined; let policyEvent: (() => void) | undefined; let reads = 0; const good = room(); const raw = { on: (event: string, listener: () => void) => { if (event === 'sync') sync = listener as (state: string) => void; if (event === 'room') policyEvent = listener; }, initRustCrypto: async () => {}, getCrypto: () => validCrypto(), downloadKeysForUsers: async () => publishedResponse(), startClient: () => {}, stopClient: async () => {}, createRoom: vi.fn(async () => ({ room_id: '!r:test' })), getRoom: () => { reads += 1; if (reads === 1) { policyEvent?.(); return undefined; } return good; } };
    sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: strictStore() as never, roomClock: deterministicRoomClock(), verifyRawChain: async () => true }).begin(session, new AbortController().signal); await vi.waitFor(() => expect(sync).toBeTypeOf('function')); sync?.('PREPARED'); await operation.readiness;
    await expect(operation.gateway!.createEncryptedRoom({ name: 'room', invitees: ['@you:test'] as never[] })).resolves.toBe('!r:test'); expect(raw.createRoom).toHaveBeenCalledWith(expect.objectContaining({ visibility: 'private', preset: 'private_chat', initial_state: expect.arrayContaining([{ type: 'm.room.history_visibility', state_key: '', content: { history_visibility: 'joined' } }]) })); expect(reads).toBeGreaterThan(1);
    const bad = room('join', [{ userId: '@invite:test', membership: 'invite' }]); raw.getRoom = () => bad; await expect(operation.gateway!.createEncryptedRoom({ name: 'room', invitees: ['@you:test'] as never[] })).rejects.toThrow('unavailable');
  });
  it('rejects absent or invalid invites before raw join, then waits for joined state', async () => {
    let sync: ((state: string) => void) | undefined; const invited = room('invite'); const joined = room('join'); let current: ReturnType<typeof room> | undefined;
    const raw = { on: (event: string, listener: (state: string) => void) => { if (event === 'sync') sync = listener; }, initRustCrypto: async () => {}, getCrypto: () => validCrypto(), downloadKeysForUsers: async () => publishedResponse(), startClient: () => {}, stopClient: async () => {}, joinRoom: vi.fn(() => { current = joined; return Promise.resolve({ roomId: '!r:test' }); }), getRoom: () => current };
    sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: strictStore() as never, roomClock: deterministicRoomClock(), verifyRawChain: async () => true }).begin(session, new AbortController().signal); await vi.waitFor(() => expect(sync).toBeTypeOf('function')); sync?.('PREPARED'); await operation.readiness;
    await expect(operation.gateway!.joinEncryptedRoom({ roomId: '!r:test' as never })).rejects.toThrow('unavailable'); expect(raw.joinRoom).not.toHaveBeenCalled(); current = invited;
    await expect(operation.gateway!.joinEncryptedRoom({ roomId: '!r:test' as never })).resolves.toBe('!r:test'); expect(raw.joinRoom).toHaveBeenCalledWith('!r:test');
    current = invited; raw.joinRoom.mockResolvedValueOnce({ roomId: '!other:test' });
    await expect(operation.gateway!.joinEncryptedRoom({ roomId: '!r:test' as never })).rejects.toThrow('unavailable');
  });
  it('create rejects every unstable or unsafe post-admission state', async () => {
    const unsafe = [
      ['raw rejection', { create: async () => { throw new Error('raw'); } }], ['malformed room_id', { create: async () => ({ room_id: 'bad' }) }], ['timeout/no cache', { getRoom: () => undefined }], ['never joined', { postRoom: room('invite') }],
      ['missing join rule', { postRoom: { ...room(), currentState: { getStateEvents: (type: string) => type === 'm.room.join_rules' ? [] : events.filter(event => event.getType() === type) } } }], ['wrong join rule', { postRoom: { ...room(), currentState: { getStateEvents: (type: string) => type === 'm.room.join_rules' ? [{ getType: () => type, getStateKey: () => '', getContent: () => ({ join_rule: 'public' }) }] : events.filter(event => event.getType() === type) } } }],
      ['missing encryption', { postRoom: { ...room(), currentState: { getStateEvents: (type: string) => type === 'm.room.encryption' ? [] : events.filter(event => event.getType() === type) } } }], ['wrong encryption', { postRoom: { ...room(), currentState: { getStateEvents: (type: string) => type === 'm.room.encryption' ? [{ getType: () => type, getStateKey: () => '', getContent: () => ({ algorithm: 'wrong' }) }] : events.filter(event => event.getType() === type) } } }], ['encryption false', { encryption: false }],
      ['zero targets', { postRoom: room('join', []) }], ['nonjoined target', { postRoom: room('join', [{ userId: '@x:test', membership: 'invite' }]) }], ['duplicate target', { postRoom: room('join', [{ userId: '@x:test', membership: 'join' }, { userId: '@x:test', membership: 'join' }]) }], ['missing device map', { devices: new Map() }], ['empty devices', { devices: new Map([['@me:test', new Map()]]) }], ['null status', { postStatus: async () => null }], ['unsigned', { postStatus: async () => ({ crossSigningVerified: false, isVerified: () => true }) }], ['unverified', { postStatus: async () => ({ crossSigningVerified: true, isVerified: () => false }) }],
    ] as const;
    for (const [name, overrides] of unsafe) { const fixture = await startAdapterFixture(overrides); await expect(fixture.operation.gateway!.createEncryptedRoom({ name: 'x', invitees: ['@you:test'] as never[] }), name).rejects.toThrow(); expect(fixture.raw.createRoom, `${name}: post-admission`).toHaveBeenCalledOnce(); }
  });
  it('join rejects every invalid prejoin state before raw invocation', async () => {
    const cases = [undefined, room('join'), { ...room('invite'), currentState: { getStateEvents: () => [] } }, { ...room('invite'), currentState: { getStateEvents: (type: string) => type === 'm.room.join_rules' ? [{ getType: () => type, getStateKey: () => '', getContent: () => ({ join_rule: 'public' }) }] : events.filter(event => event.getType() === type) } }, { ...room('invite'), currentState: { getStateEvents: (type: string) => type === 'm.room.encryption' ? [] : events.filter(event => event.getType() === type) } }, { ...room('invite'), currentState: { getStateEvents: (type: string) => type === 'm.room.encryption' ? [{ getType: () => type, getStateKey: () => '', getContent: () => ({ algorithm: 'wrong' }) }] : events.filter(event => event.getType() === type) } }];
    for (const preRoom of cases) { const fixture = await startAdapterFixture({ preRoom }); await expect(fixture.operation.gateway!.joinEncryptedRoom({ roomId: '!r:test' as never })).rejects.toThrow(); expect(fixture.raw.joinRoom).toHaveBeenCalledTimes(0); }
  });
  it('join rejects every unstable or unsafe post-admission state', async () => {
    const unsafe = [
      ['raw rejection', { join: async () => { throw new Error('raw'); } }], ['malformed room result/id', { join: async () => ({ roomId: 'bad' }) }], ['timeout', { postRoom: undefined }], ['never joined', { postRoom: room('invite') }], ['wrong post state', { postRoom: { ...room(), currentState: { getStateEvents: () => [] } } }], ['encryption false', { encryption: false }], ['zero target', { postRoom: room('join', []) }], ['nonjoined target', { postRoom: room('join', [{ userId: '@x:test', membership: 'invite' }]) }], ['duplicate target', { postRoom: room('join', [{ userId: '@x:test', membership: 'join' }, { userId: '@x:test', membership: 'join' }]) }], ['missing devices', { devices: new Map() }], ['empty devices', { devices: new Map([['@me:test', new Map()]]) }], ['null status', { postStatus: async () => null }], ['unsigned status', { postStatus: async () => ({ crossSigningVerified: false, isVerified: () => true }) }], ['unverified status', { postStatus: async () => ({ crossSigningVerified: true, isVerified: () => false }) }],
    ] as const;
    for (const [name, overrides] of unsafe) { const fixture = await startAdapterFixture({ preRoom: room('invite'), ...overrides }); await expect(fixture.operation.gateway!.joinEncryptedRoom({ roomId: '!r:test' as never }), name).rejects.toThrow(); expect(fixture.raw.joinRoom, `${name}: post-admission`).toHaveBeenCalledOnce(); }
  });
  it('restores ready after expected room and membership events during stabilization', async () => {
    for (const action of ['create', 'join'] as const) { let reads = 0; const eventsDuringWait: { emit: AdapterFixture['emit'] | undefined } = { emit: undefined }; const fixture = await startAdapterFixture({ preRoom: room('invite'), getRoom: () => { reads += 1; if (action === 'join' && reads === 1) return room('invite'); if (reads === (action === 'join' ? 2 : 1)) { eventsDuringWait.emit?.('room'); return undefined; } if (reads === (action === 'join' ? 3 : 2)) { eventsDuringWait.emit?.('member'); return room('invite'); } return room(); } }); eventsDuringWait.emit = fixture.emit; const first = () => action === 'create' ? fixture.operation.gateway!.createEncryptedRoom({ name: 'x', invitees: ['@you:test'] as never[] }) : fixture.operation.gateway!.joinEncryptedRoom({ roomId: '!r:test' as never }); await expect(first()).resolves.toBe('!r:test'); }
  });
  it('room trust or device epoch drift during post-admission blocks create and join', async () => {
    for (const action of ['create', 'join'] as const) { let resolve!: (value: Map<string, Map<string, { deviceId: string }>>) => void; const devices = new Promise<Map<string, Map<string, { deviceId: string }>>>(done => { resolve = done; }); const fixture = await startAdapterFixture({ ...(action === 'join' ? { preRoom: room('invite') } : {}), devices }); const promise = action === 'create' ? fixture.operation.gateway!.createEncryptedRoom({ name: 'x', invitees: ['@you:test'] as never[] }) : fixture.operation.gateway!.joinEncryptedRoom({ roomId: '!r:test' as never }); await vi.waitFor(() => expect(action === 'create' ? fixture.raw.createRoom : fixture.raw.joinRoom).toHaveBeenCalledOnce()); fixture.emit(action === 'create' ? 'trust' : 'devices'); resolve(new Map([['@me:test', new Map([['d', { deviceId: 'd' }]])]])); await expect(promise).rejects.toThrow('unavailable'); const control = await startAdapterFixture(action === 'join' ? { preRoom: room('invite') } : {}); await expect(action === 'create' ? control.operation.gateway!.createEncryptedRoom({ name: 'x', invitees: ['@you:test'] as never[] }) : control.operation.gateway!.joinEncryptedRoom({ roomId: '!r:test' as never })).resolves.toBe('!r:test'); }
  });
  it('create and join success return branded room identifiers only after exact policy', async () => {
    const create = await startAdapterFixture(); await expect(create.operation.gateway!.createEncryptedRoom({ name: 'x', invitees: ['@you:test'] as never[] })).resolves.toBe('!r:test'); const join = await startAdapterFixture({ preRoom: room('invite') }); await expect(join.operation.gateway!.joinEncryptedRoom({ roomId: '!r:test' as never })).resolves.toBe('!r:test');
  });
  it('admits a direct room only with the exact active self/peer pair', async () => {
    const members = [{ userId: '@me:test', membership: 'join' }, { userId: '@peer:test', membership: 'invite' }];
    const directRoom = { ...room('join', [{ userId: '@me:test', membership: 'join' }, { userId: '@peer:test', membership: 'join' }]), getMembers: () => members };
    const fixture = await startAdapterFixture({ postRoom: directRoom, devices: new Map([['@me:test', new Map([['d', { deviceId: 'd' }]])], ['@peer:test', new Map([['p', { deviceId: 'p' }]])]]) });
    await expect(fixture.operation.gateway!.createDirectConversation({ peerUserId: '@peer:test' as never })).resolves.toMatchObject({ membership: 'verification-only', peerUserId: '@peer:test' });
    members.push({ userId: '@third:test', membership: 'knock' });
    await expect(fixture.operation.gateway!.createDirectConversation({ peerUserId: '@peer:test' as never })).rejects.toThrow('unavailable');
  });

  // These fixtures intentionally drive the SDK-shaped listeners; they are not
  // reducer tests.  In particular Ready/Start enter through raw timeline events.
  /** These are deliberately raw wire events, not SDK request projections. */
  const sasWire = (type: 'request' | 'ready' | 'start', id: string, actor: 'peer' | 'self' = 'peer', reference = '$request') => {
    const sender = actor === 'peer' ? '@peer:test' : session.userId;
    const device = actor === 'peer' ? 'PEER' : session.deviceId;
    const recipient = actor === 'peer' ? session.userId : '@peer:test';
    return {
    getType: () => type === 'request' ? 'm.room.message' : `m.key.verification.${type}`,
    getContent: () => type === 'request' ? { msgtype: 'm.key.verification.request', to: recipient, from_device: device, methods: ['m.sas.v1'], body: `${sender} is requesting to verify your key, but your client does not support in-chat key verification. You will need to use legacy key verification to verify keys.` } : type === 'ready' ? { from_device: device, methods: ['m.sas.v1'], 'm.relates_to': { rel_type: 'm.reference', event_id: reference } } : { from_device: device, method: 'm.sas.v1', key_agreement_protocols: ['curve25519-hkdf-sha256'], hashes: ['sha256'], message_authentication_codes: ['hkdf-hmac-sha256.v2'], short_authentication_string: ['decimal', 'emoji'], 'm.relates_to': { rel_type: 'm.reference', event_id: reference } },
    getSender: () => sender, getId: () => id, getTs: () => 0, getRoomId: () => '!r:test', getUnsigned: () => undefined,
    };
  };
  const sasStore = () => {
    let value: Record<string, unknown> | undefined; const calls: string[] = [];
    const next = async (generation: number, phase: string) => {
      calls.push(`phase:${generation}:${phase}`);
      const from = value?.phase;
      const allowed = phase === 'cancelled' || phase === 'failed'
        ? from !== 'done' && from !== 'cancelled' && from !== 'failed'
        : (value?.direction === 'incoming' && from === 'requested' && phase === 'accepted')
          || (value?.direction === 'outgoing' && from === 'requested' && phase === 'ready')
          || (value?.direction === 'incoming' && from === 'accepted' && phase === 'ready')
          || (from === 'started' && phase === 'sas-shown') || (from === 'sas-shown' && phase === 'confirming') || (from === 'confirming' && phase === 'done');
      if (!value || value.generation !== generation || !allowed) return undefined;
      value = { ...value, phase, generation: generation + 1 }; return value;
    };
    return { calls, get value() { return value; }, getSasOperation: async () => value, createSasIntent: async (operation: Record<string, unknown>) => { calls.push(`create:outgoing:${operation.generation}`); if (value && !value.disposed) return false; value = { ...operation }; return true; }, createIncomingSasOperation: async (operation: Record<string, unknown>, requestEventId: string, transactionId: string, peerDeviceId: string) => { calls.push(`create:incoming:${operation.generation}`); if (value && !value.disposed) return false; value = { ...operation, phase: 'requested', requestEventId, transactionId, peerDeviceId }; return true; }, bindSasRequest: async (_l: unknown, generation: number, requestEventId: string, transactionId: string) => { calls.push(`bind-request:${generation}`); if (!value || value.generation !== generation || value.direction !== 'outgoing' || value.phase !== 'intent') return undefined; value = { ...value, phase: 'requested', requestEventId, transactionId, generation: generation + 1 }; return value; }, bindSasPeerDevice: async (_l: unknown, generation: number, peerDeviceId: string) => { calls.push(`bind-peer:${generation}`); if (!value || value.generation !== generation || value.disposed || value.phase !== 'requested' || value.peerDeviceId !== undefined) return undefined; value = { ...value, peerDeviceId, generation: generation + 1 }; return value; }, bindSasStartEvent: async (_l: unknown, generation: number, startEventId: string) => { calls.push(`bind-start:${generation}:${startEventId}`); if (!value || value.generation !== generation || value.disposed || value.peerDeviceId === undefined || value.startEventId !== undefined || startEventId === value.requestEventId || !((value.direction === 'outgoing' && (value.phase === 'requested' || value.phase === 'ready')) || (value.direction === 'incoming' && value.phase === 'ready'))) return undefined; value = { ...value, startEventId, phase: 'started', generation: generation + 1 }; return value; }, advanceSasPhase: async (_l: unknown, generation: number, phase: string) => await next(generation, phase), disposeSasOperation: async (_l: unknown, generation: number) => { calls.push(`dispose:${generation}`); if (!value || value.generation !== generation) return false; value = { ...value, disposed: true, generation: generation + 1 }; return true; } };
  };
  const deferred = <T = void>() => { let resolve!: (value: T | PromiseLike<T>) => void; let reject!: (reason?: unknown) => void; const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; }); return { promise, resolve, reject }; };
  const sasRequest = (outgoing = false) => {
    let phase = 0; const listeners = new Set<() => void>(); const verifierListeners = new Map<string, (value: unknown) => void>(); const lifecycle: string[] = [];
    const callbacks = { sas: { emoji: [['a', 'A'], ['b', 'B'], ['c', 'C'], ['d', 'D'], ['e', 'E'], ['f', 'F'], ['g', 'G']] as [string, string][], decimal: [1, 2, 3] }, confirm: vi.fn(async () => undefined), mismatch: vi.fn(), cancel: vi.fn() };
    const verification = deferred();
    const verifier = { userId: '@peer:test', verify: vi.fn(() => { lifecycle.push('verify'); return verification.promise; }), on: (event: string, listener: (value: unknown) => void) => { lifecycle.push(`on:${event}`); verifierListeners.set(event, listener); }, getShowSasCallbacks: vi.fn<() => typeof callbacks | undefined>(() => undefined) };
    const request = { initiatedByMe: outgoing, isSelfVerification: false, roomId: '!r:test', otherUserId: '@peer:test', otherDeviceId: 'PEER', transactionId: '$request', get phase() { return phase; }, set phase(value: number) { phase = value; }, chosenMethod: 'm.sas.v1', verifier, accept: vi.fn(async () => undefined), cancel: vi.fn(async () => undefined), startVerification: vi.fn(async () => verifier), on: (_event: string, listener: () => void) => listeners.add(listener) };
    return { request, verifier, callbacks, verification, lifecycle, change: (value: number) => { phase = value; listeners.forEach(listener => listener()); }, show: () => verifierListeners.get('show_sas')?.(callbacks), cancelVerifier: () => verifierListeners.get('cancel')?.(undefined), verifierListeners };
  };
  const directMembers = [{ userId: session.userId, membership: 'join' }, { userId: '@peer:test', membership: 'join' }];
  const directRoom = { ...room('join', directMembers), getMembers: () => directMembers };
  const initiateOutgoing = async (fixture: Awaited<ReturnType<typeof startAdapterFixture>>): Promise<void> => {
    const started = fixture.operation.gateway!.initiateSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never, roomEpoch: fixture.roomEpoch });
    fixture.emit('timeline', sasWire('request', '$request', 'self') as never);
    await started;
  };
  const fullTrust = (peerCachedKeys = cachedDeviceKeys('PEER'), peerRawKeys = { 'ed25519:PEER': fingerprint, 'curve25519:PEER': fingerprint }) => ({ crypto: { getUserDeviceInfo: async () => new Map([[session.userId, new Map([[session.deviceId, currentDevice()]])], ['@peer:test', new Map([['PEER', { deviceId: 'PEER', keys: peerCachedKeys }]])]]) }, download: async (users: string[]) => users.length === 2 ? ({ failures: {}, device_keys: { [session.userId]: publishedResponse().device_keys[session.userId], '@peer:test': { PEER: { user_id: '@peer:test', device_id: 'PEER', algorithms: deviceAlgorithms, keys: peerRawKeys, signatures: {} } } } }) : publishedResponse() });
  it('publishes a new frozen conversation and verification identity after trust epoch churn', async () => {
    const store = sasStore(); const flow = sasRequest();
    const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, ...fullTrust() });
    const conversations: import('../contract').DirectConversation[][] = [];
    fixture.operation.gateway!.subscribeDirectConversations(next => conversations.push([...next]));
    await vi.waitFor(() => expect(conversations.some(next => next.some(value => value.peerUserId === '@peer:test' && value.roomEpoch === 0))).toBe(true));
    const firstIdentity = conversations.flat().find(value => value.peerUserId === '@peer:test' && value.roomEpoch === 0)!;
    const firstStates: import('../contract').VerificationState[] = [];
    fixture.operation.gateway!.subscribeVerification(firstIdentity, value => firstStates.push(value));
    fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never);
    await vi.waitFor(() => expect(firstStates.at(-1)).toMatchObject({ phase: 'requested', roomEpoch: 0 }));
    const frozenFirst = firstStates.at(-1)!;

    fixture.emit('trust');
    await vi.waitFor(() => expect(conversations.some(next => next.some(value => value.peerUserId === '@peer:test' && value.roomEpoch === 1))).toBe(true));
    const secondIdentity = conversations.flat().find(value => value.peerUserId === '@peer:test' && value.roomEpoch === 1)!;
    const secondStates: import('../contract').VerificationState[] = [];
    fixture.operation.gateway!.subscribeVerification(secondIdentity, value => secondStates.push(value));
    await vi.waitFor(() => expect(secondStates.at(-1)).toMatchObject({ phase: 'requested', roomEpoch: 1 }));
    expect(frozenFirst).toMatchObject({ phase: 'requested', roomEpoch: 0 });
    const before = [...store.calls];
    await expect(fixture.operation.gateway!.cancelSas(firstIdentity)).rejects.toThrow('unavailable');
    expect(store.calls).toEqual(before);
    await fixture.operation.gateway!.cancelSas(secondIdentity);
  });
  it('suppresses an older deferred conversation projection after a newer epoch publishes', async () => {
    const encryption = vi.fn(async () => true);
    const fixture = await startAdapterFixture({ postRoom: directRoom, crypto: { isEncryptionEnabledInRoom: encryption } });
    const older = deferred<boolean>(); const newer = deferred<boolean>();
    encryption.mockImplementationOnce(() => older.promise).mockImplementationOnce(() => newer.promise);
    const snapshots: import('../contract').DirectConversation[][] = [];
    fixture.operation.gateway!.subscribeDirectConversations(next => snapshots.push([...next]));
    fixture.emit('trust');
    newer.resolve(true);
    await vi.waitFor(() => expect(snapshots.some(next => next.some(value => value.roomEpoch === 1))).toBe(true));
    const count = snapshots.length;
    older.resolve(true);
    await Promise.resolve(); await Promise.resolve();
    expect(snapshots).toHaveLength(count);
    expect(snapshots.flat().some(value => value.roomEpoch === 0)).toBe(false);
  });
  it('does not let hanging decrypt work retain shutdown or mutate after stop', async () => {
    const first = deferred<void>(); const second = deferred<void>();
    const fixture = await startAdapterFixture({ postRoom: directRoom, store: { ...strictStore(), getSasOperation: async () => undefined } });
    const raw = fixture.raw as unknown as { decryptEventIfNeeded: ReturnType<typeof vi.fn>; stopClient: ReturnType<typeof vi.fn> };
    raw.decryptEventIfNeeded = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    raw.stopClient = vi.fn(async () => undefined);
    const seen: unknown[][] = []; fixture.operation.gateway!.subscribeTimeline('!r:test' as never, messages => seen.push([...messages]));
    const event = (id: string) => ({ getType: () => 'm.room.encrypted', getWireType: () => 'm.room.encrypted', getContent: () => ({}), getSender: () => '@peer:test', getId: () => id, getRoomId: () => '!r:test', getTs: () => 1 });
    fixture.emit('timeline', event('$one') as never, directRoom as never);
    fixture.emit('timeline', event('$two') as never, directRoom as never);
    await vi.waitFor(() => expect(raw.decryptEventIfNeeded).toHaveBeenCalledTimes(2));
    await expect(fixture.operation.stop()).resolves.toBeUndefined();
    expect(raw.stopClient).toHaveBeenCalledOnce();
    const afterStop = seen.length;
    first.resolve(); second.reject(new Error('late'));
    await Promise.resolve(); await Promise.resolve();
    expect(seen).toHaveLength(afterStop);
  });

  it('retries a recovered indeterminate row once with its original transaction after Syncing', async () => {
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('recover'))), byte => byte.toString(16).padStart(2, '0')).join('');
    let record: Record<string, unknown> = { profileId: session.profileId, transactionId: 'recover-txn', roomId: '!r:test', bodyHash: hash, state: 'local-pending', indeterminate: true, retryConsumed: false, baselineGeneration: 0, requiredGeneration: 1, generation: 2 };
    let generation = 0;
    const store = { ...strictStore(), rebaseUnresolvedOutbox: vi.fn(async () => 1), listUnresolvedTextOutboxRecords: vi.fn(async () => [record]), getTextOutboxRecord: async () => record, incrementSyncGeneration: async () => ({ profileId: session.profileId, syncGeneration: ++generation }), consumeOutboxRetry: async (_p: unknown, _t: string, bodyHash: string, expected: number) => record.bodyHash === bodyHash && record.generation === expected && generation >= Number(record.requiredGeneration) ? { record: record = { ...record, indeterminate: false, retryConsumed: true, generation: expected + 1 } } : undefined, recordOutboxAcceptance: async (_p: unknown, _t: string, expected: number, eventId: string) => expected === record.generation ? { kind: 'updated' as const, record: record = { ...record, state: 'homeserver-accepted', eventId, generation: expected + 1 } } : { kind: 'conflict' as const } };
    const fixture = await startAdapterFixture({ postRoom: directRoom, ...fullTrust(), store });
    const raw = fixture.raw as unknown as { sendMessage: ReturnType<typeof vi.fn>; resendEvent: ReturnType<typeof vi.fn> };
    raw.sendMessage = vi.fn(async () => ({ event_id: '$recovered' })); raw.resendEvent = vi.fn();
    const timeline: unknown[][] = []; fixture.operation.gateway!.subscribeTimeline('!r:test' as never, value => timeline.push([...value]));
    fixture.emit('sync', 'SYNCING' as never); await vi.waitFor(() => expect(generation).toBe(1));
    await fixture.operation.gateway!.sendDirectText({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never, body: 'recover', transactionId: 'recover-txn' as never });
    expect(raw.sendMessage).toHaveBeenCalledWith('!r:test', { msgtype: 'm.text', body: 'recover' }, 'recover-txn'); expect(raw.resendEvent).not.toHaveBeenCalled();
    expect(record).toMatchObject({ retryConsumed: true, state: 'homeserver-accepted', eventId: '$recovered' }); expect(timeline.at(-1)).toMatchObject([{ delivery: 'homeserver-accepted', transactionId: 'recover-txn', plaintext: 'recover' }]);
  });

  it('hydrates recovered accepted or synced rows only on exact plaintext resupply', async () => {
    for (const state of ['homeserver-accepted', 'synced'] as const) {
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('recover'))), byte => byte.toString(16).padStart(2, '0')).join('');
      const record = { profileId: session.profileId, transactionId: `terminal-${state}`, roomId: '!r:test', bodyHash: hash, state, eventId: '$terminal', indeterminate: false, retryConsumed: false, baselineGeneration: 0, requiredGeneration: 0, generation: 2 };
      const fixture = await startAdapterFixture({ postRoom: directRoom, ...fullTrust(), store: { ...strictStore(), rebaseUnresolvedOutbox: async () => 0, listUnresolvedTextOutboxRecords: async () => [record], getTextOutboxRecord: async () => record } });
      const raw = fixture.raw as unknown as { sendMessage: ReturnType<typeof vi.fn> }; raw.sendMessage = vi.fn();
      const seen: unknown[][] = []; fixture.operation.gateway!.subscribeTimeline('!r:test' as never, value => seen.push([...value]));
      await fixture.operation.gateway!.sendDirectText({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never, body: 'recover', transactionId: record.transactionId as never });
      expect(raw.sendMessage).not.toHaveBeenCalled(); expect(seen.at(-1)).toMatchObject([{ delivery: state, eventId: '$terminal', plaintext: 'recover' }]);
      await expect(fixture.operation.gateway!.sendDirectText({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never, body: 'wrong', transactionId: record.transactionId as never })).rejects.toThrow('unavailable');
    }
  });
  it('reconciles an authentic decrypted self echo by hash without rendering a reload-only attempt', async () => {
    const body = 'authoritative echo'; const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))), byte => byte.toString(16).padStart(2, '0')).join('');
    const record = { profileId: session.profileId, transactionId: 'echo', roomId: '!r:test', bodyHash: hash, retryConsumed: false, state: 'local-pending' as const, indeterminate: false, baselineGeneration: 0, requiredGeneration: 0, generation: 1 };
    const reconcileOutboxRemoteEcho = vi.fn(async () => ({ kind: 'updated' as const, record: { ...record, state: 'synced' as const, eventId: '$echo', generation: 2 } }));
    const fixture = await startAdapterFixture({ postRoom: directRoom, store: { ...strictStore(), getTextOutboxRecord: async () => record, reconcileOutboxRemoteEcho } });
    const seen: unknown[][] = []; fixture.operation.gateway!.subscribeTimeline('!r:test' as never, value => seen.push([...value]));
    fixture.emit('timeline', { getType: () => 'm.room.message', getWireType: () => 'm.room.encrypted', getContent: () => ({ msgtype: 'm.text', body }), getSender: () => session.userId, getTxnId: () => 'echo', getId: () => '$echo', getRoomId: () => '!r:test', getTs: () => 1 } as never, directRoom as never);
    await vi.waitFor(() => expect(reconcileOutboxRemoteEcho).toHaveBeenCalledWith({ profileId: session.profileId }, 'echo', '$echo'));
    expect(seen.at(-1)).toMatchObject([{ delivery: 'synced', eventId: '$echo', plaintext: body }]);
  });
  it('rejects bad decrypted echoes without binding them, while unknown transactions are ignored', async () => {
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('expected'))), byte => byte.toString(16).padStart(2, '0')).join('');
    const record = { profileId: session.profileId, transactionId: 'bad', roomId: '!r:test', bodyHash: hash, retryConsumed: false, state: 'local-pending' as const, indeterminate: false, baselineGeneration: 0, requiredGeneration: 0, generation: 1 };
    const reconcileOutboxRemoteEcho = vi.fn(async () => ({ kind: 'updated' as const, record: { ...record, state: 'synced' as const, eventId: '$bad', generation: 2 } }));
    const fixture = await startAdapterFixture({ postRoom: directRoom, store: { ...strictStore(), getTextOutboxRecord: async (_: unknown, transactionId: string) => transactionId === 'bad' ? record : undefined, reconcileOutboxRemoteEcho } });
    const states: string[] = []; fixture.operation.gateway!.subscribeSecurityState(value => states.push(value));
    const event = (transactionId: string, body: string) => ({ getType: () => 'm.room.message', getWireType: () => 'm.room.encrypted', getContent: () => ({ msgtype: 'm.text', body }), getSender: () => session.userId, getTxnId: () => transactionId, getId: () => `$${transactionId}`, getRoomId: () => '!r:test', getTs: () => 1 });
    fixture.emit('timeline', event('unknown', 'anything') as never, directRoom as never); await new Promise(resolve => setTimeout(resolve));
    expect(reconcileOutboxRemoteEcho).not.toHaveBeenCalled(); expect(states).not.toContain('blocked');
    fixture.emit('timeline', event('bad', 'wrong') as never, directRoom as never);
    await vi.waitFor(() => expect(states).toContain('blocked')); expect(reconcileOutboxRemoteEcho).not.toHaveBeenCalled();
  });
  it('uses the fresh direct-trust proof for public readiness and atomic outbox send', async () => {
    const createInitialTextOutboxRecord = vi.fn(async value => ({ ...value, baselineGeneration: 0, requiredGeneration: 0, generation: 1 }));
    const recordOutboxAcceptance = vi.fn(async () => ({ kind: 'updated' as const, record: { profileId: session.profileId, transactionId: 'txn', roomId: '!r:test', bodyHash: 'a'.repeat(64), retryConsumed: false, state: 'homeserver-accepted' as const, eventId: '$sent', baselineGeneration: 0, requiredGeneration: 0, generation: 2 } }));
    const fixture = await startAdapterFixture({ postRoom: directRoom, ...fullTrust(), store: { ...strictStore(), createInitialTextOutboxRecord, recordOutboxAcceptance } });
    const sendMessage = vi.fn(async () => ({ event_id: '$sent' }));
    Object.assign(fixture.raw, { sendMessage });
    const identity = { roomId: '!r:test' as never, peerUserId: '@peer:test' as never, roomEpoch: fixture.roomEpoch };
    const trust: unknown[] = []; fixture.operation.gateway!.subscribeDirectTrust(identity, value => trust.push(value));
    const timeline: unknown[][] = []; fixture.operation.gateway!.subscribeTimeline(identity, value => timeline.push([...value]));
    await vi.waitFor(() => expect(trust.some(value => (value as { sendReady: boolean }).sendReady)).toBe(true));
    await fixture.operation.gateway!.sendDirectText({ ...identity, body: 'hello', transactionId: 'txn' as never });
    expect(createInitialTextOutboxRecord).toHaveBeenCalledWith(expect.objectContaining({ bodyHash: expect.stringMatching(/^[a-f0-9]{64}$/) }));
    expect(JSON.stringify(createInitialTextOutboxRecord.mock.calls)).not.toContain('hello');
    expect(sendMessage).toHaveBeenCalledWith('!r:test', { msgtype: 'm.text', body: 'hello' }, 'txn');
    expect(timeline.at(-1)).toMatchObject([{ delivery: 'homeserver-accepted', eventId: '$sent', plaintext: 'hello' }]);
  });
  it('keeps a rejected raw send indeterminate until a later Syncing authorizes its one same-transaction retry', async () => {
    let record: Record<string, unknown> | undefined; let syncGeneration = 0;
    const hash = async (body: string) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))), byte => byte.toString(16).padStart(2, '0')).join('');
    const store = {
      ...strictStore(),
      getTextOutboxRecord: async () => record,
      createInitialTextOutboxRecord: async (value: Record<string, unknown>) => record = { ...value, baselineGeneration: syncGeneration, requiredGeneration: syncGeneration, generation: 1 },
      markOutboxIndeterminate: async (_profile: unknown, _txn: string, generation: number) => record && record.generation === generation ? record = { ...record, indeterminate: true, requiredGeneration: syncGeneration + 1, generation: generation + 1 } : undefined,
      incrementSyncGeneration: async () => ({ profileId: session.profileId, syncGeneration: ++syncGeneration }),
      consumeOutboxRetry: async (_profile: unknown, _txn: string, bodyHash: string, generation: number) => record && record.generation === generation && record.bodyHash === bodyHash && record.indeterminate === true && syncGeneration >= Number(record.requiredGeneration) ? { record: record = { ...record, indeterminate: false, retryConsumed: true, generation: generation + 1 } } : undefined,
      recordOutboxAcceptance: async (_profile: unknown, _txn: string, generation: number, eventId: string) => record && record.generation === generation ? { kind: 'updated' as const, record: record = { ...record, state: 'homeserver-accepted', eventId, generation: generation + 1 } } : { kind: 'conflict' as const },
    };
    const fixture = await startAdapterFixture({ postRoom: directRoom, ...fullTrust(), store });
    const sendMessage = vi.fn().mockRejectedValueOnce(new Error('network')); const resendEvent = vi.fn(async () => ({ event_id: '$retried' })); Object.assign(fixture.raw, { sendMessage, resendEvent });
    const states: string[] = []; fixture.operation.gateway!.subscribeSecurityState(value => states.push(value));
    const request = { roomId: '!r:test' as never, peerUserId: '@peer:test' as never, body: 'retry me', transactionId: 'retry-txn' as never };
    await expect(fixture.operation.gateway!.sendDirectText(request)).rejects.toThrow('unavailable');
    expect(record).toMatchObject({ indeterminate: true, retryConsumed: false, requiredGeneration: 1 }); expect(states).not.toContain('blocked');
    await expect(fixture.operation.gateway!.sendDirectText(request)).rejects.toThrow('unavailable'); expect(sendMessage).toHaveBeenCalledTimes(1);
    fixture.emit('localEcho', { getRoomId: () => '!r:test', getSender: () => session.userId, getTxnId: () => 'retry-txn', getType: () => 'm.room.encrypted' } as never, directRoom as never);
    fixture.emit('sync', 'SYNCING' as never); await vi.waitFor(() => expect(syncGeneration).toBe(1));
    await fixture.operation.gateway!.sendDirectText(request);
    expect(sendMessage).toHaveBeenCalledOnce(); expect(resendEvent).toHaveBeenCalledOnce(); expect(record).toMatchObject({ state: 'homeserver-accepted', retryConsumed: true, eventId: '$retried' });
    await expect(fixture.operation.gateway!.sendDirectText(request)).rejects.toThrow('unavailable');
    expect(resendEvent).toHaveBeenCalledOnce();
    expect(await hash('retry me')).toBe(record!.bodyHash);
  });
  const incomingShown = async (store = sasStore(), dependency: Record<string, unknown> = store) => { const flow = sasRequest(); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...dependency }, postRoom: directRoom, ...fullTrust() }); const seen: unknown[] = []; fixture.operation.gateway!.subscribeVerification('!r:test' as never, value => seen.push(value)); fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never); await vi.waitFor(() => expect(store.calls).toContain('create:incoming:1')); fixture.emit('timeline', sasWire('ready', '$ready') as never); await fixture.operation.gateway!.acceptSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); flow.change(3); await vi.waitFor(() => expect(store.calls).toContain('phase:2:ready')); fixture.emit('timeline', sasWire('start', '$start') as never); flow.change(4); await vi.waitFor(() => expect(store.calls.some(call => call.startsWith('bind-start:'))).toBe(true)); flow.show(); await vi.waitFor(() => expect(seen.some(value => (value as { phase: string }).phase === 'sas-shown')).toBe(true)); return { store, flow, fixture, seen }; };

  it('completes outgoing SAS when verifier and Done arrive in either order', async () => {
    for (const order of ['done-first', 'verifier-first'] as const) { const store = sasStore(); const flow = sasRequest(true); const trust = fullTrust(); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, ...trust, crypto: { ...trust.crypto, requestVerificationDM: vi.fn(async () => flow.request) } }); const seen: unknown[] = []; fixture.operation.gateway!.subscribeVerification('!r:test' as never, value => seen.push(value)); await initiateOutgoing(fixture); fixture.emit('timeline', sasWire('ready', '$ready') as never); flow.change(3); await vi.waitFor(() => expect(flow.request.startVerification).toHaveBeenCalledOnce()); fixture.emit('timeline', sasWire('start', '$start', 'self') as never); flow.change(4); flow.show(); await vi.waitFor(() => expect(seen.some(value => (value as { phase: string }).phase === 'sas-shown')).toBe(true)); expect(flow.lifecycle).toEqual(['on:cancel', 'on:show_sas', 'verify']); const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); if (order === 'done-first') { flow.change(6); flow.verification.resolve(); } else { flow.verification.resolve(); flow.change(6); } await confirming; expect(flow.verifier.verify).toHaveBeenCalledOnce(); expect(store.calls).toEqual(['create:outgoing:1', 'bind-request:1', 'bind-peer:2', 'phase:3:ready', 'bind-start:4:$start', 'phase:5:sas-shown', 'phase:6:confirming', 'phase:7:done', 'dispose:8']); }
  });
  it('accepts incoming only after persisted consent and authoritative Ready', async () => {
    const store = sasStore(); const order: string[] = []; const flow = sasRequest(); const advance = store.advanceSasPhase;
    store.advanceSasPhase = async (...values: Parameters<typeof advance>) => { const next = await advance(...values); if (values[2] === 'accepted') order.push('store:accepted'); return next; };
    flow.request.accept.mockImplementation(async () => { order.push('request:accept'); flow.change(3); });
    const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom });
    fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never);
    await vi.waitFor(() => expect(store.calls).toContain('create:incoming:1')); expect(store.value, JSON.stringify(store.calls)).toMatchObject({ direction: 'incoming', phase: 'requested' });
    fixture.emit('timeline', sasWire('ready', '$ready', 'peer') as never);
    await fixture.operation.gateway!.acceptSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never });
    expect(order).toEqual(['store:accepted', 'request:accept']);
    await vi.waitFor(() => expect(store.calls).toContain('phase:2:ready'));
  });
  it('terminalizes an incoming Started phase received before persisted consent without attaching its verifier', async () => {
    const store = sasStore(); const flow = sasRequest(); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom });
    fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never);
    await vi.waitFor(() => expect(store.calls).toContain('create:incoming:1'));
    fixture.emit('timeline', sasWire('start', '$start') as never); flow.change(4);
    await vi.waitFor(() => expect(store.calls.some(call => call.startsWith('dispose:'))).toBe(true));
    expect(flow.request.cancel).toHaveBeenCalledOnce(); expect(flow.verifier.verify).not.toHaveBeenCalled();
  });
  it('orders Ready and Started CAS work ahead of a synchronous terminal intent', async () => {
    const store = sasStore(); const flow = sasRequest(); const startBound = deferred<Record<string, unknown> | undefined>(); const bindEntered = deferred(); const bindStart = store.bindSasStartEvent;
    store.bindSasStartEvent = async (...values: Parameters<typeof bindStart>) => { bindEntered.resolve(undefined); await startBound.promise; return await bindStart(...values); };
    const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom });
    fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never);
    await vi.waitFor(() => expect(store.calls).toContain('create:incoming:1'));
    fixture.emit('timeline', sasWire('ready', '$ready') as never); await fixture.operation.gateway!.acceptSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); flow.change(3);
    await vi.waitFor(() => expect(store.calls).toContain('phase:2:ready'));
    fixture.emit('timeline', sasWire('start', '$start') as never); flow.change(4); await bindEntered.promise;
    const cancelling = fixture.operation.gateway!.cancelSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never });
    expect(store.calls.some(call => call.startsWith('dispose:'))).toBe(false); startBound.resolve(undefined); await cancelling;
    expect(store.calls).toEqual(expect.arrayContaining(['phase:2:ready', 'bind-start:3:$start', 'phase:4:cancelled', 'dispose:5']));
  });
  it('does not CAS Ready after cancellation wins while room admission awaits', async () => {
    const store = sasStore(); const flow = sasRequest(); const admitted = deferred<boolean>(); const entered = deferred();
    const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom });
    fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never);
    await vi.waitFor(() => expect(store.calls).toContain('create:incoming:1'));
    await fixture.operation.gateway!.acceptSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never });
    fixture.emit('timeline', sasWire('ready', '$ready') as never);
    fixture.raw.getCrypto = () => validCrypto({ isEncryptionEnabledInRoom: async () => { entered.resolve(undefined); return await admitted.promise; } });
    flow.change(3); await entered.promise;
    const cancelled = fixture.operation.gateway!.cancelSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never });
    admitted.resolve(true); await cancelled;
    expect(store.calls).not.toContain('phase:2:ready'); expect(store.calls).not.toContain('bind-peer:2');
    expect(flow.request.startVerification).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(store.value).toMatchObject({ phase: 'cancelled', disposed: true }));
  });
  it('handles outgoing remote Started racing Ready without local start', async () => { const store = sasStore(); const flow = sasRequest(true); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, crypto: { requestVerificationDM: async () => flow.request } }); await initiateOutgoing(fixture); fixture.emit('timeline', sasWire('start', '$start') as never); flow.change(4); await vi.waitFor(() => expect(store.calls.some(call => call.startsWith('bind-start'))).toBe(true)); expect(flow.request.startVerification).not.toHaveBeenCalled(); });
  it('buffers early ShowSas and never emits value-less sas-shown', async () => {
    const store = sasStore(); const flow = sasRequest(true); const trust = fullTrust();
    flow.verifier.verify.mockImplementation(() => { flow.show(); return flow.verification.promise; });
    const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, ...trust, crypto: { ...trust.crypto, requestVerificationDM: async () => flow.request } }); const early: unknown[] = []; const unsubscribe = fixture.operation.gateway!.subscribeVerification('!r:test' as never, value => early.push(value));
    await initiateOutgoing(fixture); fixture.emit('timeline', sasWire('ready', '$ready') as never); flow.change(3); await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); await Promise.resolve(); expect(early.filter(value => (value as { phase: string }).phase === 'sas-shown')).toHaveLength(0);
    fixture.emit('timeline', sasWire('start', '$start', 'self') as never); flow.change(4); await vi.waitFor(() => expect(early.filter(value => (value as { phase: string }).phase === 'sas-shown')).toHaveLength(1)); const shown = early.find(value => (value as { phase: string }).phase === 'sas-shown') as { sas?: unknown }; expect(shown.sas).toEqual(expect.objectContaining({ emojis: expect.any(Array), decimals: [1, 2, 3] })); unsubscribe(); const late: unknown[] = []; fixture.operation.gateway!.subscribeVerification('!r:test' as never, value => late.push(value)); expect(late).toEqual([expect.objectContaining({ phase: 'sas-shown', sas: shown.sas })]);
    await fixture.operation.gateway!.cancelSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); await vi.waitFor(() => expect(store.value).toMatchObject({ disposed: true })); flow.show(); await Promise.resolve(); expect(late.filter(value => (value as { phase: string }).phase === 'sas-shown')).toHaveLength(1);
  });
  it('rejects independently modeled invalid incoming requests', async () => { for (const name of ['wrong room', 'wrong peer', 'self', 'to-device', 'stale', 'duplicate active', 'unsupported wire methods', 'wrong peer device'] as const) { const store = sasStore(); const flow = sasRequest(); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom }); const wire: { getTs(): number; getContent(): unknown } = sasWire('request', '$request'); if (name === 'wrong room') flow.request.roomId = '!wrong:test'; if (name === 'wrong peer') flow.request.otherUserId = '@wrong:test'; if (name === 'self') flow.request.isSelfVerification = true; if (name === 'to-device') (flow.request as { roomId?: string }).roomId = undefined; if (name === 'stale') wire.getTs = () => -600_001; if (name === 'wrong peer device') flow.request.otherDeviceId = 'OTHER'; if (name === 'unsupported wire methods') wire.getContent = () => ({ msgtype: 'm.key.verification.request', to: session.userId, from_device: 'PEER', methods: ['m.reciprocate.v1'], body: 'unsupported' }); if (name === 'duplicate active') { fixture.emit('timeline', wire as never); fixture.emit('verification', flow.request as never); await vi.waitFor(() => expect(store.calls).toContain('create:incoming:1')); const duplicate = sasRequest(); fixture.emit('verification', duplicate.request as never); await vi.waitFor(() => expect(duplicate.request.cancel).toHaveBeenCalledOnce()); expect(store.calls.filter(call => call === 'create:incoming:1')).toHaveLength(1); continue; } fixture.emit('timeline', wire as never); fixture.emit('verification', flow.request as never); await vi.waitFor(() => expect(flow.request.cancel).toHaveBeenCalledOnce()); expect(store.calls).not.toContain('create:incoming:1'); } });
  it('rejects zero or duplicate related Start events', async () => { for (const count of [0, 2]) { const store = sasStore(); const flow = sasRequest(); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom }); fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never); await vi.waitFor(() => expect(store.calls).toContain('create:incoming:1')); await fixture.operation.gateway!.acceptSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); fixture.emit('timeline', sasWire('ready', '$ready') as never); flow.change(3); await vi.waitFor(() => expect(store.calls).toContain('phase:2:ready')); for (let i = 0; i < count; i += 1) fixture.emit('timeline', sasWire('start', `$start${i}`) as never); flow.change(4); await vi.waitFor(() => expect(flow.request.cancel).toHaveBeenCalledOnce()); expect(store.calls.some(call => call.startsWith('bind-start'))).toBe(false); expect(store.calls.some(call => call.startsWith('dispose:'))).toBe(true); } });
  it('copies SAS transiently and clears it before confirm awaits', async () => { const { store, flow, fixture, seen } = await incomingShown(); const confirmation = deferred<undefined>(); flow.callbacks.confirm.mockImplementation(() => confirmation.promise); const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); await vi.waitFor(() => expect(flow.callbacks.confirm).toHaveBeenCalledOnce()); expect(store.value).not.toHaveProperty('sas'); expect(store.value).not.toHaveProperty('callbacks'); expect(seen.filter(value => (value as { phase: string }).phase === 'sas-shown')).toEqual([expect.objectContaining({ sas: { emojis: expect.any(Array), decimals: [1, 2, 3] } })]); expect(seen.at(-1)).toMatchObject({ phase: 'confirming' }); expect(seen.at(-1)).not.toHaveProperty('sas'); await expect(fixture.operation.gateway!.mismatchSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never })).rejects.toThrow('unavailable'); confirmation.resolve(undefined); flow.change(6); flow.verification.resolve(); await confirming; expect(seen.at(-1)).toMatchObject({ phase: 'done' }); expect(seen.at(-1)).not.toHaveProperty('sas'); });
  it('mismatch and cancel are one-shot terminal dispositions', async () => { for (const command of ['mismatchSas', 'cancelSas'] as const) { const { store, flow, fixture } = await incomingShown(); const generation = store.value!.generation as number; await fixture.operation.gateway![command]({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); expect(command === 'mismatchSas' ? flow.callbacks.mismatch : flow.callbacks.cancel).toHaveBeenCalledOnce(); expect(store.calls).toContain(`phase:${generation}:cancelled`); expect(store.calls).toContain(`dispose:${generation + 1}`); await expect(fixture.operation.gateway![command]({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never })).rejects.toThrow('unavailable'); expect(flow.request.cancel).toHaveBeenCalledTimes(command === 'cancelSas' ? 1 : 0); } });
  it('requires verifier resolution request Done and fresh authoritative trust', async () => { for (const missing of ['verifier', 'done', 'query failure', 'fingerprint mismatch'] as const) { const { store, flow, fixture } = await incomingShown(); const trust = fullTrust(); if (missing === 'query failure') fixture.raw.downloadKeysForUsers = async () => { throw new Error('query'); }; if (missing === 'fingerprint mismatch') fixture.raw.downloadKeysForUsers = async () => { const response = await trust.download([session.userId, '@peer:test']) as { device_keys: Record<string, Record<string, { keys: Record<string, string> }>> }; response.device_keys['@peer:test']!.PEER!.keys['ed25519:PEER'] = 'wrong'; return response; }; const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); if (missing === 'verifier') { flow.change(6); await Promise.resolve(); expect(store.calls).not.toContain('phase:7:done'); flow.verification.resolve(); } else if (missing === 'done') { flow.verification.resolve(); await Promise.resolve(); expect(store.calls).not.toContain('phase:7:done'); flow.change(6); } else { flow.change(6); flow.verification.resolve(); } if (missing === 'verifier' || missing === 'done') await expect(confirming).resolves.toBeUndefined(); else await expect(confirming).rejects.toThrow('unavailable'); } });
  it('denies fresh trust for each self and peer approval or current-device signature failure', async () => {
    for (const failure of ['self identity approval only', 'peer identity approval only', 'self current device unsigned only', 'peer bound device unsigned only'] as const) {
      const { flow, fixture } = await incomingShown(); const trust = fullTrust();
      fixture.raw.getCrypto = () => validCrypto({ ...trust.crypto,
        getUserVerificationStatus: async (id: string) => ({ known: true, needsUserApproval: failure === 'self identity approval only' ? id === session.userId : failure === 'peer identity approval only' ? id === '@peer:test' : false, isCrossSigningVerified: () => true }),
        getDeviceVerificationStatus: async (id: string, deviceId: string) => ({ signedByOwner: !(failure === 'self current device unsigned only' && id === session.userId && deviceId === session.deviceId) && !(failure === 'peer bound device unsigned only' && id === '@peer:test' && deviceId === 'PEER'), crossSigningVerified: true, isVerified: () => true }),
      });
      const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); flow.change(6); flow.verification.resolve(); await expect(confirming, failure).rejects.toThrow('unavailable');
    }
  });
  it('re-proves when trust churn races the in-flight authoritative proof', async () => {
    for (const mismatch of [false, true]) {
      const { store, flow, fixture } = await incomingShown(); const first = deferred<unknown>(); const trust = fullTrust(); const query = vi.fn(async () => query.mock.calls.length === 1 ? await first.promise : mismatch ? (() => { const response = trust.download([session.userId, '@peer:test']) as Promise<{ device_keys: Record<string, Record<string, { keys: Record<string, string> }>> }>; return response.then(value => { value.device_keys['@peer:test']!.PEER!.keys['ed25519:PEER'] = 'wrong'; return value; }); })() : await trust.download([session.userId, '@peer:test'])); fixture.raw.downloadKeysForUsers = query;
      const security: string[] = []; fixture.operation.gateway!.subscribeSecurityState(value => security.push(value)); const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); flow.change(6); flow.verification.resolve(); await vi.waitFor(() => expect(query).toHaveBeenCalledOnce()); fixture.emit('trust'); first.resolve(await trust.download([session.userId, '@peer:test']));
      if (mismatch) { await expect(confirming).rejects.toThrow('unavailable'); expect(security.at(-1)).not.toBe('ready'); expect(store.calls).not.toContain('phase:7:done'); } else { await expect(confirming).resolves.toBeUndefined(); expect(query.mock.calls.length).toBeGreaterThanOrEqual(3); expect(security.at(-1)).toBe('ready'); }
    }
  });
  it('verifier Cancel during the first proof synchronously revokes completion but waits for proof ownership', async () => {
    const { store, flow, fixture, seen } = await incomingShown(); const first = deferred<unknown>(); const trust = fullTrust();
    fixture.raw.downloadKeysForUsers = vi.fn(async () => await first.promise);
    const security: string[] = []; fixture.operation.gateway!.subscribeSecurityState(value => security.push(value)); security.length = 0;
    const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); const rejected = confirming.then(() => false, () => true); await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); flow.change(6); flow.verification.resolve(); await vi.waitFor(() => expect(fixture.raw.downloadKeysForUsers).toHaveBeenCalledOnce());
    expect(security).not.toContain('ready'); await vi.waitFor(() => expect(flow.verifierListeners.has('cancel')).toBe(true)); flow.cancelVerifier();
    // The terminal intent is immediate, but completion still owns the deferred
    // proof: no terminal CAS/disposal may run concurrently with it.
    expect(store.value).toMatchObject({ phase: 'confirming' }); expect(store.value).not.toHaveProperty('disposed');
    expect(store.calls.some(call => call.startsWith('dispose:'))).toBe(false);
    first.resolve(await trust.download([session.userId, '@peer:test'])); await vi.waitFor(() => expect(seen.some(value => (value as { phase: string }).phase === 'done')).toBe(false));
    expect(store.calls).not.toContain('phase:7:done'); expect(security).not.toContain('ready');
    await expect(rejected).resolves.toBe(true); await vi.waitFor(() => expect(store.value).toMatchObject({ phase: 'cancelled', disposed: true, generation: 8 }));
  });
  it('verifier Cancel during the second proof can never publish ready', async () => {
    const { store, flow, fixture, seen } = await incomingShown(); const second = deferred<unknown>(); const trust = fullTrust(); let queries = 0;
    fixture.raw.downloadKeysForUsers = vi.fn(async () => ++queries === 1 ? await trust.download([session.userId, '@peer:test']) : await second.promise);
    const security: string[] = []; fixture.operation.gateway!.subscribeSecurityState(value => security.push(value)); security.length = 0;
    const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); const rejected = confirming.then(() => false, () => true); await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); flow.change(6); flow.verification.resolve(); await vi.waitFor(() => expect(queries).toBe(2)); await vi.waitFor(() => expect(store.calls).toContain('phase:6:done'));
    expect(security).not.toContain('ready'); await vi.waitFor(() => expect(flow.verifierListeners.has('cancel')).toBe(true)); flow.cancelVerifier();
    // Positively witness done's durable CAS and the second query before cancel;
    // terminalization must wait and then dispose that exact done generation.
    expect(store.value).toMatchObject({ phase: 'done', generation: 7 }); expect(store.value).not.toHaveProperty('disposed');
    expect(store.calls.some(call => call === 'dispose:7')).toBe(false);
    second.resolve(await trust.download([session.userId, '@peer:test'])); await expect(rejected).resolves.toBe(true);
    expect(seen.some(value => (value as { phase: string }).phase === 'done')).toBe(false); expect(security).not.toContain('ready');
    await vi.waitFor(() => expect(store.value).toMatchObject({ phase: 'done', disposed: true, generation: 8 }));
  });
  it('clears the active authority after a real second-proof failure following done disposal', async () => {
    const { store, flow, fixture } = await incomingShown(); const trust = fullTrust(); const replacement = sasRequest(true); let queries = 0;
    fixture.raw.downloadKeysForUsers = async () => {
      if (++queries === 1) return await trust.download([session.userId, '@peer:test']);
      const response = await trust.download([session.userId, '@peer:test']) as { device_keys: Record<string, Record<string, { keys: Record<string, string> }>> };
      response.device_keys['@peer:test']!.PEER!.keys['ed25519:PEER'] = 'second-proof-mismatch'; return response;
    };
    fixture.raw.getCrypto = () => validCrypto({ ...trust.crypto, requestVerificationDM: async () => replacement.request });
    const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never });
    await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); flow.change(6); flow.verification.resolve();
    await expect(confirming).rejects.toThrow('unavailable');
    await vi.waitFor(() => expect(store.value).toMatchObject({ phase: 'done', disposed: true, generation: 8 }));
    await expect(initiateOutgoing(fixture)).resolves.toBeUndefined();
    expect(store.value).toMatchObject({ direction: 'outgoing', generation: 10 });
  });
  it('fails closed on completion disposal failure, then only permits replacement after terminal cleanup disposes', async () => {
    const store = sasStore(); const replacement = sasRequest(true); const dispose = store.disposeSasOperation; let attempts = 0;
    const disposal = vi.fn(async (...values: Parameters<typeof dispose>) => ++attempts === 1 ? false : await dispose(...values));
    // This is the exact object captured by bootstrap, rather than a later
    // mutation of the fixture source object.
    const dependency = { ...strictStore(), ...store, disposeSasOperation: disposal };
    const { flow, fixture } = await incomingShown(store, dependency);
    fixture.raw.getCrypto = () => validCrypto({ ...fullTrust().crypto, requestVerificationDM: async () => replacement.request });
    const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never });
    await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); flow.change(6); flow.verification.resolve();
    await expect(confirming).rejects.toThrow('unavailable');
    expect(disposal).toHaveBeenCalled();
    await vi.waitFor(() => expect(store.value).toMatchObject({ phase: 'done', disposed: true }));
    await expect(initiateOutgoing(fixture)).resolves.toBeUndefined();
  });
  it('retains fail-closed completion authority when disposal persistently fails', async () => {
    const store = sasStore(); const disposal = vi.fn(async () => false);
    const dependency = { ...strictStore(), ...store, disposeSasOperation: disposal };
    const { flow, fixture } = await incomingShown(store, dependency);
    const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never });
    await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); flow.change(6); flow.verification.resolve();
    await expect(confirming).rejects.toThrow('unavailable');
    expect(disposal).toHaveBeenCalled();
    expect(store.value).toMatchObject({ phase: 'done' }); expect(store.value).not.toHaveProperty('disposed');
    await expect(initiateOutgoing(fixture)).rejects.toThrow('unavailable');
  });
  it('hanging request.cancel cannot block terminal CAS, disposal, or replacement', async () => {
    const { store, flow, fixture } = await incomingShown(); const hanging = deferred<undefined>(); const replacement = sasRequest(true); flow.request.cancel.mockImplementation(() => hanging.promise);
    fixture.raw.getCrypto = () => validCrypto({ requestVerificationDM: vi.fn(async () => replacement.request) });
    await vi.waitFor(() => expect(flow.verifierListeners.has('cancel')).toBe(true)); flow.cancelVerifier(); await vi.waitFor(() => expect(store.value).toMatchObject({ phase: 'cancelled', disposed: true, generation: 7 }));
    expect(flow.request.cancel).toHaveBeenCalledOnce(); await expect(initiateOutgoing(fixture)).resolves.toBeUndefined();
    expect(store.value).toMatchObject({ generation: 9, direction: 'outgoing' });
  });
  it('hanging mismatch or cancel callbacks cannot retain the durable SAS owner', async () => {
    for (const command of ['mismatchSas', 'cancelSas'] as const) {
      const { store, flow, fixture } = await incomingShown(); const hanging = deferred<undefined>(); const replacement = sasRequest(true);
      flow.callbacks[command === 'mismatchSas' ? 'mismatch' : 'cancel'].mockImplementation(() => hanging.promise);
      fixture.raw.getCrypto = () => validCrypto({ requestVerificationDM: vi.fn(async () => replacement.request) });
      await fixture.operation.gateway![command]({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never });
      expect(store.value).toMatchObject({ phase: 'cancelled', disposed: true, generation: 7 });
      await expect(initiateOutgoing(fixture)).resolves.toBeUndefined();
      expect(store.value).toMatchObject({ generation: 9, direction: 'outgoing' });
    }
  });
  it('poison synchronously revokes displayed SAS and terminalizes its captured durable owner', async () => {
    const { store, flow, fixture, seen } = await incomingShown();
    // A throwing observer is presentation-only and must not interrupt cleanup.
    fixture.operation.gateway!.subscribeVerification('!r:test' as never, () => { throw new Error('observer'); });
    fixture.emit('timeline', { getType: () => 'm.room.message', getWireType: () => 'm.room.message', getContent: () => ({ msgtype: 'm.text', body: 'forged plaintext' }), getSender: () => session.userId, getId: () => '$forged', getRoomId: () => '!r:test', getTs: () => 1 } as never, directRoom as never);
    await vi.waitFor(() => expect(store.value).toMatchObject({ phase: 'failed', disposed: true }));
    expect(flow.request.cancel).toHaveBeenCalledOnce();
    // No terminal publication can retain SAS material, and no later SDK callback
    // may advance the now-disposed operation.
    expect(seen.at(-1)).toMatchObject({ phase: 'failed' });
    expect(seen.at(-1)).not.toHaveProperty('sas');
    const calls = [...store.calls]; flow.change(4); flow.show();
    await Promise.resolve();
    expect(store.calls).toEqual(calls);
  });
  it('retains fail-closed authority when terminal CAS or disposal fails', async () => { for (const failure of ['terminal CAS', 'disposal'] as const) { const store = sasStore(); const advance = store.advanceSasPhase; const failing = failure === 'terminal CAS' ? vi.fn(async (...values: Parameters<typeof advance>) => values[2] === 'cancelled' ? undefined : await advance(...values)) : vi.fn(async () => false); if (failure === 'terminal CAS') store.advanceSasPhase = failing as typeof store.advanceSasPhase; else store.disposeSasOperation = failing as typeof store.disposeSasOperation; const flow = sasRequest(); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom }); fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never); await vi.waitFor(() => expect(store.calls).toContain('create:incoming:1')); await fixture.operation.gateway!.cancelSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); expect(failing).toHaveBeenCalled(); await expect(failing.mock.results.at(-1)?.value).resolves.toBe(failure === 'terminal CAS' ? undefined : false); expect(store.calls.filter(call => call.startsWith('dispose:'))).toHaveLength(0); expect(store.calls).not.toContain('create:outgoing:1'); await expect(fixture.operation.gateway!.initiateSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never })).rejects.toThrow('unavailable'); expect(flow.request.cancel).toHaveBeenCalledOnce(); } });
  it('clears stale active authority when a terminal CAS loses to a tombstone', async () => {
    const store = sasStore(); const flow = sasRequest(); const replacement = sasRequest(true); const advance = store.advanceSasPhase; const dispose = store.disposeSasOperation;
    store.advanceSasPhase = async (...values: Parameters<typeof advance>) => {
      if (values[2] !== 'cancelled') return await advance(...values);
      const terminal = await advance(...values); if (terminal) await dispose({}, terminal.generation as number); return undefined;
    };
    const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, crypto: { requestVerificationDM: async () => replacement.request } });
    fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never);
    await vi.waitFor(() => expect(store.calls).toContain('create:incoming:1'));
    await fixture.operation.gateway!.cancelSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never, roomEpoch: 0 });
    await expect(initiateOutgoing(fixture)).resolves.toBeUndefined();
  });
  it('fails and disposes the exact outgoing intent generation on request, malformed response, or bind failure', async () => {
    for (const failure of ['request', 'malformed response', 'bind'] as const) {
      const store = sasStore(); const flow = sasRequest(true); const bind = store.bindSasRequest;
      if (failure === 'bind') store.bindSasRequest = async () => undefined;
      const requestVerificationDM = vi.fn().mockImplementationOnce(async () => failure === 'request' ? await Promise.reject(new Error('request')) : failure === 'malformed response' ? { ...flow.request, initiatedByMe: false } : flow.request).mockImplementation(async () => flow.request);
      const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, crypto: { requestVerificationDM } });
      await expect(initiateOutgoing(fixture)).rejects.toThrow('unavailable');
      expect(store.calls).toEqual(expect.arrayContaining(['create:outgoing:1', 'phase:1:failed', 'dispose:2']));
      if (failure !== 'request') expect(flow.request.cancel).toHaveBeenCalledOnce();
      if (failure === 'bind') store.bindSasRequest = bind;
      if (failure === 'bind') await expect(initiateOutgoing(fixture)).rejects.toThrow('unavailable');
      else await expect(initiateOutgoing(fixture)).resolves.toBeUndefined();
      expect(store.calls).toContain('create:outgoing:4'); expect(store.value).toMatchObject({ generation: failure === 'bind' ? 6 : 5, direction: 'outgoing' });
    }
  });
  it('detaches a hanging pre-binding cancellation before disposing the intent and accepting tombstone+1', async () => {
    for (const failure of ['malformed', 'bind'] as const) {
      const store = sasStore(); const flow = sasRequest(true); const hanging = deferred<undefined>(); let attempts = 0;
      if (failure === 'bind') store.bindSasRequest = async () => undefined;
      flow.request.cancel.mockImplementation(() => hanging.promise);
      const dependency = { ...strictStore(), ...store };
      const fixture = await startAdapterFixture({ store: dependency, postRoom: directRoom, crypto: { requestVerificationDM: async () => ++attempts === 1 && failure === 'malformed' ? { ...flow.request, initiatedByMe: false } : flow.request } });
      await expect(initiateOutgoing(fixture)).rejects.toThrow('unavailable');
      expect(flow.request.cancel).toHaveBeenCalledOnce(); expect(store.value).toMatchObject({ phase: 'failed', disposed: true, generation: 3 });
      if (failure === 'bind') dependency.bindSasRequest = vi.fn(async (_l: unknown, generation: number, requestEventId: string, transactionId: string) => { if (!store.value || store.value.generation !== generation || store.value.direction !== 'outgoing' || store.value.phase !== 'intent') return undefined; const restored = { ...store.value, phase: 'requested', requestEventId, transactionId, generation: generation + 1 }; Object.assign(store.value!, restored); return store.value; });
      await expect(initiateOutgoing(fixture)).resolves.toBeUndefined();
      if (failure === 'bind') expect(dependency.bindSasRequest).toHaveBeenCalled();
      expect(store.value).toMatchObject({ direction: 'outgoing' }); expect(store.value!.generation).toBeGreaterThan(3);
    }
  });
  it('cancels an issued outgoing request when stop wins its raw-event wait', async () => {
    const store = sasStore(); const flow = sasRequest(true); const requestVerificationDM = vi.fn(async () => flow.request);
    const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, crypto: { requestVerificationDM } });
    const initiating = fixture.operation.gateway!.initiateSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never }); await vi.waitFor(() => expect(requestVerificationDM).toHaveBeenCalledOnce()); await Promise.resolve();
    await fixture.operation.stop(); await expect(initiating).rejects.toThrow('unavailable');
    expect(flow.request.cancel).toHaveBeenCalledOnce(); expect(store.value).toMatchObject({ phase: 'failed', disposed: true });
    const calls = [...store.calls]; fixture.emit('timeline', sasWire('request', '$request') as never); await Promise.resolve();
    expect(store.calls).toEqual(calls); expect(store.calls.some(call => call.startsWith('bind-request'))).toBe(false);
  });

  // Recovery fixtures are deliberately stateful: every successful mutation
  // consumes its exact generation, leaving a tombstone for the next flow.
  const seededSasStore = (seed: Record<string, unknown>) => {
    let value: Record<string, unknown> | undefined = { ...seed }; const calls: string[] = [];
    const advance = async (_locator: unknown, generation: number, phase: string) => {
      calls.push(`advance:${generation}:${phase}`); if (!value || value.generation !== generation) return undefined;
      value = { ...value, phase, generation: generation + 1 }; return value;
    };
    return { calls, get value() { return value; }, getSasOperation: async () => value,
      createSasIntent: async (operation: Record<string, unknown>) => { calls.push(`create:${operation.generation}`); if (value && !value.disposed) return false; value = { ...operation }; return true; },
      createIncomingSasOperation: async (operation: Record<string, unknown>, requestEventId: string, transactionId: string, peerDeviceId: string) => { calls.push(`incoming:${operation.generation}`); if (value && !value.disposed) return false; value = { ...operation, phase: 'requested', requestEventId, transactionId, peerDeviceId }; return true; },
      bindSasRequest: async (_locator: unknown, generation: number, requestEventId: string, transactionId: string) => !value || value.generation !== generation ? undefined : (value = { ...value, generation: generation + 1, phase: 'requested', requestEventId, transactionId }),
      bindSasPeerDevice: async (_locator: unknown, generation: number, peerDeviceId: string) => !value || value.generation !== generation ? undefined : (value = { ...value, generation: generation + 1, peerDeviceId }),
      bindSasStartEvent: async (_locator: unknown, generation: number, startEventId: string) => !value || value.generation !== generation || value.disposed || value.peerDeviceId === undefined || value.startEventId !== undefined || startEventId === value.requestEventId || !((value.direction === 'outgoing' && (value.phase === 'requested' || value.phase === 'ready')) || (value.direction === 'incoming' && value.phase === 'ready')) ? undefined : (value = { ...value, generation: generation + 1, phase: 'started', startEventId }),
      advanceSasPhase: advance, disposeSasOperation: async (_locator: unknown, generation: number) => { calls.push(`dispose:${generation}`); if (!value || value.generation !== generation) return false; value = { ...value, disposed: true, generation: generation + 1 }; return true; },
    };
  };
  const persistedStarted = (direction: 'incoming' | 'outgoing', generation = 7) => ({ profileId: session.profileId, roomId: '!r:test', peerUserId: '@peer:test', localDeviceId: session.deviceId, direction, phase: 'started', expiresAt: 600_000, generation, requestEventId: '$request', transactionId: '$request', peerDeviceId: 'PEER', startEventId: '$start' });

  it('recovers exact incoming and outgoing Started operations after reload', async () => {
    for (const direction of ['incoming', 'outgoing'] as const) {
      const store = seededSasStore(persistedStarted(direction)); const flow = sasRequest(direction === 'outgoing'); flow.change(4);
      flow.verifier.getShowSasCallbacks.mockReturnValue(flow.callbacks);
      const finder = vi.fn(() => flow.request); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, timeline: [sasWire('request', '$request', direction === 'outgoing' ? 'self' : 'peer'), sasWire('start', '$start')], crypto: { findVerificationRequestDMInProgress: finder } });
      const projected: unknown[] = []; fixture.operation.gateway!.subscribeVerification('!r:test' as never, value => projected.push(value));
      await vi.waitFor(() => expect(finder).toHaveBeenCalled());
      expect(flow.verifier.verify).toHaveBeenCalledOnce();
      expect(projected).toContainEqual(expect.objectContaining({ direction, phase: 'sas-shown' }));
      expect(store.value).toMatchObject({ phase: 'sas-shown', requestEventId: '$request', transactionId: '$request', startEventId: '$start', peerDeviceId: 'PEER' });
    }
  });
  it('keeps a recovered request authoritative when its queued SDK callback overlaps the claim', async () => {
    const store = seededSasStore(persistedStarted('incoming')); const flow = sasRequest(); flow.change(4); flow.verifier.getShowSasCallbacks.mockReturnValue(flow.callbacks);
    const claimEntered = deferred(); const releaseClaim = deferred(); const get = store.getSasOperation; let reads = 0;
    store.getSasOperation = async () => { if (++reads === 2) { claimEntered.resolve(undefined); await releaseClaim.promise; } return await get(); };
    const listeners = new Map<string, Set<(...values: never[]) => void>>(); const on = (event: string, listener: (...values: never[]) => void): void => { const set = listeners.get(event) ?? new Set(); set.add(listener); listeners.set(event, set); };
    const emit = (event: string, ...values: never[]): void => { for (const listener of listeners.get(event) ?? []) listener(...values); };
    const raw = { on, initRustCrypto: async () => {}, getCrypto: () => validCrypto({ findVerificationRequestDMInProgress: vi.fn(() => flow.request) }), downloadKeysForUsers: async () => publishedResponse(), startClient: () => {}, stopClient: async () => {}, getRoom: () => directRoom };
    sdk.createClient.mockReturnValue(raw); const operation = createSdkBootstrapPort(async () => ({ accessToken: 'a', expiry: new Date() }), { store: { ...strictStore(), ...store } as never, roomClock: deterministicRoomClock(), verifyRawChain: async () => true }).begin(session, new AbortController().signal);
    await vi.waitFor(() => expect(listeners.get('sync')).toBeDefined()); emit('timeline', sasWire('request', '$request') as never); emit('timeline', sasWire('start', '$start') as never); emit('sync', 'PREPARED' as never); await claimEntered.promise;
    emit('verification', flow.request as never); releaseClaim.resolve(undefined); await operation.readiness;
    const projected: unknown[] = []; operation.gateway!.subscribeVerification({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never, roomEpoch: 0 }, value => projected.push(value));
    await vi.waitFor(() => expect(flow.verifier.verify).toHaveBeenCalledOnce()); expect(flow.request.cancel).not.toHaveBeenCalled(); expect(store.value).toMatchObject({ phase: 'sas-shown' }); expect(store.value).not.toHaveProperty('disposed'); expect(projected.at(-1)).toMatchObject({ phase: 'sas-shown' });
    await operation.gateway!.cancelSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never, roomEpoch: 0 }); await vi.waitFor(() => expect(store.value).toMatchObject({ disposed: true }));
  });

  it('fails mismatched or expired recovery and disposes the generation', async () => {
    for (const mutate of [
      (value: Record<string, unknown>) => ({ ...value, roomId: '!other:test' }), (value: Record<string, unknown>) => ({ ...value, peerUserId: '@other:test' }), (value: Record<string, unknown>) => ({ ...value, peerDeviceId: 'OTHER' }), (value: Record<string, unknown>) => ({ ...value, requestEventId: '$other' }), (value: Record<string, unknown>) => ({ ...value, transactionId: '$transaction-mismatch' }), (value: Record<string, unknown>) => ({ ...value, startEventId: '$other' }), (value: Record<string, unknown>) => ({ ...value, expiresAt: 0 }),
    ]) {
      const store = seededSasStore(mutate(persistedStarted('incoming'))); const flow = sasRequest(); flow.change(4); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, timeline: [sasWire('request', '$request'), sasWire('start', '$start')], crypto: { findVerificationRequestDMInProgress: () => flow.request } });
      await vi.waitFor(() => expect(store.calls.some(call => call.startsWith('dispose:'))).toBe(true));
      await expect(fixture.operation.gateway!.cancelSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never })).rejects.toThrow('unavailable');
    }
  });
  it('recovery terminal disposal cannot evict a callback-installed authority and clears pre-binding wire history', async () => {
    const store = seededSasStore({ ...persistedStarted('incoming'), phase: 'done' }); const flow = sasRequest();
    const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom });
    // The recovery tombstone is disposed before a callback may install a new
    // authority; its old wire index cannot poison the replacement.
    fixture.emit('timeline', sasWire('request', '$request') as never); fixture.emit('verification', flow.request as never);
    await vi.waitFor(() => expect(store.calls).toContain('incoming:9'));
    await fixture.operation.gateway!.cancelSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never, roomEpoch: 1 });
  });

  it('cancels and disposes an active SAS on room or membership drift', async () => {
    for (const event of ['room', 'member'] as const) {
      const { store, flow, fixture } = await incomingShown(); fixture.emit(event);
      await vi.waitFor(() => expect(store.calls.some(call => call.startsWith('dispose:'))).toBe(true)); expect(flow.request.cancel).toHaveBeenCalledOnce();
    }
    let expiry: (() => void) | undefined; const scheduler = { setTimeout: (callback: () => void) => { expiry = callback; return callback; }, clearTimeout: () => undefined };
    const store = seededSasStore(persistedStarted('incoming')); const flow = sasRequest(); flow.change(4); await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, timeline: [sasWire('request', '$request'), sasWire('start', '$start')], crypto: { findVerificationRequestDMInProgress: () => flow.request }, sasScheduler: scheduler });
    await vi.waitFor(() => expect(expiry).toBeTypeOf('function')); expiry?.(); await vi.waitFor(() => expect(store.calls.some(call => call.startsWith('dispose:'))).toBe(true));
  });

  it('keeps active SAS through trust, device, and key churn, then re-proves fresh trust before ready', async () => {
    for (const event of ['trust', 'devices', 'keys'] as const) {
      const { store, flow, fixture } = await incomingShown(); const security: string[] = []; fixture.operation.gateway!.subscribeSecurityState(value => security.push(value));
      fixture.emit(event); await vi.waitFor(() => expect(security).toContain('unverified'));
      expect(store.calls.some(call => call.startsWith('dispose:'))).toBe(false); expect(flow.request.cancel).not.toHaveBeenCalled();
      const confirming = fixture.operation.gateway!.confirmSas({ roomId: '!r:test' as never, peerUserId: '@peer:test' as never });
      flow.change(6); flow.verification.resolve(); await expect(confirming).resolves.toBeUndefined(); expect(flow.callbacks.confirm).toHaveBeenCalledOnce();
      expect(store.calls.some(call => call.endsWith(':done'))).toBe(true); expect(security.at(-1)).toBe('ready');
    }
  });

  it('ignores stale request verifier and timeout callbacks after replacement', async () => {
    const timeouts: (() => void)[] = []; const scheduler = { setTimeout: (callback: () => void) => { timeouts.push(callback); return callback; }, clearTimeout: () => undefined };
    const oldStore = seededSasStore(persistedStarted('incoming')); const old = sasRequest(); const replacement = sasRequest(true); old.change(4); const fixture = await startAdapterFixture({ store: { ...strictStore(), ...oldStore }, postRoom: directRoom, timeline: [sasWire('request', '$request'), sasWire('start', '$start')], crypto: { findVerificationRequestDMInProgress: () => old.request, requestVerificationDM: async () => replacement.request }, sasScheduler: scheduler });
    await vi.waitFor(() => expect(old.verifier.verify).toHaveBeenCalledOnce()); fixture.emit('room'); await vi.waitFor(() => expect(oldStore.value).toMatchObject({ disposed: true }));
    await initiateOutgoing(fixture);
    const replacementGeneration = oldStore.value?.generation; old.change(5); old.show(); old.cancelVerifier(); old.verification.resolve(); timeouts[0]?.();
    await vi.waitFor(() => expect(oldStore.value).toMatchObject({ generation: replacementGeneration, direction: 'outgoing' })); expect(replacement.request.cancel).not.toHaveBeenCalled();
  });

  it('uses tombstone generation for a new operation', async () => {
    const store = seededSasStore({ ...persistedStarted('incoming', 11), disposed: true }); const flow = sasRequest(true);
    const fixture = await startAdapterFixture({ store: { ...strictStore(), ...store }, postRoom: directRoom, crypto: { requestVerificationDM: async () => flow.request } });
    await initiateOutgoing(fixture);
    expect(store.calls).toContain('create:12'); expect(store.value).toMatchObject({ generation: 13, direction: 'outgoing', requestEventId: '$request', transactionId: '$request' });
  });
});
