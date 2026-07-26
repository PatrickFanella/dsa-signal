import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { canonicalProfileId } from '../auth/canonical-profile';
import { MATRIX_AUTHORIZATION_ENDPOINT, MATRIX_HOMESERVER, MATRIX_ISSUER, MATRIX_REDIRECT_URI, MATRIX_REGISTRATION_ENDPOINT, MATRIX_REVOCATION_ENDPOINT, MATRIX_TOKEN_ENDPOINT } from '../auth/matrix-topology';
import { IndexedDbSessionStore, type SasAuthorization, type SasStableGrantBinding } from '../auth/session-store';
import { beginDormantOutgoingSasFlow } from './sas-authorization-flow-controller';

const b64 = (byte: number) => btoa(String.fromCharCode(...new Uint8Array(32).fill(byte))).replace(/=+$/, '');
const binding = async (): Promise<SasStableGrantBinding> => ({ schemaVersion: 1, profileId: await canonicalProfileId({ homeserver: MATRIX_HOMESERVER, userId: '@me:example.test', deviceId: 'd'.repeat(43) }), sessionGeneration: 1, homeserver: MATRIX_HOMESERVER, localUserId: '@me:example.test', localDeviceId: 'd'.repeat(43), roomId: '!room:example.test', peerUserId: '@peer:example.test', localEd25519: b64(1), localCurve25519: b64(2), peerDeviceId: 'peer-device', peerEd25519: b64(3), peerCurve25519: b64(4), localMasterRef: b64(5), peerMasterRef: b64(6) });
const candidate = async () => {
  const value = await binding(); const calls: string[] = [];
  const store = {
    getSasAuthorization: vi.fn(async () => { calls.push('authoritative get'); return { ...value, state: 'active', direction: 'outgoing', stage: 'intent', expiresAt: 20, generation: 5 } as SasAuthorization; }),
    createOutgoingSasIntent: vi.fn(async () => { calls.push('intent'); return { ...value, state: 'active', direction: 'outgoing', stage: 'intent', expiresAt: 20, generation: 5 } as SasAuthorization; }),
    bindOutgoingSasFlow: vi.fn(async () => { calls.push('bind'); return { ...value, state: 'active', direction: 'outgoing', stage: 'bound', expiresAt: 20, generation: 6, flowId: '$flow' } as SasAuthorization; }),
    requireSasReverification: vi.fn(async (_profile, generation) => ({ schemaVersion: 1, profileId: value.profileId, sessionGeneration: 1, homeserver: value.homeserver, localUserId: value.localUserId, localDeviceId: value.localDeviceId, state: 'reverification-required', generation: generation + 1 } as SasAuthorization)),
  };
  return { value, calls, store, input: { locator: { profileId: value.profileId, generation: 1 }, binding: value, expectedGeneration: 4, roomEpoch: 0, readRoomEpoch: () => 0, now: 10, readNow: () => 10, expiresAt: 20, store, requestFlow: vi.fn(async () => { calls.push('effect'); return '$flow'; }) } };
};
const databases: string[] = [];
afterEach(async () => { await Promise.all(databases.splice(0).map(name => new Promise<void>(resolve => { const request = indexedDB.deleteDatabase(name); request.onsuccess = request.onerror = request.onblocked = () => resolve(); }))); });
const seedRealStore = async () => {
  const value = await binding(); const name = `controller-${crypto.randomUUID()}`; databases.push(name); const store = await IndexedDbSessionStore.open(indexedDB, name);
  const metadata = { key: MATRIX_ISSUER, issuer: MATRIX_ISSUER, authorizationEndpoint: MATRIX_AUTHORIZATION_ENDPOINT, tokenEndpoint: MATRIX_TOKEN_ENDPOINT, registrationEndpoint: MATRIX_REGISTRATION_ENDPOINT, revocationEndpoint: MATRIX_REVOCATION_ENDPOINT, issuerParameterSupported: false };
  await store.createAttempt({ state: 'a'.repeat(43), codeVerifier: 'b'.repeat(43), clientId: 'client', redirectUri: MATRIX_REDIRECT_URI, deviceId: 'd'.repeat(43), homeserver: MATRIX_HOMESERVER, metadata, createdAt: 1, expiresAt: 1000, spent: false }, 10); await store.consumeAttempt('a'.repeat(43), 10);
  await store.commitSession({ profileId: value.profileId, homeserver: MATRIX_HOMESERVER, issuer: MATRIX_ISSUER, metadata, clientId: 'client', redirectUri: MATRIX_REDIRECT_URI, userId: value.localUserId, deviceId: value.localDeviceId, accessToken: 'access', refreshToken: 'refresh', expiresAt: 1000, generation: 1 }, 'a'.repeat(43));
  const db = (store as unknown as { db: IDBDatabase }).db; const operation = { profileId: value.profileId, roomId: value.roomId, peerUserId: value.peerUserId, localDeviceId: value.localDeviceId, direction: 'outgoing', phase: 'intent', expiresAt: 1000, generation: 1 };
  await new Promise<void>((resolve, reject) => { const tx = db.transaction('sasOperations', 'readwrite'); tx.objectStore('sasOperations').put(operation); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
  return { value, store, operation };
};

describe('dormant outgoing SAS intent controller', () => {
  it('records intent, authoritative get, effect, then bind in exact order', async () => {
    const value = await candidate();
    expect(await beginDormantOutgoingSasFlow(value.input)).toBe('recorded');
    expect(value.calls).toEqual(['intent', 'authoritative get', 'effect', 'bind']); expect(value.input.requestFlow).toHaveBeenCalledOnce();
  });
  it('contains stale persisted intent before the effect and does not invoke it', async () => {
    const value = await candidate(); let reads = 0;
    value.input.readRoomEpoch = () => ++reads === 2 ? 1 : 0;
    expect(await beginDormantOutgoingSasFlow(value.input)).toBe('denied');
    expect(value.store.requireSasReverification).toHaveBeenCalledWith(expect.any(Object), 5); expect(value.input.requestFlow).not.toHaveBeenCalled();
  });
  it('contains pre-effect expiry drift without invoking the effect', async () => {
    const value = await candidate(); let reads = 0;
    value.input.readNow = () => ++reads === 2 ? 20 : 10;
    expect(await beginDormantOutgoingSasFlow(value.input)).toBe('denied');
    expect(value.store.requireSasReverification).toHaveBeenCalledWith(expect.any(Object), 5);
    expect(value.input.requestFlow).not.toHaveBeenCalled();
  });
  it('contains rejecting or malformed authoritative pre-effect rereads', async () => {
    for (const configure of [
      (value: Awaited<ReturnType<typeof candidate>>) => value.store.getSasAuthorization.mockRejectedValue(new Error('storage uncertainty')),
      (value: Awaited<ReturnType<typeof candidate>>) => value.store.getSasAuthorization.mockResolvedValue({} as SasAuthorization),
    ]) {
      const value = await candidate(); configure(value);
      expect(await beginDormantOutgoingSasFlow(value.input)).toBe('blocked');
      expect(value.store.requireSasReverification).toHaveBeenCalledWith(expect.any(Object), 5);
      expect(value.input.requestFlow).not.toHaveBeenCalled();
    }
  });
  it('makes every post-effect failure indeterminate and fences both possible generations', async () => {
    const value = await candidate(); value.input.requestFlow = vi.fn(async () => '$flow'); value.store.bindOutgoingSasFlow.mockRejectedValue(new Error('uncertain'));
    expect(await beginDormantOutgoingSasFlow(value.input)).toBe('indeterminate');
    expect(value.input.requestFlow).toHaveBeenCalledOnce(); expect(value.store.requireSasReverification).toHaveBeenNthCalledWith(1, expect.any(Object), 5); expect(value.store.requireSasReverification).toHaveBeenNthCalledWith(2, expect.any(Object), 6);
  });
  it('rejects malformed and exhausted inputs before persistence or effects', async () => {
    const value = await candidate();
    for (const input of [{ ...value.input, expectedGeneration: Number.MAX_SAFE_INTEGER - 2 }, { ...value.input, expiresAt: 10 }, { ...value.input, binding: { ...value.value, roomId: '!bad' } }]) {
      expect(await beginDormantOutgoingSasFlow(input as never)).toBe('blocked');
    }
    expect(value.store.createOutgoingSasIntent).not.toHaveBeenCalled(); expect(value.input.requestFlow).not.toHaveBeenCalled();
  });
  it('treats exact initial and create CAS misses as ordinary denials without containment', async () => {
    const stale = await candidate(); stale.input.readRoomEpoch = () => 1;
    expect(await beginDormantOutgoingSasFlow(stale.input)).toBe('denied'); expect(stale.store.createOutgoingSasIntent).not.toHaveBeenCalled();
    const miss = await candidate(); miss.store.createOutgoingSasIntent.mockResolvedValue(undefined as never);
    expect(await beginDormantOutgoingSasFlow(miss.input)).toBe('denied'); expect(miss.store.requireSasReverification).not.toHaveBeenCalled();
  });
  it('contains every pre-effect create, record, clock, and barrier uncertainty', async () => {
    const cases: Array<(value: Awaited<ReturnType<typeof candidate>>) => void> = [
      value => value.store.createOutgoingSasIntent.mockRejectedValue(new Error('commit then reject')),
      value => value.store.createOutgoingSasIntent.mockResolvedValue({} as SasAuthorization),
      value => { value.input.readRoomEpoch = (() => { let reads = 0; return () => ++reads === 2 ? Number.NaN : 0; })(); },
      value => { value.input.readNow = (() => { let reads = 0; return () => { if (++reads === 2) throw new Error('clock'); return 10; }; })(); },
    ];
    for (const configure of cases) {
      const value = await candidate(); configure(value);
      expect(await beginDormantOutgoingSasFlow(value.input)).toBe('blocked');
      expect(value.store.requireSasReverification).toHaveBeenCalledWith(expect.any(Object), 5);
      expect(value.input.requestFlow).not.toHaveBeenCalled();
    }
  });
  it('contains nonthenable, rejecting, malformed flow and bind outcomes without retrying the caller effect', async () => {
    const cases: Array<(value: Awaited<ReturnType<typeof candidate>>) => void> = [
      value => value.input.requestFlow = vi.fn(() => '$flow') as never,
      value => value.input.requestFlow = vi.fn(async () => { throw new Error('reject'); }),
      value => value.input.requestFlow = vi.fn(async () => 'bad'),
      value => value.store.bindOutgoingSasFlow.mockResolvedValue(undefined as never),
      value => value.store.bindOutgoingSasFlow.mockRejectedValue(new Error('commit then reject')),
    ];
    for (const configure of cases) {
      const value = await candidate(); configure(value);
      expect(await beginDormantOutgoingSasFlow(value.input)).toBe('indeterminate');
      expect(value.input.requestFlow).toHaveBeenCalledTimes(1);
      expect(value.store.requireSasReverification).toHaveBeenNthCalledWith(1, expect.any(Object), 5);
      expect(value.store.requireSasReverification).toHaveBeenNthCalledWith(2, expect.any(Object), 6);
    }
  });
  it('does not mutate caller input or retain mutable methods', async () => {
    const value = await candidate(); const before = structuredClone({ locator: value.input.locator, binding: value.input.binding });
    expect(await beginDormantOutgoingSasFlow(value.input)).toBe('recorded');
    expect({ locator: value.input.locator, binding: value.input.binding }).toEqual(before);
    value.input.requestFlow = vi.fn(async () => '$other');
    expect(value.input.requestFlow).not.toHaveBeenCalled();
  });
  it('captures original input, store methods, effect, epoch, clock, and identity before an awaited effect', async () => {
    const value = await candidate(); let release!: (id: string) => void;
    const pending = new Promise<string>(resolve => { release = resolve; });
    const originalEffect = vi.fn(() => pending); const replacementEffect = vi.fn(async () => '$replacement');
    const originalBind = value.store.bindOutgoingSasFlow; const originalBarrier = value.store.requireSasReverification;
    value.input.requestFlow = originalEffect;
    const running = beginDormantOutgoingSasFlow(value.input);
    await vi.waitFor(() => expect(originalEffect).toHaveBeenCalledOnce());
    value.input.requestFlow = replacementEffect;
    value.input.readRoomEpoch = () => 99; value.input.readNow = () => 99;
    value.input.binding = { ...value.input.binding, peerUserId: '@replacement:example.test' };
    value.store.bindOutgoingSasFlow = vi.fn(async () => { throw new Error('replacement bind'); });
    value.store.requireSasReverification = vi.fn(async () => { throw new Error('replacement barrier'); });
    release('$flow');
    expect(await running).toBe('recorded');
    expect(replacementEffect).not.toHaveBeenCalled(); expect(originalBind).toHaveBeenCalledOnce(); expect(originalBarrier).not.toHaveBeenCalled();
  });
  it.each(['epoch', 'expiry'] as const)('makes post-bind %s drift indeterminate and contains it', async (drift) => {
    const value = await candidate(); let reads = 0;
    if (drift === 'epoch') value.input.readRoomEpoch = () => ++reads >= 3 ? 1 : 0;
    else value.input.readNow = () => ++reads >= 3 ? 20 : 10;
    expect(await beginDormantOutgoingSasFlow(value.input)).toBe('indeterminate');
    expect(value.store.requireSasReverification).toHaveBeenNthCalledWith(1, expect.any(Object), 5);
    expect(value.store.requireSasReverification).toHaveBeenNthCalledWith(2, expect.any(Object), 6);
  });
  it('accepts the MAX_SAFE_INTEGER minus three generation boundary', async () => {
    const value = await candidate(); const generation = Number.MAX_SAFE_INTEGER - 3;
    value.store.createOutgoingSasIntent.mockResolvedValue({ ...value.value, state: 'active', direction: 'outgoing', stage: 'intent', expiresAt: 20, generation: generation + 1 } as SasAuthorization);
    value.store.getSasAuthorization.mockResolvedValue({ ...value.value, state: 'active', direction: 'outgoing', stage: 'intent', expiresAt: 20, generation: generation + 1 } as SasAuthorization);
    value.store.bindOutgoingSasFlow.mockResolvedValue({ ...value.value, state: 'active', direction: 'outgoing', stage: 'bound', expiresAt: 20, generation: generation + 2, flowId: '$flow' } as SasAuthorization);
    expect(await beginDormantOutgoingSasFlow({ ...value.input, expectedGeneration: generation })).toBe('recorded');
  });
  it('with real IndexedDB, startup quarantines a create that committed before its stale return', async () => {
    const { value, store, operation } = await seedRealStore(); let release!: () => void; const gate = new Promise<void>(done => { release = done; });
    const createOutgoingSasIntent = async (...args: Parameters<typeof store.createOutgoingSasIntent>) => { const created = await store.createOutgoingSasIntent(...args); await gate; return created; };
    const port = { getSasAuthorization: store.getSasAuthorization.bind(store), createOutgoingSasIntent, bindOutgoingSasFlow: store.bindOutgoingSasFlow.bind(store), requireSasReverification: store.requireSasReverification.bind(store) };
    const requestFlow = vi.fn(async () => '$flow');
    const running = beginDormantOutgoingSasFlow({ locator: { profileId: value.profileId, generation: 1 }, binding: value, expectedGeneration: 0, roomEpoch: 0, readRoomEpoch: () => 0, now: 10, readNow: () => 10, expiresAt: 20, store: port, requestFlow });
    await vi.waitFor(async () => expect(await store.getSasAuthorization({ profileId: value.profileId, generation: 1 })).toMatchObject({ state: 'active', stage: 'intent' }));
    expect(await store.prepareSasAuthorizationForStartup({ profileId: value.profileId, generation: 1 })).toBe('reverification-required'); release();
    expect(await running).toBe('denied'); expect(requestFlow).not.toHaveBeenCalled();
    expect(await store.getSasOperation({ profileId: value.profileId })).toEqual(operation);
    expect(await store.getSasAuthorization({ profileId: value.profileId, generation: 1 })).toMatchObject({ state: 'reverification-required', generation: 2 });
  });
  it('with real IndexedDB, startup wins a pending-effect bind race without touching v3', async () => {
    const { value, store, operation } = await seedRealStore(); let resolve!: (id: string) => void; const requested = new Promise<string>(done => { resolve = done; }); const requestFlow = vi.fn(() => requested);
    const running = beginDormantOutgoingSasFlow({ locator: { profileId: value.profileId, generation: 1 }, binding: value, expectedGeneration: 0, roomEpoch: 0, readRoomEpoch: () => 0, now: 10, readNow: () => 10, expiresAt: 20, store, requestFlow });
    await vi.waitFor(() => expect(requestFlow).toHaveBeenCalledOnce());
    expect(await store.prepareSasAuthorizationForStartup({ profileId: value.profileId, generation: 1 })).toBe('reverification-required'); resolve('$flow');
    expect(await running).toBe('indeterminate'); expect(await store.getSasOperation({ profileId: value.profileId })).toEqual(operation);
    expect(await store.getSasAuthorization({ profileId: value.profileId, generation: 1 })).toMatchObject({ state: 'reverification-required' });
  });
  it('with real IndexedDB, startup wins after bind commits before the final read', async () => {
    const { value, store, operation } = await seedRealStore(); let bound!: () => void; let release!: () => void; const afterBind = new Promise<void>(done => { bound = done; }); const gate = new Promise<void>(done => { release = done; });
    const port = { getSasAuthorization: store.getSasAuthorization.bind(store), createOutgoingSasIntent: store.createOutgoingSasIntent.bind(store), requireSasReverification: store.requireSasReverification.bind(store), bindOutgoingSasFlow: async (stable: SasStableGrantBinding, generation: number, flow: string) => { const result = await store.bindOutgoingSasFlow(stable, generation, flow); bound(); await gate; return result; } };
    const running = beginDormantOutgoingSasFlow({ locator: { profileId: value.profileId, generation: 1 }, binding: value, expectedGeneration: 0, roomEpoch: 0, readRoomEpoch: () => 0, now: 10, readNow: () => 10, expiresAt: 20, store: port, requestFlow: vi.fn(async () => '$flow') });
    await afterBind; expect(await store.prepareSasAuthorizationForStartup({ profileId: value.profileId, generation: 1 })).toBe('reverification-required'); release();
    // `recorded` is historical: bind committed even though startup subsequently made generation 3 durable.
    expect(await running).toBe('recorded'); expect(await store.getSasOperation({ profileId: value.profileId })).toEqual(operation);
    expect(await store.getSasAuthorization({ profileId: value.profileId, generation: 1 })).toMatchObject({ state: 'reverification-required', generation: 3 });
  });
});
