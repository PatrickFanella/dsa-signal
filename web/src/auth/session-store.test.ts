import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import { IndexedDbSessionStore, MAX_TERMINAL_OUTBOX, SessionStoreError, isAuthorizedOutboxRetry, type EndpointMetadata, type MatrixSession, type OAuthAttempt, type SasOperation, type SasStableGrantBinding, type TextOutboxRecord } from './session-store';
import { reduceOutgoing, type OutgoingMessage } from '../matrix/message-timeline';
import { MATRIX_AUTHORIZATION_ENDPOINT, MATRIX_CLIENT_METADATA_VERSION, MATRIX_HOMESERVER, MATRIX_ISSUER, MATRIX_REDIRECT_URI, MATRIX_REGISTRATION_ENDPOINT, MATRIX_REVOCATION_ENDPOINT, MATRIX_TOKEN_ENDPOINT } from './matrix-topology';

const ids: string[] = [];
afterEach(async () => { await Promise.all(ids.splice(0).map(name => new Promise<void>(resolve => { const request = indexedDB.deleteDatabase(name); request.onsuccess = request.onerror = request.onblocked = () => resolve(); }))); });
const open = () => { const name = `session-store-${crypto.randomUUID()}`; ids.push(name); return IndexedDbSessionStore.open(indexedDB, name); };
const metadata: EndpointMetadata = { key: MATRIX_ISSUER, issuer: MATRIX_ISSUER, authorizationEndpoint: MATRIX_AUTHORIZATION_ENDPOINT, tokenEndpoint: MATRIX_TOKEN_ENDPOINT, registrationEndpoint: MATRIX_REGISTRATION_ENDPOINT, revocationEndpoint: MATRIX_REVOCATION_ENDPOINT, issuerParameterSupported: false };
const attempt = (overrides: Partial<OAuthAttempt> = {}): OAuthAttempt => ({ state: 'a'.repeat(43), codeVerifier: 'b'.repeat(43), clientId: 'client', redirectUri: MATRIX_REDIRECT_URI, deviceId: 'd'.repeat(43), homeserver: MATRIX_HOMESERVER, metadata, createdAt: 1, expiresAt: 1000, spent: false, ...overrides });
const session = (overrides: Partial<MatrixSession> = {}): MatrixSession => ({ profileId: '4421c6877a6168a50fc657194c2cb7c665e0e570aa84b2cc5ef7d5bfe6f2a991', homeserver: MATRIX_HOMESERVER, issuer: metadata.issuer, metadata, clientId: 'client', redirectUri: MATRIX_REDIRECT_URI, userId: '@user:hs.example', deviceId: 'd'.repeat(43), accessToken: 'access', refreshToken: 'refresh', expiresAt: 1000, generation: 1, ...overrides });
const profile = { profileId: session().profileId };
const bootstrapBinding = { profileId: session().profileId, locatorGeneration: 1, sessionGeneration: 1, localDeviceId: 'd'.repeat(43) };
const legacySas = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({ ...profile, roomId: '!room:hs.example', peerUserId: '@peer:hs.example', localDeviceId: 'd'.repeat(43), direction: 'outgoing', phase: 'intent', expiresAt: 1000, generation: 1, ...overrides });
const b64_32 = (byte: number): string => btoa(String.fromCharCode(...new Uint8Array(32).fill(byte))).replace(/=+$/, '');
const sasBinding = (overrides: Partial<SasStableGrantBinding> = {}): SasStableGrantBinding => ({ schemaVersion: 1, ...profile, sessionGeneration: 1, homeserver: MATRIX_HOMESERVER, localUserId: '@user:hs.example', localDeviceId: 'd'.repeat(43), roomId: '!room:hs.example', peerUserId: '@peer:hs.example', localEd25519: b64_32(0), localCurve25519: b64_32(1), peerDeviceId: 'peer', peerEd25519: b64_32(2), peerCurve25519: b64_32(3), localMasterRef: b64_32(4), peerMasterRef: b64_32(5), ...overrides });
const sasOperation = (overrides: Partial<SasOperation> = {}): SasOperation => ({ ...profile, roomId: '!room:hs.example', peerUserId: '@peer:hs.example', localDeviceId: 'd'.repeat(43), direction: 'outgoing', phase: 'intent', expiresAt: 1000, generation: 1, ...overrides });
const outbox = (overrides: Partial<TextOutboxRecord> = {}): TextOutboxRecord => ({ ...profile, transactionId: 'txn', roomId: '!room:hs.example', bodyHash: 'a'.repeat(64), state: 'local-pending', baselineGeneration: 0, requiredGeneration: 0, retryConsumed: false, indeterminate: false, generation: 1, ...overrides } as unknown as TextOutboxRecord);
const activate = async (store: IndexedDbSessionStore): Promise<void> => { await store.createAttempt(attempt(), 10); await store.consumeAttempt('a'.repeat(43), 10); await store.commitSession(session(), 'a'.repeat(43)); };

describe('IndexedDbSessionStore', () => {
  it('keeps v3 SAS operations and v4 authorizations independent for the same profile', async () => {
    const store = await open(); await activate(store);
    const raw = (store as unknown as { db: IDBDatabase }).db;
    await new Promise<void>((resolve, reject) => { const tx = raw.transaction('sasOperations', 'readwrite'); tx.objectStore('sasOperations').put(sasOperation()); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    expect(await store.getSasAuthorization({ ...profile, generation: 1 })).toBeUndefined();
    expect(await store.createOutgoingSasIntent(sasBinding(), 0, 1000)).toMatchObject({ state: 'active' });
    expect(await store.getSasOperation(profile)).toEqual(sasOperation());
  });
  it('quarantines every active v4 authorization at store-only startup without touching v3', async () => {
    const store = await open(); await activate(store); const binding = sasBinding();
    const raw = (store as unknown as { db: IDBDatabase }).db;
    const putAuthorization = async (authorization: unknown): Promise<void> => new Promise((resolve, reject) => {
      const tx = raw.transaction(['sasAuthorizations', 'sasOperations'], 'readwrite');
      tx.objectStore('sasAuthorizations').put(authorization); tx.objectStore('sasOperations').put(sasOperation());
      tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
    });
    const authorization = async (): Promise<unknown> => new Promise((resolve, reject) => {
      const tx = raw.transaction('sasAuthorizations'); const request = tx.objectStore('sasAuthorizations').get(profile.profileId);
      tx.oncomplete = () => resolve(request.result); tx.onerror = () => reject(tx.error);
    });
    const operation = async (): Promise<unknown> => new Promise((resolve, reject) => {
      const tx = raw.transaction('sasOperations'); const request = tx.objectStore('sasOperations').get(profile.profileId);
      tx.oncomplete = () => resolve(request.result); tx.onerror = () => reject(tx.error);
    });
    const stages: Array<readonly ['incoming' | 'outgoing', 'intent' | 'bound' | 'consented' | 'sas-shown' | 'confirmation-intent']> = [
      ['outgoing', 'intent'], ['outgoing', 'bound'], ['outgoing', 'consented'], ['outgoing', 'sas-shown'], ['outgoing', 'confirmation-intent'],
      ['incoming', 'bound'], ['incoming', 'consented'], ['incoming', 'sas-shown'], ['incoming', 'confirmation-intent'],
    ];
    for (const [direction, stage] of stages) {
      const active = { ...binding, state: 'active', direction, stage, expiresAt: 1000, generation: 10, ...(stage === 'intent' ? {} : { flowId: '$flow' }) };
      await putAuthorization(active);
      expect(await store.prepareSasAuthorizationForStartup({ ...profile, generation: 1 })).toBe('reverification-required');
      expect(await authorization()).toEqual({ schemaVersion: 1, ...profile, sessionGeneration: 1, homeserver: MATRIX_HOMESERVER, localUserId: '@user:hs.example', localDeviceId: 'd'.repeat(43), state: 'reverification-required', generation: 11 });
      expect(await operation()).toEqual(sasOperation());
    }
    const firstBarrier = await authorization();
    expect(await store.prepareSasAuthorizationForStartup({ ...profile, generation: 1 })).toBe('reverification-required');
    expect(await authorization()).toEqual(firstBarrier);
    store.close();
    const reopened = await IndexedDbSessionStore.open(indexedDB, raw.name);
    expect(await reopened.prepareSasAuthorizationForStartup({ ...profile, generation: 1 })).toBe('reverification-required');
    const reopenedRaw = (reopened as unknown as { db: IDBDatabase }).db;
    await new Promise<void>((resolve, reject) => { const tx = reopenedRaw.transaction('sasAuthorizations', 'readwrite'); tx.objectStore('sasAuthorizations').put({ ...binding, state: 'granted', generation: 12 }); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    const grant = await new Promise<unknown>((resolve, reject) => { const tx = reopenedRaw.transaction('sasAuthorizations'); const request = tx.objectStore('sasAuthorizations').get(profile.profileId); tx.oncomplete = () => resolve(request.result); tx.onerror = () => reject(tx.error); });
    expect(await reopened.prepareSasAuthorizationForStartup({ ...profile, generation: 1 })).toBe('grant-revalidation-required');
    await expect(new Promise<unknown>((resolve, reject) => { const tx = reopenedRaw.transaction('sasAuthorizations'); const request = tx.objectStore('sasAuthorizations').get(profile.profileId); tx.oncomplete = () => resolve(request.result); tx.onerror = () => reject(tx.error); })).resolves.toEqual(grant);
  });
  it('leaves absent and stale startup authorizations untouched and fails closed atomically', async () => {
    const store = await open(); await activate(store); const raw = (store as unknown as { db: IDBDatabase }).db; const binding = sasBinding();
    const put = async (value: unknown): Promise<void> => new Promise((resolve, reject) => { const tx = raw.transaction('sasAuthorizations', 'readwrite'); tx.objectStore('sasAuthorizations').put(value); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    const get = async (): Promise<unknown> => new Promise((resolve, reject) => { const tx = raw.transaction('sasAuthorizations'); const request = tx.objectStore('sasAuthorizations').get(profile.profileId); tx.oncomplete = () => resolve(request.result); tx.onerror = () => reject(tx.error); });
    expect(await store.prepareSasAuthorizationForStartup({ ...profile, generation: 1 })).toBe('absent');
    const stale = { ...binding, state: 'granted', generation: 3, sessionGeneration: 2 };
    await put(stale); expect(await store.prepareSasAuthorizationForStartup({ ...profile, generation: 1 })).toBeUndefined(); expect(await get()).toEqual(stale);
    await put({ ...binding, state: 'active', direction: 'outgoing', stage: 'intent', expiresAt: 1000, generation: Number.MAX_SAFE_INTEGER });
    await expect(store.prepareSasAuthorizationForStartup({ ...profile, generation: 1 })).rejects.toMatchObject({ code: 'conflict' });
    expect(await get()).toMatchObject({ generation: Number.MAX_SAFE_INTEGER, state: 'active' });
    const malformed = { profileId: profile.profileId, state: 'active' };
    await put(malformed); await expect(store.prepareSasAuthorizationForStartup({ ...profile, generation: 1 })).rejects.toMatchObject({ code: 'invalid-record' });
    const inspector = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(raw.name); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    const persisted = await new Promise<unknown>((resolve, reject) => { const tx = inspector.transaction('sasAuthorizations'); const request = tx.objectStore('sasAuthorizations').get(profile.profileId); tx.oncomplete = () => resolve(request.result); tx.onerror = () => reject(tx.error); });
    inspector.close(); expect(persisted).toEqual(malformed);
  });
  it('does not mutate valid-shaped startup authorizations whose user or device identity drifts', async () => {
    const store = await open(); await activate(store); const raw = (store as unknown as { db: IDBDatabase }).db;
    const put = async (value: unknown): Promise<void> => new Promise((resolve, reject) => { const tx = raw.transaction('sasAuthorizations', 'readwrite'); tx.objectStore('sasAuthorizations').put(value); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    const bytes = async (): Promise<string> => new Promise((resolve, reject) => { const tx = raw.transaction('sasAuthorizations'); const request = tx.objectStore('sasAuthorizations').get(profile.profileId); tx.oncomplete = () => resolve(JSON.stringify(request.result)); tx.onerror = () => reject(tx.error); });
    for (const authorization of [
      { ...sasBinding(), state: 'active' as const, direction: 'outgoing' as const, stage: 'intent' as const, expiresAt: 1000, generation: 7, localUserId: '@other:hs.example' },
      { ...sasBinding(), state: 'active' as const, direction: 'outgoing' as const, stage: 'intent' as const, expiresAt: 1000, generation: 7, localDeviceId: 'e'.repeat(43) },
    ]) {
      await put(authorization); const before = await bytes();
      expect(await store.prepareSasAuthorizationForStartup({ ...profile, generation: 1 })).toBeUndefined();
      expect(await bytes()).toBe(before);
    }
  });
  it('does not inspect or mutate startup authorizations unless the exact active locator and session remain valid', async () => {
    const cases: Array<readonly [string, (db: IDBDatabase) => Promise<void>]> = [
      ['missing locator', db => mutate(db, ['locator'], stores => stores.locator.delete('active'))],
      ['malformed locator', db => mutate(db, ['locator'], stores => stores.locator.put({ key: 'active', profileId: 3, generation: 1 }))],
      ['replaced locator and session', db => mutate(db, ['locator', 'sessions'], stores => { stores.sessions.delete(profile.profileId); stores.sessions.put(session({ profileId: 'f'.repeat(64) })); stores.locator.put({ key: 'active', profileId: 'f'.repeat(64), generation: 1 }); })],
      ['generation-mismatched locator', db => mutate(db, ['locator'], stores => stores.locator.put({ key: 'active', ...profile, generation: 2 }))],
      ['missing session', db => mutate(db, ['sessions'], stores => stores.sessions.delete(profile.profileId))],
      ['malformed session', db => mutate(db, ['sessions'], stores => stores.sessions.put({ profileId: profile.profileId }))],
      ['generation-mismatched session', db => mutate(db, ['sessions'], stores => stores.sessions.put(session({ generation: 2 })))]
    ];
    const mutate = (db: IDBDatabase, names: string[], change: (stores: Record<string, IDBObjectStore>) => void): Promise<void> => new Promise((resolve, reject) => {
      const tx = db.transaction(names, 'readwrite'); const stores = Object.fromEntries(names.map(name => [name, tx.objectStore(name)])) as Record<string, IDBObjectStore>; change(stores); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error);
    });
    const readAuthorization = (db: IDBDatabase): Promise<unknown> => new Promise((resolve, reject) => {
      const tx = db.transaction('sasAuthorizations'); const request = tx.objectStore('sasAuthorizations').get(profile.profileId); tx.oncomplete = () => resolve(request.result); tx.onerror = () => reject(tx.error);
    });
    for (const [name, invalidate] of cases) for (const authorization of [undefined, { ...sasBinding(), state: 'active' as const, direction: 'outgoing' as const, stage: 'intent' as const, expiresAt: 1000, generation: 7 }]) {
      const store = await open(); await activate(store); const db = (store as unknown as { db: IDBDatabase }).db;
      if (authorization !== undefined) await mutate(db, ['sasAuthorizations'], stores => stores.sasAuthorizations.put(authorization));
      await invalidate(db);
      expect(await store.prepareSasAuthorizationForStartup({ ...profile, generation: 1 }), `${name}, ${authorization === undefined ? 'absent' : 'present'} authorization`).toBeUndefined();
      expect(await readAuthorization(db)).toEqual(authorization);
    }
  });
  it('persists the v3 request, peer, start, terminal, and disposal CAS lineage', async () => {
    const store = await open(); await activate(store);
    expect(await store.createSasIntent(sasOperation())).toBe(true);
    const requested = await store.bindSasRequest(profile, 1, '$request', '$request');
    const peer = await store.bindSasPeerDevice(profile, requested!.generation, 'peer');
    const ready = await store.advanceSasPhase(profile, peer!.generation, 'ready');
    const started = await store.bindSasStartEvent(profile, ready!.generation, '$start');
    const failed = await store.advanceSasPhase(profile, started!.generation, 'failed');
    expect(await store.disposeSasOperation(profile, failed!.generation)).toBe(true);
    expect(await store.getSasOperation(profile)).toMatchObject({ disposed: true, generation: failed!.generation + 1 });
  });
  it('persists only the v4 authorization progression and never grants early', async () => {
    const store = await open(); await activate(store); const binding = sasBinding();
    const intent = await store.createOutgoingSasIntent(binding, 0, 1000);
    expect(intent).toMatchObject({ state: 'active', stage: 'intent', generation: 1 });
    expect(await store.grantSasAuthorization(binding, intent!.generation)).toBeUndefined();
    const bound = await store.bindOutgoingSasFlow(binding, intent!.generation, '$flow');
    expect(await store.advanceSasAuthorizationStage(binding, bound!.generation, 'consented')).toBeUndefined();
    const shown = await store.advanceSasAuthorizationStage(binding, bound!.generation, 'sas-shown');
    const confirmation = await store.advanceSasAuthorizationStage(binding, shown!.generation, 'confirmation-intent');
    const grant = await store.grantSasAuthorization(binding, confirmation!.generation);
    expect(grant).toMatchObject({ state: 'granted' }); expect(grant).not.toHaveProperty('flowId'); expect(grant).not.toHaveProperty('expiresAt');
    expect(Object.keys(grant!).sort()).toEqual(['generation', 'homeserver', 'localCurve25519', 'localDeviceId', 'localEd25519', 'localMasterRef', 'localUserId', 'peerCurve25519', 'peerDeviceId', 'peerEd25519', 'peerMasterRef', 'peerUserId', 'profileId', 'roomId', 'schemaVersion', 'sessionGeneration', 'state'].sort());
  });
  it('requires durable incoming consent before showing, confirming, or granting SAS', async () => {
    const store = await open(); await activate(store); const binding = sasBinding();
    const bound = await store.createIncomingSasAuthorization(binding, 0, 1000, '$flow');
    expect(await store.advanceSasAuthorizationStage(binding, bound!.generation, 'sas-shown')).toBeUndefined();
    expect(await store.advanceSasAuthorizationStage(binding, bound!.generation, 'confirmation-intent')).toBeUndefined();
    expect(await store.grantSasAuthorization(binding, bound!.generation)).toBeUndefined();
    const consented = await store.advanceSasAuthorizationStage(binding, bound!.generation, 'consented');
    store.close();
    const reopened = await IndexedDbSessionStore.open(indexedDB, (store as unknown as { db: IDBDatabase }).db.name);
    expect(await reopened.getSasAuthorization({ ...profile, generation: 1 })).toMatchObject({ stage: 'consented' });
    const shown = await reopened.advanceSasAuthorizationStage(binding, consented!.generation, 'sas-shown');
    const confirmation = await reopened.advanceSasAuthorizationStage(binding, shown!.generation, 'confirmation-intent');
    expect(await reopened.grantSasAuthorization(binding, confirmation!.generation)).toMatchObject({ state: 'granted' });
  });
  it('rejects extra SAS authorization keys and stale session generations', async () => {
    const store = await open(); await activate(store); const binding = sasBinding();
    await expect(store.createOutgoingSasIntent({ ...binding, sas: 'secret' } as SasStableGrantBinding, 1, 1000)).rejects.toMatchObject({ code: 'invalid-record' });
    const fresh = await open(); await activate(fresh); expect(await fresh.createOutgoingSasIntent(binding, 1, 1000)).toBeUndefined();
    const raw = (fresh as unknown as { db: IDBDatabase }).db;
    await new Promise<void>((resolve, reject) => { const tx = raw.transaction('locator', 'readwrite'); tx.objectStore('locator').put({ key: 'active', ...profile, generation: 2 }); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    expect(await fresh.createOutgoingSasIntent(binding, 0, 1000)).toBeUndefined();
  });
  it('uses record generation zero for creation and keeps it independent of the active session generation', async () => {
    const store = await open(); await activate(store); const binding = sasBinding(); const common = { schemaVersion: binding.schemaVersion, profileId: binding.profileId, sessionGeneration: binding.sessionGeneration, homeserver: binding.homeserver, localUserId: binding.localUserId, localDeviceId: binding.localDeviceId } as const;
    const barrier = await store.requireSasReverification(common, 0);
    expect(barrier).toMatchObject({ state: 'reverification-required', generation: 1, sessionGeneration: 1 });
    const retry = await store.requireSasReverification(common, 0);
    expect(retry).toEqual(barrier);
    const converged = await store.requireSasReverification(common, 1);
    expect(converged).toEqual(barrier);
    expect(await store.createOutgoingSasIntent(binding, 1, 1000)).toMatchObject({ state: 'active', generation: 2 });
  });
  it('accepts canonical unpadded refs, equal valid keys, and only supported stable room IDs', async () => {
    const store = await open(); await activate(store); const binding = sasBinding({ peerEd25519: b64_32(0), peerCurve25519: b64_32(1), peerMasterRef: b64_32(4) });
    expect(await store.createOutgoingSasIntent(binding, 0, 1000)).toBeTruthy();
    await expect(store.createOutgoingSasIntent(sasBinding({ localEd25519: `${b64_32(0)}=` }), 0, 1000)).rejects.toMatchObject({ code: 'invalid-record' });
    await expect(store.createOutgoingSasIntent(sasBinding({ roomId: '!domainless' }), 0, 1000)).rejects.toMatchObject({ code: 'invalid-record' });
  });
  it('rejects noncanonical 32-byte standard Base64 fingerprint and master ref encodings', async () => {
    const invalid = [
      `${b64_32(0).slice(0, -1)}_`, // invalid alphabet
      `${b64_32(0)}=`, // padding
      b64_32(0).slice(0, -1), // wrong decoded length
      `${b64_32(0).slice(0, -1)}B`, // noncanonical pad bits
    ];
    const fields = ['localEd25519', 'localCurve25519', 'peerEd25519', 'peerCurve25519', 'localMasterRef', 'peerMasterRef'] as const;
    const store = await open(); await activate(store);
    for (const field of fields) for (const value of invalid) await expect(store.createOutgoingSasIntent(sasBinding({ [field]: value }), 0, 1000)).rejects.toMatchObject({ code: 'invalid-record' });
  });
  it('has a durable single-active attempt and consumes it once', async () => {
    const store = await open();
    await store.createAttempt(attempt(), 10);
    await expect(store.createAttempt(attempt({ state: 'c'.repeat(43) }), 10)).rejects.toMatchObject({ code: 'conflict' });
    expect((await store.consumeAttempt('a'.repeat(43), 10)).spent).toBe(true);
    await expect(store.consumeAttempt('a'.repeat(43), 10)).rejects.toMatchObject({ code: 'conflict' });
  });

  it('finalizes callback state and logout removes all session material', async () => {
    const store = await open();
    await store.createAttempt(attempt(), 10); await store.finalizeAttempt('a'.repeat(43));
    await expect(store.consumeAttempt('a'.repeat(43), 10)).rejects.toMatchObject({ code: 'conflict' });
    await store.createAttempt(attempt(), 10); await store.consumeAttempt('a'.repeat(43), 10); await store.commitSession(session(), 'a'.repeat(43));
    const active = await store.getActiveProfile(); await store.clearSessionAndAttemptsForLocator(active!); expect(await store.getActiveProfile()).toBeUndefined();
  });

  it('preserves a replacement locator during exact logout cleanup', async () => {
    const store = await open(); await store.createAttempt(attempt(), 10); await store.consumeAttempt('a'.repeat(43), 10); const active = await store.commitSession(session(), 'a'.repeat(43));
    await expect(store.clearSessionAndAttemptsForLocator({ ...active, generation: 2 })).resolves.toBe(false);
    expect(await store.getActiveProfile()).toEqual(active); expect(await store.loadSession(active)).toMatchObject({ accessToken: 'access' });
  });

  it('requires a spent attempt, detects locator drift, and preserves an omitted refresh token', async () => {
    const store = await open();
    await store.createAttempt(attempt(), 10);
    await expect(store.commitSession(session(), 'a'.repeat(43))).rejects.toMatchObject({ code: 'conflict' });
    await store.consumeAttempt('a'.repeat(43), 10);
    const active = await store.commitSession(session(), 'a'.repeat(43));
    expect(await store.loadSession({ ...active, generation: 2 })).toBeUndefined();
    expect((await store.commitRefreshedTokens(active, { accessToken: 'new-access', expiresAt: 2000 }))?.refreshToken).toBe('refresh');
  });
  it('recomputes the canonical profile ID before beginning a durable commit', async () => {
    const store = await open(); await store.createAttempt(attempt(), 10); await store.consumeAttempt('a'.repeat(43), 10);
    await expect(store.commitSession(session({ profileId: 'f'.repeat(64) }), 'a'.repeat(43))).rejects.toMatchObject({ code: 'invalid-record' });
    expect(await store.getActiveProfile()).toBeUndefined();
  });

  it('fails closed for corrupt records and never uses localStorage', async () => {
    const name = `session-store-${crypto.randomUUID()}`; ids.push(name);
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 1); request.onupgradeneeded = () => request.result.createObjectStore('locator', { keyPath: 'key' }); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    db.close();
    const raw = await new Promise<void>((resolve, reject) => { const request = indexedDB.open(name, 1); request.onsuccess = () => { const tx = request.result.transaction('locator', 'readwrite'); tx.objectStore('locator').put({ key: 'active', profileId: 3, generation: 1 }); tx.oncomplete = () => { request.result.close(); resolve(); }; tx.onerror = () => reject(tx.error); }; request.onerror = () => reject(request.error); });
    void raw;
    const store = await IndexedDbSessionStore.open(indexedDB, name);
    await expect(store.getActiveProfile()).rejects.toBeInstanceOf(SessionStoreError);
  });
  it('notifies once when an otherwise idle database closes unexpectedly', async () => {
    const store = await open(); let losses = 0; store.subscribeStorageLoss(() => { losses += 1; });
    // Invoke the registered event seam directly: fake-indexeddb closes before dispatch completes.
    const db = (store as unknown as { db: IDBDatabase }).db;
    db.onclose?.(new Event('close'));
    db.onclose?.(new Event('close'));
    expect(losses).toBe(1); await expect(store.getActiveProfile()).rejects.toMatchObject({ code: 'storage-lost' });
  });
  it('migrates a v1 database without losing its OAuth records', async () => {
    const name = `session-store-${crypto.randomUUID()}`; ids.push(name);
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 1); request.onupgradeneeded = () => { for (const [store, keyPath] of [['registrations', 'metadataKey'], ['attempts', 'state'], ['sessions', 'profileId'], ['locator', 'key']] as const) request.result.createObjectStore(store, { keyPath }); request.transaction!.objectStore('registrations').put({ metadataKey: metadata.key, clientId: 'client', redirectUri: MATRIX_REDIRECT_URI, metadata, createdAt: 1, clientMetadataVersion: MATRIX_CLIENT_METADATA_VERSION }); request.transaction!.objectStore('attempts').put(attempt()); request.transaction!.objectStore('sessions').put(session()); request.transaction!.objectStore('locator').put({ key: 'active', ...profile, generation: 1 }); }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    db.close(); const store = await IndexedDbSessionStore.open(indexedDB, name);
    expect(await store.getRegistration(metadata.key)).toMatchObject({ clientId: 'client' });
    expect(await store.loadSession({ ...profile, generation: 1 })).toMatchObject({ accessToken: 'access' });
    expect(await store.getBootstrapDisposition(profile)).toMatchObject({ state: 'never-attempted', generation: 0 });
    expect(await store.getSyncGeneration(profile)).toMatchObject({ syncGeneration: 0 });
  });
  it('upgrades v2 outbox records with indexes and bounded terminal retention', async () => {
    const name = `session-store-${crypto.randomUUID()}`; ids.push(name);
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 2); request.onupgradeneeded = () => { for (const [store, keyPath] of [['registrations', 'metadataKey'], ['attempts', 'state'], ['sessions', 'profileId'], ['locator', 'key'], ['bootstrapDispositions', 'profileId'], ['sasOperations', 'profileId'], ['syncProfiles', 'profileId']] as const) request.result.createObjectStore(store, { keyPath }); const { indeterminate: ignored, ...synced } = outbox({ state: 'synced', eventId: '$old' }); void ignored; request.result.createObjectStore('textOutbox', { keyPath: ['profileId', 'transactionId'] }).put(synced); }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    db.close(); const store = await IndexedDbSessionStore.open(indexedDB, name);
    const outboxStore = (store as unknown as { db: IDBDatabase }).db.transaction('textOutbox').objectStore('textOutbox');
    const eventId = outboxStore.index('eventId'); const profileState = outboxStore.index('profileState');
    expect({ name: eventId.name, keyPath: eventId.keyPath, unique: eventId.unique }).toEqual({ name: 'eventId', keyPath: 'eventId', unique: true });
    expect({ name: profileState.name, keyPath: profileState.keyPath, unique: profileState.unique }).toEqual({ name: 'profileState', keyPath: ['profileId', 'state'], unique: false });
    expect(await store.getTextOutboxRecord(profile, 'txn')).toMatchObject({ eventId: '$old', state: 'synced' });
  });
  it('fails the v3 upgrade when existing event ownership is duplicated', async () => {
    const name = `session-store-${crypto.randomUUID()}`; ids.push(name);
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 2); request.onupgradeneeded = () => { const store = request.result.createObjectStore('textOutbox', { keyPath: ['profileId', 'transactionId'] }); for (const transactionId of ['one', 'two']) { const { indeterminate: ignored, ...synced } = outbox({ transactionId, state: 'synced', eventId: '$duplicate' }); void ignored; store.put(synced); } }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    db.close(); await expect(IndexedDbSessionStore.open(indexedDB, name)).rejects.toMatchObject({ code: 'storage-unavailable' });
  });
  it('upgrades v3 directly to v5 without rewriting an active v3 SAS operation', async () => {
    const name = `session-store-${crypto.randomUUID()}`; ids.push(name);
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 3); request.onupgradeneeded = () => { for (const [store, keyPath] of [['sessions', 'profileId'], ['locator', 'key'], ['sasOperations', 'profileId']] as const) request.result.createObjectStore(store, { keyPath }); request.transaction!.objectStore('sessions').put(session()); request.transaction!.objectStore('locator').put({ key: 'active', ...profile, generation: 1 }); request.transaction!.objectStore('sasOperations').put(legacySas({ generation: 7 })); }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    db.close(); const store = await IndexedDbSessionStore.open(indexedDB, name);
    expect(await store.getSasOperation(profile)).toEqual(legacySas({ generation: 7 }));
    expect(await store.bindSasRequest(profile, 7, '$request', '$request')).toMatchObject({ phase: 'requested', generation: 8 });
    expect(await store.getSasAuthorization({ ...profile, generation: 1 })).toBeUndefined();
  });
  it('relocates exact v4 authorizations and aborts malformed or colliding v4 SAS rows', async () => {
    const create = async (operation: unknown, authorization?: unknown): Promise<string> => { const name = `session-store-${crypto.randomUUID()}`; ids.push(name); const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 4); request.onupgradeneeded = () => { for (const [store, keyPath] of [['sessions', 'profileId'], ['locator', 'key'], ['sasOperations', 'profileId']] as const) request.result.createObjectStore(store, { keyPath }); if (authorization !== undefined) request.result.createObjectStore('sasAuthorizations', { keyPath: 'profileId' }).put(authorization); request.transaction!.objectStore('sessions').put(session()); request.transaction!.objectStore('locator').put({ key: 'active', ...profile, generation: 1 }); request.transaction!.objectStore('sasOperations').put(operation); }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); }); db.close(); return name; };
    const authorization = { ...sasBinding(), state: 'active' as const, direction: 'incoming' as const, stage: 'consented' as const, expiresAt: 1000, flowId: '$flow', generation: 7 };
    const migrated = await IndexedDbSessionStore.open(indexedDB, await create(authorization));
    expect(await migrated.getSasAuthorization({ ...profile, generation: 1 })).toEqual(authorization);
    expect(await migrated.getSasOperation(profile)).toBeUndefined();
    const raw = (migrated as unknown as { db: IDBDatabase }).db;
    const old = await new Promise<unknown>((resolve, reject) => { const request = raw.transaction('sasOperations').objectStore('sasOperations').get(profile.profileId); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    expect(old).toBeUndefined();
    expect(await migrated.createSasIntent(sasOperation())).toBe(true);
    await expect(IndexedDbSessionStore.open(indexedDB, await create({ ...profile, generation: 'bad' }))).rejects.toMatchObject({ code: 'storage-unavailable' });
    await expect(IndexedDbSessionStore.open(indexedDB, await create(authorization, authorization))).rejects.toMatchObject({ code: 'storage-unavailable' });
  });
  it('upgrades mixed v4 SAS rows across profiles without rewriting either record shape', async () => {
    const name = `session-store-${crypto.randomUUID()}`; ids.push(name);
    const operation = legacySas({ generation: 7 });
    const authorizationProfile = { profileId: 'f'.repeat(64) };
    const authorization = { ...sasBinding({ ...authorizationProfile }), state: 'active' as const, direction: 'incoming' as const, stage: 'consented' as const, expiresAt: 1000, flowId: '$flow', generation: 7 };
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 4); request.onupgradeneeded = () => { for (const [store, keyPath] of [['sessions', 'profileId'], ['locator', 'key'], ['sasOperations', 'profileId']] as const) request.result.createObjectStore(store, { keyPath }); request.transaction!.objectStore('sessions').put(session()); request.transaction!.objectStore('locator').put({ key: 'active', ...profile, generation: 1 }); request.transaction!.objectStore('sasOperations').put(operation); request.transaction!.objectStore('sasOperations').put(authorization); }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    db.close(); const store = await IndexedDbSessionStore.open(indexedDB, name);
    expect(await store.getSasOperation(profile)).toEqual(operation);
    const raw = (store as unknown as { db: IDBDatabase }).db;
    const [operations, authorizations] = await new Promise<[unknown[], unknown[]]>((resolve, reject) => { const tx = raw.transaction(['sasOperations', 'sasAuthorizations']); const source = tx.objectStore('sasOperations').getAll(); const destination = tx.objectStore('sasAuthorizations').getAll(); tx.oncomplete = () => resolve([source.result, destination.result]); tx.onerror = () => reject(tx.error); });
    expect(operations).toEqual([operation]);
    expect(authorizations).toEqual([authorization]);
  });
  it('atomically rolls v5 relocation back for malformed and destination-colliding v4 rows', async () => {
    const create = async (operation: unknown, authorization?: unknown): Promise<string> => { const name = `session-store-${crypto.randomUUID()}`; ids.push(name); const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 4); request.onupgradeneeded = () => { for (const [store, keyPath] of [['sessions', 'profileId'], ['locator', 'key'], ['sasOperations', 'profileId'], ['sasAuthorizations', 'profileId']] as const) request.result.createObjectStore(store, { keyPath }); if (authorization !== undefined) request.transaction!.objectStore('sasAuthorizations').put(authorization); request.transaction!.objectStore('sasOperations').put(operation); }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); }); db.close(); return name; };
    const inspectV4 = async (name: string): Promise<[unknown[], unknown[]]> => { const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 4); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); }); const rows = await new Promise<[unknown[], unknown[]]>((resolve, reject) => { const tx = db.transaction(['sasOperations', 'sasAuthorizations']); const source = tx.objectStore('sasOperations').getAll(); const destination = tx.objectStore('sasAuthorizations').getAll(); tx.oncomplete = () => resolve([source.result, destination.result]); tx.onerror = () => reject(tx.error); }); db.close(); return rows; };
    const valid = { ...sasBinding(), state: 'active' as const, direction: 'incoming' as const, stage: 'consented' as const, expiresAt: 1000, flowId: '$flow', generation: 7 };
    for (const [operation, authorization] of [[{ ...profile, generation: 'bad' }, undefined], [valid, valid]] as const) {
      const name = await create(operation, authorization);
      const before = await inspectV4(name);
      await expect(IndexedDbSessionStore.open(indexedDB, name)).rejects.toMatchObject({ code: 'storage-unavailable' });
      expect(await inspectV4(name)).toEqual(before);
    }
  });
  it('prunes only synced v2 rows during v3 upgrade and retains every unresolved row', async () => {
    const name = `session-store-${crypto.randomUUID()}`; ids.push(name);
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(name, 2); request.onupgradeneeded = () => { const store = request.result.createObjectStore('textOutbox', { keyPath: ['profileId', 'transactionId'] }); for (let index = 0; index < MAX_TERMINAL_OUTBOX + 2; index += 1) { const { indeterminate: ignored, ...synced } = outbox({ transactionId: `synced-${index}`, state: 'synced', eventId: `$synced-${index}` }); void ignored; store.put(synced); } for (let index = 0; index < 3; index += 1) store.put(outbox({ transactionId: `pending-${index}`, indeterminate: true })); }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    db.close(); const store = await IndexedDbSessionStore.open(indexedDB, name);
    const raw = (store as unknown as { db: IDBDatabase }).db; const rows = await new Promise<TextOutboxRecord[]>((resolve, reject) => { const request = raw.transaction('textOutbox').objectStore('textOutbox').getAll(); request.onsuccess = () => resolve(request.result as TextOutboxRecord[]); request.onerror = () => reject(request.error); });
    expect(rows.filter(row => row.state === 'synced')).toHaveLength(MAX_TERMINAL_OUTBOX); expect(rows.filter(row => row.state === 'local-pending')).toHaveLength(3);
  });
  it('retains at most the documented terminal history while never pruning unresolved rows', async () => {
    const store = await open();
    for (let index = 0; index <= MAX_TERMINAL_OUTBOX; index += 1) {
      const transactionId = `terminal-${index}`;
      await store.createTextOutboxRecord(outbox({ transactionId }));
      await store.reconcileOutboxRemoteEcho(profile, transactionId, `$event-${index}`);
    }
    await store.createTextOutboxRecord(outbox({ transactionId: 'unresolved' }));
    const raw = (store as unknown as { db: IDBDatabase }).db;
    const terminal = await new Promise<unknown[]>((resolve, reject) => { const tx = raw.transaction('textOutbox'); const request = tx.objectStore('textOutbox').index('profileState').getAll(IDBKeyRange.only([profile.profileId, 'synced'])); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    expect(terminal).toHaveLength(MAX_TERMINAL_OUTBOX);
    expect(await store.getTextOutboxRecord(profile, `terminal-${MAX_TERMINAL_OUTBOX}`)).toMatchObject({ state: 'synced' });
    expect(await store.getTextOutboxRecord(profile, 'unresolved')).toMatchObject({ state: 'local-pending' });
  });
  it('CASes bootstrap disposition and rejects its terminal recovery transition', async () => {
    const store = await open(); await activate(store); const initial = await store.getBootstrapDisposition(profile);
    const pending = await store.compareAndSetBootstrapDisposition(initial, 'pending-uia', bootstrapBinding);
    expect(pending).toMatchObject({ state: 'pending-uia', generation: 1 });
    expect(await store.compareAndSetBootstrapDisposition(initial, 'recovery-required', bootstrapBinding)).toBeUndefined();
    const published = await store.compareAndSetBootstrapDisposition(pending!, 'published', bootstrapBinding);
    const recovery = await store.compareAndSetBootstrapDisposition(published!, 'recovery-required', bootstrapBinding);
    await expect(store.compareAndSetBootstrapDisposition(recovery!, 'pending-uia', bootstrapBinding)).rejects.toMatchObject({ code: 'conflict' });
  });
  it('does not mutate bootstrap disposition when the active locator or session device drifts', async () => {
    const store = await open(); await activate(store); const initial = await store.getBootstrapDisposition(profile);
    const raw = (store as unknown as { db: IDBDatabase }).db;
    await new Promise<void>((resolve, reject) => { const tx = raw.transaction('locator', 'readwrite'); tx.objectStore('locator').put({ key: 'active', ...profile, generation: 2 }); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    expect(await store.compareAndSetBootstrapDisposition(initial, 'pending-uia', bootstrapBinding)).toBeUndefined();
    await new Promise<void>((resolve, reject) => { const tx = raw.transaction(['locator', 'sessions'], 'readwrite'); tx.objectStore('locator').put({ key: 'active', ...profile, generation: 1 }); tx.objectStore('sessions').put(session({ deviceId: 'replacement-device' })); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    expect(await store.compareAndSetBootstrapDisposition(initial, 'pending-uia', bootstrapBinding)).toBeUndefined();
    expect(await store.getBootstrapDisposition(profile)).toMatchObject({ state: 'never-attempted', generation: 0 });
  });
  it('rebases every unresolved send, invalidating stale callbacks and requiring a later sync', async () => {
    const name = `session-store-${crypto.randomUUID()}`; ids.push(name); const store = await IndexedDbSessionStore.open(indexedDB, name);
    await store.createTextOutboxRecord(outbox());
    expect(await store.rebaseUnresolvedOutbox(profile)).toBe(1);
    const rebased = await store.getTextOutboxRecord(profile, 'txn');
    expect(rebased).toMatchObject({ indeterminate: true, requiredGeneration: 1, generation: 2 });
    expect(await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), 1)).toBeUndefined();
    expect(await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), 2)).toBeUndefined();
    await store.incrementSyncGeneration(profile);
    expect(await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), 2)).toMatchObject({ record: { retryConsumed: true } });
  });
  it('atomically captures the sync baseline for an initial plaintext-free outbox row', async () => {
    const store = await open(); await store.incrementSyncGeneration(profile);
    const { baselineGeneration: _baseline, requiredGeneration: _required, generation: _generation, ...initial } = outbox();
    void _baseline; void _required; void _generation;
    const created = await store.createInitialTextOutboxRecord(initial);
    expect(created).toMatchObject({ baselineGeneration: 1, requiredGeneration: 1, generation: 1, bodyHash: 'a'.repeat(64) });
    expect(await store.createInitialTextOutboxRecord(initial)).toBeUndefined();
  });
  it('rebases ordinary and already-indeterminate crash-window rows, and makes settlement outcomes explicit', async () => {
    const store = await open(); await store.createTextOutboxRecord(outbox());
    await store.createTextOutboxRecord(outbox({ transactionId: 'other' }));
    await store.markOutboxIndeterminate(profile, 'other', 1);
    expect(await store.rebaseUnresolvedOutbox(profile)).toBe(2);
    const ordinary = await store.getTextOutboxRecord(profile, 'txn'); const prior = await store.getTextOutboxRecord(profile, 'other');
    expect(ordinary).toMatchObject({ indeterminate: true, generation: 2, requiredGeneration: 1 });
    expect(prior).toMatchObject({ indeterminate: true, generation: 3, requiredGeneration: 1 });
    const accepted = await store.recordOutboxAcceptance(profile, 'txn', ordinary!.generation, '$event');
    expect(accepted).toMatchObject({ kind: 'updated', record: { eventId: '$event' } });
    expect(await store.recordOutboxAcceptance(profile, 'txn', ordinary!.generation, '$event')).toMatchObject({ kind: 'unchanged' });
    expect(await store.recordOutboxAcceptance(profile, 'txn', ordinary!.generation, '$other')).toEqual({ kind: 'conflict' });
    expect(await store.reconcileOutboxRemoteEcho(profile, 'other', '$event')).toEqual({ kind: 'conflict' });
    const echoed = await store.reconcileOutboxRemoteEcho(profile, 'other', '$echo');
    expect(echoed).toMatchObject({ kind: 'updated', record: { state: 'synced' } });
    expect(await store.recordOutboxAcceptance(profile, 'other', prior!.generation, '$different')).toEqual({ kind: 'conflict' });
  });
  it('marks raw rejection with an atomic barrier and permits exactly one retry after sync', async () => {
    const store = await open(); await store.createTextOutboxRecord(outbox());
    const rejected = await store.markOutboxIndeterminate(profile, 'txn', 1);
    expect(rejected).toMatchObject({ indeterminate: true, requiredGeneration: 1, generation: 2 });
    expect(await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), 2)).toBeUndefined();
    await store.incrementSyncGeneration(profile);
    const retry = await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), 2);
    expect(retry).toMatchObject({ record: { retryConsumed: true } });
    expect(await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), retry!.record.generation)).toBeUndefined();
  });
  it('rolls an uninvoked authorized retry back without weakening its sync barrier', async () => {
    const store = await open(); await store.createTextOutboxRecord(outbox());
    const indeterminate = await store.markOutboxIndeterminate(profile, 'txn', 1); await store.incrementSyncGeneration(profile);
    const retry = await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), indeterminate!.generation);
    const rollback = await store.rollbackOutboxRetry(profile, 'txn', 'a'.repeat(64), retry!.record.generation);
    expect(rollback).toMatchObject({ indeterminate: true, retryConsumed: false, requiredGeneration: indeterminate!.requiredGeneration, generation: retry!.record.generation + 1 });
    expect(await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), rollback!.generation)).toMatchObject({ record: { retryConsumed: true } });
    expect(await store.rollbackOutboxRetry(profile, 'txn', 'a'.repeat(64), retry!.record.generation)).toBeUndefined();
  });
  it('projects a store-CAS-authorized retry into the reducer exactly once', async () => {
    const store = await open(); await store.createTextOutboxRecord(outbox());
    const indeterminate = await store.markOutboxIndeterminate(profile, 'txn', 1); await store.incrementSyncGeneration(profile);
    const retry = await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), indeterminate!.generation);
    const current: OutgoingMessage = { localId: 'local', profileId: profile.profileId, transactionId: 'txn', bodyHash: 'a'.repeat(64), delivery: 'local-pending', indeterminate: true, retryConsumed: false, generation: indeterminate!.generation, requiredGeneration: indeterminate!.requiredGeneration };
    expect(isAuthorizedOutboxRetry(retry)).toBe(true);
    const projected = reduceOutgoing(current, { type: 'retry', authorized: retry! });
    expect(projected).toMatchObject({ kind: 'updated', message: { generation: retry!.record.generation, retryConsumed: true } });
    expect(reduceOutgoing(projected.message, { type: 'retry', authorized: retry! })).toMatchObject({ kind: 'unchanged' });
    const fabricated = { record: retry!.record } as unknown as typeof retry;
    const cloned = structuredClone(retry) as typeof retry;
    const serialized = JSON.parse(JSON.stringify(retry)) as typeof retry;
    expect(isAuthorizedOutboxRetry(fabricated)).toBe(false);
    expect(isAuthorizedOutboxRetry(cloned)).toBe(false);
    expect(isAuthorizedOutboxRetry(serialized)).toBe(false);
    expect(reduceOutgoing(current, { type: 'retry', authorized: fabricated! })).toMatchObject({ kind: 'unchanged' });
    expect(reduceOutgoing(current, { type: 'retry', authorized: cloned! })).toMatchObject({ kind: 'unchanged' });
    expect(reduceOutgoing(current, { type: 'retry', authorized: serialized! })).toMatchObject({ kind: 'unchanged' });
  });
  it('leaves resolved rows untouched by rebase and rejects generation overflow before writing', async () => {
    const store = await open(); await store.createTextOutboxRecord(outbox());
    const accepted = await store.recordOutboxAcceptance(profile, 'txn', 1, '$event');
    await store.reconcileOutboxRemoteEcho(profile, 'txn', '$event');
    expect(await store.rebaseUnresolvedOutbox(profile)).toBe(0);
    expect(await store.getTextOutboxRecord(profile, 'txn')).toMatchObject({ state: 'synced', generation: accepted.kind === 'updated' ? accepted.record.generation + 1 : 0 });
    const raw = (store as unknown as { db: IDBDatabase }).db;
    await new Promise<void>((resolve, reject) => { const tx = raw.transaction('textOutbox', 'readwrite'); tx.objectStore('textOutbox').put(outbox({ transactionId: 'max', generation: Number.MAX_SAFE_INTEGER })); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    await expect(store.rebaseUnresolvedOutbox(profile)).rejects.toMatchObject({ code: 'conflict' });
    expect(await store.getTextOutboxRecord(profile, 'max')).toMatchObject({ generation: Number.MAX_SAFE_INTEGER, indeterminate: false });
    await new Promise<void>((resolve, reject) => { const tx = raw.transaction('syncProfiles', 'readwrite'); tx.objectStore('syncProfiles').put({ ...profile, syncGeneration: Number.MAX_SAFE_INTEGER }); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    await expect(store.markOutboxIndeterminate(profile, 'max', Number.MAX_SAFE_INTEGER)).rejects.toMatchObject({ code: 'conflict' });
    expect(await store.getTextOutboxRecord(profile, 'max')).toMatchObject({ generation: Number.MAX_SAFE_INTEGER, indeterminate: false });
  });
  it('preflights every rebase before writing any selected row', async () => {
    const store = await open();
    await store.createTextOutboxRecord(outbox({ transactionId: 'early' }));
    const before = await store.getTextOutboxRecord(profile, 'early');
    const raw = (store as unknown as { db: IDBDatabase }).db;
    await new Promise<void>((resolve, reject) => { const tx = raw.transaction('textOutbox', 'readwrite'); tx.objectStore('textOutbox').put(outbox({ transactionId: 'later', generation: Number.MAX_SAFE_INTEGER })); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    await expect(store.rebaseUnresolvedOutbox(profile)).rejects.toMatchObject({ code: 'conflict' });
    expect(await store.getTextOutboxRecord(profile, 'early')).toEqual(before);
  });
  it('rejects unknown plaintext/display keys rather than persisting them', async () => {
    const store = await open();
    await expect(store.createTextOutboxRecord({ ...outbox(), body: 'plaintext' } as unknown as TextOutboxRecord)).rejects.toMatchObject({ code: 'invalid-record' });
    await activate(store); const initial = await store.getBootstrapDisposition(profile);
    await store.compareAndSetBootstrapDisposition(initial, 'pending-uia', bootstrapBinding);
    const raw = (store as unknown as { db: IDBDatabase }).db;
    await new Promise<void>((resolve, reject) => { const tx = raw.transaction('syncProfiles', 'readwrite'); tx.objectStore('syncProfiles').put({ ...profile, syncGeneration: 1, since: 'secret-token' }); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    await expect(store.getSyncGeneration(profile)).rejects.toMatchObject({ code: 'invalid-record' });
  });
  it('keeps definite failure out of durable outbox records', async () => {
    const store = await open();
    await expect(store.createTextOutboxRecord(outbox({ indeterminate: true, requiredGeneration: 1 }))).rejects.toMatchObject({ code: 'invalid-record' });
    await store.createTextOutboxRecord(outbox());
    const indeterminate = await store.markOutboxIndeterminate(profile, 'txn', 1);
    expect(indeterminate).toMatchObject({ state: 'local-pending', indeterminate: true });
  });
  it('does not let a different remote echo replace an accepted event identity', async () => {
    const store = await open(); await store.createTextOutboxRecord(outbox());
    const accepted = await store.recordOutboxAcceptance(profile, 'txn', 1, '$accepted');
    expect(accepted).toMatchObject({ kind: 'updated', record: { state: 'homeserver-accepted', eventId: '$accepted' } });
    expect(await store.reconcileOutboxRemoteEcho(profile, 'txn', '$other')).toEqual({ kind: 'conflict' });
    expect(await store.reconcileOutboxRemoteEcho(profile, 'txn', '$accepted')).toMatchObject({ kind: 'updated', record: { state: 'synced', eventId: '$accepted' } });
  });
  it('enumerates no-plaintext unresolved records and requires the exact body hash to retry', async () => {
    const store = await open(); await store.createTextOutboxRecord(outbox());
    const failed = await store.markOutboxIndeterminate(profile, 'txn', 1);
    expect(await store.listUnresolvedTextOutboxRecords(profile, 1)).toEqual([expect.objectContaining({ transactionId: 'txn', bodyHash: 'a'.repeat(64) })]);
    expect(await store.consumeOutboxRetry(profile, 'txn', 'b'.repeat(64), failed!.generation)).toBeUndefined();
    await store.incrementSyncGeneration(profile);
    expect(await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), failed!.generation)).toMatchObject({ record: { state: 'local-pending', retryConsumed: true } });
  });
  it('bounds unresolved outbox enumeration to the requested limit', async () => {
    const store = await open();
    await store.createTextOutboxRecord(outbox({ transactionId: 'txn-1' }));
    await store.createTextOutboxRecord(outbox({ transactionId: 'txn-2' }));
    await store.createTextOutboxRecord(outbox({ transactionId: 'txn-3' }));
    expect(await store.listUnresolvedTextOutboxRecords(profile, 2)).toHaveLength(2);
    await expect(store.listUnresolvedTextOutboxRecords(profile, 0)).rejects.toMatchObject({ code: 'invalid-record' });
  });
  it('allows a consumed retry to settle once and rejects event IDs held by another profile transaction pair', async () => {
    const store = await open(); await store.createTextOutboxRecord(outbox());
    const failed = await store.markOutboxIndeterminate(profile, 'txn', 1); await store.incrementSyncGeneration(profile);
    const retry = await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), failed!.generation);
    expect(await store.consumeOutboxRetry(profile, 'txn', 'a'.repeat(64), retry!.record.generation)).toBeUndefined();
    const accepted = await store.recordOutboxAcceptance(profile, 'txn', retry!.record.generation, '$event');
    expect(accepted).toMatchObject({ kind: 'updated', record: { state: 'homeserver-accepted', retryConsumed: true } });
    const other = { profileId: 'f'.repeat(64) }; await store.createTextOutboxRecord(outbox({ ...other }));
    expect(await store.recordOutboxAcceptance(other, 'txn', 1, '$event')).toEqual({ kind: 'conflict' });
  });
});
