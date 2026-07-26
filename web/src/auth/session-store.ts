/** Browser-only, fail-closed persistence for Matrix OAuth material. */
import { MATRIX_AUTHORIZATION_ENDPOINT, MATRIX_CLIENT_METADATA_VERSION, MATRIX_HOMESERVER, MATRIX_ISSUER, MATRIX_REDIRECT_URI, MATRIX_REGISTRATION_ENDPOINT, MATRIX_REVOCATION_ENDPOINT, MATRIX_TOKEN_ENDPOINT } from './matrix-topology';
import { canonicalProfileId } from './canonical-profile';
import { parseMatrixDeviceId, parseMatrixUserId, parseSupportedDomainRoomId } from '../matrix/identifiers';
export type CanonicalBase64Url = string;

export interface EndpointMetadata {
  readonly key: string;
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly registrationEndpoint?: string;
  readonly revocationEndpoint: string;
  readonly issuerParameterSupported: boolean;
}

export interface OAuthRegistration {
  readonly metadataKey: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly metadata: EndpointMetadata;
  readonly createdAt: number;
  readonly clientMetadataVersion: string;
}

export interface OAuthAttempt {
  readonly state: CanonicalBase64Url;
  readonly codeVerifier: CanonicalBase64Url;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly deviceId: string;
  /** Exact homeserver selected before the authorization redirect. */
  readonly homeserver: string;
  readonly metadata: EndpointMetadata;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly spent: boolean;
}

export interface MatrixSession {
  readonly profileId: string;
  readonly homeserver: string;
  readonly issuer: string;
  readonly metadata: EndpointMetadata;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresAt: number;
  readonly generation: number;
}

export interface ActiveProfileLocator { readonly profileId: string; readonly generation: number; }
export interface RefreshTokens { readonly accessToken: string; readonly refreshToken?: string; readonly expiresAt: number; }

export class SessionStoreError extends Error {
  public constructor(public readonly code: 'storage-unavailable' | 'storage-lost' | 'conflict' | 'invalid-record', message = 'Secure browser storage is unavailable') {
    super(message);
    this.name = 'SessionStoreError';
  }
}

const DATABASE = 'dsa-signal-session-v1';
// Version 1 contained only OAuth state.  New state is deliberately separate
// from sessions so a token replacement cannot accidentally replace crypto work.
const VERSION = 5;
const REGISTRATIONS = 'registrations';
const ATTEMPTS = 'attempts';
const SESSIONS = 'sessions';
const LOCATOR = 'locator';
const ACTIVE = 'active';
const BOOTSTRAPS = 'bootstrapDispositions';
const SAS_OPERATIONS = 'sasOperations';
const SAS_AUTHORIZATIONS = 'sasAuthorizations';
const OUTBOX = 'textOutbox';
const SYNC_PROFILES = 'syncProfiles';
const OUTBOX_EVENT_ID = 'eventId';
const OUTBOX_PROFILE_STATE = 'profileState';
/** Terminal delivery history is diagnostic only; unresolved work is never evicted. */
export const MAX_TERMINAL_OUTBOX = 256;
const b64url43 = /^[A-Za-z0-9_-]{43}$/;
/** Matrix device IDs are opaque server identifiers, not OAuth random values. */
const matrixDeviceId = (value: unknown): value is string => parseMatrixDeviceId(value) !== undefined;
const profileId = /^[a-f0-9]{64}$/;
const hash = /^[a-f0-9]{64}$/;
const object = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const text = (value: unknown): value is string => typeof value === 'string' && value.length > 0;
const number = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);
const url = (value: unknown): value is string => {
  if (!text(value)) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '' && parsed.search === '' && parsed.hash === '';
  } catch { return false; }
};

function metadata(value: unknown): value is EndpointMetadata {
  return object(value) && text(value.key) && url(value.issuer) && url(value.authorizationEndpoint) && url(value.tokenEndpoint)
    && text(value.revocationEndpoint) && url(value.revocationEndpoint) && typeof value.issuerParameterSupported === 'boolean'
    && value.key === MATRIX_ISSUER && value.issuer === MATRIX_ISSUER && value.authorizationEndpoint === MATRIX_AUTHORIZATION_ENDPOINT && value.tokenEndpoint === MATRIX_TOKEN_ENDPOINT && value.registrationEndpoint === MATRIX_REGISTRATION_ENDPOINT && value.revocationEndpoint === MATRIX_REVOCATION_ENDPOINT;
}
function registration(value: unknown): value is OAuthRegistration {
  return object(value) && text(value.metadataKey) && text(value.clientId) && url(value.redirectUri)
    && number(value.createdAt) && value.clientMetadataVersion === MATRIX_CLIENT_METADATA_VERSION && metadata(value.metadata) && value.metadata.key === value.metadataKey && value.redirectUri === MATRIX_REDIRECT_URI;
}
function attempt(value: unknown): value is OAuthAttempt {
  return object(value) && text(value.state) && b64url43.test(value.state) && text(value.codeVerifier) && b64url43.test(value.codeVerifier)
    && text(value.clientId) && value.redirectUri === MATRIX_REDIRECT_URI && text(value.deviceId) && b64url43.test(value.deviceId) && value.homeserver === MATRIX_HOMESERVER && metadata(value.metadata)
    && number(value.createdAt) && number(value.expiresAt) && typeof value.spent === 'boolean';
}
function session(value: unknown): value is MatrixSession {
  return object(value) && text(value.profileId) && profileId.test(value.profileId) && value.homeserver === MATRIX_HOMESERVER && value.issuer === MATRIX_ISSUER && metadata(value.metadata) && value.issuer === value.metadata.issuer
    && text(value.clientId) && value.redirectUri === MATRIX_REDIRECT_URI && parseMatrixUserId(value.userId) !== undefined && text(value.deviceId) && b64url43.test(value.deviceId) && text(value.accessToken)
    && (value.refreshToken === undefined || text(value.refreshToken)) && number(value.expiresAt) && number(value.generation) && Number.isSafeInteger(value.generation) && value.generation > 0;
}
function locator(value: unknown): value is ActiveProfileLocator {
  return object(value) && text(value.profileId) && profileId.test(value.profileId) && number(value.generation) && Number.isSafeInteger(value.generation) && value.generation > 0;
}
const clone = <T>(value: T): T => structuredClone(value);

export type CrossSigningBootstrapState = 'never-attempted' | 'pending-uia' | 'published' | 'recovery-required';
export interface ProfileStateKey { readonly profileId: string; }
export interface CrossSigningBootstrapDisposition extends ProfileStateKey {
  readonly state: CrossSigningBootstrapState;
  readonly generation: number;
}
/** Immutable session binding required for a cross-signing state transition. */
export interface CrossSigningBootstrapBinding extends ProfileStateKey {
  readonly locatorGeneration: number;
  readonly sessionGeneration: number;
  readonly localDeviceId: string;
}
export type SasDirection = 'incoming' | 'outgoing';
export type SasAuthorizationStage = 'intent' | 'bound' | 'consented' | 'sas-shown' | 'confirmation-intent';
export interface SasProfileBinding extends ProfileStateKey { readonly schemaVersion: 1; readonly sessionGeneration: number; readonly homeserver: string; readonly localUserId: string; readonly localDeviceId: string; }
export interface SasStableGrantBinding extends SasProfileBinding { readonly roomId: string; readonly peerUserId: string; readonly localEd25519: string; readonly localCurve25519: string; readonly peerDeviceId: string; readonly peerEd25519: string; readonly peerCurve25519: string; readonly localMasterRef: string; readonly peerMasterRef: string; }
export type SasAuthorization = (SasProfileBinding & { readonly state: 'reverification-required'; readonly generation: number }) | (SasStableGrantBinding & { readonly state: 'active'; readonly direction: 'outgoing'; readonly stage: 'intent'; readonly expiresAt: number; readonly generation: number; readonly flowId?: never }) | (SasStableGrantBinding & { readonly state: 'active'; readonly direction: SasDirection; readonly stage: Exclude<SasAuthorizationStage, 'intent'>; readonly expiresAt: number; readonly generation: number; readonly flowId: string }) | (SasStableGrantBinding & { readonly state: 'granted'; readonly generation: number });
/** Store-only startup disposition; callers must perform any runtime work separately. */
export type SasStartupAuthorizationPreparationResult = undefined | 'absent' | 'reverification-required' | 'grant-revalidation-required';
export type SasPhase = 'intent' | 'requested' | 'accepted' | 'ready' | 'started' | 'sas-shown' | 'confirming' | 'done' | 'failed' | 'cancelled';
export interface SasOperation extends ProfileStateKey { readonly roomId: string; readonly peerUserId: string; readonly localDeviceId: string; readonly direction: SasDirection; readonly phase: SasPhase; readonly expiresAt: number; readonly generation: number; readonly requestEventId?: string; readonly transactionId?: string; readonly peerDeviceId?: string; readonly startEventId?: string; readonly disposed?: boolean; }
export interface SasWireContext { readonly roomId: string; readonly sender: string; readonly requestEventId: string; readonly peerDeviceId: string; readonly localDeviceId: string; }
export const matchesSasWireContext = (operation: SasOperation, context: SasWireContext): boolean => operation.roomId === context.roomId && operation.requestEventId === context.requestEventId && operation.peerUserId === context.sender && operation.peerDeviceId === context.peerDeviceId && operation.localDeviceId === context.localDeviceId;
export type TextOutboxState = 'local-pending' | 'homeserver-accepted' | 'synced';
interface TextOutboxBase extends ProfileStateKey {
  /** Stable logical id, normally the Matrix transaction id. */
  readonly transactionId: string;
  readonly roomId: string;
  /** SHA-256 of the plaintext; plaintext is intentionally never persisted. */
  readonly bodyHash: string;
  readonly baselineGeneration: number;
  readonly requiredGeneration: number;
  readonly retryConsumed: boolean;
  readonly generation: number;
}
export type TextOutboxRecord = TextOutboxBase & (
  | { readonly state: 'local-pending'; readonly eventId?: never; readonly indeterminate: boolean }
  | { readonly state: 'homeserver-accepted' | 'synced'; readonly eventId: string; readonly indeterminate?: never }
);
/** Opaque runtime proof that this exact retry was durably consumed by this store. */
export interface AuthorizedOutboxRetry { readonly record: Readonly<TextOutboxRecord>; }
const authorizedOutboxRetries = new WeakSet<object>();
export const isAuthorizedOutboxRetry = (value: unknown): value is AuthorizedOutboxRetry =>
  object(value) && authorizedOutboxRetries.has(value);
const authorizeOutboxRetry = (record: TextOutboxRecord): AuthorizedOutboxRetry => {
  const authorized = Object.freeze({ record: Object.freeze(clone(record)) });
  authorizedOutboxRetries.add(authorized);
  return authorized;
};
/** Explicit send-settlement outcomes; identities are never overwritten. */
export type TextOutboxOutcome =
  | { readonly kind: 'updated' | 'unchanged'; readonly record: TextOutboxRecord }
  | { readonly kind: 'missing' | 'conflict' };
export interface ProfileSyncGeneration extends ProfileStateKey { readonly syncGeneration: number; }
const integer = (value: unknown): value is number => number(value) && Number.isSafeInteger(value) && value >= 0;
const increment = (value: number): number => {
  if (value >= Number.MAX_SAFE_INTEGER) throw new SessionStoreError('conflict');
  return value + 1;
};
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => Object.keys(value).length === keys.length && Object.keys(value).every(key => keys.includes(key));
const key = (value: unknown): value is Record<string, unknown> => object(value) && text(value.profileId) && profileId.test(value.profileId);
const matrixId = (value: unknown, sigil: '$' | '!' | '@'): value is string => text(value) && value.length <= 1024 && value.startsWith(sigil) && !/\s/.test(value) && !value.includes('\0');
const txnId = (value: unknown): value is string => text(value) && value.length <= 128 && /^[A-Za-z0-9._~-]+$/.test(value);
const bootstrap = (value: unknown): value is CrossSigningBootstrapDisposition => key(value) && exactKeys(value, ['profileId', 'state', 'generation']) && (value.state === 'never-attempted' || value.state === 'pending-uia' || value.state === 'published' || value.state === 'recovery-required') && integer(value.generation) && value.generation > 0;
/** Canonical standard base64 for a 32-byte value, without padding. */
const standardB64_32 = (value: unknown): value is string => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}$/.test(value)) return false;
  try {
    const decoded = atob(value);
    return decoded.length === 32 && btoa(decoded).replace(/=+$/, '') === value;
  } catch { return false; }
};
const sasCommon = (value: unknown): value is SasProfileBinding => key(value) && exactKeys(value, ['schemaVersion', 'profileId', 'sessionGeneration', 'homeserver', 'localUserId', 'localDeviceId']) && value.schemaVersion === 1 && integer(value.sessionGeneration) && value.sessionGeneration > 0 && value.homeserver === MATRIX_HOMESERVER && parseMatrixUserId(value.localUserId) !== undefined && matrixDeviceId(value.localDeviceId);
const sasStable = (value: unknown): value is SasStableGrantBinding => object(value) && sasCommon({ schemaVersion: value.schemaVersion, profileId: value.profileId, sessionGeneration: value.sessionGeneration, homeserver: value.homeserver, localUserId: value.localUserId, localDeviceId: value.localDeviceId }) && parseSupportedDomainRoomId(value.roomId) !== undefined && parseMatrixUserId(value.peerUserId) !== undefined && value.peerUserId !== value.localUserId && matrixDeviceId(value.peerDeviceId) && [value.localEd25519, value.localCurve25519, value.peerEd25519, value.peerCurve25519, value.localMasterRef, value.peerMasterRef].every(standardB64_32);
const sasAuthorization = (value: unknown): value is SasAuthorization => {
  if (!object(value) || !integer(value.generation) || value.generation < 1) return false;
  const record = value;
  const common = ['schemaVersion', 'profileId', 'sessionGeneration', 'homeserver', 'localUserId', 'localDeviceId'];
  const stable = [...common, 'roomId', 'peerUserId', 'localEd25519', 'localCurve25519', 'peerDeviceId', 'peerEd25519', 'peerCurve25519', 'localMasterRef', 'peerMasterRef'];
  if (record.state === 'reverification-required') return exactKeys(record, [...common, 'state', 'generation']) && sasCommon({ schemaVersion: record.schemaVersion, profileId: record.profileId, sessionGeneration: record.sessionGeneration, homeserver: record.homeserver, localUserId: record.localUserId, localDeviceId: record.localDeviceId });
  if (record.state === 'granted') return exactKeys(record, [...stable, 'state', 'generation']) && sasStable(record);
  if (record.state !== 'active' || !sasStable(record)) return false;
  const active = record as SasStableGrantBinding & Record<string, unknown>;
  if (!number(active.expiresAt) || (active.direction !== 'incoming' && active.direction !== 'outgoing') || !['intent', 'bound', 'consented', 'sas-shown', 'confirmation-intent'].includes(active.stage as string) || (active.direction === 'incoming' && active.stage === 'intent')) return false;
  const noFlow = active.direction === 'outgoing' && active.stage === 'intent';
  return exactKeys(active, noFlow ? [...stable, 'state', 'direction', 'stage', 'expiresAt', 'generation'] : [...stable, 'state', 'direction', 'stage', 'expiresAt', 'generation', 'flowId']) && (noFlow ? active.flowId === undefined : matrixId(active.flowId, '$'));
};
const sasOperation = (value: unknown): value is SasOperation => {
  if (!object(value) || !key(value) || !matrixId(value.roomId, '!') || !parseMatrixUserId(value.peerUserId) || !matrixDeviceId(value.localDeviceId) || (value.direction !== 'incoming' && value.direction !== 'outgoing') || !number(value.expiresAt) || !integer(value.generation) || value.generation < 1 || !['intent', 'requested', 'accepted', 'ready', 'started', 'sas-shown', 'confirming', 'done', 'failed', 'cancelled'].includes(value.phase as string) || (value.disposed !== undefined && value.disposed !== true)) return false;
  const ids = [value.requestEventId, value.transactionId, value.peerDeviceId, value.startEventId];
  if (!ids.every(id => id === undefined || (typeof id === 'string' && (id === value.peerDeviceId ? matrixDeviceId(id) : matrixId(id, '$'))))) return false;
  const hasRequest = value.requestEventId !== undefined && value.transactionId !== undefined && value.requestEventId === value.transactionId;
  const hasPeer = value.peerDeviceId !== undefined;
  const hasStart = value.startEventId !== undefined && value.startEventId !== value.requestEventId;
  const terminal = value.phase === 'done' || value.phase === 'failed' || value.phase === 'cancelled';
  const expected = ['profileId', 'roomId', 'peerUserId', 'localDeviceId', 'direction', 'phase', 'expiresAt', 'generation', ...(hasRequest ? ['requestEventId', 'transactionId'] : []), ...(hasPeer ? ['peerDeviceId'] : []), ...(hasStart ? ['startEventId'] : []), ...(value.disposed ? ['disposed'] : [])];
  if (!exactKeys(value, expected) || (value.disposed && !terminal)) return false;
  if (value.phase === 'intent') return !hasRequest && !hasPeer && !hasStart && !value.disposed;
  if (value.phase === 'requested') return hasRequest && !hasStart && !value.disposed;
  if (value.phase === 'accepted' || value.phase === 'ready') return hasRequest && hasPeer && !hasStart && !value.disposed;
  if (value.phase === 'started' || value.phase === 'sas-shown' || value.phase === 'confirming') return hasRequest && hasPeer && hasStart && !value.disposed;
  return (value.phase === 'failed' || value.phase === 'cancelled') ? !value.disposed || terminal : hasRequest && hasPeer && (value.phase === 'done' ? hasStart : true);
};
const outbox = (value: unknown): value is TextOutboxRecord => key(value) && exactKeys(value, ['profileId', 'transactionId', 'roomId', 'bodyHash', 'state', 'eventId', 'baselineGeneration', 'requiredGeneration', 'retryConsumed', 'indeterminate', 'generation'].filter(field => value[field] !== undefined)) && txnId(value.transactionId) && matrixId(value.roomId, '!') && text(value.bodyHash) && hash.test(value.bodyHash)
  && (value.state === 'local-pending' || value.state === 'homeserver-accepted' || value.state === 'synced') && (value.eventId === undefined || matrixId(value.eventId, '$')) && integer(value.baselineGeneration) && integer(value.requiredGeneration) && value.requiredGeneration >= value.baselineGeneration && typeof value.retryConsumed === 'boolean' && integer(value.generation) && value.generation > 0
  && (value.state === 'local-pending' ? value.eventId === undefined && typeof value.indeterminate === 'boolean' : value.eventId !== undefined && value.indeterminate === undefined);
const syncProfile = (value: unknown): value is ProfileSyncGeneration => key(value) && exactKeys(value, ['profileId', 'syncGeneration']) && integer(value.syncGeneration);

export class IndexedDbSessionStore {
  private lost = false;
  private readonly lossListeners = new Set<() => void>();
  private constructor(private readonly db: IDBDatabase) {
    db.onversionchange = () => { this.markLost(); db.close(); };
    db.onclose = () => this.markLost();
  }

  public static open(factory: IDBFactory = globalThis.indexedDB, name = DATABASE): Promise<IndexedDbSessionStore> {
    return new Promise((resolve, reject) => {
      if (!factory) { reject(new SessionStoreError('storage-unavailable')); return; }
      let blocked = false;
      let request: IDBOpenDBRequest;
      try { request = factory.open(name, VERSION); } catch { reject(new SessionStoreError('storage-unavailable')); return; }
      request.onupgradeneeded = event => {
        const db = request.result;
        if (!db.objectStoreNames.contains(REGISTRATIONS)) db.createObjectStore(REGISTRATIONS, { keyPath: 'metadataKey' });
        if (!db.objectStoreNames.contains(ATTEMPTS)) db.createObjectStore(ATTEMPTS, { keyPath: 'state' });
        if (!db.objectStoreNames.contains(SESSIONS)) db.createObjectStore(SESSIONS, { keyPath: 'profileId' });
        if (!db.objectStoreNames.contains(LOCATOR)) db.createObjectStore(LOCATOR, { keyPath: 'key' });
        if (!db.objectStoreNames.contains(BOOTSTRAPS)) db.createObjectStore(BOOTSTRAPS, { keyPath: 'profileId' });
        if (!db.objectStoreNames.contains(SAS_OPERATIONS)) db.createObjectStore(SAS_OPERATIONS, { keyPath: 'profileId' });
        if (!db.objectStoreNames.contains(SAS_AUTHORIZATIONS)) db.createObjectStore(SAS_AUTHORIZATIONS, { keyPath: 'profileId' });
        if (!db.objectStoreNames.contains(OUTBOX)) db.createObjectStore(OUTBOX, { keyPath: ['profileId', 'transactionId'] });
        if (!db.objectStoreNames.contains(SYNC_PROFILES)) db.createObjectStore(SYNC_PROFILES, { keyPath: 'profileId' });
        if ((event as IDBVersionChangeEvent).oldVersion === 4) {
          const operations = request.transaction!.objectStore(SAS_OPERATIONS);
          const authorizations = request.transaction!.objectStore(SAS_AUTHORIZATIONS);
          const rows = operations.getAll();
          rows.onerror = () => request.transaction!.abort();
          rows.onsuccess = () => {
            for (const row of rows.result) {
              if (sasOperation(row)) continue;
              if (!sasAuthorization(row)) { request.transaction!.abort(); return; }
              const existing = authorizations.get(row.profileId);
              existing.onerror = () => request.transaction!.abort();
              existing.onsuccess = () => {
                if (existing.result !== undefined) { request.transaction!.abort(); return; }
                const put = authorizations.add(clone(row));
                put.onerror = () => request.transaction!.abort();
                put.onsuccess = () => { const remove = operations.delete(row.profileId); remove.onerror = () => request.transaction!.abort(); };
              };
            }
          };
        }
        const store = request.transaction!.objectStore(OUTBOX);
        // Validate old rows before creating the unique index: otherwise a corrupt
        // v2 database could be silently opened with ambiguous event ownership.
        if (!store.indexNames.contains(OUTBOX_EVENT_ID) || !store.indexNames.contains(OUTBOX_PROFILE_STATE)) {
          const rows = store.getAll();
          rows.onerror = () => request.transaction!.abort();
          rows.onsuccess = () => {
            const eventIds = new Set<string>();
            const profiles = new Set<string>();
            for (const row of rows.result) {
              if (!outbox(row) || (row.eventId !== undefined && (eventIds.has(row.eventId) || (eventIds.add(row.eventId), false)))) { request.transaction!.abort(); return; }
              profiles.add(row.profileId);
            }
            if (!store.indexNames.contains(OUTBOX_EVENT_ID)) store.createIndex(OUTBOX_EVENT_ID, 'eventId', { unique: true });
            if (!store.indexNames.contains(OUTBOX_PROFILE_STATE)) store.createIndex(OUTBOX_PROFILE_STATE, ['profileId', 'state']);
            // Upgrade-time retention uses primary-key order, the same deterministic
            // order returned by the compound index below.
            for (const profileIdValue of profiles) {
              const synced = rows.result.filter(row => row.profileId === profileIdValue && row.state === 'synced');
              for (const row of synced.slice(0, Math.max(0, synced.length - MAX_TERMINAL_OUTBOX))) store.delete([row.profileId, row.transactionId]);
            }
          };
        }
      };
      request.onblocked = () => { blocked = true; reject(new SessionStoreError('storage-unavailable')); };
      request.onerror = () => reject(new SessionStoreError('storage-unavailable'));
      request.onsuccess = () => { if (blocked) { request.result.close(); return; } resolve(new IndexedDbSessionStore(request.result)); };
    });
  }

  /** Fires once when this handle can no longer safely participate in startup. */
  public subscribeStorageLoss(listener: () => void): () => void { if (this.lost) { listener(); return () => {}; } this.lossListeners.add(listener); return () => this.lossListeners.delete(listener); }
  private markLost(): void { if (!this.lost) { this.lost = true; this.db.close(); this.lossListeners.forEach(listener => listener()); } }
  public close(): void { this.markLost(); this.db.close(); }
  private assertOpen(): void { if (this.lost) throw new SessionStoreError('storage-lost'); }
  private transaction<T>(stores: string[], mode: IDBTransactionMode, work: (tx: IDBTransaction) => Promise<T>): Promise<T> {
    try { this.assertOpen(); } catch (error) { return Promise.reject(error); }
    return new Promise((resolve, reject) => {
      let tx: IDBTransaction;
      try { tx = this.db.transaction(stores, mode); } catch { this.markLost(); reject(new SessionStoreError('storage-lost')); return; }
      let result: T;
      let finished = false;
      const fail = (code: SessionStoreError['code'] = this.lost ? 'storage-lost' : 'storage-unavailable') => {
        if (!finished) { finished = true; reject(new SessionStoreError(code)); }
      };
      tx.onabort = () => fail(); tx.onerror = () => fail();
      tx.oncomplete = () => { if (!finished) { finished = true; resolve(result!); } };
      void work(tx).then(value => { result = value; }).catch(error => { try { tx.abort(); } catch { /* already complete */ } if (error instanceof SessionStoreError && error.code === 'invalid-record') this.markLost(); if (!finished) { finished = true; reject(error instanceof SessionStoreError ? error : new SessionStoreError('storage-unavailable')); } });
    });
  }
  private request<T>(request: IDBRequest<T>): Promise<T> { return new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => { this.markLost(); reject(new SessionStoreError('storage-lost')); }; }); }

  public getRegistration(metadataKey: string): Promise<OAuthRegistration | undefined> {
    return this.transaction([REGISTRATIONS], 'readonly', async tx => { const value = await this.request(tx.objectStore(REGISTRATIONS).get(metadataKey)); if (value === undefined) return undefined; if (!registration(value)) throw new SessionStoreError('invalid-record'); return clone(value); });
  }
  public putRegistration(value: OAuthRegistration): Promise<void> {
    if (!registration(value)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([REGISTRATIONS], 'readwrite', async tx => { await this.request(tx.objectStore(REGISTRATIONS).put(clone(value))); });
  }
  public createAttempt(value: OAuthAttempt, now = Date.now()): Promise<void> {
    if (!attempt(value) || value.expiresAt <= now) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([ATTEMPTS], 'readwrite', async tx => {
      const store = tx.objectStore(ATTEMPTS); const all = await this.request(store.getAll());
      for (const item of all) { if (!attempt(item)) throw new SessionStoreError('invalid-record'); if (item.expiresAt <= now) await this.request(store.delete(item.state)); else throw new SessionStoreError('conflict'); }
      await this.request(store.add(clone(value)));
    });
  }
  public consumeAttempt(state: CanonicalBase64Url, now = Date.now()): Promise<OAuthAttempt> {
    if (!b64url43.test(state)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([ATTEMPTS], 'readwrite', async tx => {
      const store = tx.objectStore(ATTEMPTS); const value = await this.request(store.get(state));
      if (!attempt(value)) throw new SessionStoreError(value === undefined ? 'conflict' : 'invalid-record');
      if (value.spent || value.expiresAt <= now) { await this.request(store.delete(state)); throw new SessionStoreError('conflict'); }
      const spent = { ...value, spent: true }; await this.request(store.put(spent)); return clone(spent);
    });
  }
  public clearAttempts(now = Date.now()): Promise<void> {
    return this.transaction([ATTEMPTS], 'readwrite', async tx => { const store = tx.objectStore(ATTEMPTS); for (const value of await this.request(store.getAll())) { if (!attempt(value)) throw new SessionStoreError('invalid-record'); if (value.spent || value.expiresAt <= now) await this.request(store.delete(value.state)); } });
  }
  /** Explicit callback-cleanup primitive; no revocation or network ordering is implied. */
  public finalizeAttempt(state: CanonicalBase64Url): Promise<void> {
    if (!b64url43.test(state)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([ATTEMPTS], 'readwrite', async tx => { await this.request(tx.objectStore(ATTEMPTS).delete(state)); });
  }
  public async commitSession(value: MatrixSession, expectedSpentState: CanonicalBase64Url): Promise<ActiveProfileLocator> {
    if (!session(value) || !b64url43.test(expectedSpentState)) return Promise.reject(new SessionStoreError('invalid-record'));
    let expectedProfileId: string;
    try { expectedProfileId = await canonicalProfileId({ homeserver: value.homeserver, userId: value.userId, deviceId: value.deviceId }); } catch { throw new SessionStoreError('storage-unavailable'); }
    if (value.profileId !== expectedProfileId) throw new SessionStoreError('invalid-record');
    return this.transaction([ATTEMPTS, SESSIONS, LOCATOR], 'readwrite', async tx => {
      const attemptValue = await this.request(tx.objectStore(ATTEMPTS).get(expectedSpentState));
      if (!attempt(attemptValue)) throw new SessionStoreError(attemptValue === undefined ? 'conflict' : 'invalid-record');
      if (!attemptValue.spent || attemptValue.clientId !== value.clientId || attemptValue.deviceId !== value.deviceId || attemptValue.redirectUri !== value.redirectUri || attemptValue.homeserver !== value.homeserver || !equalEndpointMetadata(attemptValue.metadata, value.metadata) || value.issuer !== attemptValue.metadata.issuer) throw new SessionStoreError('conflict');
      const locatorValue = await this.request(tx.objectStore(LOCATOR).get(ACTIVE));
      const sessions = await this.request(tx.objectStore(SESSIONS).getAll());
      if (locatorValue !== undefined || sessions.length !== 0) { if (locatorValue !== undefined && !locator(locatorValue)) throw new SessionStoreError('invalid-record'); for (const item of sessions) if (!session(item)) throw new SessionStoreError('invalid-record'); throw new SessionStoreError('conflict'); }
      const active = { key: ACTIVE, profileId: value.profileId, generation: value.generation };
      await this.request(tx.objectStore(SESSIONS).add(clone(value))); await this.request(tx.objectStore(LOCATOR).put(active)); await this.request(tx.objectStore(ATTEMPTS).delete(expectedSpentState)); return { profileId: active.profileId, generation: active.generation };
    });
  }
  public getActiveProfile(): Promise<ActiveProfileLocator | undefined> {
    return this.transaction([LOCATOR], 'readonly', async tx => { const value = await this.request(tx.objectStore(LOCATOR).get(ACTIVE)); if (value === undefined) return undefined; if (!locator(value)) throw new SessionStoreError('invalid-record'); return { profileId: value.profileId, generation: value.generation }; });
  }
  public loadSession(expected: ActiveProfileLocator): Promise<MatrixSession | undefined> {
    if (!locator(expected)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SESSIONS, LOCATOR], 'readonly', async tx => { const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE)); if (active === undefined) return undefined; if (!locator(active)) throw new SessionStoreError('invalid-record'); if (active.profileId !== expected.profileId || active.generation !== expected.generation) return undefined; const value = await this.request(tx.objectStore(SESSIONS).get(expected.profileId)); if (value === undefined || !session(value) || value.generation !== expected.generation) throw new SessionStoreError('invalid-record'); return clone(value); });
  }
  /** Low-level persistence only. Runtime stop and token revocation ordering are external; never use as logout. */
  public commitRefreshedTokens(expected: ActiveProfileLocator, tokens: RefreshTokens): Promise<MatrixSession | undefined> {
    if (!locator(expected) || !text(tokens.accessToken) || !number(tokens.expiresAt) || (tokens.refreshToken !== undefined && !text(tokens.refreshToken))) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SESSIONS, LOCATOR], 'readwrite', async tx => { const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE)); if (active === undefined) return undefined; if (!locator(active)) throw new SessionStoreError('invalid-record'); if (active.profileId !== expected.profileId || active.generation !== expected.generation) return undefined; const store = tx.objectStore(SESSIONS); const value = await this.request(store.get(expected.profileId)); if (!session(value) || value.generation !== expected.generation) throw new SessionStoreError('invalid-record'); const updated: MatrixSession = { ...value, accessToken: tokens.accessToken, expiresAt: tokens.expiresAt, ...(tokens.refreshToken === undefined ? {} : { refreshToken: tokens.refreshToken }) }; await this.request(store.put(updated)); return clone(updated); });
  }
  /** Low-level record deletion only. Runtime stop and token revocation ordering are external; never use as logout. */
  public clearSessionRecords(profileId?: string): Promise<void> {
    return this.transaction([SESSIONS, LOCATOR], 'readwrite', async tx => { const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE)); if (active !== undefined && !locator(active)) throw new SessionStoreError('invalid-record'); const target = profileId ?? (locator(active) ? active.profileId : undefined); if (target !== undefined) await this.request(tx.objectStore(SESSIONS).delete(target)); if (locator(active) && (profileId === undefined || active.profileId === profileId)) await this.request(tx.objectStore(LOCATOR).delete(ACTIVE)); });
  }
  /** Deletes only the session still named by this immutable locator; never erase a replacement. */
  public clearSessionForLocator(expected: ActiveProfileLocator): Promise<boolean> {
    if (!locator(expected)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SESSIONS, LOCATOR], 'readwrite', async tx => {
      const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE));
      if (active === undefined) return false;
      if (!locator(active)) throw new SessionStoreError('invalid-record');
      if (active.profileId !== expected.profileId || active.generation !== expected.generation) return false;
      const value = await this.request(tx.objectStore(SESSIONS).get(expected.profileId));
      if (!session(value) || value.generation !== expected.generation) return false;
      await this.request(tx.objectStore(SESSIONS).delete(expected.profileId));
      await this.request(tx.objectStore(LOCATOR).delete(ACTIVE));
      return true;
    });
  }
  /** Logout-only atomic cleanup: delete attempts only with the exact active session. */
  public clearSessionAndAttemptsForLocator(expected: ActiveProfileLocator): Promise<boolean> {
    if (!locator(expected)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SESSIONS, LOCATOR, ATTEMPTS], 'readwrite', async tx => {
      const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE));
      if (active === undefined) return false;
      if (!locator(active)) throw new SessionStoreError('invalid-record');
      if (active.profileId !== expected.profileId || active.generation !== expected.generation) return false;
      const sessions = tx.objectStore(SESSIONS); const value = await this.request(sessions.get(expected.profileId));
      if (!session(value) || value.generation !== expected.generation) return false;
      await this.request(sessions.delete(expected.profileId)); await this.request(tx.objectStore(LOCATOR).delete(ACTIVE)); await this.request(tx.objectStore(ATTEMPTS).clear());
      return true;
    });
  }
  /** Low-level record deletion only. Runtime stop and token revocation ordering are external; never use as logout. */
  public clearAllSessionRecords(): Promise<void> {
    return this.transaction([SESSIONS, LOCATOR, ATTEMPTS], 'readwrite', async tx => {
      await this.request(tx.objectStore(SESSIONS).clear());
      await this.request(tx.objectStore(LOCATOR).clear());
      await this.request(tx.objectStore(ATTEMPTS).clear());
    });
  }

  /** The implicit initial disposition is durable only once a CAS changes it. */
  public getBootstrapDisposition(profile: ProfileStateKey): Promise<CrossSigningBootstrapDisposition> {
    if (!key(profile)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([BOOTSTRAPS], 'readonly', async tx => {
      const value = await this.request(tx.objectStore(BOOTSTRAPS).get(profile.profileId));
      if (value === undefined) return { profileId: profile.profileId, state: 'never-attempted', generation: 0 };
      if (!bootstrap(value)) throw new SessionStoreError('invalid-record');
      return clone(value);
    });
  }
  /**
   * Generation CAS prevents a stale UIA completion from publishing.  Unlike a
   * standalone bootstrap record CAS, this also proves the exact active locator,
   * session generation, and local device in the same IndexedDB transaction.
   */
  public compareAndSetBootstrapDisposition(expected: CrossSigningBootstrapDisposition, next: CrossSigningBootstrapState, binding: CrossSigningBootstrapBinding): Promise<CrossSigningBootstrapDisposition | undefined> {
    if (!key(expected) || !bootstrap({ ...expected, generation: expected.generation || 1 }) || expected.generation < 0) return Promise.reject(new SessionStoreError('invalid-record'));
    if (!key(binding) || !integer(binding.locatorGeneration) || binding.locatorGeneration < 1 || !integer(binding.sessionGeneration) || binding.sessionGeneration < 1 || !matrixDeviceId(binding.localDeviceId) || binding.profileId !== expected.profileId) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([BOOTSTRAPS, LOCATOR, SESSIONS], 'readwrite', async tx => {
      const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE));
      if (!locator(active) || active.profileId !== binding.profileId || active.generation !== binding.locatorGeneration) return undefined;
      const activeSession = await this.request(tx.objectStore(SESSIONS).get(binding.profileId));
      if (!session(activeSession) || activeSession.generation !== binding.sessionGeneration || activeSession.deviceId !== binding.localDeviceId) return undefined;
      const store = tx.objectStore(BOOTSTRAPS); const current = await this.request(store.get(expected.profileId));
      const actual: CrossSigningBootstrapDisposition = current === undefined ? { profileId: expected.profileId, state: 'never-attempted', generation: 0 } : (() => { if (!bootstrap(current)) throw new SessionStoreError('invalid-record'); return current; })();
      if (actual.state !== expected.state || actual.generation !== expected.generation) return undefined;
      const allowed = (actual.state === 'never-attempted' && (next === 'pending-uia' || next === 'recovery-required'))
        || (actual.state === 'pending-uia' && (next === 'published' || next === 'recovery-required'))
        || (actual.state === 'published' && next === 'recovery-required');
      // Recovery is terminal; a published identity may only be durably quarantined.
      if (!allowed) throw new SessionStoreError('conflict');
      const updated = { profileId: expected.profileId, state: next, generation: actual.generation + 1 } as const;
      await this.request(store.put(updated)); return updated;
    });
  }

  /** v3 operations and v4 authorizations have independent physical stores. */
  public getSasOperation(profile: ProfileStateKey): Promise<SasOperation | undefined> {
    if (!key(profile)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SAS_OPERATIONS, SESSIONS, LOCATOR], 'readonly', async tx => { const value = await this.request(tx.objectStore(SAS_OPERATIONS).get(profile.profileId)); if (value === undefined) return undefined; if (!sasOperation(value)) throw new SessionStoreError('invalid-record'); return await this.sasOperationSessionMatches(tx, value) ? clone(value) : undefined; });
  }
  public createSasIntent(operation: SasOperation): Promise<boolean> {
    if (!sasOperation(operation) || operation.disposed || (operation.phase !== 'intent' && !(operation.direction === 'incoming' && operation.phase === 'requested' && operation.requestEventId === operation.transactionId && operation.peerDeviceId !== undefined))) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SAS_OPERATIONS, SESSIONS, LOCATOR], 'readwrite', async tx => { if (!await this.sasOperationSessionMatches(tx, operation)) return false; const store = tx.objectStore(SAS_OPERATIONS); const current = await this.request(store.get(operation.profileId)); if (current !== undefined) { if (!sasOperation(current)) throw new SessionStoreError('invalid-record'); if (!current.disposed) return false; } await this.request(current === undefined ? store.add(clone(operation)) : store.put(clone(operation))); return true; });
  }
  public createIncomingSasOperation(operation: SasOperation, requestEventId: string, transactionId: string, peerDeviceId: string): Promise<boolean> {
    if (!sasOperation(operation) || operation.phase !== 'intent' || operation.direction !== 'incoming' || !matrixId(requestEventId, '$') || requestEventId !== transactionId || !matrixDeviceId(peerDeviceId)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.createSasIntent({ ...operation, phase: 'requested', requestEventId, transactionId, peerDeviceId });
  }
  public bindSasRequest(profile: ProfileStateKey, generation: number, requestEventId: string, transactionId: string): Promise<SasOperation | undefined> { return this.sasOperationCas(profile, generation, current => current.direction === 'outgoing' && current.phase === 'intent' && matrixId(requestEventId, '$') && requestEventId === transactionId ? { ...current, phase: 'requested', requestEventId, transactionId } : undefined); }
  public bindSasPeerDevice(profile: ProfileStateKey, generation: number, peerDeviceId: string): Promise<SasOperation | undefined> { return this.sasOperationCas(profile, generation, current => current.phase === 'requested' && current.peerDeviceId === undefined && matrixDeviceId(peerDeviceId) ? { ...current, peerDeviceId } : undefined); }
  public bindSasStartEvent(profile: ProfileStateKey, generation: number, startEventId: string): Promise<SasOperation | undefined> { return this.sasOperationCas(profile, generation, current => current.peerDeviceId !== undefined && current.requestEventId !== undefined && current.startEventId === undefined && startEventId !== current.requestEventId && matrixId(startEventId, '$') && ((current.direction === 'outgoing' && (current.phase === 'requested' || current.phase === 'ready')) || (current.direction === 'incoming' && current.phase === 'ready')) ? { ...current, phase: 'started', startEventId } : undefined); }
  public advanceSasPhase(profile: ProfileStateKey, generation: number, phase: SasPhase): Promise<SasOperation | undefined> { return this.sasOperationCas(profile, generation, current => { const allowed = (current.phase === 'requested' && phase === 'accepted' && current.direction === 'incoming') || ((current.phase === 'requested' || current.phase === 'accepted') && phase === 'ready') || (current.phase === 'started' && phase === 'sas-shown') || (current.phase === 'sas-shown' && phase === 'confirming') || (current.phase === 'confirming' && phase === 'done') || (!['done', 'failed', 'cancelled'].includes(current.phase) && (phase === 'failed' || phase === 'cancelled')); return allowed ? { ...current, phase } : undefined; }); }
  public disposeSasOperation(profile: ProfileStateKey, generation: number): Promise<boolean> { return this.transaction([SAS_OPERATIONS, SESSIONS, LOCATOR], 'readwrite', async tx => { if (!key(profile) || !integer(generation)) throw new SessionStoreError('invalid-record'); const store = tx.objectStore(SAS_OPERATIONS); const current = await this.request(store.get(profile.profileId)); if (!sasOperation(current)) { if (current !== undefined) throw new SessionStoreError('invalid-record'); return false; } if (!await this.sasOperationSessionMatches(tx, current) || current.generation !== generation || !['done', 'failed', 'cancelled'].includes(current.phase) || current.disposed) return false; const next = { ...current, disposed: true, generation: increment(current.generation) }; if (!sasOperation(next)) throw new SessionStoreError('invalid-record'); await this.request(store.put(clone(next))); return true; }); }
  private sasOperationCas(profile: ProfileStateKey, generation: number, update: (current: SasOperation) => Omit<SasOperation, 'generation'> | undefined): Promise<SasOperation | undefined> { if (!key(profile) || !integer(generation)) return Promise.reject(new SessionStoreError('invalid-record')); return this.transaction([SAS_OPERATIONS, SESSIONS, LOCATOR], 'readwrite', async tx => { const store = tx.objectStore(SAS_OPERATIONS); const current = await this.request(store.get(profile.profileId)); if (!sasOperation(current)) { if (current !== undefined) throw new SessionStoreError('invalid-record'); return undefined; } if (!await this.sasOperationSessionMatches(tx, current) || current.generation !== generation || current.disposed) return undefined; const changed = update(current); if (!changed) return undefined; const next = { ...changed, generation: increment(current.generation) }; if (!sasOperation(next)) throw new SessionStoreError('invalid-record'); await this.request(store.put(clone(next))); return clone(next); }); }
  private async sasOperationSessionMatches(tx: IDBTransaction, operation: SasOperation): Promise<boolean> { const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE)); const activeSession = await this.request(tx.objectStore(SESSIONS).get(operation.profileId)); return locator(active) && session(activeSession) && active.profileId === operation.profileId && active.generation === activeSession.generation && activeSession.deviceId === operation.localDeviceId; }
  public getSasAuthorization(expected: ActiveProfileLocator): Promise<SasAuthorization | undefined> {
    if (!locator(expected)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SAS_AUTHORIZATIONS, SESSIONS, LOCATOR], 'readonly', async tx => {
      if (!await this.sasSessionMatches(tx, expected.profileId, expected.generation)) return undefined;
      const value = await this.request(tx.objectStore(SAS_AUTHORIZATIONS).get(expected.profileId));
      if (value === undefined) return undefined;
      if (!sasAuthorization(value)) throw new SessionStoreError('invalid-record');
      return value.sessionGeneration === expected.generation ? clone(value) : undefined;
    });
  }
  /** Atomically proves the active session before inspecting startup state. */
  public prepareSasAuthorizationForStartup(expected: ActiveProfileLocator): Promise<SasStartupAuthorizationPreparationResult> {
    if (!locator(expected)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SAS_AUTHORIZATIONS, SESSIONS, LOCATOR], 'readwrite', async tx => {
      const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE));
      const activeSession = await this.request(tx.objectStore(SESSIONS).get(expected.profileId));
      if (!locator(active) || !session(activeSession) || active.profileId !== expected.profileId || active.generation !== expected.generation || activeSession.generation !== expected.generation) return undefined;
      const store = tx.objectStore(SAS_AUTHORIZATIONS);
      const current = await this.request(store.get(expected.profileId));
      if (current === undefined) return 'absent';
      if (!sasAuthorization(current)) throw new SessionStoreError('invalid-record');
      if (current.profileId !== expected.profileId || current.sessionGeneration !== expected.generation || current.homeserver !== activeSession.homeserver || current.localUserId !== activeSession.userId || current.localDeviceId !== activeSession.deviceId) return undefined;
      if (current.state === 'reverification-required') return 'reverification-required';
      if (current.state === 'granted') return 'grant-revalidation-required';
      const next = {
        schemaVersion: current.schemaVersion,
        profileId: current.profileId,
        sessionGeneration: current.sessionGeneration,
        homeserver: current.homeserver,
        localUserId: current.localUserId,
        localDeviceId: current.localDeviceId,
        state: 'reverification-required' as const,
        generation: increment(current.generation),
      };
      if (!sasAuthorization(next)) throw new SessionStoreError('invalid-record');
      await this.request(store.put(clone(next)));
      return 'reverification-required';
    });
  }
  public requireSasReverification(binding: SasProfileBinding, expectedGeneration: number): Promise<SasAuthorization | undefined> {
    if (!object(binding) || !exactKeys(binding, ['schemaVersion', 'profileId', 'sessionGeneration', 'homeserver', 'localUserId', 'localDeviceId']) || !sasCommon(binding) || !integer(expectedGeneration)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SAS_AUTHORIZATIONS, SESSIONS, LOCATOR], 'readwrite', async tx => {
      if (!await this.sasBindingMatches(tx, binding)) return undefined;
      const store = tx.objectStore(SAS_AUTHORIZATIONS); const current = await this.request(store.get(binding.profileId));
      if (current !== undefined && !sasAuthorization(current)) throw new SessionStoreError('invalid-record');
      if (current?.state === 'reverification-required' && this.sasProfileEqual(current, binding)) return clone(current);
      if ((current?.generation ?? 0) !== expectedGeneration) return undefined;
      const next = { ...binding, state: 'reverification-required' as const, generation: increment(current?.generation ?? 0) };
      await this.request(current === undefined ? store.add(clone(next)) : store.put(clone(next))); return clone(next);
    });
  }
  public createOutgoingSasIntent(binding: SasStableGrantBinding, expectedGeneration: number, expiresAt: number): Promise<SasAuthorization | undefined> { return this.createSasActive(binding, expectedGeneration, expiresAt, 'outgoing', 'intent'); }
  public createIncomingSasAuthorization(binding: SasStableGrantBinding, expectedGeneration: number, expiresAt: number, flowId: string): Promise<SasAuthorization | undefined> { return this.createSasActive(binding, expectedGeneration, expiresAt, 'incoming', 'bound', flowId); }
  public bindOutgoingSasFlow(binding: SasStableGrantBinding, expectedGeneration: number, flowId: string): Promise<SasAuthorization | undefined> { return this.sasCas(binding, expectedGeneration, current => current.state === 'active' && current.direction === 'outgoing' && current.stage === 'intent' && matrixId(flowId, '$') ? { ...current, stage: 'bound' as const, flowId } : undefined); }
  public advanceSasAuthorizationStage(binding: SasStableGrantBinding, expectedGeneration: number, stage: SasAuthorizationStage): Promise<SasAuthorization | undefined> { return this.sasCas(binding, expectedGeneration, current => current.state !== 'active' ? undefined : ((current.direction === 'incoming' && current.stage === 'bound' && stage === 'consented') || (current.direction === 'incoming' && current.stage === 'consented' && stage === 'sas-shown') || (current.direction === 'outgoing' && (current.stage === 'bound' || current.stage === 'consented') && stage === 'sas-shown') || (current.stage === 'sas-shown' && stage === 'confirmation-intent')) ? { ...current, stage } : undefined); }
  public grantSasAuthorization(binding: SasStableGrantBinding, expectedGeneration: number): Promise<SasAuthorization | undefined> { return this.sasCas(binding, expectedGeneration, current => current.state === 'active' && current.stage === 'confirmation-intent' ? (() => { const { state: _state, direction: _direction, stage: _stage, expiresAt: _expiresAt, flowId: _flowId, ...grant } = current; void _state; void _direction; void _stage; void _expiresAt; void _flowId; return { ...grant, state: 'granted' as const }; })() : undefined); }
  private createSasActive(binding: SasStableGrantBinding, expectedGeneration: number, expiresAt: number, direction: SasDirection, stage: SasAuthorizationStage, flowId?: string): Promise<SasAuthorization | undefined> {
    if (!object(binding) || !exactKeys(binding, ['schemaVersion', 'profileId', 'sessionGeneration', 'homeserver', 'localUserId', 'localDeviceId', 'roomId', 'peerUserId', 'localEd25519', 'localCurve25519', 'peerDeviceId', 'peerEd25519', 'peerCurve25519', 'localMasterRef', 'peerMasterRef']) || !sasStable(binding) || !integer(expectedGeneration) || !number(expiresAt) || (flowId !== undefined && !matrixId(flowId, '$'))) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SAS_AUTHORIZATIONS, SESSIONS, LOCATOR], 'readwrite', async tx => { if (!await this.sasBindingMatches(tx, binding)) return undefined; const store = tx.objectStore(SAS_AUTHORIZATIONS); const current = await this.request(store.get(binding.profileId)); if (current !== undefined && !sasAuthorization(current)) throw new SessionStoreError('invalid-record'); if ((current?.generation ?? 0) !== expectedGeneration || (current !== undefined && !(current.state === 'reverification-required' || current.state === 'granted'))) return undefined; const next = { ...binding, state: 'active' as const, direction, stage, expiresAt, generation: increment(current?.generation ?? 0), ...(flowId === undefined ? {} : { flowId }) }; if (!sasAuthorization(next)) throw new SessionStoreError('invalid-record'); await this.request(current === undefined ? store.add(clone(next)) : store.put(clone(next))); return clone(next); });
  }
  private sasCas(binding: SasStableGrantBinding, expectedGeneration: number, update: (current: SasAuthorization) => Omit<SasAuthorization, 'generation'> | undefined): Promise<SasAuthorization | undefined> {
    if (!object(binding) || !exactKeys(binding, ['schemaVersion', 'profileId', 'sessionGeneration', 'homeserver', 'localUserId', 'localDeviceId', 'roomId', 'peerUserId', 'localEd25519', 'localCurve25519', 'peerDeviceId', 'peerEd25519', 'peerCurve25519', 'localMasterRef', 'peerMasterRef']) || !sasStable(binding) || !integer(expectedGeneration)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SAS_AUTHORIZATIONS, SESSIONS, LOCATOR], 'readwrite', async tx => { if (!await this.sasBindingMatches(tx, binding)) return undefined; const store = tx.objectStore(SAS_AUTHORIZATIONS); const current = await this.request(store.get(binding.profileId)); if (!sasAuthorization(current) || current.generation !== expectedGeneration || !this.sasStableEqual(current, binding)) return undefined; const changed = update(current); if (changed === undefined) return undefined; const next = { ...changed, generation: increment(current.generation) }; if (!sasAuthorization(next)) throw new SessionStoreError('invalid-record'); await this.request(store.put(clone(next))); return clone(next); });
  }
  private sasProfileEqual(left: SasProfileBinding, right: SasProfileBinding): boolean { return left.schemaVersion === right.schemaVersion && left.profileId === right.profileId && left.sessionGeneration === right.sessionGeneration && left.homeserver === right.homeserver && left.localUserId === right.localUserId && left.localDeviceId === right.localDeviceId; }
  private sasStableEqual(left: SasStableGrantBinding | SasAuthorization, right: SasStableGrantBinding): boolean { const stable = left as Partial<SasStableGrantBinding>; return stable.schemaVersion === right.schemaVersion && stable.profileId === right.profileId && stable.sessionGeneration === right.sessionGeneration && stable.homeserver === right.homeserver && stable.localUserId === right.localUserId && stable.localDeviceId === right.localDeviceId && stable.roomId === right.roomId && stable.peerUserId === right.peerUserId && stable.localEd25519 === right.localEd25519 && stable.localCurve25519 === right.localCurve25519 && stable.peerDeviceId === right.peerDeviceId && stable.peerEd25519 === right.peerEd25519 && stable.peerCurve25519 === right.peerCurve25519 && stable.localMasterRef === right.localMasterRef && stable.peerMasterRef === right.peerMasterRef; }
  private async sasSessionMatches(tx: IDBTransaction, profileIdValue: string, generation: number): Promise<boolean> { const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE)); const activeSession = await this.request(tx.objectStore(SESSIONS).get(profileIdValue)); return locator(active) && session(activeSession) && active.profileId === profileIdValue && active.generation === generation && activeSession.generation === generation; }
  private async sasBindingMatches(tx: IDBTransaction, binding: SasProfileBinding): Promise<boolean> { const active = await this.request(tx.objectStore(LOCATOR).get(ACTIVE)); const activeSession = await this.request(tx.objectStore(SESSIONS).get(binding.profileId)); return locator(active) && session(activeSession) && active.profileId === binding.profileId && active.generation === binding.sessionGeneration && activeSession.generation === binding.sessionGeneration && activeSession.homeserver === binding.homeserver && activeSession.userId === binding.localUserId && activeSession.deviceId === binding.localDeviceId; }
  public getSyncGeneration(profile: ProfileStateKey): Promise<ProfileSyncGeneration> {
    if (!key(profile)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SYNC_PROFILES], 'readonly', async tx => { const value = await this.request(tx.objectStore(SYNC_PROFILES).get(profile.profileId)); if (value === undefined) return { profileId: profile.profileId, syncGeneration: 0 }; if (!syncProfile(value)) throw new SessionStoreError('invalid-record'); return clone(value); });
  }
  /** Call only after a completed sync callback; no sync tokens are persisted or compared. */
  public incrementSyncGeneration(profile: ProfileStateKey): Promise<ProfileSyncGeneration> {
    if (!key(profile)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SYNC_PROFILES], 'readwrite', async tx => { const store = tx.objectStore(SYNC_PROFILES); const current = await this.request(store.get(profile.profileId)); if (current !== undefined && !syncProfile(current)) throw new SessionStoreError('invalid-record'); const next = { profileId: profile.profileId, syncGeneration: increment(current?.syncGeneration ?? 0) }; await this.request(store.put(next)); return next; });
  }
  /** Startup invalidates every unresolved invocation, including its stale callbacks. */
  public rebaseUnresolvedOutbox(profile: ProfileStateKey): Promise<number> {
    if (!key(profile)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([SYNC_PROFILES, OUTBOX], 'readwrite', async tx => {
      const generation = await this.request(tx.objectStore(SYNC_PROFILES).get(profile.profileId)); if (generation !== undefined && !syncProfile(generation)) throw new SessionStoreError('invalid-record');
      const required = increment(generation?.syncGeneration ?? 0); const store = tx.objectStore(OUTBOX);
      const nextRecords: TextOutboxRecord[] = [];
      for (const value of await this.request(store.getAll())) {
        if (!outbox(value)) throw new SessionStoreError('invalid-record');
        if (value.profileId === profile.profileId && value.state === 'local-pending' && value.eventId === undefined) {
          nextRecords.push({ ...value, indeterminate: true, requiredGeneration: Math.max(value.requiredGeneration, required), generation: increment(value.generation) });
        }
      }
      for (const next of nextRecords) await this.request(store.put(next));
      // Startup recovery is also the retention sweep for historical terminals.
      await this.pruneTerminalOutbox(tx, profile.profileId, '');
      return nextRecords.length;
    });
  }
  private async pruneTerminalOutbox(tx: IDBTransaction, profileIdValue: string, retainTransactionId: string): Promise<void> {
    const store = tx.objectStore(OUTBOX);
    const records = await this.request(store.index(OUTBOX_PROFILE_STATE).getAll(IDBKeyRange.only([profileIdValue, 'synced'])));
    for (const record of records) if (!outbox(record)) throw new SessionStoreError('invalid-record');
    let excess = records.length - MAX_TERMINAL_OUTBOX;
    for (const record of records) {
      if (excess <= 0) return;
      if (record.transactionId === retainTransactionId) continue;
      await this.request(store.delete([record.profileId, record.transactionId]));
      excess -= 1;
    }
  }
  /** Startup/recovery enumeration intentionally returns metadata only, never plaintext. */
  public listUnresolvedTextOutboxRecords(profile: ProfileStateKey, limit: number): Promise<readonly TextOutboxRecord[]> {
    if (!key(profile) || !Number.isSafeInteger(limit) || limit < 1) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([OUTBOX], 'readonly', async tx => {
      const records: TextOutboxRecord[] = [];
      const range = IDBKeyRange.bound([profile.profileId, ''], [profile.profileId, '\uffff']);
      await new Promise<void>((resolve, reject) => {
        const request = tx.objectStore(OUTBOX).openCursor(range);
        request.onerror = () => { this.markLost(); reject(new SessionStoreError('storage-lost')); };
        request.onsuccess = () => {
          const cursor = request.result;
          if (cursor === null) { resolve(); return; }
          const value: unknown = cursor.value;
          if (!outbox(value)) { reject(new SessionStoreError('invalid-record')); return; }
          if (value.state !== 'synced') records.push(clone(value));
          if (records.length >= limit) { resolve(); return; }
          cursor.continue();
        };
      });
      return records;
    });
  }
  public getTextOutboxRecord(profile: ProfileStateKey, transactionId: string): Promise<TextOutboxRecord | undefined> {
    if (!key(profile) || !txnId(transactionId)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([OUTBOX], 'readonly', async tx => { const value = await this.request(tx.objectStore(OUTBOX).get([profile.profileId, transactionId])); if (value === undefined) return undefined; if (!outbox(value)) throw new SessionStoreError('invalid-record'); return clone(value); });
  }
  public createTextOutboxRecord(value: TextOutboxRecord): Promise<boolean> {
    if (!outbox(value) || value.generation !== 1 || value.state !== 'local-pending' || value.retryConsumed || value.indeterminate) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([OUTBOX, SYNC_PROFILES], 'readwrite', async tx => { const sync = await this.request(tx.objectStore(SYNC_PROFILES).get(value.profileId)); if (sync !== undefined && !syncProfile(sync)) throw new SessionStoreError('invalid-record'); const currentSync = sync?.syncGeneration ?? 0; if (value.baselineGeneration !== currentSync || (value.indeterminate ? (currentSync === Number.MAX_SAFE_INTEGER || value.requiredGeneration < increment(currentSync)) : value.requiredGeneration !== currentSync)) throw new SessionStoreError('invalid-record'); const store = tx.objectStore(OUTBOX); const existing = await this.request(store.get([value.profileId, value.transactionId])); if (existing !== undefined) { if (!outbox(existing)) throw new SessionStoreError('invalid-record'); return false; } await this.request(store.add(clone(value))); return true; });
  }
  /** Atomically captures the current sync generation with the first outbox row. */
  public createInitialTextOutboxRecord(value: Omit<TextOutboxRecord, 'baselineGeneration' | 'requiredGeneration' | 'generation'>): Promise<TextOutboxRecord | undefined> {
    if (!outbox({ ...value, baselineGeneration: 0, requiredGeneration: 0, generation: 1 })) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([OUTBOX, SYNC_PROFILES], 'readwrite', async tx => {
      const sync = await this.request(tx.objectStore(SYNC_PROFILES).get(value.profileId));
      if (sync !== undefined && !syncProfile(sync)) throw new SessionStoreError('invalid-record');
      const baselineGeneration = sync?.syncGeneration ?? 0;
      const record = { ...value, baselineGeneration, requiredGeneration: baselineGeneration, generation: 1 } as TextOutboxRecord;
      const store = tx.objectStore(OUTBOX); const existing = await this.request(store.get([record.profileId, record.transactionId]));
      if (existing !== undefined) { if (!outbox(existing)) throw new SessionStoreError('invalid-record'); return undefined; }
      await this.request(store.add(clone(record))); return clone(record);
    });
  }
  /** CASes the single allowed retry only after the persisted later-sync barrier. */
  public consumeOutboxRetry(profile: ProfileStateKey, transactionId: string, bodyHash: string, generation: number): Promise<AuthorizedOutboxRetry | undefined> {
    if (!key(profile) || !txnId(transactionId) || !hash.test(bodyHash) || !integer(generation)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([OUTBOX, SYNC_PROFILES], 'readwrite', async tx => { const store = tx.objectStore(OUTBOX); const current = await this.request(store.get([profile.profileId, transactionId])); if (current === undefined) return undefined; if (!outbox(current)) throw new SessionStoreError('invalid-record'); const sync = await this.request(tx.objectStore(SYNC_PROFILES).get(profile.profileId)); if (sync !== undefined && !syncProfile(sync)) throw new SessionStoreError('invalid-record'); const ready = current.state === 'local-pending' && current.indeterminate && !current.retryConsumed && current.eventId === undefined && (sync?.syncGeneration ?? 0) >= current.requiredGeneration; if (current.generation !== generation || current.bodyHash !== bodyHash || !ready) return undefined; const next: TextOutboxRecord = { ...current, indeterminate: false, retryConsumed: true, generation: increment(current.generation) }; await this.request(store.put(next)); return authorizeOutboxRetry(next); });
  }

  /** Undo an authorized retry only while no transport outcome can exist. */
  public rollbackOutboxRetry(profile: ProfileStateKey, transactionId: string, bodyHash: string, generation: number): Promise<TextOutboxRecord | undefined> {
    if (!txnId(transactionId) || !hash.test(bodyHash) || !Number.isSafeInteger(generation) || generation < 1) return Promise.resolve(undefined);
    return this.transaction([OUTBOX], 'readwrite', async tx => { const store = tx.objectStore(OUTBOX); const current = await this.request(store.get([profile.profileId, transactionId])); if (current === undefined) return undefined; if (!outbox(current)) throw new SessionStoreError('invalid-record'); if (current.generation !== generation || current.bodyHash !== bodyHash || current.state !== 'local-pending' || current.indeterminate || !current.retryConsumed || current.eventId !== undefined) return undefined; const next: TextOutboxRecord = { ...current, indeterminate: true, retryConsumed: false, generation: increment(current.generation) }; await this.request(store.put(next)); return clone(next); });
  }
  /** Raw invocation rejection is uncertain and therefore always establishes a later-sync barrier. */
  public markOutboxIndeterminate(profile: ProfileStateKey, transactionId: string, generation: number): Promise<TextOutboxRecord | undefined> {
    if (!key(profile) || !txnId(transactionId) || !integer(generation)) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([OUTBOX, SYNC_PROFILES], 'readwrite', async tx => { const store = tx.objectStore(OUTBOX); const current = await this.request(store.get([profile.profileId, transactionId])); if (current === undefined) return undefined; if (!outbox(current)) throw new SessionStoreError('invalid-record'); const sync = await this.request(tx.objectStore(SYNC_PROFILES).get(profile.profileId)); if (sync !== undefined && !syncProfile(sync)) throw new SessionStoreError('invalid-record'); if (current.generation !== generation || current.state !== 'local-pending' || current.eventId !== undefined) return undefined; const next: TextOutboxRecord = { ...current, indeterminate: true, requiredGeneration: Math.max(current.requiredGeneration, increment(sync?.syncGeneration ?? 0)), generation: increment(current.generation) }; await this.request(store.put(next)); return clone(next); });
  }
  /** Records the send result once; exact repeats are harmless and mismatches are conflicts. */
  public recordOutboxAcceptance(profile: ProfileStateKey, transactionId: string, generation: number, eventId: string): Promise<TextOutboxOutcome> {
    if (!key(profile) || !txnId(transactionId) || !integer(generation) || !matrixId(eventId, '$')) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([OUTBOX], 'readwrite', async tx => { const store = tx.objectStore(OUTBOX); const owner = await this.request(store.index(OUTBOX_EVENT_ID).get(eventId)); if (owner !== undefined && !outbox(owner)) throw new SessionStoreError('invalid-record'); if (owner !== undefined && (owner.profileId !== profile.profileId || owner.transactionId !== transactionId)) return { kind: 'conflict' }; const current = await this.request(store.get([profile.profileId, transactionId])); if (current === undefined) return { kind: 'missing' }; if (!outbox(current)) throw new SessionStoreError('invalid-record'); if (current.eventId !== undefined) return current.eventId === eventId ? { kind: 'unchanged', record: clone(current) } : { kind: 'conflict' }; if (current.generation !== generation || current.state !== 'local-pending') return { kind: 'conflict' }; const { indeterminate: ignored, ...base } = current; void ignored; const next: TextOutboxRecord = { ...base, state: 'homeserver-accepted', eventId, generation: increment(current.generation) }; await this.request(store.put(next)); return { kind: 'updated', record: clone(next) }; });
  }
  /** Remote echo wins over late transport results and is terminal. */
  public reconcileOutboxRemoteEcho(profile: ProfileStateKey, transactionId: string, eventId: string): Promise<TextOutboxOutcome> {
    if (!key(profile) || !txnId(transactionId) || !matrixId(eventId, '$')) return Promise.reject(new SessionStoreError('invalid-record'));
    return this.transaction([OUTBOX], 'readwrite', async tx => { const store = tx.objectStore(OUTBOX); const owner = await this.request(store.index(OUTBOX_EVENT_ID).get(eventId)); if (owner !== undefined && !outbox(owner)) throw new SessionStoreError('invalid-record'); if (owner !== undefined && (owner.profileId !== profile.profileId || owner.transactionId !== transactionId)) return { kind: 'conflict' }; const current = await this.request(store.get([profile.profileId, transactionId])); if (current === undefined) return { kind: 'missing' }; if (!outbox(current)) throw new SessionStoreError('invalid-record'); if (current.eventId !== undefined && current.eventId !== eventId) return { kind: 'conflict' }; if (current.state === 'synced') return { kind: 'unchanged', record: clone(current) }; const { indeterminate: ignored, ...base } = current; void ignored; const next: TextOutboxRecord = { ...base, eventId, state: 'synced', generation: increment(current.generation) }; await this.request(store.put(next)); await this.pruneTerminalOutbox(tx, profile.profileId, transactionId); return { kind: 'updated', record: clone(next) }; });
  }
}

/** Endpoint metadata is a small DTO, so structural comparison is safer than a mutable key. */
export function equalEndpointMetadata(left: EndpointMetadata, right: EndpointMetadata): boolean {
  return left.key === right.key && left.issuer === right.issuer && left.authorizationEndpoint === right.authorizationEndpoint
    && left.tokenEndpoint === right.tokenEndpoint && left.registrationEndpoint === right.registrationEndpoint
    && left.revocationEndpoint === right.revocationEndpoint && left.issuerParameterSupported === right.issuerParameterSupported;
}
