import { createCipheriv, createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { acquireRuntimeWriteFence } from '../db.js';
import type { KeyRing } from '../config.js';
import { HandoffRejectedError, validateHandoff, type IdentityHandoffResult } from './identity-handoff.js';
import { lockMappingAccess, lockSession, lockSourceSet } from '../entitlements/runtime-locks.js';

type Queryable = Pick<PoolClient, 'query'>;
export type SessionAuthentication = Readonly<{ mappingId: string; sessionId: string; bindingFingerprint: Uint8Array; bindingKeyId: string }>;
export type SessionRepository = Readonly<{
  establishFromHandoff(result: IdentityHandoffResult, newSessionId: string, previousSessionId?: string): Promise<Readonly<{ mappingId: string; sessionId: string }>>;
  authenticate(sessionId: string, origin: string): Promise<SessionAuthentication | undefined>;
  renew(sessionId: string, origin: string): Promise<boolean>;
  revoke(sessionId: string): Promise<boolean>;
}>;
export class IdentityStorageError extends Error { constructor(options?: ErrorOptions) { super('identity storage unavailable', options); this.name = 'IdentityStorageError'; } }
export type SessionRepositoryOptions = Readonly<{ pool: Pick<Pool, 'connect'>; pwaOrigin: string; sector: string; subjectKeys: KeyRing; envelopeKeys: KeyRing; bindingKeys: KeyRing }>;
const utf8 = (value: string): Buffer => Buffer.from(value, 'utf8');
const fingerprint = (id: string, key: Uint8Array): Buffer => createHmac('sha256', key).update('dsa-signal-session-fingerprint:v1\0').update(id, 'utf8').digest();
const subject = (sector: string, did: string, key: Uint8Array): string => createHmac('sha256', key).update('dsa-signal-subject:v1\0').update(sector, 'utf8').update('\0').update(did, 'utf8').digest('base64url');
const isSessionId = (id: string): boolean => /^[A-Za-z0-9_-]{43}$/.test(id) && Buffer.from(id, 'base64url').length === 32;
const pairs = (id: string, ring: KeyRing): readonly [readonly string[], readonly Buffer[]] => [Object.keys(ring.keys), Object.values(ring.keys).map((key) => fingerprint(id, key))];
const decisionClock = async (client: Queryable): Promise<Date> => {
  const result = await client.query<{ decision_now: Date }>('SELECT clock_timestamp() AS decision_now');
  const value = result.rows[0]?.decision_now;
  if (!(value instanceof Date) || !Number.isFinite(value.valueOf())) throw new IdentityStorageError();
  return value;
};
const sessionRow = `FROM control_plane.identity_sessions WHERE (binding_key_id,binding_fingerprint) IN (SELECT * FROM unnest($1::text[],$2::bytea[]))`;
const sessionMatch = `(binding_key_id,binding_fingerprint) IN (SELECT * FROM unnest($1::text[],$2::bytea[]))`;

/** DB-backed mapping/session boundary. All mutable decisions happen in one checked-out transaction. */
export function createSessionRepository(options: SessionRepositoryOptions): SessionRepository {
  const { pool, pwaOrigin, sector, subjectKeys, envelopeKeys, bindingKeys } = options;
  const transaction = async <T>(work: (client: PoolClient) => Promise<T>): Promise<T> => {
    let client: PoolClient;
    try { client = await pool.connect(); } catch { throw new IdentityStorageError(); }
    let releaseError: Error | undefined;
    try { await client.query('BEGIN'); await acquireRuntimeWriteFence(client); const value = await work(client); await client.query('COMMIT'); return value; }
    catch (error) {
      try { await client.query('ROLLBACK'); } catch (rollbackError) { releaseError = rollbackError instanceof Error ? rollbackError : new Error('identity rollback failed'); }
      if (error instanceof HandoffRejectedError) throw error;
      throw new IdentityStorageError({ cause: error });
    } finally { if (releaseError) client.release(releaseError); else client.release(); }
  };
  return {
    async establishFromHandoff(result, newSessionId, previousSessionId) {
      if (!isSessionId(newSessionId) || (previousSessionId !== undefined && !isSessionId(previousSessionId))) throw new IdentityStorageError();
      return transaction(async (client) => {
        const now = await decisionClock(client);
        const did = validateHandoff(result, pwaOrigin, now);
        await lockSourceSet(client);
        const candidates = Object.entries(subjectKeys.keys).map(([keyId, key]) => ({ keyId, value: subject(sector, did, key) }));
        // Serialize only competing creation of this opaque candidate set.
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [candidates.map((item) => item.value).sort().join(':')]);
        const found = await client.query<{ id: string }>('SELECT id FROM control_plane.did_mappings WHERE sector=$1 AND erased_at IS NULL AND (subject_key_id,subject) IN (SELECT * FROM unnest($2::text[],$3::text[])) LIMIT 1', [sector, candidates.map((item) => item.keyId), candidates.map((item) => item.value)]);
        let mappingId = found.rows[0]?.id;
        if (!mappingId) {
          mappingId = randomUUID(); const envelopeId = randomUUID(); const nonce = randomBytes(12);
          const key = envelopeKeys.keys[envelopeKeys.active];
          if (!key || key.length !== 32) throw new IdentityStorageError();
          const aad = utf8(`dsa-signal-did-mapping:v1\0${mappingId}\0${sector}`);
          const plaintext = utf8(did);
          let ciphertext: Buffer;
          try { const cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(aad); ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]); }
          finally { plaintext.fill(0); aad.fill(0); }
          const activeSubject = subjectKeys.keys[subjectKeys.active];
          if (!activeSubject) throw new IdentityStorageError();
          const activeValue = subject(sector, did, activeSubject);
          try {
            await client.query('INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose,created_at) VALUES($1,$2,$3,$4,\'did\',$5)', [envelopeId, envelopeKeys.active, nonce, ciphertext, now]);
            await client.query('INSERT INTO control_plane.did_mappings(id,sector,subject_key_id,subject,envelope_id,created_at) VALUES($1,$2,$3,$4,$5,$6)', [mappingId, sector, subjectKeys.active, activeValue, envelopeId, now]);
            await client.query("INSERT INTO control_plane.membership_access_states(mapping_id,barrier_state,revision,changed_at) VALUES($1,'active',0,$2)", [mappingId, now]);
          } finally { nonce.fill(0); ciphertext.fill(0); }
        }
        // No session lock is acquired before the mapping barrier.  A cookie
        // belonging to another mapping is intentionally not touched below.
        if (!await lockMappingAccess(client, mappingId)) throw new HandoffRejectedError();
        const bindingKey = bindingKeys.keys[bindingKeys.active]; if (!bindingKey) throw new IdentityStorageError();
        const binding = fingerprint(newSessionId, bindingKey);
        try {
          await lockSession(client, bindingKeys.active, binding);
          await client.query("INSERT INTO control_plane.identity_sessions(id,binding_key_id,binding_fingerprint,mapping_id,origin,created_at,last_seen_at,idle_expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,$5,$6,$6,$6::timestamptz + interval '5 minutes',$6::timestamptz + interval '15 minutes')", [randomUUID(), bindingKeys.active, binding, mappingId, pwaOrigin, now]);
          if (previousSessionId) { const [ids, prints] = pairs(previousSessionId, bindingKeys); await client.query(`UPDATE control_plane.identity_sessions SET revoked_at=$3 WHERE ${sessionMatch} AND mapping_id=$4 AND revoked_at IS NULL AND idle_expires_at>$3 AND absolute_expires_at>$3`, [ids, prints, now, mappingId]); }
        } finally { binding.fill(0); }
        return { mappingId, sessionId: newSessionId };
      });
    },
    async authenticate(sessionId, origin) {
      // `undefined` is reserved for an authenticated lookup which found no row.
      if (!isSessionId(sessionId)) throw new IdentityStorageError();
      return transaction(async (client) => {
        const now = await decisionClock(client); const [ids, prints] = pairs(sessionId, bindingKeys);
        try {
          const result = await client.query<{ mapping_id: string; binding_fingerprint: Buffer; binding_key_id: string }>(`SELECT mapping_id,binding_fingerprint,binding_key_id ${sessionRow} AND origin=$3 AND revoked_at IS NULL AND idle_expires_at>$4 AND absolute_expires_at>$4 LIMIT 1`, [ids, prints, origin, now]);
          const row = result.rows[0]; return row && { mappingId: row.mapping_id, sessionId, bindingFingerprint: new Uint8Array(row.binding_fingerprint), bindingKeyId: row.binding_key_id };
        } finally { for (const value of prints) value.fill(0); }
      });
    },
    async renew(sessionId, origin) {
      if (!isSessionId(sessionId)) return false;
      try { return await transaction(async (client) => { const now = await decisionClock(client); const [ids, prints] = pairs(sessionId, bindingKeys); const result = await client.query(`UPDATE control_plane.identity_sessions SET last_seen_at=$4,idle_expires_at=LEAST($4::timestamptz + interval '5 minutes',absolute_expires_at) WHERE ${sessionMatch} AND origin=$3 AND revoked_at IS NULL AND idle_expires_at>$4 AND absolute_expires_at>$4`, [ids, prints, origin, now]); return result.rowCount === 1; }); } catch { return false; }
    },
    async revoke(sessionId) {
      if (!isSessionId(sessionId)) return false;
      try { return await transaction(async (client) => { const now = await decisionClock(client); const [ids, prints] = pairs(sessionId, bindingKeys); const result = await client.query(`UPDATE control_plane.identity_sessions SET revoked_at=$3 WHERE ${sessionMatch} AND revoked_at IS NULL AND absolute_expires_at>$3`, [ids, prints, now]); return result.rowCount === 1; }); } catch { return false; }
    },
  };
}
export const sessionBindingFingerprint = fingerprint;
