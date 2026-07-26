import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { acquireRuntimeWriteFence } from '../db.js';
import type { KeyRing } from '../config.js';
import type { PolicyRefreshService } from '../refresh-policy.js';
import { lockSourceSet } from './runtime-locks.js';
export type Fingerprint = Readonly<{ keyId: string; value: Uint8Array }>;
export function fingerprint(ring: KeyRing, domain: string, bytes: Uint8Array): Fingerprint {
  const key = ring.keys[ring.active];
  if (!key) throw new Error('inactive fingerprint key');
  const keyCopy = Buffer.from(key);
  try { return { keyId: ring.active, value: createHmac('sha256', keyCopy).update(domain).update('\0').update(bytes).digest() }; }
  finally { keyCopy.fill(0); }
}
/** Fingerprint with a specific retained key; used for rotation-safe lookups. */
export function fingerprintWithKey(ring: KeyRing, keyId: string, domain: string, bytes: Uint8Array): Fingerprint {
  const key = ring.keys[keyId];
  if (!key) throw new Error('unknown fingerprint key');
  const keyCopy = Buffer.from(key);
  try { return { keyId, value: createHmac('sha256', keyCopy).update(domain).update('\0').update(bytes).digest() }; }
  finally { keyCopy.fill(0); }
}
export function issueChallenge(ring: KeyRing): Readonly<{ challenge: string; fingerprint: Fingerprint }> {
  const bytes = randomBytes(32);
  try { return { challenge: bytes.toString('base64url'), fingerprint: fingerprint(ring, 'dsa-signal-challenge-fingerprint:v1', bytes) }; }
  finally { bytes.fill(0); }
}
export function sessionBinding(ring: KeyRing, sessionId: string): Fingerprint {
  return fingerprint(ring, 'dsa-signal-session-fingerprint:v1', Buffer.from(sessionId, 'utf8'));
}

const canonical32 = (value: string): Buffer | undefined => {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return undefined;
  const bytes = Buffer.from(value, 'base64url'); return bytes.length === 32 && bytes.toString('base64url') === value ? bytes : undefined;
};
const aliases = (ring: KeyRing, domain: string, bytes: Uint8Array): readonly Fingerprint[] => Object.keys(ring.keys).map(keyId => fingerprintWithKey(ring, keyId, domain, bytes));
export class ChallengeUnavailableError extends Error { constructor() { super('unavailable'); } }
export class ChallengeRejectedError extends Error { constructor() { super('rejected'); } }
/** The HTTP adapter maps this deliberately distinct boundary error to 400. */
export class InvalidChallengeRequest extends Error { constructor() { super('invalid_request'); } }
export type ChallengeServiceOptions = Readonly<{ pool: Pick<Pool, 'connect'>; challengeKeys: KeyRing; bindingKeys: KeyRing; pwaOrigin: string; policyRefresh: PolicyRefreshService }>;

/** Issues a challenge only after checking session and policy in the same transaction. */
export function createChallengeService(options: ChallengeServiceOptions): Readonly<{ issue(sessionId: string, origin: string, jkt: string): Promise<Readonly<{ challenge: string; expiresAt: number }>> }> {
  return { async issue(sessionId, origin, jkt) {
    const jktBytes = canonical32(jkt); if (!jktBytes) throw new InvalidChallengeRequest();
    if (origin !== options.pwaOrigin) { jktBytes.fill(0); throw new ChallengeRejectedError(); }
    const client = await options.pool.connect().catch(() => { throw new ChallengeUnavailableError(); });
    let releaseError: Error | undefined;
    try {
      await client.query('BEGIN');
      await acquireRuntimeWriteFence(client);
      await lockSourceSet(client);
      const now = (await client.query<{ decision_now: Date }>('SELECT clock_timestamp() AS decision_now')).rows[0]?.decision_now;
      if (!(now instanceof Date)) throw new ChallengeUnavailableError();
      const sessionBytes = Buffer.from(sessionId); const bindings = aliases(options.bindingKeys, 'dsa-signal-session-fingerprint:v1', sessionBytes); sessionBytes.fill(0);
      let session: { rows: { mapping_id: string; binding_key_id: string; binding_fingerprint: Buffer }[] };
      try { session = await client.query<{ mapping_id: string; binding_key_id: string; binding_fingerprint: Buffer }>('SELECT mapping_id,binding_key_id,binding_fingerprint FROM control_plane.identity_sessions WHERE (binding_key_id,binding_fingerprint) IN (SELECT * FROM unnest($1::text[],$2::bytea[])) AND origin=$3 AND revoked_at IS NULL AND idle_expires_at>$4 AND absolute_expires_at>$4 LIMIT 1 FOR UPDATE', [bindings.map(x => x.keyId), bindings.map(x => x.value), origin, now]); }
      finally { for (const binding of bindings) binding.value.fill(0); }
      const row = session.rows[0]; if (!row) throw new ChallengeRejectedError();
      // A missing/stale policy is an infrastructure condition, never a rejection.
      await options.policyRefresh.loadActive(client, now);
      const issued = issueChallenge(options.challengeKeys);
      await client.query("INSERT INTO control_plane.proof_challenges(id,challenge_key_id,challenge_fingerprint,binding_key_id,binding_fingerprint,mapping_id,jkt,audience,origin,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,'dsa-signal',$8,$9,$9::timestamptz + interval '120 seconds')", [randomUUID(), issued.fingerprint.keyId, issued.fingerprint.value, row.binding_key_id, row.binding_fingerprint, row.mapping_id, jktBytes, origin, now]);
      const renewed = await client.query("UPDATE control_plane.identity_sessions SET last_seen_at=$4,idle_expires_at=LEAST($4::timestamptz + interval '5 minutes',absolute_expires_at) WHERE binding_key_id=$1 AND binding_fingerprint=$2 AND origin=$3 AND revoked_at IS NULL AND idle_expires_at>$4 AND absolute_expires_at>$4", [row.binding_key_id, row.binding_fingerprint, origin, now]);
      if (renewed.rowCount !== 1) throw new ChallengeRejectedError();
      await client.query('COMMIT'); return { challenge: issued.challenge, expiresAt: Math.floor(now.getTime() / 1000) + 120 };
    } catch (error) {
      try { await client.query('ROLLBACK'); }
      catch (rollbackError) { releaseError = rollbackError instanceof Error ? rollbackError : new Error('rollback failed'); }
      if (releaseError) throw new ChallengeUnavailableError();
      if (error instanceof ChallengeRejectedError || error instanceof InvalidChallengeRequest) throw error;
      throw new ChallengeUnavailableError();
    }
    finally { client.release(releaseError); jktBytes.fill(0); }
  } };
}
