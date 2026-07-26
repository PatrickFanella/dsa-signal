import { compactVerify, importJWK } from 'jose';
import { createDecipheriv, createHash, createHmac, randomUUID, webcrypto } from 'node:crypto';
import type { Pool } from 'pg';
import { acquireRuntimeWriteFence } from '../db.js';
import type { KeyRing } from '../config.js';
import { parseStrictJson } from '../http/strict-json.js';
import { parseMembershipEntitlement, parseMembershipEntitlementAt, validateDid, type MembershipEntitlement } from './claims.js';
import { selectIssuerKey } from './issuer-policy.js';
import type { PolicyRefreshService } from '../refresh-policy.js';
import { lockSourceSet } from './runtime-locks.js';

const encoder = new TextEncoder(); const B64_32 = /^[A-Za-z0-9_-]{43}$/; const KID_MAX_BYTES = 2113;
export type PublicJwk = Readonly<{ kty: 'EC'; crv: 'P-256'; x: string; y: string }>;
export class InvalidVerificationRequest extends Error { constructor() { super('invalid_request'); } }
export class VerificationRejectedError extends Error { constructor() { super('rejected'); } }
export class VerificationUnavailableError extends Error { constructor() { super('unavailable'); } }
function invalid(): never { throw new InvalidVerificationRequest(); }
function invalidCredential(): never { throw new Error('invalid credential'); }

/** Decode and re-encode coordinates: JOSE must never receive an alternate encoding. */
export function parsePublicJwk(value: unknown): PublicJwk {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'crv,kty,x,y') invalid();
  const jwk = value as PublicJwk;
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !B64_32.test(jwk.x) || !B64_32.test(jwk.y)) invalid();
  for (const coordinate of [jwk.x, jwk.y]) { const bytes = Buffer.from(coordinate, 'base64url'); if (bytes.length !== 32 || bytes.toString('base64url') !== coordinate) invalid(); }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
export function jwkThumbprint(jwk: PublicJwk): string { return createHash('sha256').update(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`, 'utf8').digest('base64url'); }
const b64bytes = (value: unknown, length: number): Buffer | undefined => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  const bytes = Buffer.from(value, 'base64url'); return bytes.length === length && bytes.toString('base64url') === value ? bytes : undefined;
};
const fp = (ring: KeyRing, keyId: string, domain: string, bytes: Uint8Array): Buffer => {
  const key = ring.keys[keyId]; if (!key) throw new VerificationUnavailableError(); return createHmac('sha256', key).update(domain).update('\0').update(bytes).digest();
};
const allFp = (ring: KeyRing, domain: string, bytes: Uint8Array): readonly { keyId: string; value: Buffer }[] => Object.keys(ring.keys).map(keyId => ({ keyId, value: fp(ring, keyId, domain, bytes) }));
const transcript = (challenge: string, origin: string, did: string, jkt: string, jti: string): string => `dsa-signal-proof:v1\n${challenge}\n${origin}\ndsa-signal\n${did}\n${jkt}\n${jti}`;
export type InspectedCredential = Readonly<{ compact: string; header: Readonly<{ alg: 'ES256'; typ: 'dsa-signal-membership+jwt'; kid: string }>; claims: MembershipEntitlement }>;
/** The only credential codec: strict parse first, then its exact compact bytes are verified. */
export function inspectCredential(compact: unknown): InspectedCredential {
  try {
    if (typeof compact !== 'string' || Buffer.byteLength(compact) > 8192) invalidCredential();
    const parts = compact.split('.'); if (parts.length !== 3) invalidCredential();
    const head = b64bytes(parts[0], Buffer.from(parts[0], 'base64url').length); const payload = b64bytes(parts[1], Buffer.from(parts[1], 'base64url').length); const sig = b64bytes(parts[2], 64);
    if (!head || !payload || !sig || head.length > 1024 || payload.length > 4096) invalidCredential();
    const header = parseStrictJson(head) as Record<string, unknown>;
    if (Object.keys(header).sort().join(',') !== 'alg,kid,typ' || header.alg !== 'ES256' || header.typ !== 'dsa-signal-membership+jwt' || typeof header.kid !== 'string' || Buffer.byteLength(header.kid) > KID_MAX_BYTES) invalidCredential();
    const kid = header.kid as string; const claims = parseMembershipEntitlement(parseStrictJson(payload)); const prefix = `${claims.iss}#`;
    if (!kid.startsWith(prefix) || !/^[A-Za-z0-9._-]{1,64}$/.test(kid.slice(prefix.length))) invalidCredential();
    return { compact, header: { alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid }, claims };
  } catch { return invalidCredential(); }
}
export async function verifyCredential(compact: string, key: PublicJwk, now: number): Promise<MembershipEntitlement> {
  const inspected = inspectCredential(compact); await compactVerify(inspected.compact, await importJWK(key, 'ES256'), { algorithms: ['ES256'] }); return parseMembershipEntitlementAt(inspected.claims, now);
}
export async function verifyHolderSignature(jwk: PublicJwk, message: string, signature: string): Promise<boolean> {
  const raw = b64bytes(signature, 64); if (!raw) return false;
  try { return await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await webcrypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']), raw, encoder.encode(message)); } finally { raw.fill(0); }
}

export type VerificationServiceOptions = Readonly<{ pool: Pick<Pool, 'connect'>; envelopeKeys: KeyRing; challengeKeys: KeyRing; bindingKeys: KeyRing; jtiKeys: KeyRing; idempotencyKeys: KeyRing; requestKeys: KeyRing; revocationEvidenceKeys: KeyRing; oidcEpoch: string; pwaOrigin: string; sector: string; policyRefresh: PolicyRefreshService }>;
type Answer = Readonly<{ status: 200 | 401 | 409; body: Record<string, unknown> }>;
const rejected = (): Answer => ({ status: 401, body: { version: 'v1', result: 'rejected', error: 'rejected' } }); const conflict = (): Answer => ({ status: 409, body: { version: 'v1', result: 'rejected', error: 'conflict' } }); const authorized = (): Answer => ({ status: 200, body: { version: 'v1', result: 'authorized' } });
const isRetryable = (e: unknown) => typeof e === 'object' && e !== null && 'code' in e && ((e as { code: string }).code === '40001' || (e as { code: string }).code === '40P01');
class IdempotencyCollisionError extends Error {}

export function createVerificationService(options: VerificationServiceOptions): Readonly<{ verify(sessionId: string, origin: string, rawBody: Uint8Array): Promise<Answer> }> {
  if (!/^[A-Za-z0-9_-]{22}$/.test(options.oidcEpoch) || Buffer.from(options.oidcEpoch, 'base64url').length !== 16 || Buffer.from(options.oidcEpoch, 'base64url').toString('base64url') !== options.oidcEpoch) throw new VerificationUnavailableError();
  return { async verify(sessionId, origin, rawBody) {
    const requestBytes = Buffer.concat([Buffer.from('application/json\0v1\0'), Buffer.from(rawBody)]);
    let req: readonly { keyId: string; value: Buffer }[] | undefined; let idems: readonly { keyId: string; value: Buffer }[] | undefined; let bindings: readonly { keyId: string; value: Buffer }[] | undefined; let request: Record<string, unknown>; let idem: Buffer | undefined; let challenge: Buffer | undefined; let signature: string; let jwk: PublicJwk; let credential: string;
    try {
      // Fingerprint the exact transport bytes before inspecting their parsed form.
      req = allFp(options.requestKeys, 'dsa-signal-request-fingerprint:v1', requestBytes);
      const input = parseStrictJson(rawBody); if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).sort().join(',') !== 'challenge,credential,idempotencyKey,publicJwk,signature,version') invalid(); request = input as Record<string, unknown>;
      idem = b64bytes(request.idempotencyKey, 32)!; challenge = b64bytes(request.challenge, 32)!; signature = typeof request.signature === 'string' ? request.signature : '';
      if (request.version !== 'v1' || !idem || !challenge || !b64bytes(signature, 64) || typeof request.credential !== 'string') invalid(); jwk = parsePublicJwk(request.publicJwk); credential = request.credential;
    } catch (e) { if (e instanceof InvalidVerificationRequest) throw e; throw new InvalidVerificationRequest(); }
    const idempotencyKey = idem; const challengeBytes = challenge;
    // eslint-disable-next-line prefer-const -- the outer cleanup must also cover retry failures.
    idems = allFp(options.idempotencyKeys, 'dsa-signal-idempotency-fingerprint:v1', idempotencyKey); const sessionBytes = Buffer.from(sessionId); // eslint-disable-next-line prefer-const -- the outer cleanup must also cover retry failures.
    bindings = allFp(options.bindingKeys, 'dsa-signal-session-fingerprint:v1', sessionBytes); sessionBytes.fill(0);
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const client = await options.pool.connect().catch(() => { throw new VerificationUnavailableError(); });
        let releaseError: Error | undefined;
        try {
          await client.query('BEGIN');
          await acquireRuntimeWriteFence(client);
          await lockSourceSet(client);
          await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [idems.map(item => item.value.toString('base64url')).sort().join(':')]);
          const now = (await client.query<{ decision_now: Date }>('SELECT clock_timestamp() AS decision_now')).rows[0]?.decision_now; if (!(now instanceof Date)) throw new VerificationUnavailableError();
          const session = await client.query<{ mapping_id:string; binding_key_id:string; binding_fingerprint:Buffer }>('SELECT mapping_id,binding_key_id,binding_fingerprint FROM control_plane.identity_sessions WHERE (binding_key_id,binding_fingerprint) IN (SELECT * FROM unnest($1::text[],$2::bytea[])) AND origin=$3 AND revoked_at IS NULL AND idle_expires_at>$4 AND absolute_expires_at>$4 LIMIT 1 FOR UPDATE', [bindings.map(x => x.keyId), bindings.map(x => x.value), origin, now]); const s = session.rows[0]; if (!s || origin !== options.pwaOrigin) { await client.query('ROLLBACK'); throw new VerificationRejectedError(); }
          // Idempotency is deliberately before policy, mapping, and replay work.
          const cached = await client.query<{ response_status:200|401|409; request_key_id:string; request_fingerprint:Buffer; binding_key_id:string; binding_fingerprint:Buffer }>('SELECT r.response_status,r.request_key_id,r.request_fingerprint,r.binding_key_id,r.binding_fingerprint FROM control_plane.idempotency_key_aliases a JOIN control_plane.idempotency_results r ON r.id=a.result_id WHERE (a.key_id,a.fingerprint) IN (SELECT * FROM unnest($1::text[],$2::bytea[])) AND r.expires_at>$3 LIMIT 1', [idems.map(x => x.keyId), idems.map(x => x.value), now]); const old = cached.rows[0];
          if (old) { const same = req.some(x => x.keyId === old.request_key_id && x.value.equals(old.request_fingerprint)) && old.binding_key_id === s.binding_key_id && Buffer.from(old.binding_fingerprint).equals(s.binding_fingerprint); const renewed = await client.query("UPDATE control_plane.identity_sessions SET last_seen_at=$4,idle_expires_at=LEAST($4::timestamptz + interval '5 minutes',absolute_expires_at) WHERE binding_key_id=$1 AND binding_fingerprint=$2 AND origin=$3 AND revoked_at IS NULL AND idle_expires_at>$4 AND absolute_expires_at>$4", [s.binding_key_id, s.binding_fingerprint, origin, now]); if (renewed.rowCount !== 1) throw new VerificationRejectedError(); await client.query('COMMIT'); return same ? (old.response_status === 200 ? authorized() : old.response_status === 409 ? conflict() : rejected()) : conflict(); }
          let answer: Answer = rejected(); let snapshot: string | undefined; let consumed = false;
          try {
            const inspected = inspectCredential(credential); const loaded = await options.policyRefresh.loadActive(client, now); snapshot = loaded.snapshotId; const issuer = selectIssuerKey(loaded.policy, inspected.claims.iss, inspected.header.kid, inspected.claims.policyVersion, Math.floor(now.getTime() / 1000)); const claims = await verifyCredential(inspected.compact, issuer, Math.floor(now.getTime() / 1000));
            if (claims.cnf.jkt !== jwkThumbprint(jwk)) throw new VerificationRejectedError();
            const map = await client.query<{ id:string; envelope_key_id:string; nonce:Buffer; ciphertext:Buffer }>('SELECT m.id,e.envelope_key_id,e.nonce,e.ciphertext FROM control_plane.did_mappings m JOIN control_plane.encrypted_envelopes e ON e.id=m.envelope_id WHERE m.id=$1 AND m.sector=$2 AND m.erased_at IS NULL', [s.mapping_id, options.sector]); const m = map.rows[0]; const key = m && options.envelopeKeys.keys[m.envelope_key_id]; if (!m || !key) throw new VerificationUnavailableError(); const aad = Buffer.from(`dsa-signal-did-mapping:v1\0${m.id}\0${options.sector}`); const ct = Buffer.from(m.ciphertext); let did: string;
            let plain: Buffer | undefined;
            try { const keyCopy = Buffer.from(key); try { const d = createDecipheriv('aes-256-gcm', keyCopy, m.nonce); d.setAAD(aad); d.setAuthTag(ct.subarray(-16)); plain = Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]); did = plain.toString('utf8'); if (!validateDid(did)) throw new Error('invalid did mapping'); } finally { keyCopy.fill(0); } } catch { throw new VerificationUnavailableError(); } finally { plain?.fill(0); aad.fill(0); ct.fill(0); }
            if (did !== claims.sub) throw new VerificationRejectedError();
            const challengeAliases = allFp(options.challengeKeys, 'dsa-signal-challenge-fingerprint:v1', challengeBytes); const available = await client.query<{ id:string }>('SELECT id FROM control_plane.proof_challenges WHERE (challenge_key_id,challenge_fingerprint) IN (SELECT * FROM unnest($1::text[],$2::bytea[])) AND binding_key_id=$3 AND binding_fingerprint=$4 AND mapping_id=$5 AND jkt=$6 AND audience=$7 AND origin=$8 AND consumed_at IS NULL AND expires_at>$9 FOR UPDATE', [challengeAliases.map(x => x.keyId), challengeAliases.map(x => x.value), s.binding_key_id, s.binding_fingerprint, s.mapping_id, Buffer.from(claims.cnf.jkt, 'base64url'), 'dsa-signal', origin, now]);
            if (!available.rows[0] || !await verifyHolderSignature(jwk, transcript(request.challenge as string, origin, did, claims.cnf.jkt, claims.jti), signature)) throw new VerificationRejectedError();
            // Signature has passed. This savepoint covers both consumption and JTI writes.
            await client.query('SAVEPOINT authorization_mutation');
            await client.query('SAVEPOINT jti_write'); const jtiBytes = Buffer.concat([Buffer.from(claims.iss, 'utf8'), Buffer.from('\0'), Buffer.from(claims.jti, 'base64url')]);
            try { await client.query('UPDATE control_plane.proof_challenges SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL', [available.rows[0].id, now]); consumed = true; const use = randomUUID(); await client.query("INSERT INTO control_plane.jti_uses(id,policy_snapshot_id,credential_expires_at,retained_until,decision_clock,decision) VALUES($1,$2,to_timestamp($3),to_timestamp($3)+interval '30 seconds',$4,'authorized')", [use, snapshot, claims.exp, now]); const activeJti = fp(options.jtiKeys, options.jtiKeys.active, 'dsa-signal-jti-fingerprint:v1', jtiBytes); try { await client.query('INSERT INTO control_plane.jti_key_aliases(jti_use_id,key_id,fingerprint) VALUES($1,$2,$3)', [use, options.jtiKeys.active, activeJti]); } finally { activeJti.fill(0); } await client.query('RELEASE SAVEPOINT jti_write'); await client.query('RELEASE SAVEPOINT authorization_mutation'); answer = authorized(); } catch (e) { await client.query('ROLLBACK TO SAVEPOINT authorization_mutation'); if (!(typeof e === 'object' && e !== null && 'code' in e && (e as { code:string }).code === '23505')) throw e; consumed = false; answer = rejected(); }
            finally { jtiBytes.fill(0); }
            if (answer.status !== 401) { const entitlement = await client.query<{ id: string }>("INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) VALUES($1,$2,$3,'chat','active',$4,$5,$6,to_timestamp($7),'membership_verified',$8,$9,$10,1) ON CONFLICT(session_binding_key_id,session_binding_fingerprint,entitlement) DO UPDATE SET mapping_id=EXCLUDED.mapping_id,jkt=EXCLUDED.jkt,status='active',policy_snapshot_id=EXCLUDED.policy_snapshot_id,policy_version=EXCLUDED.policy_version,authorized_at=EXCLUDED.authorized_at,expires_at=EXCLUDED.expires_at,revoked_at=NULL,reason='membership_verified',oidc_epoch=EXCLUDED.oidc_epoch,generation=control_plane.entitlements.generation+1 WHERE control_plane.entitlements.generation<9223372036854775807 AND control_plane.entitlements.mapping_id=EXCLUDED.mapping_id AND control_plane.entitlements.oidc_epoch=EXCLUDED.oidc_epoch RETURNING id", [randomUUID(), s.mapping_id, Buffer.from(claims.cnf.jkt, 'base64url'), snapshot, claims.policyVersion, now, claims.exp, options.oidcEpoch, s.binding_key_id, s.binding_fingerprint]); if (options.revocationEvidenceKeys) { const entitlementId = entitlement.rows[0]?.id; if (!entitlementId) throw new VerificationUnavailableError(); const evidence = [['issuer', Buffer.from(claims.iss)], ['issuer_key', Buffer.from(inspected.header.kid)], ['policy', Buffer.from(claims.policyVersion)]] as const; const aliases: { evidence_kind: string; fingerprint_key_id: string; fingerprint: string }[] = []; try { for (const [kind, value] of evidence) try { for (const alias of allFp(options.revocationEvidenceKeys, `dsa-signal-revocation-evidence:${kind}:v1`, value)) { aliases.push({ evidence_kind: kind, fingerprint_key_id: alias.keyId, fingerprint: alias.value.toString('hex') }); alias.value.fill(0); } } finally { value.fill(0); } await client.query('SELECT control_plane.replace_entitlement_evidence_aliases($1,$2::jsonb)', [entitlementId, JSON.stringify(aliases)]); } finally { aliases.fill({ evidence_kind: '', fingerprint_key_id: '', fingerprint: '' }); } } answer = authorized(); }
          } catch (e) { if (e instanceof VerificationUnavailableError || (e instanceof Error && e.message === 'policy unavailable')) throw e; answer = rejected(); }
          if (consumed) await client.query("INSERT INTO control_plane.security_audit_events(id,event_type,mapping_id,snapshot_id,outcome,reason,occurred_at) VALUES($1,'challenge_consumed',$2,$3,'success','completed',$4)", [randomUUID(), s.mapping_id, snapshot ?? null, now]);
          await client.query("INSERT INTO control_plane.security_audit_events(id,event_type,mapping_id,snapshot_id,outcome,reason,occurred_at) VALUES($1,'entitlement_decided',$2,$3,$4,'authorization',$5)", [randomUUID(), s.mapping_id, snapshot ?? null, answer.status === 200 ? 'success' : 'denied', now]);
          const renewed = await client.query("UPDATE control_plane.identity_sessions SET last_seen_at=$4,idle_expires_at=LEAST($4::timestamptz + interval '5 minutes',absolute_expires_at) WHERE binding_key_id=$1 AND binding_fingerprint=$2 AND origin=$3 AND revoked_at IS NULL AND idle_expires_at>$4 AND absolute_expires_at>$4", [s.binding_key_id, s.binding_fingerprint, origin, now]);
          if (renewed.rowCount !== 1) throw new VerificationRejectedError();
          const result = randomUUID(); const activeReq = req.find(x => x.keyId === options.requestKeys.active)!; const activeIdem = idems.find(x => x.keyId === options.idempotencyKeys.active)!;
          await client.query('SAVEPOINT idempotency_write');
          try {
            await client.query("WITH t AS (SELECT clock_timestamp() created_at) INSERT INTO control_plane.idempotency_results(id,request_key_id,request_fingerprint,binding_key_id,binding_fingerprint,response_status,result,error_code,created_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,created_at,created_at+interval '60 seconds' FROM t", [result, activeReq.keyId, activeReq.value, s.binding_key_id, s.binding_fingerprint, answer.status, answer.status === 200 ? 'authorized' : 'rejected', answer.status === 200 ? null : 'rejected']);
            await client.query('INSERT INTO control_plane.idempotency_key_aliases(result_id,key_id,fingerprint) VALUES($1,$2,$3)', [result, activeIdem.keyId, activeIdem.value]); await client.query('RELEASE SAVEPOINT idempotency_write');
          } catch (e) {
            await client.query('ROLLBACK TO SAVEPOINT idempotency_write');
            if (!(typeof e === 'object' && e !== null && 'code' in e && (e as { code:string }).code === '23505')) throw e;
            throw new IdempotencyCollisionError();
          }
          await client.query('COMMIT'); return answer;
        } catch (e) { try { await client.query('ROLLBACK'); } catch (rollbackError) { releaseError = rollbackError instanceof Error ? rollbackError : new Error('verification rollback failed'); } if (releaseError) throw new VerificationUnavailableError(); if (e instanceof VerificationRejectedError) throw e; if ((isRetryable(e) || e instanceof IdempotencyCollisionError) && attempt < 2) continue; if (e instanceof VerificationUnavailableError) throw e; throw new VerificationUnavailableError(); } finally { client.release(releaseError); }
      }
      throw new VerificationUnavailableError();
    } finally { idem?.fill(0); challenge?.fill(0); requestBytes.fill(0); for (const value of req ?? []) value.value.fill(0); for (const value of bindings ?? []) value.value.fill(0); for (const value of idems ?? []) value.value.fill(0); }
  } };
}
