import { createCipheriv, createDecipheriv, createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { KeyRing } from '../config.js';
import { requireOidcRequestContext, serializeOidcAdapterCall } from './request-context.js';

const models = new Set(['AuthorizationCode', 'AccessToken', 'Session', 'Grant', 'Interaction']);
type Payload = Record<string, unknown>;
type Rings = Readonly<{ epoch: string; adapter: KeyRing; index: KeyRing }>;
/** Explicit bridge for the one cross-model adapter mutation. */
export type AuthorizationCodeClaim = (code: string, payload: Readonly<Record<string, unknown>>) => Promise<void>;
export type AuthorizationCodeRedemption = (code: string, payload: Readonly<Record<string, unknown>>, match: Readonly<{ keyId: string; fingerprint: Buffer; consumedAt: Date | null }>) => Promise<Date | undefined>;
export interface OidcAdapterInstance {
  readonly model: string;
  upsert(id: string, payload: Payload, expiresIn: number): Promise<void>;
  find(id: string): Promise<Payload | undefined>;
  findByUid(uid: string): Promise<Payload | undefined>;
  consume(id: string): Promise<void>;
  destroy(id: string): Promise<void>;
  revokeByGrantId(id: string): Promise<void>;
}
export type OidcAdapterFactory = new (model: string) => OidcAdapterInstance;
const decoder = new TextDecoder('utf-8', { fatal: true });

function fingerprint(key: Uint8Array, domain: string, value: string | Buffer): Buffer {
  return createHmac('sha256', key).update(`${domain}\0`).update(value).digest();
}
// The artifact grammar is deliberately epoch then model; it is an external storage contract.
function artifact(key: Uint8Array, epoch: string, model: string, id: string): Buffer {
  return fingerprint(key, `dsa-signal-oidc-artifact-id:v1\0${epoch}\0${model}`, id);
}
function candidates(ring: KeyRing): readonly [string, Uint8Array][] { return Object.entries(ring.keys); }
function ttl(model: string, seconds: number): void {
  const valid = (model === 'AuthorizationCode' && seconds === 60) ||
    ((model === 'AccessToken' || model === 'Interaction') && seconds > 0 && seconds <= 300) ||
    ((model === 'Grant' || model === 'Session') && seconds > 0 && seconds <= 900);
  if (!valid) throw new Error('invalid OIDC artifact lifetime');
}

/** Encrypted, retained-key-aware oidc-provider adapter. All calls require the request transaction ALS. */
export function createOidcAdapter(rings: Rings, claimAuthorizationCode?: AuthorizationCodeClaim, redeemAuthorizationCode?: AuthorizationCodeRedemption): OidcAdapterFactory {
  return class OidcAdapter implements OidcAdapterInstance {
    readonly model: string;
    constructor(model: string) { if (model !== 'Client' && !models.has(model)) throw new Error(`unsupported OIDC model ${model}`); this.model = model; }

    async upsert(id: string, payload: Payload, expiresIn: number): Promise<void> {
      if (this.model === 'Client') return;
      ttl(this.model, expiresIn);
      const { client, decisionNow } = requireOidcRequestContext();
      const indexKey = rings.index.keys[rings.index.active]!;
      const artifactFingerprint = artifact(indexKey, rings.epoch, this.model, id);
      const sessionUid = this.model === 'Session' && typeof payload.uid === 'string' ? payload.uid : undefined;
      const grantId = ['Grant', 'AuthorizationCode', 'AccessToken'].includes(this.model) ? (this.model === 'Grant' ? id : typeof payload.grantId === 'string' ? payload.grantId : undefined) : undefined;
      if (['AuthorizationCode', 'AccessToken'].includes(this.model) && !grantId) throw new Error('OIDC child artifact has no grant');
      let grantKeyId: string | undefined; let grantFingerprint: Buffer | undefined;
      if (grantId && this.model === 'Grant') { grantKeyId = rings.index.active; grantFingerprint = fingerprint(indexKey, `dsa-signal-oidc-grant-id:v1\0${rings.epoch}`, grantId); }
      else if (grantId) {
        const matches: Array<{ keyId: string; fingerprint: Buffer }> = [];
        for (const [candidateKeyId, candidateKey] of candidates(rings.index)) {
          const candidate = fingerprint(candidateKey, `dsa-signal-oidc-grant-id:v1\0${rings.epoch}`, grantId);
          const found = await client.query('SELECT id FROM oidc.provider_artifacts WHERE epoch=$1 AND model=\'Grant\' AND grant_key_id=$2 AND grant_fingerprint=$3 AND expires_at>$4 AND revoked_at IS NULL FOR UPDATE', [rings.epoch, candidateKeyId, candidate, decisionNow]);
          if (found.rowCount === 1) matches.push({ keyId: candidateKeyId, fingerprint: candidate }); else candidate.fill(0);
        }
        if (matches.length !== 1) { for (const match of matches) match.fingerprint.fill(0); throw new Error('OIDC child artifact grant unavailable'); }
        grantKeyId = matches[0]!.keyId; grantFingerprint = matches[0]!.fingerprint;
      }
      const json = Buffer.from(JSON.stringify(payload), 'utf8');
      if (json.length > 32_768) { json.fill(0); throw new Error('OIDC payload too large'); }
      // Serialize natural keys so a session rotation cannot split its UID and artifact rows.
      await client.query("SELECT pg_advisory_xact_lock(('x' || encode($1::bytea, 'hex'))::bit(64)::bigint)", [artifactFingerprint.subarray(0, 8)]);
      const uidFingerprint = sessionUid ? fingerprint(indexKey, `dsa-signal-oidc-session-uid:v1\0${rings.epoch}`, sessionUid) : undefined;
      if (uidFingerprint) await client.query("SELECT pg_advisory_xact_lock(('x' || encode($1::bytea, 'hex'))::bit(64)::bigint)", [uidFingerprint.subarray(0, 8)]);
      const artifactRows: string[] = []; const uidRows: string[] = [];
      for (const [keyId, key] of candidates(rings.index)) {
        const retainedArtifact = artifact(key, rings.epoch, this.model, id);
        try {
          const found = await client.query<{ id: string }>('SELECT id FROM oidc.provider_artifacts WHERE epoch=$1 AND model=$2 AND artifact_key_id=$3 AND artifact_fingerprint=$4 FOR UPDATE', [rings.epoch, this.model, keyId, retainedArtifact]);
          if (found.rows[0]) artifactRows.push(found.rows[0].id);
        } finally { retainedArtifact.fill(0); }
        if (this.model === 'Session' && sessionUid) {
          const retainedUid = fingerprint(key, `dsa-signal-oidc-session-uid:v1\0${rings.epoch}`, sessionUid);
          try {
            const found = await client.query<{ id: string }>('SELECT id FROM oidc.provider_artifacts WHERE epoch=$1 AND model=$2 AND session_uid_key_id=$3 AND session_uid_fingerprint=$4 FOR UPDATE', [rings.epoch, this.model, keyId, retainedUid]);
            if (found.rows[0]) uidRows.push(found.rows[0].id);
          } finally { retainedUid.fill(0); }
        }
      }
      const artifactRow = [...new Set(artifactRows)]; const uidRow = [...new Set(uidRows)];
      if (artifactRow.length > 1 || uidRow.length > 1 || (artifactRow[0] && uidRow[0] && artifactRow[0] !== uidRow[0])) throw new Error('OIDC session rotation ambiguity');
      const rowId = artifactRow[0] ?? uidRow[0] ?? randomUUID();
      const keyId = rings.adapter.active; const key = Buffer.from(rings.adapter.keys[keyId]!); const nonce = randomBytes(12);
      const aad = Buffer.from(`dsa-signal-oidc-adapter:v1\0${rowId}\0${this.model}\0${artifactFingerprint.toString('base64url')}\0${rings.epoch}`);
      let ciphertext: Buffer;
      try { const cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(aad); ciphertext = Buffer.concat([cipher.update(json), cipher.final(), cipher.getAuthTag()]); }
      finally { key.fill(0); json.fill(0); aad.fill(0); }
      try {
        const expiry = new Date(decisionNow.getTime() + expiresIn * 1000);
        const result = artifactRow[0] || uidRow[0]
          ? await client.query('UPDATE oidc.provider_artifacts SET artifact_key_id=$1,artifact_fingerprint=$2,cipher_key_id=$3,nonce=$4,ciphertext=$5,session_uid_key_id=$6,session_uid_fingerprint=$7,grant_key_id=$8,grant_fingerprint=$9,created_at=$10,expires_at=$11::timestamptz,retained_until=$11::timestamptz+interval \'30 seconds\',consumed_at=NULL,revoked_at=NULL WHERE id=$12', [rings.index.active, artifactFingerprint, keyId, nonce, ciphertext, sessionUid ? rings.index.active : null, uidFingerprint ?? null, grantKeyId ?? null, grantFingerprint ?? null, decisionNow, expiry, rowId])
          : await client.query(`INSERT INTO oidc.provider_artifacts(id,epoch,model,artifact_key_id,artifact_fingerprint,session_uid_key_id,session_uid_fingerprint,grant_key_id,grant_fingerprint,cipher_key_id,nonce,ciphertext,created_at,expires_at,retained_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::timestamptz,$14::timestamptz+interval '30 seconds')`, [rowId, rings.epoch, this.model, rings.index.active, artifactFingerprint, sessionUid ? rings.index.active : null, sessionUid ? fingerprint(indexKey, `dsa-signal-oidc-session-uid:v1\0${rings.epoch}`, sessionUid) : null, grantKeyId ?? null, grantFingerprint ?? null, keyId, nonce, ciphertext, decisionNow, expiry]);
        if (result.rowCount !== 1) throw new Error('OIDC artifact mutation missing');
        if (this.model === 'AuthorizationCode' && claimAuthorizationCode) await claimAuthorizationCode(id, payload);
      } finally { ciphertext.fill(0); nonce.fill(0); artifactFingerprint.fill(0); grantFingerprint?.fill(0); }
    }

    private async decrypt(row: { id: string; cipher_key_id: string; nonce: Buffer; ciphertext: Buffer; artifact_fingerprint: Buffer; consumed_at: Date | null }): Promise<Payload> {
      const key = Buffer.from(rings.adapter.keys[row.cipher_key_id] ?? []); if (key.length !== 32) { key.fill(0); throw new Error('OIDC retained encryption key unavailable'); }
      const aad = Buffer.from(`dsa-signal-oidc-adapter:v1\0${row.id}\0${this.model}\0${row.artifact_fingerprint.toString('base64url')}\0${rings.epoch}`);
      const encrypted = Buffer.from(row.ciphertext.subarray(0, -16)); const tag = Buffer.from(row.ciphertext.subarray(-16)); let plain: Buffer | undefined;
      try { const decipher = createDecipheriv('aes-256-gcm', key, row.nonce); decipher.setAAD(aad); decipher.setAuthTag(tag); plain = Buffer.concat([decipher.update(encrypted), decipher.final()]); if (plain.length > 32_768) throw new Error('OIDC payload too large'); const parsed: unknown = JSON.parse(decoder.decode(plain)); if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('OIDC payload is not an object'); return row.consumed_at ? { ...(parsed as Payload), consumed: Math.floor(row.consumed_at.getTime() / 1000) } : parsed as Payload; }
      finally { key.fill(0); aad.fill(0); encrypted.fill(0); tag.fill(0); plain?.fill(0); }
    }

    async find(id: string): Promise<Payload | undefined> {
      if (this.model === 'Client') return undefined; const { client, decisionNow } = requireOidcRequestContext();
      for (const [keyId, key] of candidates(rings.index)) {
        const value = artifact(key, rings.epoch, this.model, id);
        try {
          const found = await client.query<{ id: string; cipher_key_id: string; nonce: Buffer; ciphertext: Buffer; artifact_fingerprint: Buffer; consumed_at: Date | null }>('SELECT id,cipher_key_id,nonce,ciphertext,artifact_fingerprint,consumed_at FROM oidc.provider_artifacts WHERE epoch=$1 AND model=$2 AND artifact_key_id=$3 AND artifact_fingerprint=$4 AND expires_at>$5 AND revoked_at IS NULL', [rings.epoch, this.model, keyId, value, decisionNow]);
          if (found.rowCount) {
            const payload = await this.decrypt(found.rows[0]!);
            if (this.model === 'AuthorizationCode' && redeemAuthorizationCode) {
              const consumedAt = await redeemAuthorizationCode(id, payload, { keyId, fingerprint: value, consumedAt: found.rows[0]!.consumed_at });
              if (consumedAt && !payload.consumed) return { ...payload, consumed: Math.floor(consumedAt.getTime() / 1000) };
            }
            return payload;
          }
        } finally { value.fill(0); }
      } return undefined;
    }
    async findByUid(uid: string): Promise<Payload | undefined> {
      if (this.model !== 'Session') throw new Error('findByUid only supports Session'); const { client, decisionNow } = requireOidcRequestContext();
      for (const [keyId, key] of candidates(rings.index)) { const value = fingerprint(key, `dsa-signal-oidc-session-uid:v1\0${rings.epoch}`, uid); try { const found = await client.query<{ id: string; cipher_key_id: string; nonce: Buffer; ciphertext: Buffer; artifact_fingerprint: Buffer; consumed_at: Date | null }>('SELECT id,cipher_key_id,nonce,ciphertext,artifact_fingerprint,consumed_at FROM oidc.provider_artifacts WHERE epoch=$1 AND model=$2 AND session_uid_key_id=$3 AND session_uid_fingerprint=$4 AND expires_at>$5 AND revoked_at IS NULL', [rings.epoch, 'Session', keyId, value, decisionNow]); if (found.rowCount) return this.decrypt(found.rows[0]!); } finally { value.fill(0); } } return undefined;
    }
    async consume(id: string): Promise<void> { const request = requireOidcRequestContext(); const { client, decisionNow } = request; for (const [keyId, key] of candidates(rings.index)) { const value = artifact(key, rings.epoch, this.model, id); try { const changed = await client.query('UPDATE oidc.provider_artifacts SET consumed_at=$1 WHERE epoch=$2 AND model=$3 AND artifact_key_id=$4 AND artifact_fingerprint=$5 AND expires_at>$1 AND revoked_at IS NULL AND consumed_at IS NULL', [decisionNow, rings.epoch, this.model, keyId, value]); if (changed.rowCount === 1) { if (this.model === 'AuthorizationCode') { if (request.tokenConsumeSavepoint) throw new Error('OIDC code consumed twice'); await client.query('SAVEPOINT oidc_after_code_consume'); request.tokenConsumeSavepoint = 'oidc_after_code_consume'; } return; } } finally { value.fill(0); } } throw new Error('OIDC artifact consume missing'); }
    async destroy(id: string): Promise<void> { await serializeOidcAdapterCall(async () => { const { client, decisionNow } = requireOidcRequestContext(); for (const [keyId, key] of candidates(rings.index)) { const value = artifact(key, rings.epoch, this.model, id); try { const changed = await client.query('UPDATE oidc.provider_artifacts SET revoked_at=$1 WHERE epoch=$2 AND model=$3 AND artifact_key_id=$4 AND artifact_fingerprint=$5 AND revoked_at IS NULL AND retained_until>=$1', [decisionNow, rings.epoch, this.model, keyId, value]); if (changed.rowCount === 1) return; } finally { value.fill(0); } } }); }
    async revokeByGrantId(id: string): Promise<void> { await serializeOidcAdapterCall(async () => { const { client, decisionNow } = requireOidcRequestContext(); for (const [keyId, key] of candidates(rings.index)) { const value = fingerprint(key, `dsa-signal-oidc-grant-id:v1\0${rings.epoch}`, id); try { await client.query('UPDATE oidc.provider_artifacts SET revoked_at=$1 WHERE epoch=$2 AND model=$3 AND grant_key_id=$4 AND grant_fingerprint=$5 AND revoked_at IS NULL AND retained_until>=$1', [decisionNow, rings.epoch, this.model, keyId, value]); } finally { value.fill(0); } } }); }
  };
}
