import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { parseStrictJson } from './http/strict-json.js';
import { verifyIssuerPolicy, type IssuerPolicy } from './entitlements/issuer-policy.js';
import type { PublicJwk } from './entitlements/verify-entitlement.js';
import type { FoundationService } from './foundation/foundation-service.js';
import { acquireRuntimeWriteFence } from './db.js';

const MAX_BYTES = 16_384;
type QueryResult<T> = { rows: T[] };
export interface PolicyTransaction { query<T extends Record<string, unknown> = Record<string, unknown>>(sql: string, values?: readonly unknown[]): Promise<QueryResult<T>>; }
export interface PolicyDatabase { connect(): Promise<PolicyTransaction & { release(error?: Error): void }>; }
export type EnvelopeKey = Readonly<{ id: string; key: Uint8Array }>;
export type KeyRing = Readonly<{ active: EnvelopeKey; keys: readonly EnvelopeKey[] }>;
export type PolicyProvenance = Readonly<{ uri: string; cid: string; repoDid: string; repoRev: string; sequence: number; observedAt: string; status: 'verified'; authority: Readonly<{ status: 'official'; policyUri: string; policyVersion: string; rootDid: string; evaluatedAt: string }> }>;
/** Exact stored signed-policy digest; callers must not substitute a version. */
export type LoadedPolicy = Readonly<{ snapshotId: string; snapshotDigest: Uint8Array; policy: IssuerPolicy }>;

function unavailable(): never { throw new Error('policy unavailable'); }
function obj(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) unavailable(); return value as Record<string, unknown>; }
function ascii(value: unknown, min: number, max: number): string { if (typeof value !== 'string' || value.length < min || value.length > max || /[^\x20-\x7e]/.test(value)) unavailable(); return value; }
function rfc3339(value: unknown): string {
  if (typeof value !== 'string') unavailable();
  const match = value.match(/^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|([+-])(\d\d):(\d\d))$/);
  if (!match) unavailable(); const time = Date.parse(value); const offset = match[7] === 'Z' ? 0 : (Number(match[9]) * 60 + Number(match[10])) * (match[8] === '+' ? 1 : -1);
  if (!Number.isFinite(time) || Number(match[4]) > 23 || Number(match[5]) > 59 || Number(match[6]) > 59 || Math.abs(offset) > 23 * 60 + 59) unavailable();
  const local = new Date(time + offset * 60_000);
  if (local.getUTCFullYear() !== Number(match[1]) || local.getUTCMonth() + 1 !== Number(match[2]) || local.getUTCDate() !== Number(match[3]) || local.getUTCHours() !== Number(match[4]) || local.getUTCMinutes() !== Number(match[5]) || local.getUTCSeconds() !== Number(match[6])) unavailable();
  return value;
}
function own(object: Record<string, unknown>, name: string): unknown { if (!Object.hasOwn(object, name)) unavailable(); return object[name]; }
function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void { const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) unavailable(); }
function aad(snapshotId: string, version: string): Buffer { return Buffer.from(`dsa-signal-policy-snapshot:v1\0${snapshotId}\0${version}`, 'utf8'); }
function keyBytes(key: EnvelopeKey): Buffer { if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(key.id) || key.key.byteLength !== 32) unavailable(); return Buffer.from(key.key); }
function wipe(...buffers: (Uint8Array | undefined)[]): void { for (const buffer of buffers) buffer?.fill(0); }
function decisionSeconds(value: Date): number { if (!(value instanceof Date) || !Number.isFinite(value.getTime())) unavailable(); return Math.floor(value.getTime() / 1000); }

function validateFlattened(value: unknown, policy: IssuerPolicy): PolicyProvenance {
  const record = obj(value); exactKeys(record, ['uri', 'cid', 'repoDid', 'repoRev', 'sequence', 'observedAt', 'status', 'authority']);
  const authority = obj(own(record, 'authority')); exactKeys(authority, ['status', 'policyUri', 'policyVersion', 'rootDid', 'evaluatedAt']);
  const selected: PolicyProvenance = { uri: own(record, 'uri') as string, cid: ascii(own(record, 'cid'), 1, 128), repoDid: own(record, 'repoDid') as string, repoRev: ascii(own(record, 'repoRev'), 1, 64), sequence: own(record, 'sequence') as number, observedAt: rfc3339(own(record, 'observedAt')), status: own(record, 'status') as 'verified', authority: { status: own(authority, 'status') as 'official', policyUri: own(authority, 'policyUri') as string, policyVersion: own(authority, 'policyVersion') as string, rootDid: own(authority, 'rootDid') as string, evaluatedAt: rfc3339(own(authority, 'evaluatedAt')) } };
  if (selected.uri !== policy.policyUri || selected.repoDid !== policy.rootDid || selected.status !== 'verified' || !Number.isSafeInteger(selected.sequence) || selected.sequence < 0 || selected.authority.status !== 'official' || selected.authority.policyUri !== policy.policyUri || selected.authority.policyVersion !== policy.policyVersion || selected.authority.rootDid !== policy.rootDid) unavailable();
  return selected;
}

/** Discards non-contract Foundation fields and verifies both source and selected provenance URIs. */
export function selectProvenance(response: unknown, policy: IssuerPolicy): PolicyProvenance {
  const source = obj(response); if (Object.hasOwn(source, 'deletedAt')) unavailable();
  if (own(source, 'uri') !== policy.policyUri) unavailable();
  const provenance = obj(own(source, 'provenance')); const authority = obj(own(source, 'authority'));
  const selected = validateFlattened({ uri: own(provenance, 'uri'), cid: own(provenance, 'cid'), repoDid: own(provenance, 'repoDid'), repoRev: own(provenance, 'repoRev'), sequence: own(provenance, 'sequence'), observedAt: own(provenance, 'observedAt'), status: own(provenance, 'status'), authority: { status: own(authority, 'status'), policyUri: own(authority, 'policyUri'), policyVersion: own(authority, 'policyVersion'), rootDid: own(authority, 'rootDid'), evaluatedAt: own(authority, 'evaluatedAt') } }, policy);
  if (selected.uri !== policy.policyUri) unavailable();
  return selected;
}

export class PolicyRefreshService {
  constructor(private readonly database: PolicyDatabase, private readonly foundation: FoundationService, private readonly roots: Readonly<Record<string, PublicJwk>>, private readonly expectedVersion: string, private readonly envelopeKeys: KeyRing, private readonly maxStaleness: number = 86_400, private readonly minimumIssuedAt: number = 0) {}
  private key(id: string): EnvelopeKey { const result = this.envelopeKeys.keys.find(item => item.id === id); if (!result) unavailable(); return result; }
  async refresh(compact: string): Promise<string> {
    const client = await this.database.connect(); let releaseError: Error | undefined; let commitAttempted = false;
    try {
      // This DB clock is the policy decision clock; no host clock participates in validation.
      const preflight = (await client.query<{ decision_now: Date }>('SELECT clock_timestamp() AS decision_now')).rows[0]?.decision_now;
      const policy = await verifyIssuerPolicy(compact, this.roots, this.expectedVersion, decisionSeconds(preflight), this.maxStaleness);
      if (policy.issuedAt < this.minimumIssuedAt) unavailable();
      const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 5_000);
      let provenance: PolicyProvenance;
      try { provenance = selectProvenance(await this.foundation.resolveAuthority({ uri: policy.policyUri, depth: 16 }, { signal: controller.signal }), policy); } catch { unavailable(); } finally { clearTimeout(timer); }
      await client.query('BEGIN');
      await acquireRuntimeWriteFence(client);
      // A fresh activation clock intentionally revalidates refresh-time state after the network call.
      await client.query("SELECT pg_advisory_xact_lock(hashtext('control_plane.active_policy'))");
      const activation = (await client.query<{ decision_now: Date }>('SELECT clock_timestamp() AS decision_now')).rows[0]?.decision_now;
      const activationSeconds = decisionSeconds(activation);
      await verifyIssuerPolicy(compact, this.roots, this.expectedVersion, activationSeconds, this.maxStaleness);
      const active = (await client.query<{ signed_at: Date }>('SELECT p.signed_at FROM control_plane.active_policy a JOIN control_plane.policy_snapshots p ON p.id=a.snapshot_id WHERE a.singleton=true FOR UPDATE OF a')).rows[0];
      if (active && policy.issuedAt <= decisionSeconds(active.signed_at)) unavailable();
      const snapshotId = randomUUID(); let envelopeId = randomUUID(); while (envelopeId === snapshotId) envelopeId = randomUUID();
      let key: Buffer | undefined; let plaintext: Buffer | undefined; let associated: Buffer | undefined; let ciphertext: Buffer | undefined;
      try {
        key = keyBytes(this.envelopeKeys.active); plaintext = Buffer.from(JSON.stringify({ compact, provenance }), 'utf8'); associated = aad(snapshotId, policy.policyVersion);
        const nonce = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(associated); ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
        const digest = createHash('sha256').update(Buffer.from(compact, 'utf8')).digest();
        await client.query('INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose,created_at) VALUES($1,$2,$3,$4,$5,$6)', [envelopeId, this.envelopeKeys.active.id, nonce, ciphertext, 'policy', activation]);
        await client.query('INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) VALUES($1,$2,$3,$4,to_timestamp($5),$6,to_timestamp($7),$6)', [snapshotId, digest, envelopeId, policy.policyVersion, policy.issuedAt, activation, policy.freshUntil]);
        await client.query('INSERT INTO control_plane.active_policy(singleton,snapshot_id,activated_at) VALUES(true,$1,$2) ON CONFLICT(singleton) DO UPDATE SET snapshot_id=EXCLUDED.snapshot_id,activated_at=EXCLUDED.activated_at', [snapshotId, activation]);
        await client.query("INSERT INTO control_plane.security_audit_events(id,event_type,snapshot_id,outcome,reason,occurred_at) VALUES($1,'policy_activated',$2,'success','policy',$3)", [randomUUID(), snapshotId, activation]);
      } finally { wipe(key, plaintext, associated, ciphertext); }
      commitAttempted = true; await client.query('COMMIT'); return snapshotId;
    } catch (error) { if (commitAttempted) releaseError = error instanceof Error ? error : new Error('policy commit outcome unknown'); else try { await client.query('ROLLBACK'); } catch (rollback) { releaseError = rollback instanceof Error ? rollback : new Error('policy rollback failed'); } unavailable(); } finally { client.release(releaseError); }
  }
  /** Must be called inside the authorization transaction. */
  async loadActive(transaction: PolicyTransaction, decisionNow?: Date): Promise<LoadedPolicy> {
    let key: Buffer | undefined; let ciphertext: Buffer | undefined; let plain: Buffer | undefined; let associated: Buffer | undefined;
    try {
      const row = await transaction.query<{ snapshot_id: string; fresh_until: Date; envelope_id: string; envelope_key_id: string; nonce: Buffer; ciphertext: Buffer; version: string; digest: Buffer }>('SELECT p.id AS snapshot_id,p.fresh_until,p.envelope_id,e.envelope_key_id,e.nonce,e.ciphertext,p.version,p.digest FROM control_plane.active_policy a JOIN control_plane.policy_snapshots p ON p.id=a.snapshot_id JOIN control_plane.encrypted_envelopes e ON e.id=p.envelope_id WHERE a.singleton=true FOR SHARE OF a');
      const active = row.rows[0]; const decision = decisionNow ?? (await transaction.query<{ decision_now: Date }>('SELECT clock_timestamp() AS decision_now')).rows[0]?.decision_now;
      if (!active || !(decision instanceof Date) || decision.getTime() >= active.fresh_until.getTime() || !Buffer.isBuffer(active.nonce) || active.nonce.length !== 12) unavailable();
      key = keyBytes(this.key(active.envelope_key_id)); ciphertext = Buffer.from(active.ciphertext); if (ciphertext.length < 16) unavailable(); associated = aad(active.snapshot_id, active.version);
      const decipher = createDecipheriv('aes-256-gcm', key, active.nonce); decipher.setAAD(associated); decipher.setAuthTag(ciphertext.subarray(-16)); plain = Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
      const stored = obj(parseStrictJson(plain)); if (Object.keys(stored).sort().join(',') !== 'compact,provenance' || typeof stored.compact !== 'string') unavailable();
      const digest = createHash('sha256').update(Buffer.from(stored.compact, 'utf8')).digest(); if (!Buffer.from(active.digest).equals(digest)) unavailable();
      const policy = await verifyIssuerPolicy(stored.compact, this.roots, this.expectedVersion, decisionSeconds(decision), this.maxStaleness); if (policy.issuedAt < this.minimumIssuedAt) unavailable(); validateFlattened(stored.provenance, policy);
      return { snapshotId: active.snapshot_id, snapshotDigest: new Uint8Array(active.digest), policy };
    } catch { unavailable(); } finally { wipe(key, ciphertext, plain, associated); }
  }
}

/** Reads only an operator-owned regular policy file through one non-followed descriptor. */
export async function readPolicyFile(path: string): Promise<string> {
  let handle: Awaited<ReturnType<typeof open>> | undefined; let bytes: Buffer | undefined;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW); const stat = await handle.stat(); const uid = process.getuid?.();
    if (uid === undefined || !stat.isFile() || stat.uid !== uid || (stat.mode & 0o022) !== 0 || stat.size > MAX_BYTES) unavailable();
    bytes = Buffer.alloc(stat.size); let offset = 0; while (offset < bytes.length) { const result = await handle.read(bytes, offset, bytes.length - offset, offset); if (result.bytesRead === 0) unavailable(); offset += result.bytesRead; }
    if ((await handle.stat()).size !== bytes.length) unavailable(); return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch { return unavailable(); } finally { wipe(bytes); await handle?.close(); }
}
export async function refreshPolicyFromFile(path: string, service: Pick<PolicyRefreshService, 'refresh'>): Promise<string> { return service.refresh(await readPolicyFile(path)); }
export function parseRefreshPolicyArgs(args: readonly string[]): string { if (args.length !== 2 || args[0] !== '--file' || args[1].length === 0) unavailable(); return args[1]; }
export async function runRefreshPolicyCli(args: readonly string[], factory: () => Promise<Pick<PolicyRefreshService, 'refresh'>>, stderr: (message: string) => void): Promise<number> { try { await refreshPolicyFromFile(parseRefreshPolicyArgs(args), await factory()); return 0; } catch { stderr('policy refresh failed\n'); return 1; } }
