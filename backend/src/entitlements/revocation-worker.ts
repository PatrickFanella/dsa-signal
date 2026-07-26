import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';

export const MAS_STEP_KINDS = ['mas_lock', 'mas_finish_sessions'] as const;
export const ROOM_STEP_KINDS = ['room_ban'] as const;
export const CRYPTO_STEP_KINDS = ['crypto_gate'] as const;
export type StepKind = (typeof MAS_STEP_KINDS)[number] | (typeof ROOM_STEP_KINDS)[number] | (typeof CRYPTO_STEP_KINDS)[number];
export type SafeErrorCode = 'executor_failed' | 'executor_timeout' | 'mas_rejected' | 'room_rejected' | 'crypto_unavailable';
type ResultStatus = 'succeeded' | 'retryable' | 'permanent';
const SAFE_CODES: readonly SafeErrorCode[] = ['executor_failed', 'executor_timeout', 'mas_rejected', 'room_rejected', 'crypto_unavailable'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type ClaimantStore = Readonly<{
  claim(owner: string, stepKinds: readonly StepKind[]): Promise<unknown>;
  record(record: StepRecord): Promise<boolean>;
}>;
export type StepRecord = Readonly<{ claimAttemptId: string; stepId: string; leaseGeneration: bigint; leaseToken: Uint8Array; owner: string; result: ResultStatus; errorCode: SafeErrorCode | null; evidenceFingerprint: Uint8Array | null }>;
export type MasClaim = Readonly<{ kind: 'mas_lock' | 'mas_finish_sessions'; operationId: string; mappingId: string; transitionRevision: bigint; masTargetId: string; masUserId: string; matrixUserId: string }>;
export type RoomClaim = Readonly<{ kind: 'room_ban'; operationId: string; mappingId: string; transitionRevision: bigint; roomTargetId: string; roomId: string; moderatorUserId: string; transactionId: string }>;
export type CryptoClaim = Readonly<{ kind: 'crypto_gate'; operationId: string; mappingId: string; transitionRevision: bigint; cryptoCapabilityId: string; capabilityVersion: string }>;
export type ExecutableClaim = MasClaim | RoomClaim | CryptoClaim;
export type ExecutorResult = Readonly<{ status: 'succeeded'; evidenceFingerprint: Uint8Array }> | Readonly<{ status: 'retryable' | 'permanent'; errorCode: SafeErrorCode }>;
export type StepExecutor<K extends StepKind = StepKind> = Readonly<{ readonly kinds: readonly K[]; execute(claim: Extract<ExecutableClaim, { kind: K }>, signal: AbortSignal): Promise<ExecutorResult> }>;
export type RunDisposition = 'idle' | 'exhausted' | 'succeeded' | 'retry_wait' | 'blocked' | 'stale';

export class RevocationWorkerStoreError extends Error { constructor() { super('revocation worker store unavailable'); this.name = 'RevocationWorkerStoreError'; } }

/** Database adapter only; executor authority is intentionally supplied separately. */
export function createPostgresClaimantStore(pool: Pick<Pool, 'connect'>): ClaimantStore {
  async function transaction<T>(sql: string, values: readonly unknown[], read: (row: unknown) => T): Promise<T> {
    let client: PoolClient | undefined;
    try {
      client = await pool.connect(); await client.query('BEGIN');
      const result = await client.query(sql, [...values]);
      const value = read(result.rows[0]);
      await client.query('COMMIT'); return value;
    } catch {
      if (client) try { await client.query('ROLLBACK'); } catch { /* coarse boundary */ }
      throw new RevocationWorkerStoreError();
    } finally { client?.release(); }
  }
  return {
    claim: async (owner, stepKinds) => {
      if (!stepKinds.length) throw new RevocationWorkerStoreError();
      return transaction('SELECT * FROM control_plane.claim_membership_access_step($1,$2)', [owner, stepKinds], row => row ?? undefined);
    },
    record: async record => transaction('SELECT control_plane.record_membership_access_step_result($1,$2,$3,$4,$5,$6,$7,$8) AS accepted', [record.claimAttemptId, record.stepId, record.leaseGeneration, Buffer.from(record.leaseToken), record.owner, record.result, record.errorCode, record.evidenceFingerprint === null ? null : Buffer.from(record.evidenceFingerprint)], row => isObject(row) && row.accepted === true),
  };
}

export function roomTransactionId(operationId: string, roomTargetId: string): string {
  return `dsa-rb-${createHash('sha256').update(`dsa-signal-membership-access:room-ban:v1:${operationId}:${roomTargetId}`).digest('base64url')}`;
}

type ValidClaim = Readonly<{ record: Omit<StepRecord, 'owner' | 'result' | 'errorCode' | 'evidenceFingerprint'>; claim: ExecutableClaim }>;
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null;
const uuid = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);
const text = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 255;
const matrixUser = (value: unknown): value is string => text(value) && value.startsWith('@');
const room = (value: unknown): value is string => text(value) && value.startsWith('!');
const positiveInt = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
const positiveBigInt = (value: unknown): bigint | undefined => {
  if (typeof value !== 'string' || !/^[1-9]\d*$/.test(value)) return undefined;
  const parsed = BigInt(value);
  return parsed > 0n ? parsed : undefined;
};
const bytea32 = (value: unknown): value is Uint8Array => value instanceof Uint8Array && value.length === 32;
function common(row: Record<string, unknown>): Omit<ValidClaim, 'claim'>['record'] | undefined {
  const transitionRevision = positiveBigInt(row.transition_revision);
  const leaseGeneration = positiveBigInt(row.lease_generation);
  if (!uuid(row.claim_attempt_id) || !uuid(row.step_id) || !uuid(row.operation_id) || !uuid(row.mapping_id) || !transitionRevision || !leaseGeneration || !bytea32(row.lease_token) || !(typeof row.lease_expires_at === 'string' || row.lease_expires_at instanceof Date)) return undefined;
  return { claimAttemptId: row.claim_attempt_id, stepId: row.step_id, leaseGeneration, leaseToken: row.lease_token };
}
function validateClaim(value: unknown, allowed: ReadonlySet<StepKind>): ValidClaim | undefined {
  if (!isObject(value) || value.disposition !== 'claimed' || !allowed.has(value.step_kind as StepKind)) return undefined;
  const transitionRevision = positiveBigInt(value.transition_revision);
  const record = common(value); if (!record || !uuid(value.operation_id) || !uuid(value.mapping_id) || !transitionRevision) return undefined;
  const base = { operationId: value.operation_id, mappingId: value.mapping_id, transitionRevision };
  if ((value.step_kind === 'mas_lock' || value.step_kind === 'mas_finish_sessions') && uuid(value.mas_target_id) && text(value.mas_user_id) && matrixUser(value.matrix_user_id)) return { record, claim: { kind: value.step_kind, ...base, masTargetId: value.mas_target_id, masUserId: value.mas_user_id, matrixUserId: value.matrix_user_id } };
  if (value.step_kind === 'room_ban' && uuid(value.room_target_id) && room(value.room_id) && matrixUser(value.moderator_user_id)) return { record, claim: { kind: 'room_ban', ...base, roomTargetId: value.room_target_id, roomId: value.room_id, moderatorUserId: value.moderator_user_id, transactionId: roomTransactionId(value.operation_id, value.room_target_id) } };
  if (value.step_kind === 'crypto_gate' && uuid(value.crypto_capability_id) && text(value.crypto_capability_version)) return { record, claim: { kind: 'crypto_gate', ...base, cryptoCapabilityId: value.crypto_capability_id, capabilityVersion: value.crypto_capability_version } };
  return undefined;
}
function validResult(value: unknown): ExecutorResult | undefined {
  if (!isObject(value)) return undefined;
  if (value.status === 'succeeded' && value.evidenceFingerprint instanceof Uint8Array && value.evidenceFingerprint.length === 32) return { status: 'succeeded', evidenceFingerprint: value.evidenceFingerprint };
  if ((value.status === 'retryable' || value.status === 'permanent') && SAFE_CODES.includes(value.errorCode as SafeErrorCode)) return { status: value.status, errorCode: value.errorCode as SafeErrorCode };
  return undefined;
}

export function createRevocationWorker<K extends StepKind>(store: ClaimantStore, executor: StepExecutor<K>, options: Readonly<{ timeoutMs?: number }> = {}): Readonly<{ runOnce(owner: string): Promise<RunDisposition> }> {
  const kinds = [...executor.kinds] as StepKind[];
  const sameKinds = (expected: readonly StepKind[]): boolean => kinds.length === expected.length && expected.every(kind => kinds.filter(value => value === kind).length === 1);
  if (!(sameKinds(MAS_STEP_KINDS) || sameKinds(ROOM_STEP_KINDS) || sameKinds(CRYPTO_STEP_KINDS))) throw new Error('invalid executor capability');
  const timeoutMs = options.timeoutMs ?? 20_000; if (!positiveInt(timeoutMs) || timeoutMs > 20_000) throw new Error('invalid worker timeout');
  return { async runOnce(owner) {
    let response: unknown; try { response = await store.claim(owner, kinds); } catch { return 'retry_wait'; }
    if (response === undefined || (isObject(response) && response.disposition === 'idle')) return 'idle';
    if (isObject(response) && response.disposition === 'exhausted') return 'exhausted';
    const validated = validateClaim(response, new Set(kinds)); if (!validated) return 'retry_wait';
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
    let result: ExecutorResult | undefined;
    try {
      result = await Promise.race([executor.execute(validated.claim as Extract<ExecutableClaim, { kind: K }>, controller.signal).then(value => validResult(value) ?? { status: 'retryable' as const, errorCode: 'executor_failed' as const }), new Promise<undefined>(resolve => { timer = setTimeout(() => { controller.abort(); resolve(undefined); }, timeoutMs); })]);
    } catch { result = { status: 'retryable', errorCode: 'executor_failed' }; } finally { if (timer) clearTimeout(timer); }
    const normalized = result ?? { status: 'retryable' as const, errorCode: 'executor_timeout' as const };
    const record: StepRecord = normalized.status === 'succeeded' ? { ...validated.record, owner, result: 'succeeded', errorCode: null, evidenceFingerprint: normalized.evidenceFingerprint } : { ...validated.record, owner, result: normalized.status, errorCode: normalized.errorCode, evidenceFingerprint: null };
    try { if (!(await store.record(record))) return 'stale'; } catch { return 'retry_wait'; }
    return normalized.status === 'succeeded' ? 'succeeded' : normalized.status === 'permanent' ? 'blocked' : 'retry_wait';
  } };
}
