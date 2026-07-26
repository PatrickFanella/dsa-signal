import { describe, expect, it, vi } from 'vitest';
import { createPostgresClaimantStore, createRevocationWorker, roomTransactionId, type ClaimantStore, type StepExecutor } from './revocation-worker.js';

const ids = { attempt: '00000000-0000-4000-8000-000000000001', step: '00000000-0000-4000-8000-000000000002', operation: '00000000-0000-4000-8000-000000000003', mapping: '00000000-0000-4000-8000-000000000004', target: '00000000-0000-4000-8000-000000000005' };
const leaseToken = Buffer.alloc(32, 7);
const claimed = (step_kind: string = 'room_ban') => ({ disposition: 'claimed', claim_attempt_id: ids.attempt, step_id: ids.step, operation_id: ids.operation, mapping_id: ids.mapping, transition_revision: '9007199254740993', step_kind, lease_generation: '9007199254740995', lease_token: leaseToken, lease_expires_at: new Date(), mas_target_id: ids.target, mas_user_id: 'mas-user', matrix_user_id: '@user:example', room_target_id: ids.target, room_id: '!room:example', moderator_user_id: '@moderator:example', crypto_capability_id: ids.target, crypto_capability_version: 'v1.2.3' });
const executor = (execute: StepExecutor<'room_ban'>['execute'] = async () => ({ status: 'succeeded' as const, evidenceFingerprint: new Uint8Array(32) })) => ({ kinds: ['room_ban'] as const, execute }) satisfies StepExecutor<'room_ban'>;
const store = (response: unknown, accepted = true): ClaimantStore => ({ claim: vi.fn(async () => response), record: vi.fn(async () => accepted) });

describe('Postgres claimant store', () => {
  it('uses a separate one-call transaction for claim and result', async () => {
    const calls: string[] = []; const values: unknown[][] = [];
    const pool = { connect: vi.fn(async () => ({ query: async (sql: string, parameters?: unknown[]) => { calls.push(sql); if (parameters) values.push(parameters); return { rows: sql.includes('claim_') ? [claimed()] : [{ accepted: true }] }; }, release: () => calls.push('release') })) };
    const subject = createPostgresClaimantStore(pool as never);
    await subject.claim('owner', ['room_ban']);
    await subject.record({ claimAttemptId: ids.attempt, stepId: ids.step, leaseGeneration: 9007199254740995n, leaseToken, owner: 'owner', result: 'succeeded', errorCode: null, evidenceFingerprint: new Uint8Array(32) });
    expect(calls).toEqual(['BEGIN', 'SELECT * FROM control_plane.claim_membership_access_step($1,$2)', 'COMMIT', 'release', 'BEGIN', 'SELECT control_plane.record_membership_access_step_result($1,$2,$3,$4,$5,$6,$7,$8) AS accepted', 'COMMIT', 'release']);
    expect(values[1]?.[2]).toBe(9007199254740995n);
    expect(values[1]?.[3]).toEqual(leaseToken);
    expect(Buffer.isBuffer(values[1]?.[3])).toBe(true);
  });
  it('rolls back and hides database errors', async () => {
    const calls: string[] = []; const pool = { connect: async () => ({ query: async (sql: string) => { calls.push(sql); if (sql.startsWith('SELECT')) throw new Error('secret database detail'); return { rows: [] }; }, release: () => calls.push('release') }) };
    await expect(createPostgresClaimantStore(pool as never).claim('owner', ['room_ban'])).rejects.toThrow('revocation worker store unavailable');
    expect(calls).toEqual(['BEGIN', 'SELECT * FROM control_plane.claim_membership_access_step($1,$2)', 'ROLLBACK', 'release']);
  });
});

describe('revocation worker', () => {
  it.each([['idle', 'idle'], ['exhausted', 'exhausted']])('does not execute terminal claim disposition %s', async (disposition, expected) => {
    const execute = vi.fn(); const subject = createRevocationWorker(store({ disposition }), executor(execute));
    await expect(subject.runOnce('owner')).resolves.toBe(expected); expect(execute).not.toHaveBeenCalled();
  });
  it('filters claim kinds and commits before executor I/O', async () => {
    const events: string[] = []; const claimant: ClaimantStore = { claim: async (_owner, kinds) => { events.push(`claim:${kinds.join(',')}`); return claimed(); }, record: async () => { events.push('record'); return true; } };
    const subject = createRevocationWorker(claimant, executor(async claim => { events.push(`execute:${claim.transactionId}`); return { status: 'succeeded' as const, evidenceFingerprint: new Uint8Array(32) }; }));
    await expect(subject.runOnce('owner')).resolves.toBe('succeeded'); expect(events).toEqual([`claim:room_ban`, `execute:${roomTransactionId(ids.operation, ids.target)}`, 'record']);
  });
  it('derives a stable room transaction ID from operation and exact target', () => {
    expect(roomTransactionId(ids.operation, ids.target)).toBe(roomTransactionId(ids.operation, ids.target));
    expect(roomTransactionId(ids.operation, ids.target)).not.toBe(roomTransactionId(ids.operation, ids.step));
  });
  it.each([
    ['mas_lock'], ['mas_finish_sessions'], ['room_ban'], ['crypto_gate'],
  ])('strictly validates each claim discriminant and target: %s', async kind => {
    const execute = vi.fn(async () => ({ status: 'retryable' as const, errorCode: 'room_rejected' as const }));
    const kinds = kind === 'crypto_gate' ? ['crypto_gate'] as const : kind === 'room_ban' ? ['room_ban'] as const : ['mas_lock', 'mas_finish_sessions'] as const;
    const subject = createRevocationWorker(store(claimed(kind)), { kinds, execute } as never);
    await expect(subject.runOnce('owner')).resolves.toBe('retry_wait'); expect(execute).toHaveBeenCalledOnce();
  });
  it.each([
    ['room_id_not_a_room', 'room_id', 'not-a-room'], ['moderator_user_id_not_a_user', 'moderator_user_id', 'not-a-user'], ['lease_token_empty', 'lease_token', ''], ['lease_token_31_bytes', 'lease_token', Buffer.alloc(31)], ['lease_generation_leading_zero', 'lease_generation', '01'], ['transition_revision_decimal', 'transition_revision', '1.0'], ['room_target_id_not_an_id', 'room_target_id', 'not-an-id'], ['disposition_unexpected', 'disposition', 'unexpected'],
  ])('fails closed on malformed database row: %s', async (_label, field, value) => {
    const row = claimed(); Object.assign(row, { [field]: value });
    const execute = vi.fn(); await expect(createRevocationWorker(store(row), executor(execute)).runOnce('owner')).resolves.toBe('retry_wait'); expect(execute).not.toHaveBeenCalled();
  });
  it.each([['number', 1], ['empty_string', '']])('fails closed on malformed crypto capability version: %s', async (_label, value) => {
    const row = claimed('crypto_gate'); row.crypto_capability_version = value as never;
    const execute = vi.fn();
    await expect(createRevocationWorker(store(row), { kinds: ['crypto_gate'] as const, execute } as never).runOnce('owner')).resolves.toBe('retry_wait'); expect(execute).not.toHaveBeenCalled();
  });
  it.each([
    ['mas_lock', 'mas_target_id'], ['room_ban', 'room_target_id'], ['crypto_gate', 'crypto_capability_id'],
  ])('does not grant an executor malformed %s target', async (kind, field) => {
    const row = claimed(kind); Object.assign(row, { [field]: 'not-an-id' });
    const execute = vi.fn(); const kinds = kind === 'room_ban' ? ['room_ban'] as const : kind === 'crypto_gate' ? ['crypto_gate'] as const : ['mas_lock', 'mas_finish_sessions'] as const;
    await expect(createRevocationWorker(store(row), { kinds, execute } as never).runOnce('owner')).resolves.toBe('retry_wait'); expect(execute).not.toHaveBeenCalled();
  });
  it.each([
    ['succeeded_31_byte_fingerprint', { status: 'succeeded', evidenceFingerprint: new Uint8Array(31) }], ['retryable_unbounded_error', { status: 'retryable', errorCode: 'unbounded' }],
  ])('maps malformed executor output to a coarse retry: %s', async (_label, output) => {
    const claimant = store(claimed()); await expect(createRevocationWorker(claimant, executor(async () => output as never)).runOnce('owner')).resolves.toBe('retry_wait');
    expect((claimant.record as ReturnType<typeof vi.fn>).mock.calls[0][0].errorCode).toBe('executor_failed');
  });
  it('records success, retryable, permanent, and stale CAS outcomes', async () => {
    for (const [output, expected] of [[{ status: 'succeeded', evidenceFingerprint: new Uint8Array(32) }, 'succeeded'], [{ status: 'retryable', errorCode: 'room_rejected' }, 'retry_wait'], [{ status: 'permanent', errorCode: 'room_rejected' }, 'blocked']] as const) {
      await expect(createRevocationWorker(store(claimed()), executor(async () => output)).runOnce('owner')).resolves.toBe(expected);
    }
    await expect(createRevocationWorker(store(claimed(), false), executor()).runOnce('owner')).resolves.toBe('stale');
  });
  it('preserves bigint revisions, bytea lease tokens, and text crypto versions', async () => {
    const execute = vi.fn(async () => ({ status: 'succeeded' as const, evidenceFingerprint: new Uint8Array(32) }));
    const claimant = store(claimed('crypto_gate'));
    await expect(createRevocationWorker(claimant, { kinds: ['crypto_gate'] as const, execute } as never).runOnce('owner')).resolves.toBe('succeeded');
    expect(execute).toHaveBeenCalledWith(expect.objectContaining({ transitionRevision: 9007199254740993n, capabilityVersion: 'v1.2.3' }), expect.any(AbortSignal));
    expect((claimant.record as ReturnType<typeof vi.fn>).mock.calls[0][0]).toEqual(expect.objectContaining({ leaseGeneration: 9007199254740995n, leaseToken }));
  });
  it.each([
    [['mas_lock']], [['mas_finish_sessions']], [['mas_lock', 'room_ban']], [['room_ban', 'room_ban']], [['crypto_gate', 'crypto_gate']], [['mas_lock', 'mas_finish_sessions', 'mas_lock']],
  ])('rejects isolated executor capability set %j', kinds => {
    expect(() => createRevocationWorker(store(claimed()), { kinds, execute: async () => ({ status: 'succeeded' as const, evidenceFingerprint: new Uint8Array(32) }) } as never)).toThrow('invalid executor capability');
  });
  it('maps timeout and unexpected executor errors without details', async () => {
    const timed = store(claimed()); await expect(createRevocationWorker(timed, executor(async () => new Promise(() => undefined)), { timeoutMs: 1 }).runOnce('owner')).resolves.toBe('retry_wait');
    expect((timed.record as ReturnType<typeof vi.fn>).mock.calls[0][0].errorCode).toBe('executor_timeout');
    const failed = store(claimed()); await expect(createRevocationWorker(failed, executor(async () => { throw new Error('credential leaked'); })).runOnce('owner')).resolves.toBe('retry_wait');
    expect((failed.record as ReturnType<typeof vi.fn>).mock.calls[0][0].errorCode).toBe('executor_failed');
  });
});
