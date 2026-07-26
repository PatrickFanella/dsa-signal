import { describe, expect, it } from 'vitest';
import { decryptIncoming, provisionalFailedOutgoing, reduceIncoming, reduceOutgoing, type OutgoingMessage } from './message-timeline';
import type { AuthorizedOutboxRetry, TextOutboxRecord } from '../auth/session-store';

const pending: OutgoingMessage = { localId: 'local', profileId: 'p'.repeat(64), transactionId: 'txn', bodyHash: 'a'.repeat(64), delivery: 'local-pending', indeterminate: false, retryConsumed: false, generation: 2, requiredGeneration: 3 };
const retryRecord = (overrides: Partial<TextOutboxRecord> = {}): TextOutboxRecord => ({ profileId: pending.profileId, transactionId: pending.transactionId, roomId: '!room:hs.example', bodyHash: pending.bodyHash, state: 'local-pending', indeterminate: false, retryConsumed: true, baselineGeneration: 0, requiredGeneration: 3, generation: 3, ...overrides } as TextOutboxRecord);
describe('message timeline reducer', () => {
  it('reports identity conflicts before terminal early returns', () => {
    const accepted = reduceOutgoing(pending, { type: 'accepted', eventId: '$event' });
    expect(accepted.kind).toBe('updated');
    expect(reduceOutgoing(accepted.message, { type: 'remote-echo', eventId: '$other' })).toMatchObject({ kind: 'conflict' });
    const echo = reduceOutgoing(pending, { type: 'remote-echo', eventId: '$event' });
    expect(reduceOutgoing(echo.message, { type: 'accepted', eventId: '$late' })).toMatchObject({ kind: 'conflict' });
    expect(reduceOutgoing(echo.message, { type: 'remote-echo', eventId: '$late' })).toMatchObject({ kind: 'conflict' });
  });
  it('rejects retry records without the exact store-minted authority', () => {
    const indeterminate = reduceOutgoing(pending, { type: 'indeterminate-failure' }).message;
    const fabricated = { localId: 'local', record: retryRecord() } as unknown as AuthorizedOutboxRetry;
    expect(reduceOutgoing(indeterminate, { type: 'retry', authorized: fabricated })).toMatchObject({ kind: 'unchanged' });
  });
  it('creates failed rows only through the presentation-only constructor', () => {
    expect(provisionalFailedOutgoing('local', pending.profileId, 'txn', pending.bodyHash, 3, 2)).toMatchObject({ delivery: 'failed', retryable: true });
  });
  it('keeps incoming terminal identities immutable', () => {
    expect(decryptIncoming({ eventId: '$in', delivery: 'decrypting' }, undefined)).toEqual({ eventId: '$in', delivery: 'decryption-failed' });
    const failed = decryptIncoming({ eventId: '$in', delivery: 'decrypting' }, undefined);
    expect(reduceIncoming(failed, { eventId: '$in', plaintext: 'late' })).toEqual(failed);
  });
});
