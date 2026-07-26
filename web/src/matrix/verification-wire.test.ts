import { describe, expect, it } from 'vitest';
import { ownedVerificationEnvelope, validateVerificationEnvelope, type VerificationEnvelope, type VerificationWireContext } from './verification-wire';

const now = 1_000_000;
const context: VerificationWireContext = { roomId: '!room:test', expectedSender: '@peer:test', expectedSenderDeviceId: 'PEER', expectedRecipient: '@me:test', direction: 'incoming', now };
const request = (): VerificationEnvelope => ({ type: 'm.room.message', content: { msgtype: 'm.key.verification.request', to: '@me:test', from_device: 'PEER', methods: ['m.sas.v1'], body: '@peer:test is requesting to verify your key, but your client does not support in-chat key verification. You will need to use legacy key verification to verify keys.' }, sender: '@peer:test', eventId: '$request', originServerTs: now - 600_000, roomId: '!room:test', unsigned: { age: 0, transaction_id: 'txn_1' } });
const related = (type: 'm.key.verification.ready' | 'm.key.verification.start'): VerificationEnvelope => ({ type, content: type.endsWith('ready') ? { from_device: 'PEER', methods: ['m.sas.v1'], 'm.relates_to': { rel_type: 'm.reference', event_id: '$request' } } : { from_device: 'PEER', method: 'm.sas.v1', key_agreement_protocols: ['curve25519-hkdf-sha256'], hashes: ['sha256'], message_authentication_codes: ['hkdf-hmac-sha256.v2', 'org.matrix.msc3783.hkdf-hmac-sha256'], short_authentication_string: ['decimal', 'emoji'], 'm.relates_to': { rel_type: 'm.reference', event_id: '$request' } }, sender: '@peer:test', eventId: type.endsWith('ready') ? '$ready' : '$start', originServerTs: now, roomId: '!room:test' });
const relationContext = (): VerificationWireContext => ({ ...context, requestEventId: '$request' });
const invalid = (envelope: VerificationEnvelope, contextValue = context): void => expect(validateVerificationEnvelope(envelope, contextValue)).toBeUndefined();

describe('exact verification wire validator', () => {
  it('accepts the exact request, ready, and start fixtures without leaking content', () => {
    expect(validateVerificationEnvelope(request(), context)).toEqual({ kind: 'request', eventId: '$request', requestEventId: '$request', roomId: '!room:test', sender: '@peer:test', peerDeviceId: 'PEER' });
    expect(validateVerificationEnvelope(related('m.key.verification.ready'), relationContext())?.kind).toBe('ready');
    expect(validateVerificationEnvelope(related('m.key.verification.start'), relationContext())?.kind).toBe('start');
  });
  it('rejects every request envelope/content field mutation and unknown fields', () => {
    for (const mutate of [
      (e: VerificationEnvelope) => ({ ...e, type: 'wrong' }), (e: VerificationEnvelope) => ({ ...e, sender: '@wrong:test' }), (e: VerificationEnvelope) => ({ ...e, eventId: 'bad' }), (e: VerificationEnvelope) => ({ ...e, originServerTs: -1 }), (e: VerificationEnvelope) => ({ ...e, roomId: '!wrong:test' }), (e: VerificationEnvelope) => ({ ...e, unsigned: { nope: 1 } }), (e: VerificationEnvelope) => ({ ...e, extra: true }),
      (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), msgtype: 'wrong' } }), (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), to: '@wrong:test' } }), (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), from_device: '' } }), (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), methods: ['m.sas.v1', 'x'] } }), (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), body: 'forged' } }), (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), extra: true } }),
    ]) invalid(mutate(request()));
  });
  it('enforces inclusive freshness boundaries and request directionality', () => {
    expect(validateVerificationEnvelope({ ...request(), originServerTs: now + 300_000 }, context)).toBeDefined();
    invalid({ ...request(), originServerTs: now - 600_001 }); invalid({ ...request(), originServerTs: now + 300_001 });
    expect(validateVerificationEnvelope({ ...request(), sender: '@me:test', content: { ...(request().content as object), to: '@peer:test', from_device: 'LOCAL', body: '@me:test is requesting to verify your key, but your client does not support in-chat key verification. You will need to use legacy key verification to verify keys.' } }, { ...context, expectedSender: '@me:test', expectedSenderDeviceId: 'LOCAL', expectedRecipient: '@peer:test', direction: 'outgoing' })).toBeDefined();
  });
  it('rejects relation, no-to violations, duplicates, unsupported subsets, and reused start identity', () => {
    for (const mutate of [
      (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), to: '@me:test' } }),
      (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), 'm.relates_to': { rel_type: 'm.reference', event_id: '$other', extra: true } } }),
      (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), message_authentication_codes: ['hkdf-hmac-sha256.v2', 'hkdf-hmac-sha256.v2'] } }),
      (e: VerificationEnvelope) => ({ ...e, content: { ...(e.content as object), short_authentication_string: ['other'] } }),
      (e: VerificationEnvelope) => ({ ...e, eventId: '$request' }),
    ]) invalid(mutate(related('m.key.verification.start')), relationContext());
    invalid({ ...related('m.key.verification.ready'), content: { ...(related('m.key.verification.ready').content as object), 'm.relates_to': { rel_type: 'm.reference', event_id: '$request', nested: true } } }, relationContext());
  });
  it('rejects each ready/start protocol field and nested unknown object member', () => {
    const ready = related('m.key.verification.ready'); const start = related('m.key.verification.start');
    for (const mutation of [
      { from_device: '' }, { methods: [] }, { 'm.relates_to': { rel_type: 'wrong', event_id: '$request' } }, { extra: true },
    ]) invalid({ ...ready, content: { ...(ready.content as object), ...mutation } }, relationContext());
    for (const mutation of [
      { from_device: '' }, { method: 'wrong' }, { key_agreement_protocols: ['wrong'] }, { hashes: ['wrong'] },
      { message_authentication_codes: [] }, { short_authentication_string: ['decimal', 'decimal'] },
      { 'm.relates_to': { rel_type: 'm.reference', event_id: '$request', unknown: true } }, { unknown: true },
    ]) invalid({ ...start, content: { ...(start.content as object), ...mutation } }, relationContext());
  });
  it('translates only the exact MatrixEvent getter surface and fails closed on a missing getter', () => {
    const source = request(); const matrix = { getType: () => source.type, getContent: () => source.content, getSender: () => source.sender, getId: () => source.eventId, getTs: () => source.originServerTs, getRoomId: () => source.roomId, getUnsigned: () => source.unsigned };
    expect(ownedVerificationEnvelope(matrix)).toBeDefined();
    expect(ownedVerificationEnvelope({ ...matrix, getContent: () => { throw new Error('bad'); } })).toBeUndefined();
  });
});
