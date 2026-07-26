import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { IndexedDbSessionStore, SessionStoreError, type TextOutboxRecord } from '../src/auth/session-store';
import { classifyLockedVerification, validateVerificationEnvelope, type VerificationEnvelope, type VerificationWireContext } from '../src/matrix/verification-wire';

const sender = '@peer:example'; const requestId = '$request'; const context: VerificationWireContext = { roomId: '!room:example', expectedSender: sender, expectedSenderDeviceId: 'DEVICE', expectedRecipient: '@me:example', direction: 'incoming', now: 1_000 };
const fallback = `${sender} is requesting to verify your key, but your client does not support in-chat key verification. You will need to use legacy key verification to verify keys.`;
const envelope = (type: string, content: object, eventId = '$event'): VerificationEnvelope => ({ type, content, sender, eventId, originServerTs: 1_000 });
const request = envelope('m.room.message', { msgtype: 'm.key.verification.request', to: '@me:example', from_device: 'DEVICE', methods: ['m.sas.v1'], body: fallback }, requestId);
const relation = { rel_type: 'm.reference', event_id: requestId };
const b64_32 = 'A'.repeat(43);

describe('Task 9 production boundaries', () => {
  it('accepts locked request/ready/start fixtures and rejects chat, unknown, additional, and nested fields', () => {
    expect(validateVerificationEnvelope(request, context)?.kind).toBe('request');
    const bound = { ...context, expectedRecipient: undefined, requestEventId: requestId };
    expect(validateVerificationEnvelope(envelope('m.key.verification.ready', { from_device: 'DEVICE', methods: ['m.sas.v1'], 'm.relates_to': relation }), bound)?.kind).toBe('ready');
    expect(validateVerificationEnvelope(envelope('m.key.verification.start', { from_device: 'DEVICE', method: 'm.sas.v1', key_agreement_protocols: ['curve25519-hkdf-sha256'], hashes: ['sha256'], message_authentication_codes: ['hkdf-hmac-sha256.v2'], short_authentication_string: ['decimal'], 'm.relates_to': relation }), bound)?.kind).toBe('start');
    expect(validateVerificationEnvelope(envelope('m.room.message', { msgtype: 'm.text', body: 'chat plaintext' }), context)).toBeUndefined();
    expect(validateVerificationEnvelope(envelope('m.room.message', { ...(request.content as object), extra: 'no' }, requestId), context)).toBeUndefined();
    expect(validateVerificationEnvelope(envelope('m.key.verification.ready', { from_device: 'DEVICE', methods: ['m.sas.v1'], 'm.relates_to': { ...relation, nested: true } }), bound)).toBeUndefined();
  });
  it('classifies every locked schema for exact browser bodies and server envelopes', () => {
    const base = { from_device: 'DEVICE', 'm.relates_to': relation }; const fixtures: Record<string, object> = {
      request: request.content as object,
      ready: { ...base, methods: ['m.sas.v1'] },
      start: { ...base, method: 'm.sas.v1', key_agreement_protocols: ['curve25519-hkdf-sha256'], hashes: ['sha256'], message_authentication_codes: ['hkdf-hmac-sha256.v2'], short_authentication_string: ['decimal'] },
      accept: { 'm.relates_to': relation, key_agreement_protocol: 'curve25519-hkdf-sha256', hash: 'sha256', message_authentication_code: 'hkdf-hmac-sha256.v2', short_authentication_string: ['emoji'], commitment: b64_32 },
      key: { 'm.relates_to': relation, key: b64_32 }, mac: { 'm.relates_to': relation, mac: { 'ed25519:DEVICE': b64_32 }, keys: b64_32 }, done: { 'm.relates_to': relation },
      cancel: { 'm.relates_to': relation, code: 'm.user', reason: 'cancelled' }
    };
    for (const [kind, body] of Object.entries(fixtures)) {
      const lockedContext = { expectedSender: sender, expectedRecipient: '@me:example', requestEventId: requestId, roomId: '!room:example', freshness: { now: 1_000, maxPastMs: 0, maxFutureMs: 0 } };
      expect(classifyLockedVerification('browser-send-body', body, lockedContext)?.kind).toBe(kind);
      const type = kind === 'request' ? 'm.room.message' : `m.key.verification.${kind}`;
      const server = { type, content: body, sender, event_id: kind === 'request' ? requestId : '$server', origin_server_ts: 1_000, room_id: '!room:example', unsigned: { age: 0 } };
      expect(classifyLockedVerification('server-envelope', server, lockedContext)?.kind).toBe(kind);
      expect(classifyLockedVerification('browser-send-body', { ...body, extra: true }, lockedContext)).toBeUndefined();
    }
    expect(classifyLockedVerification('server-envelope', { type: 'm.key.verification.done', content: { 'm.relates_to': { ...relation, extra: true } }, sender, event_id: '$server', origin_server_ts: 1_000, room_id: '!room:example', unsigned: {} }, { expectedSender: sender, expectedRecipient: '@me:example', requestEventId: requestId, freshness: { now: 1_000, maxPastMs: 0, maxFutureMs: 0 } })).toBeUndefined();
  });
  it('rejects noncanonical, wrong-length, and malformed values for every locked event on both targets', () => {
    const valid: Record<string, object> = { request: request.content as object, ready: { from_device: 'DEVICE', methods: ['m.sas.v1'], 'm.relates_to': relation }, start: { from_device: 'DEVICE', method: 'm.sas.v1', key_agreement_protocols: ['curve25519-hkdf-sha256'], hashes: ['sha256'], message_authentication_codes: ['hkdf-hmac-sha256.v2'], short_authentication_string: ['decimal'], 'm.relates_to': relation }, accept: { commitment: b64_32, key_agreement_protocol: 'curve25519-hkdf-sha256', hash: 'sha256', message_authentication_code: 'hkdf-hmac-sha256.v2', short_authentication_string: ['decimal'], 'm.relates_to': relation }, key: { key: b64_32, 'm.relates_to': relation }, mac: { mac: { 'ed25519:DEVICE': b64_32 }, keys: b64_32, 'm.relates_to': relation }, done: { 'm.relates_to': relation }, cancel: { code: 'm.user', reason: 'cancelled', 'm.relates_to': relation } };
    const context = { expectedSender: sender, expectedRecipient: '@me:example', requestEventId: requestId, roomId: '!room:example', freshness: { now: 1_000, maxPastMs: 0, maxFutureMs: 0 } } as const;
    for (const [kind, body] of Object.entries(valid)) {
      const invalid = kind === 'accept' ? { ...body, commitment: 'AA==' } : kind === 'key' ? { ...body, key: 'A'.repeat(42) } : kind === 'mac' ? { ...body, mac: { 'ed25519:bad key': 'A'.repeat(43) } } : kind === 'cancel' ? { ...body, reason: 'bad\nreason' } : { ...body, extra: true };
      expect(classifyLockedVerification('browser-send-body', invalid, context)).toBeUndefined();
      const type = kind === 'request' ? 'm.room.message' : `m.key.verification.${kind}`;
      expect(classifyLockedVerification('server-envelope', { type, content: invalid, sender, event_id: kind === 'request' ? requestId : '$server', origin_server_ts: 1_000, room_id: '!room:example' }, context)).toBeUndefined();
    }
    expect(classifyLockedVerification('server-envelope', { type: 'm.room.message', content: request.content, sender, event_id: '$other', origin_server_ts: 1_000, room_id: '!room:example' }, context)).toBeUndefined();
    expect(classifyLockedVerification('browser-send-body', request.content, { ...context, expectedRecipient: '@other:example' })).toBeUndefined();
    expect(classifyLockedVerification('server-envelope', { type: 'm.key.verification.done', content: valid.done, sender, event_id: requestId, origin_server_ts: 1_000, room_id: '!room:example' }, context)).toBeUndefined();
  });
  it('durably stores only valid hash/metadata outbox records in fake IndexedDB', async () => {
    const name = `task9-${crypto.randomUUID()}`; const store = await IndexedDbSessionStore.open(indexedDB, name);
    const record: TextOutboxRecord = { profileId: 'a'.repeat(64), transactionId: 'txn', roomId: '!room:example', bodyHash: 'b'.repeat(64), state: 'local-pending', baselineGeneration: 0, requiredGeneration: 0, retryConsumed: false, indeterminate: false, generation: 1 };
    await expect(store.createTextOutboxRecord(record)).resolves.toBe(true);
    expect(await store.getTextOutboxRecord({ profileId: record.profileId }, 'txn')).toEqual(record);
    await expect(store.createTextOutboxRecord({ ...record, transactionId: 'bad', bodyHash: 'plaintext' })).rejects.toBeInstanceOf(SessionStoreError);
    const db = (store as unknown as { db: IDBDatabase }).db; const raw = await new Promise<unknown>((resolve, reject) => { const get = db.transaction('textOutbox').objectStore('textOutbox').get([record.profileId, 'txn']); get.onsuccess = () => resolve(get.result); get.onerror = () => reject(get.error); });
    expect(raw).toEqual(record); expect(JSON.stringify(raw)).not.toContain('chat plaintext'); store.close(); indexedDB.deleteDatabase(name);
  });
});
