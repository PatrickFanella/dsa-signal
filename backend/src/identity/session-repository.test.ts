import { createDecipheriv } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createSessionRepository, IdentityStorageError } from './session-repository.js';

const key = (byte: number) => new Uint8Array(Buffer.alloc(32, byte));
const ring = (byte: number) => ({ active: 'v1', keys: { v1: key(byte) } });
const id = Buffer.alloc(32, 4).toString('base64url');
describe('session repository', () => {
  it('creates an AES mapping under an advisory lock before atomically replacing a session', async () => {
    const calls: Array<{ sql: string; values?: readonly unknown[] }> = [];
    const client = { query: async (sql: string, values?: readonly unknown[]) => {
      calls.push({ sql, values: values?.map((value) => Buffer.isBuffer(value) ? Buffer.from(value) : value) });
      if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date('2026-07-17T00:00:00Z') }], rowCount: 1 };
      if (sql.startsWith('SELECT id FROM control_plane.did_mappings')) return { rows: [], rowCount: 0 };
      if (sql.startsWith('SELECT barrier_state FROM control_plane.membership_access_states')) return { rows: [{ barrier_state: 'active' }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }, release: () => undefined };
    const repository = createSessionRepository({ pool: { connect: async () => client } as never, pwaOrigin: 'https://chat.example', sector: 'chat-sector', subjectKeys: ring(1), envelopeKeys: ring(2), bindingKeys: ring(3) });
    await repository.establishFromHandoff({ did: 'did:plc:abcdefghijklmnopqrstuvwx', audience: 'https://chat.example', authenticatedAt: '2026-07-17T00:00:00Z', expiresIn: 60 }, id, Buffer.alloc(32, 5).toString('base64url'));
    expect(calls.findIndex(({ sql }) => sql.includes('membership_access_source_set_fence'))).toBeLessThan(calls.findIndex(({ sql }) => sql.startsWith('SELECT id FROM control_plane.did_mappings')));
    expect(calls.some(({ sql }) => sql.includes('pg_advisory_xact_lock'))).toBe(true);
    const envelope = calls.find(({ sql }) => sql.startsWith('INSERT INTO control_plane.encrypted_envelopes'))!.values!;
    const mapping = calls.find(({ sql }) => sql.startsWith('INSERT INTO control_plane.did_mappings'))!.values!;
    expect(envelope[0]).not.toBe(mapping[0]);
    const ciphertext = envelope[3] as Buffer; const decipher = createDecipheriv('aes-256-gcm', key(2), envelope[2] as Buffer);
    decipher.setAAD(Buffer.from(`dsa-signal-did-mapping:v1\0${mapping[0]}\0chat-sector`)); decipher.setAuthTag(ciphertext.subarray(-16));
    expect(Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]).toString()).toBe('did:plc:abcdefghijklmnopqrstuvwx');
    const revoke = calls.findIndex(({ sql }) => sql.startsWith('UPDATE control_plane.identity_sessions SET revoked_at'));
    const insert = calls.findIndex(({ sql }) => sql.startsWith('INSERT INTO control_plane.identity_sessions'));
    expect(revoke).toBeGreaterThan(insert);
    expect(mapping[1]).toBe('chat-sector');
    expect(calls.find(({ sql }) => sql.startsWith('INSERT INTO control_plane.identity_sessions'))!.values![4]).toBe('https://chat.example');
  });
  it('reuses a retained-subject mapping during subject-key rotation', async () => {
    const calls: Array<{ sql: string; values?: readonly unknown[] }> = [];
    const client = { query: async (sql: string, values?: readonly unknown[]) => {
      calls.push({ sql, values });
      if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date('2026-07-17T00:00:00Z') }] };
      if (sql.startsWith('SELECT id FROM control_plane.did_mappings')) return { rows: [{ id: 'old-mapping' }] };
      if (sql.startsWith('SELECT barrier_state FROM control_plane.membership_access_states')) return { rows: [{ barrier_state: 'active' }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    }, release: () => undefined };
    const subjectKeys = { active: 'new', keys: { new: key(1), old: key(2) } };
    const repository = createSessionRepository({ pool: { connect: async () => client } as never, pwaOrigin: 'https://chat.example', sector: 'chat-sector', subjectKeys, envelopeKeys: ring(2), bindingKeys: ring(3) });
    await expect(repository.establishFromHandoff({ did: 'did:plc:abcdefghijklmnopqrstuvwx', audience: 'https://chat.example', authenticatedAt: '2026-07-17T00:00:00Z', expiresIn: 60 }, id)).resolves.toEqual({ mappingId: 'old-mapping', sessionId: id });
    const lookup = calls.find(call => call.sql.startsWith('SELECT id FROM control_plane.did_mappings'))!;
    expect(lookup.values?.[1]).toEqual(['new', 'old']);
    expect(calls.some(call => call.sql.startsWith('INSERT INTO control_plane.did_mappings'))).toBe(false);
    expect(calls.some(call => call.sql.startsWith('INSERT INTO control_plane.encrypted_envelopes'))).toBe(false);
    expect(calls.filter(call => call.sql.startsWith('INSERT INTO control_plane.identity_sessions'))).toHaveLength(1);
  });
  it('distinguishes a missing row from storage and malformed-session failures', async () => {
    const client = { query: async (sql: string) => sql.includes('clock_timestamp') ? { rows: [{ decision_now: new Date() }] } : { rows: [], rowCount: 0 }, release: () => undefined };
    const repository = createSessionRepository({ pool: { connect: async () => client } as never, pwaOrigin: 'https://chat.example', sector: 'chat-sector', subjectKeys: ring(1), envelopeKeys: ring(2), bindingKeys: ring(3) });
    await expect(repository.authenticate(id, 'https://chat.example')).resolves.toBeUndefined();
    await expect(repository.authenticate('malformed', 'https://chat.example')).rejects.toBeInstanceOf(IdentityStorageError);
    const unavailable = createSessionRepository({ pool: { connect: async () => { throw new Error('db'); } }, pwaOrigin: 'https://chat.example', sector: 'chat-sector', subjectKeys: ring(1), envelopeKeys: ring(2), bindingKeys: ring(3) });
    await expect(unavailable.authenticate(id, 'https://chat.example')).rejects.toBeInstanceOf(IdentityStorageError);
  });
});
