import { describe, expect, it } from 'vitest';
import { ChallengeRejectedError, ChallengeUnavailableError, InvalidChallengeRequest, createChallengeService, fingerprint, issueChallenge, sessionBinding } from './challenge-service.js';

const ring = { active: 'v1', keys: { v1: new Uint8Array([...Array(32).keys()]) } };

describe('challenge fingerprints', () => {
  it('uses the contract challenge byte domain', () => {
    expect(Buffer.from(fingerprint(ring, 'dsa-signal-challenge-fingerprint:v1', new Uint8Array([...Array(32).keys()])).value).toString('base64url')).toBe('wwFirTEsGhYm_ydyVpzERg1Yykf1LjTvkjKCLeHB1e4');
  });

  it('keeps the session identifier in a distinct domain', () => {
    expect(Buffer.from(sessionBinding(ring, 'a'.repeat(43)).value)).not.toEqual(Buffer.from(fingerprint(ring, 'dsa-signal-challenge-fingerprint:v1', Buffer.from('a'.repeat(43))).value));
  });

  it('does not clear key-ring material while clearing helper copies', () => {
    const before = Buffer.from(ring.keys.v1);
    issueChallenge(ring);
    expect(Buffer.from(ring.keys.v1)).toEqual(before);
  });

  it('classifies malformed JKT separately from a rejected session', async () => {
    const service = createChallengeService({ pool: { connect: async () => { throw new Error('not reached'); } }, challengeKeys: ring, bindingKeys: ring, pwaOrigin: 'https://chat.example', policyRefresh: {} as never });
    await expect(service.issue('session', 'https://chat.example', 'not-base64')).rejects.toBeInstanceOf(InvalidChallengeRequest);
    await expect(service.issue('session', 'https://other.example', 'A'.repeat(43))).rejects.toBeInstanceOf(ChallengeRejectedError);
  });

  it('destroys a client whose rollback fails', async () => {
    const rollbackError = new Error('rollback failed');
    const releasedWith: Array<Error | undefined> = [];
    const client = {
      query: async (sql: string) => {
        if (sql === 'BEGIN') return { rows: [] };
        if (sql === 'ROLLBACK') throw rollbackError;
        throw new Error('clock failed');
      },
      release: (error?: Error) => { releasedWith.push(error); },
    };
    const service = createChallengeService({ pool: { connect: async () => client as never }, challengeKeys: ring, bindingKeys: ring, pwaOrigin: 'https://chat.example', policyRefresh: {} as never });

    await expect(service.issue('session', 'https://chat.example', 'A'.repeat(43))).rejects.toBeInstanceOf(ChallengeUnavailableError);
    expect(releasedWith).toEqual([rollbackError]);
  });

  it('makes rollback failure unavailable even when the session is rejected', async () => {
    const rollbackError = new Error('rollback failed'); const releasedWith: Array<Error | undefined> = [];
    const client = { query: async (sql: string) => {
      if (sql === 'ROLLBACK') throw rollbackError;
      if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date() }] };
      if (sql.includes('identity_sessions WHERE')) return { rows: [] };
      return { rows: [] };
    }, release: (error?: Error) => { releasedWith.push(error); } };
    const service = createChallengeService({ pool: { connect: async () => client as never }, challengeKeys: ring, bindingKeys: ring, pwaOrigin: 'https://chat.example', policyRefresh: {} as never });
    await expect(service.issue('session', 'https://chat.example', 'A'.repeat(43))).rejects.toBeInstanceOf(ChallengeUnavailableError);
    expect(releasedWith).toEqual([rollbackError]);
  });

  it('uses retained binding keys for lookup but only the active challenge key for writes', async () => {
    const rotatingRing = {
      active: 'v2',
      keys: {
        v1: new Uint8Array([...Array(32).keys()]),
        v2: new Uint8Array([...Array(32).keys()].map(value => value + 1)),
      },
    };
    const queries: Array<{ sql: string; values?: readonly unknown[] }> = [];
    const now = new Date('2026-07-18T12:00:00.000Z');
    const client = {
      query: async (sql: string, values?: readonly unknown[]) => {
        queries.push({ sql, values });
        if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: now }] };
        if (sql.includes('identity_sessions WHERE')) return { rows: [{ mapping_id: 'mapping', binding_key_id: 'v1', binding_fingerprint: Buffer.alloc(32, 7) }] };
        return { rows: [], rowCount: sql.includes('UPDATE control_plane.identity_sessions') ? 1 : 0 };
      },
      release: () => undefined,
    };
    const service = createChallengeService({
      pool: { connect: async () => client as never },
      challengeKeys: rotatingRing,
      bindingKeys: rotatingRing,
      pwaOrigin: 'https://chat.example',
      policyRefresh: { loadActive: async () => ({}) } as never,
    });

    await service.issue('session', 'https://chat.example', 'A'.repeat(43));

    const lookup = queries.find(query => query.sql.includes('identity_sessions WHERE'));
    expect(queries.findIndex(query => query.sql.includes('membership_access_source_set_fence'))).toBeLessThan(queries.indexOf(lookup!));
    expect(lookup?.values?.[0]).toEqual(['v1', 'v2']);
    const insert = queries.find(query => query.sql.includes('INSERT INTO control_plane.proof_challenges'));
    expect(insert?.values?.[1]).toBe('v2');
    expect(queries.filter(query => query.sql.includes('INSERT INTO control_plane.proof_challenges'))).toHaveLength(1);
  });
});
