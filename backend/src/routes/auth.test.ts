import { describe, expect, it } from 'vitest';
import { createLogoutService, LogoutUnavailableError } from './auth.js';
import { OidcIndeterminateCommitError } from '../oidc/request-context.js';
import type { Pool } from 'pg';

const id = Buffer.alloc(32, 9).toString('base64url');
const ring = { active: 'v1', keys: { v1: Buffer.alloc(32, 7) } };
function database(rows: Record<string, unknown[]> = {}, clocks = [new Date('2026-07-19T00:00:00Z')]) {
  const sql: string[] = [];
  let clock = 0;
  const client = { query: async <T extends Record<string, unknown>>(statement: string) => {
    sql.push(statement);
    if (statement === 'SELECT clock_timestamp() AS decision_now') return { rowCount: 1, rows: [{ decision_now: clocks[Math.min(clock++, clocks.length - 1)] }] as unknown as T[] };
    if (statement.includes('FROM control_plane.identity_sessions') && statement.includes('unnest($1::text[]')) return { rowCount: rows.match?.length ?? 0, rows: (rows.match ?? []) as T[] };
    if (statement.startsWith('SELECT DISTINCT mapping_id')) return { rowCount: 1, rows: [{ mapping_id: 'mapping-id' }] as unknown as T[] };
    if (statement.includes('membership_access_states WHERE mapping_id=$1')) return { rowCount: 1, rows: [{ barrier_state: 'active' }] as unknown as T[] };
    if (statement.includes('FROM control_plane.identity_sessions WHERE binding_key_id') && statement.includes('FOR UPDATE')) return { rowCount: rows.identityLock?.length ?? 1, rows: (rows.identityLock ?? [{ binding_key_id: 'v1', binding_fingerprint: Buffer.alloc(32, 1) }]) as T[] };
    if (statement.startsWith('SELECT 1 FROM control_plane.identity_sessions')) return { rowCount: rows.eligible?.length ?? 1, rows: (rows.eligible ?? [{}]) as T[] };
    if (statement.includes('FROM oidc.authorization_contexts')) return { rowCount: rows.contexts?.length ?? 1, rows: (rows.contexts ?? [{ grant_key_id: 'v1', grant_fingerprint: Buffer.alloc(32, 2) }]) as T[] };
    return { rowCount: 1, rows: [] as T[] };
  }, release: () => undefined };
  return { sql, pool: { connect: async () => client } as unknown as Pick<Pool, 'connect'> };
}
describe('logout service', () => {
  it('treats an unknown session as successful', async () => {
    const db = database(); await createLogoutService({ pool: db.pool, oidcEpoch: 'A'.repeat(21) + 'A', bindingKeys: ring }).logout(id);
    expect(db.sql.some(value => value.includes('hashtextextended') || value.includes("encode($1::bytea"))).toBe(false);
  });
  it('locks session, entitlement, policy, contexts, then artifacts and revokes by fingerprints', async () => {
    const db = database({ match: [{ binding_key_id: 'v1', binding_fingerprint: Buffer.alloc(32, 1) }] }); await createLogoutService({ pool: db.pool, oidcEpoch: 'A'.repeat(21) + 'A', bindingKeys: ring }).logout(id);
    const position = (needle: string) => db.sql.map(value => value.includes(needle)).lastIndexOf(true);
    expect(position('membership_access_source_set_fence')).toBeLessThan(position('dsa-signal-membership-access'));
    const sessionLock = db.sql.findIndex(value => value.includes('identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2 FOR UPDATE'));
    expect(position('dsa-signal-membership-access')).toBeLessThan(sessionLock);
    expect(sessionLock).toBeLessThan(position('control_plane.entitlements'));
    expect(position('control_plane.entitlements')).toBeLessThan(position('control_plane.active_policy'));
    expect(position('control_plane.active_policy')).toBeLessThan(position('oidc.authorization_contexts'));
    expect(db.sql.findIndex(value => value.includes('oidc.authorization_contexts'))).toBeLessThan(db.sql.findIndex(value => value.includes('oidc.provider_artifacts')));
    expect(db.sql.join('\n')).toContain('grant_expires_at>$4');
    expect(db.sql.filter(value => value === 'SELECT clock_timestamp() AS decision_now')).toHaveLength(3);
    expect(db.sql.join('\n')).not.toContain('Grant ID');
  });
  it('uses only the current epoch for both logout candidate reads', async () => {
    const db = database({ match: [{ binding_key_id: 'v1', binding_fingerprint: Buffer.alloc(32, 1) }] });
    const epoch = 'A'.repeat(22);
    await createLogoutService({ pool: db.pool, oidcEpoch: epoch, bindingKeys: ring }).logout(id);
    const candidates = db.sql.filter(value => value.startsWith('SELECT DISTINCT mapping_id'));
    expect(candidates).toHaveLength(2);
    expect(candidates.every(value => value.includes('epoch=$3') && value.includes('grant_expires_at>$4'))).toBe(true);
  });
  it('does not mutate identity, context, or provider artifacts when a context-only logout candidate expires while exact artifact locks wait', async () => {
    const db = database({
      match: [{ binding_key_id: 'v1', binding_fingerprint: Buffer.alloc(32, 1) }],
      eligible: [],
      contexts: [{ grant_key_id: 'v1', grant_fingerprint: Buffer.alloc(32, 2), revoked_at: null, grant_expires_at: new Date('2026-07-19T00:00:30Z') }],
    }, [new Date('2026-07-19T00:00:00Z'), new Date('2026-07-19T00:00:00Z'), new Date('2026-07-19T00:01:00Z')]);
    await createLogoutService({ pool: db.pool, oidcEpoch: 'A'.repeat(22), bindingKeys: ring }).logout(id);
    expect(db.sql.filter(value => value.startsWith('UPDATE control_plane.identity_sessions'))).toHaveLength(0);
    expect(db.sql.filter(value => value.startsWith('UPDATE oidc.authorization_contexts'))).toHaveLength(0);
    expect(db.sql.filter(value => value.startsWith('UPDATE oidc.provider_artifacts'))).toHaveLength(0);
    expect(db.sql.filter(value => value === 'SELECT clock_timestamp() AS decision_now')).toHaveLength(3);
    const eligibility = db.sql.find(value => value.startsWith('SELECT 1 FROM control_plane.identity_sessions'));
    expect(eligibility).toContain('grant_expires_at>$3');
    expect(eligibility).toContain('absolute_expires_at');
  });
  it('coarsens storage failures but preserves indeterminate commits', async () => {
    const unavailable = { connect: async () => { throw new Error('secret'); } } as unknown as Pick<Pool, 'connect'>;
    await expect(createLogoutService({ pool: unavailable, oidcEpoch: 'A'.repeat(21) + 'A', bindingKeys: ring }).logout(id)).rejects.toBeInstanceOf(LogoutUnavailableError);
    const indeterminate = new OidcIndeterminateCommitError(new Error());
    const db = { connect: async () => ({ query: async (sql: string) => { if (sql === 'COMMIT') throw indeterminate; if (sql === 'SELECT clock_timestamp() AS decision_now') return { rows: [{ decision_now: new Date() }], rowCount: 1 }; return { rows: [], rowCount: 0 }; }, release: () => undefined }) } as unknown as Pick<Pool, 'connect'>;
    await expect(createLogoutService({ pool: db, oidcEpoch: 'A'.repeat(21) + 'A', bindingKeys: ring }).logout(id)).rejects.toBeInstanceOf(OidcIndeterminateCommitError);
  });
});
