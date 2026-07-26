import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { chmod, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PolicyRefreshService, parseRefreshPolicyArgs, readPolicyFile, runRefreshPolicyCli, selectProvenance, type PolicyTransaction } from './refresh-policy.js';
import type { IssuerPolicy } from './entitlements/issuer-policy.js';
import type { PublicJwk } from './entitlements/verify-entitlement.js';
import { FoundationResponseUnavailableError } from './composition.js';

const now = 1_700_000_000;
const policy: IssuerPolicy = { version: 'v1', policyVersion: '2026.07-1', policyUri: 'at://did:plc:abcdefghijklmnopqrstuvwx/us.dsaslate.temp.dsaPolicy/record', rootDid: 'did:plc:abcdefghijklmnopqrstuvwx', issuedAt: now - 1, freshUntil: now + 60, issuers: [] };
const response = { uri: policy.policyUri, provenance: { uri: policy.policyUri, cid: 'bafytest', repoDid: policy.rootDid, repoRev: '3k', sequence: 0, observedAt: '2026-07-18T12:00:00.000+00:00', status: 'verified' as const }, authority: { status: 'official' as const, policyUri: policy.policyUri, policyVersion: policy.policyVersion, rootDid: policy.rootDid, evaluatedAt: '2026-07-18T12:00:00Z' } };
const key = Buffer.alloc(32, 7); const ring = { active: { id: 'active', key }, keys: [{ id: 'active', key }, { id: 'retained', key }] };

async function signed(at = now): Promise<{ compact: string; roots: Record<string, PublicJwk> }> {
  const pair = await generateKeyPair('ES256'); const issuer = await generateKeyPair('ES256'); const root = await exportJWK(pair.publicKey) as PublicJwk; const issuerKey = await exportJWK(issuer.publicKey) as PublicJwk;
  const body = { ...policy, issuedAt: at - 1, freshUntil: at + 60, issuers: [{ did: 'did:plc:bcdefghijklmnopqrstuvwxy', policies: [{ version: policy.policyVersion, state: 'active', transitionedAt: at - 1 }], keys: [{ kid: 'did:plc:bcdefghijklmnopqrstuvwxy#key', state: 'active', transitionedAt: at - 1, publicJwk: issuerKey }] }] };
  return { compact: await new SignJWT(body).setProtectedHeader({ alg: 'ES256', typ: 'dsa-signal-issuer-policy+jws', kid: `${policy.rootDid}#root` }).sign(pair.privateKey), roots: { [`${policy.rootDid}#root`]: root } };
}
function encrypted(compact: string, snapshotId = 'snapshot', version = policy.policyVersion, provenance: unknown = selectProvenance(response, policy), keyId = 'retained') {
  const nonce = randomBytes(12); const aad = Buffer.from(`dsa-signal-policy-snapshot:v1\0${snapshotId}\0${version}`); const cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(aad);
  return { snapshot_id: snapshotId, fresh_until: new Date((now + 60) * 1000), envelope_id: 'envelope', envelope_key_id: keyId, nonce, ciphertext: Buffer.concat([cipher.update(JSON.stringify({ compact, provenance })), cipher.final(), cipher.getAuthTag()]), version, digest: createHash('sha256').update(compact).digest() };
}
function service(roots: Record<string, PublicJwk>, database: { connect: () => Promise<PolicyTransaction & { release(error?: Error): void }> }, resolve: (input: { uri: string; depth: 16 }, options: { signal: AbortSignal }) => Promise<unknown> = async () => response) { return new PolicyRefreshService(database, { resolveAuthority: resolve } as never, roots, policy.policyVersion, ring); }

describe('policy refresh boundaries', () => {
  it('flattens only the nested verified provenance selected for the policy', () => {
    expect(selectProvenance(response, policy)).toMatchObject({ uri: policy.policyUri, cid: 'bafytest', authority: { status: 'official' } });
    expect(() => selectProvenance({ ...response, uri: 'at://wrong' }, policy)).toThrow('policy unavailable');
    expect(() => selectProvenance({ ...response, provenance: { ...response.provenance, uri: 'at://wrong' } }, policy)).toThrow('policy unavailable');
    expect(() => selectProvenance({ ...response, deletedAt: '2026-07-18T12:00:00Z' }, policy)).toThrow('policy unavailable');
  });
  it('discards live Foundation extensions and coarsely rejects invalid timestamps', () => {
    const selected = selectProvenance({ ...response, trace: 'foundation-extension', provenance: { ...response.provenance, diagnostic: 'discarded' }, authority: { ...response.authority, explanation: 'discarded' } }, policy);
    expect(selected).not.toHaveProperty('trace'); expect(selected).not.toHaveProperty('diagnostic'); expect(selected.authority).not.toHaveProperty('explanation');
    for (const malformed of [{ observedAt: '2026-02-30T12:00:00Z' }, { observedAt: '2026-07-18T12:00:00+24:00' }, { authority: { ...response.authority, evaluatedAt: '2026-07-18T12:00:00-24:00' } }]) {
      const input = { ...response, ...malformed, provenance: { ...response.provenance, ...malformed } };
      expect(() => selectProvenance(input, policy)).toThrow('policy unavailable');
      try { selectProvenance(input, policy); } catch (error) { expect(String(error)).not.toContain('2026-'); }
    }
  });
  it('keeps CLI errors coarse and never constructs a service for invalid arguments', async () => {
    const messages: string[] = []; let constructed = false;
    await expect(runRefreshPolicyCli(['--bad', 'secret-policy'], async () => { constructed = true; return { refresh: async () => 'snapshot' }; }, message => messages.push(message))).resolves.toBe(1);
    expect(constructed).toBe(false); expect(messages).toEqual(['policy refresh failed\n']); expect(() => parseRefreshPolicyArgs(['--file'])).toThrow('policy unavailable');
  });

  it('rejects an unavailable Foundation resolution before any policy persistence', async () => {
    const fixture = await signed(); const queries: string[] = [];
    const db = { connect: async () => ({ query: async <T extends Record<string, unknown>>(sql: string) => { queries.push(sql); if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date(now * 1000) }] as unknown as T[] }; return { rows: [] as T[] }; }, release: () => undefined }) };
    await expect(service(fixture.roots, db, async () => { throw new FoundationResponseUnavailableError(); }).refresh(fixture.compact)).rejects.toThrow('policy unavailable');
    expect(queries.some(sql => sql.includes('INSERT INTO control_plane.encrypted_envelopes') || sql.includes('INSERT INTO control_plane.policy_snapshots') || sql.includes('policy_activated'))).toBe(false);
  });
  it('enforces the restore floor before any policy write', async () => {
    const fixture = await signed(); const queries: string[] = []; const db = { connect: async () => ({ query: async <T extends Record<string, unknown>>(sql: string) => { queries.push(sql); return { rows: (sql.includes('clock_timestamp') ? [{ decision_now: new Date(now * 1000) }] : []) as unknown as T[] }; }, release: () => undefined }) };
    const refresh = new PolicyRefreshService(db, { resolveAuthority: async () => response } as never, fixture.roots, policy.policyVersion, ring, 86_400, now);
    await expect(refresh.refresh(fixture.compact)).rejects.toThrow('policy unavailable'); expect(queries.some(sql => sql.includes('INSERT INTO'))).toBe(false);
  });

  it('loads a retained envelope key, rejects the fresh_until boundary, and strictly checks decrypted digest and provenance', async () => {
    const fixture = await signed(); const row = encrypted(fixture.compact); const queries: string[] = [];
    const transaction: PolicyTransaction = { query: async <T extends Record<string, unknown>>(sql: string) => { queries.push(sql); return { rows: [row] as unknown as T[] }; } };
    const refresh = service(fixture.roots, { connect: async () => ({ ...transaction, release: () => undefined }) });
    await expect(refresh.loadActive(transaction, new Date(now * 1000))).resolves.toMatchObject({ snapshotId: 'snapshot' });
    expect(queries[0]).toContain('FOR SHARE');
    await expect(refresh.loadActive(transaction, new Date((now + 60) * 1000))).rejects.toThrow('policy unavailable');
    for (const changed of [encrypted(fixture.compact, 'snapshot', policy.policyVersion, { ...response.provenance, cid: 'wrong' }), { ...encrypted(fixture.compact), digest: Buffer.alloc(32) }]) {
      const tx: PolicyTransaction = { query: async <T extends Record<string, unknown>>() => ({ rows: [changed] as unknown as T[] }) };
      await expect(refresh.loadActive(tx, new Date(now * 1000))).rejects.toThrow('policy unavailable');
    }
  });

  it('uses exclusive refresh locks before the pointer and does not publish until a conflicting authorization share lock releases', async () => {
    const fixture = await signed(); const events: string[] = []; let releaseShare!: () => void; let reached!: () => void; let reachedUpdate!: () => void; const shareReleased = new Promise<void>(resolve => { releaseShare = resolve; }); const reachedAdvisory = new Promise<void>(resolve => { reached = resolve; }); const reachedPointer = new Promise<void>(resolve => { reachedUpdate = resolve; });
    let shared = false;
    const authorization: PolicyTransaction = { query: async <T extends Record<string, unknown>>(sql: string) => { events.push(`auth:${sql}`); shared = true; return { rows: [encrypted(fixture.compact)] as unknown as T[] }; } };
    const db = { connect: async () => ({ query: async <T extends Record<string, unknown>>(sql: string) => { events.push(`refresh:${sql}`); if (sql.includes('pg_advisory_xact_lock')) reached(); if (sql.includes('FOR UPDATE') && shared) { reachedUpdate(); await shareReleased; } if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date(now * 1000) }] as unknown as T[] }; return { rows: [] as T[] }; }, release: () => undefined }) };
    const refresh = service(fixture.roots, db); await refresh.loadActive(authorization, new Date(now * 1000));
    const pending = refresh.refresh(fixture.compact); await reachedAdvisory; await reachedPointer;
    expect(events.some(item => item.includes('pg_advisory_xact_lock'))).toBe(true); expect(events.some(item => item.includes('FOR UPDATE'))).toBe(true); expect(events.some(item => item.includes('policy_activated'))).toBe(false);
    releaseShare(); await expect(pending).resolves.toBeTypeOf('string'); expect(events.some(item => item.includes('policy_activated'))).toBe(true);
  });

  it('checks the locked active signed_at before writing and coarsely rejects equal or older fresh policies', async () => {
    const newer = await signed(now + 2); const equal = await signed(now + 1); const older = await signed(now); const activeSignedAt = new Date(now * 1000);
    for (const fixture of [equal, older]) {
      const queries: string[] = [];
      const db = { connect: async () => ({ query: async <T extends Record<string, unknown>>(sql: string) => {
        queries.push(sql);
        if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date((now + 1) * 1000) }] as unknown as T[] };
        if (sql.includes('FROM control_plane.active_policy')) return { rows: [{ signed_at: activeSignedAt }] as unknown as T[] };
        return { rows: [] as T[] };
      }, release: () => undefined }) };
      await expect(service(fixture.roots, db).refresh(fixture.compact)).rejects.toThrow('policy unavailable');
      expect(queries.findIndex(sql => sql.includes('pg_advisory_xact_lock'))).toBeLessThan(queries.findIndex(sql => sql.includes('signed_at')));
      expect(queries.some(sql => sql.includes('INSERT INTO control_plane.encrypted_envelopes') || sql.includes('INSERT INTO control_plane.policy_snapshots') || sql.includes('policy_activated'))).toBe(false);
    }
    const queries: string[] = [];
    const db = { connect: async () => ({ query: async <T extends Record<string, unknown>>(sql: string) => {
      queries.push(sql);
      if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date((now + 1) * 1000) }] as unknown as T[] };
      if (sql.includes('FROM control_plane.active_policy')) return { rows: [{ signed_at: activeSignedAt }] as unknown as T[] };
      return { rows: [] as T[] };
    }, release: () => undefined }) };
    await expect(service(newer.roots, db).refresh(newer.compact)).resolves.toBeTypeOf('string');
    expect(queries.some(sql => sql.includes('policy_activated'))).toBe(true);
  });

  it('rolls back failed writes and releases with a rollback error', async () => {
    const fixture = await signed(); const released: Error[] = []; const db = { connect: async () => ({ query: async <T extends Record<string, unknown>>(sql: string) => { if (sql === 'ROLLBACK') throw new Error('rollback failure'); if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date(now * 1000) }] as unknown as T[] }; if (sql.includes('encrypted_envelopes')) throw new Error('storage failure'); return { rows: [] as T[] }; }, release: (error?: Error) => { if (error) released.push(error); } }) };
    await expect(service(fixture.roots, db).refresh(fixture.compact)).rejects.toThrow('policy unavailable'); expect(released.map(error => error.message)).toEqual(['rollback failure']);
  });

  it('leaves the prior pointer and no snapshot, envelope, or audit orphan on signature, provenance, stale, or storage failure', async () => {
    const fixture = await signed(); const prior = 'prior-active'; const committed = { pointer: prior, snapshots: 0, envelopes: 0, audits: 0 }; let staged = { snapshots: 0, envelopes: 0, audits: 0 };
    const db = { connect: async () => ({ query: async <T extends Record<string, unknown>>(sql: string) => {
      if (sql === 'ROLLBACK') { staged = { snapshots: 0, envelopes: 0, audits: 0 }; return { rows: [] as T[] }; }
      if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date(now * 1000) }] as unknown as T[] };
      if (sql.includes('encrypted_envelopes')) { staged.envelopes += 1; return { rows: [] as T[] }; }
      if (sql.includes('policy_snapshots')) { staged.snapshots += 1; throw new Error('storage'); }
      if (sql.includes('security_audit_events')) staged.audits += 1;
      return { rows: [] as T[] };
    }, release: () => undefined }) };
    await expect(service(fixture.roots, db).refresh(fixture.compact)).rejects.toThrow('policy unavailable');
    expect(committed).toEqual({ pointer: prior, snapshots: 0, envelopes: 0, audits: 0 }); expect(staged).toEqual({ snapshots: 0, envelopes: 0, audits: 0 });
    await expect(service(fixture.roots, db, async () => ({ ...response, provenance: { ...response.provenance, cid: '' } })).refresh(fixture.compact)).rejects.toThrow('policy unavailable');
    await expect(service(fixture.roots, db).refresh('not-a-signature')).rejects.toThrow('policy unavailable');
    const stale = await signed(now - 90_000); await expect(service(stale.roots, db).refresh(stale.compact)).rejects.toThrow('policy unavailable');
    expect(committed).toEqual({ pointer: prior, snapshots: 0, envelopes: 0, audits: 0 });
  });

  it('aborts a stalled Foundation policy resolve after five seconds without exposing its canary', async () => {
    vi.useFakeTimers(); const fixture = await signed(); let aborted = false; let began!: () => void; const begun = new Promise<void>(resolve => { began = resolve; });
    const refresh = service(fixture.roots, { connect: async () => ({ query: async <T extends Record<string, unknown>>(sql: string) => ({ rows: (sql.includes('clock_timestamp') ? [{ decision_now: new Date(now * 1000) }] : []) as unknown as T[] }), release: () => undefined }) }, async (_input: { uri: string; depth: 16 }, options: { signal: AbortSignal }) => { began(); return await new Promise((_, reject) => options.signal.addEventListener('abort', () => { aborted = true; reject(new Error('canary compact provenance')); })); });
    const result = expect(refresh.refresh(fixture.compact)).rejects.toThrow('policy unavailable'); await begun; await vi.advanceTimersByTimeAsync(5_000); await result; expect(aborted).toBe(true); vi.useRealTimers();
  });
});

describe('readPolicyFile', () => {
  const directories: string[] = []; afterEach(async () => { vi.useRealTimers(); await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true }))); });
  async function file(name: string, content: string): Promise<string> { const directory = await mkdtemp(join(tmpdir(), 'policy-')); directories.push(directory); const path = join(directory, name); await writeFile(path, content, { mode: 0o600 }); return path; }
  it('accepts only a private regular owner file and keeps file canaries out of errors and CLI output', async () => {
    const path = await file('policy', 'compact.canary.payload'); await expect(readPolicyFile(path)).resolves.toBe('compact.canary.payload');
    await chmod(path, 0o622); await expect(readPolicyFile(path)).rejects.toThrow('policy unavailable');
    const output: string[] = []; await expect(runRefreshPolicyCli(['--file', path], async () => ({ refresh: async () => { throw new Error('compact.canary.payload'); } }), value => output.push(value))).resolves.toBe(1); expect(output.join('')).not.toContain('canary');
  });
  it('rejects symlinks and oversized files without returning their bytes', async () => {
    const target = await file('target', 'secret-policy-canary'); const link = join(tmpdir(), `policy-link-${Date.now()}-${Math.random()}`); directories.push(link);
    await symlink(target, link); await expect(readPolicyFile(link)).rejects.toThrow('policy unavailable');
    const large = await file('large', 'x'.repeat(16_385)); await expect(readPolicyFile(large)).rejects.toThrow('policy unavailable');
  });
});
