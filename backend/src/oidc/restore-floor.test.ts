import { chmod, lstat, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { appendOidcActivation, appendRestoreFloor, INITIAL_RESTORE_FLOOR_HEAD, loadPublishedRestoreFloor, loadRestoreFloor, loadRestoreFloorHistory, loadRestoreFloorLedger, type RestoreActivation } from './restore-floor.js';

const dirs: string[] = [];
const fingerprint = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
const initial = 'BQSLpPDcieO3Yt-iBZbnZTblaCULvwaJAAxi4Pd8TtA';
const v2Head = 'jf_QH1dzSaFwcyusyOKWQBIrhxtV9sbBaUSiUptL0J0';
const v3Head = 'i9p-1qZ6tD7nL1eYELesO8u3aV7K0PtIKzUv7yUqS6Y';
const binding: RestoreActivation = { epoch: 'AQEBAQEBAQEBAQEBAQEBAQ', adapter: { active: 'adapter', keys: [{ id: 'adapter', fingerprint }] }, index: { active: 'index', keys: [{ id: 'index', fingerprint }] }, cookieKeyFingerprints: [fingerprint], clientSecretFingerprint: fingerprint, signingKeys: [{ kid: 'signing', fingerprint }, { kid: 'z', fingerprint }] };
const historicalV2 = '{"version":"v2","sequence":1,"minimumIssuedAt":"2026-01-01T00:00:01Z","previousHead":"BQSLpPDcieO3Yt-iBZbnZTblaCULvwaJAAxi4Pd8TtA","activation":{"epoch":"AQEBAQEBAQEBAQEBAQEBAQ","adapter":{"active":"adapter","keys":[{"id":"adapter","fingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}]},"index":{"active":"index","keys":[{"id":"index","fingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}]},"cookieKeyFingerprints":["BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"],"clientSecretFingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","signingKeys":[{"kid":"signing","fingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"},{"kid":"z","fingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}]}}';
const historicalV3 = '{"version":"v3","kind":"activation","sequence":2,"minimumIssuedAt":"2026-01-01T00:00:01Z","previousHead":"jf_QH1dzSaFwcyusyOKWQBIrhxtV9sbBaUSiUptL0J0","activation":{"epoch":"AQEBAQEBAQEBAQEBAQEBAQ","adapter":{"active":"adapter","keys":[{"id":"adapter","fingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}]},"index":{"active":"index","keys":[{"id":"index","fingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}]},"cookieKeyFingerprints":["BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"],"clientSecretFingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","signingKeys":[{"kid":"signing","fingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"},{"kid":"z","fingerprint":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}]}}';

async function directory(): Promise<string> { const dir = await mkdtemp(join(tmpdir(), 'restore-floor-')); dirs.push(dir); await chmod(dir, 0o700); return dir; }
const name = (sequence: number): string => sequence.toString().padStart(20, '0');
async function put(dir: string, sequence: number, bytes: string): Promise<void> { await writeFile(join(dir, name(sequence)), bytes, { mode: 0o600 }); await chmod(join(dir, name(sequence)), 0o600); }
const expectation = (floor = 0, sequence = 1, head = INITIAL_RESTORE_FLOOR_HEAD) => ({ expectedPreviousFloor: floor, expectedNextSequence: sequence, expectedHead: head });
const unavailable = (promise: Promise<unknown>) => expect(promise).rejects.toThrow('restore floor unavailable');
afterEach(async () => { await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); });

describe('OIDC restore-floor ledger publication', () => {
  it('loads hard-coded historical v2 bytes using kid-sorted legacy binding and appends the known v3 head', async () => {
    const dir = await directory(); await put(dir, 1, historicalV2);
    const runtimeOrder = { ...binding, signingKeys: [...binding.signingKeys].reverse() };
    // v2 historically signs a kid-sorted representation; this runtime order must not matter.
    const legacy = { ...binding, signingKeys: runtimeOrder.signingKeys };
    expect(initial).toBe(INITIAL_RESTORE_FLOOR_HEAD);
    expect(await loadRestoreFloor(dir, v2Head, legacy)).toEqual({ minimumIssuedAt: 1767225601, sequence: 1, head: v2Head });
    const activation = await appendOidcActivation(dir, binding, expectation(1767225601, 2, v2Head));
    expect(activation).toEqual({ minimumIssuedAt: 1767225601, sequence: 2, head: v3Head });
    expect(await loadRestoreFloor(dir, v3Head, binding)).toEqual(activation);
  });

  it('returns every validated non-secret activation in sequence order', async () => {
    const dir = await directory(); const first = await appendRestoreFloor(dir, new Date(0), binding, expectation());
    const later = { ...binding, epoch: Buffer.alloc(16, 2).toString('base64url') };
    const second = await appendOidcActivation(dir, later, expectation(first.minimumIssuedAt, 2, first.head));
    const ledger = await loadRestoreFloorLedger(dir, second.head, later);
    expect(ledger).toMatchObject({ minimumIssuedAt: first.minimumIssuedAt, sequence: 2, head: second.head });
    expect(ledger.activations).toEqual([binding, later]);
  });

  it('loads predecessor history independently of the latest runtime binding, while startup remains bound', async () => {
    const dir = await directory(); const first = await appendRestoreFloor(dir, new Date(0), binding, expectation());
    const latest = { ...binding, epoch: Buffer.alloc(16, 2).toString('base64url') };
    const second = await appendOidcActivation(dir, latest, expectation(first.minimumIssuedAt, 2, first.head));
    await unavailable(loadRestoreFloor(dir, second.head, binding));
    expect((await loadRestoreFloorHistory(dir, second.head)).activations).toEqual([binding, latest]);
  });

  it('authenticates only the exact already-published restore candidate, clock, and predecessor', async () => {
    const dir = await directory(); const clock = new Date('2026-01-01T00:00:00Z'); const published = await appendRestoreFloor(dir, clock, binding, expectation());
    expect(await loadPublishedRestoreFloor(dir, clock, binding, expectation())).toEqual(published);
    expect(await loadPublishedRestoreFloor(dir, new Date('2026-01-01T00:00:01Z'), binding, expectation())).toBeUndefined();
    expect(await loadPublishedRestoreFloor(dir, clock, { ...binding, epoch: Buffer.alloc(16, 2).toString('base64url') }, expectation())).toBeUndefined();
    expect(await loadPublishedRestoreFloor(dir, clock, binding, expectation(0, 1, fingerprint))).toBeUndefined();
  });

  it('rejects v2 after v3 and non-canonical JSON encodings', async () => {
    const dir = await directory(); await put(dir, 1, historicalV2); await put(dir, 2, historicalV3);
    await put(dir, 3, historicalV2.replace('"sequence":1', '"sequence":3').replace(initial, v3Head));
    await unavailable(loadRestoreFloor(dir, v3Head, binding));
    const record = JSON.parse(historicalV2) as { version: 'v2'; sequence: number; minimumIssuedAt: string; previousHead: string; activation: RestoreActivation };
    const reorderedTop = JSON.stringify({ sequence: record.sequence, version: record.version, minimumIssuedAt: record.minimumIssuedAt, previousHead: record.previousHead, activation: record.activation });
    const reorderedActivation = JSON.stringify({ ...record, activation: { adapter: record.activation.adapter, epoch: record.activation.epoch, index: record.activation.index, cookieKeyFingerprints: record.activation.cookieKeyFingerprints, clientSecretFingerprint: record.activation.clientSecretFingerprint, signingKeys: record.activation.signingKeys } });
    const reorderedRing = JSON.stringify({ ...record, activation: { ...record.activation, adapter: { keys: record.activation.adapter.keys, active: record.activation.adapter.active } } });
    const reorderedKey = JSON.stringify({ ...record, activation: { ...record.activation, adapter: { ...record.activation.adapter, keys: [{ fingerprint, id: 'adapter' }] } } });
    for (const bytes of [reorderedTop, reorderedActivation, reorderedRing, reorderedKey, `${historicalV2} `, `${historicalV2}x`]) {
      const malformed = await directory(); await put(malformed, 1, bytes); await unavailable(loadRestoreFloor(malformed, v2Head, binding));
    }
  });

  it('preserves floor for activation, strictly raises it for restore, and rejects invalid v3 transitions', async () => {
    const dir = await directory(); const restore = await appendRestoreFloor(dir, new Date('2026-01-01T00:00:00.999Z'), binding, expectation());
    const activation = await appendOidcActivation(dir, binding, expectation(restore.minimumIssuedAt, 2, restore.head));
    expect(activation.minimumIssuedAt).toBe(restore.minimumIssuedAt);
    const next = await appendRestoreFloor(dir, new Date(0), binding, expectation(activation.minimumIssuedAt, 3, activation.head));
    expect(next.minimumIssuedAt).toBeGreaterThan(activation.minimumIssuedAt);
    const bad = JSON.stringify({ version: 'v3', kind: 'restore', sequence: 4, minimumIssuedAt: new Date(next.minimumIssuedAt * 1000).toISOString().replace('.000Z', 'Z'), previousHead: next.head, activation: binding });
    await put(dir, 4, bad); await unavailable(loadRestoreFloor(dir, next.head, binding));
  });

  it('enforces CAS expectations and exact durable retry without a second numeric record', async () => {
    const dir = await directory(); const first = await appendRestoreFloor(dir, new Date(0), binding, expectation());
    for (const e of [expectation(0, 2, first.head), expectation(first.minimumIssuedAt, 3, first.head), expectation(first.minimumIssuedAt, 2, fingerprint)]) await unavailable(appendRestoreFloor(dir, new Date(0), binding, e));
    expect((await readdir(dir)).sort()).toEqual(['.staging', name(1)]);
    expect(await appendRestoreFloor(dir, new Date(0), binding, expectation())).toEqual(first);
    await unavailable(appendOidcActivation(dir, binding, expectation()));
    expect((await lstat(join(dir, name(1)))).mode & 0o777).toBe(0o600);
  });

  it('rejects unsafe staging and poisoned numeric entries while retaining orphan candidates', async () => {
    const dir = await directory(); await writeFile(join(dir, '.staging'), 'not-a-directory', { mode: 0o600 }); await unavailable(appendRestoreFloor(dir, new Date(0), binding, expectation()));
    const linked = await directory(); await symlink(tmpdir(), join(linked, '.staging')); await unavailable(loadRestoreFloor(linked));
    const poison = await directory(); await put(poison, 1, '{'); await unavailable(loadRestoreFloor(poison));
    const orphan = await directory(); await (await import('node:fs/promises')).mkdir(join(orphan, '.staging'), { mode: 0o700 }); await writeFile(join(orphan, '.staging', 'orphan'), 'candidate', { mode: 0o600 }); await appendRestoreFloor(orphan, new Date(0), binding, expectation()); expect(await lstat(join(orphan, '.staging', 'orphan'))).toBeTruthy();
  });

  it('converges identical concurrent appends, rejects conflicting winner, then advances sequence', async () => {
    const dir = await directory(); const e = expectation(); const [a, b] = await Promise.all([appendRestoreFloor(dir, new Date(0), binding, e), appendRestoreFloor(dir, new Date(0), binding, e)]);
    expect(a).toEqual(b); expect((await readdir(dir)).filter(x => /^\d/.test(x))).toEqual([name(1)]);
    const changed = { ...binding, epoch: Buffer.alloc(16, 2).toString('base64url') };
    const conflict = await Promise.allSettled([appendRestoreFloor(dir, new Date(1_000), binding, expectation(a.minimumIssuedAt, 2, a.head)), appendRestoreFloor(dir, new Date(1_000), changed, expectation(a.minimumIssuedAt, 2, a.head))]);
    expect(conflict.filter(x => x.status === 'fulfilled')).toHaveLength(1); expect(conflict.filter(x => x.status === 'rejected')).toHaveLength(1);
    const winner = (conflict.find(x => x.status === 'fulfilled') as PromiseFulfilledResult<{ minimumIssuedAt: number; sequence: number; head: string }>).value;
    const winnerBinding = conflict[0]!.status === 'fulfilled' ? binding : changed;
    await expect(appendRestoreFloor(dir, new Date(2_000), winnerBinding, expectation(winner.minimumIssuedAt, 3, winner.head))).resolves.toMatchObject({ sequence: 3 });
  });
});
