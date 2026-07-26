import { chmod, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { appendRestoreFloor, INITIAL_RESTORE_FLOOR_HEAD } from './restore-floor.js';
import { loadFreshRestoreState, restoreActivation, runOidcActivation, runOidcRestore, type FreshRestoreState } from './restore.js';
import { LATEST_CONTROL_PLANE_CATALOG } from '../db.js';
import type { Config, KeyRing } from '../config.js';
import type { OidcSecrets, SigningJwk } from './secrets.js';

const dirs: string[] = [];
async function state(value: string, mode = 0o600): Promise<string> { const dir = await mkdtemp(join(tmpdir(), 'oidc-restore-')); dirs.push(dir); await chmod(dir, 0o700); const path = join(dir, 'state'); await writeFile(path, value, { mode }); await chmod(path, mode); return path; }
afterEach(async () => { await Promise.all(dirs.splice(0).map(dir => rm(dir, { recursive: true, force: true }))); });
describe('OIDC restore isolated inputs', () => {
  it('loads only exact fresh v1 state', async () => { const key = Buffer.alloc(32, 7).toString('base64url'); const result = loadFreshRestoreState(await state(JSON.stringify({ version: 'v1', epoch: Buffer.alloc(16, 3).toString('base64url'), adapter: { active: 'a', keys: { a: key } }, index: { active: 'i', keys: { i: Buffer.alloc(32, 4).toString('base64url') } } }))); expect(result.adapter.active).toBe('a'); });
  it('rejects duplicate JSON and non-owner-only state', async () => { const duplicate = await state('{"version":"v1","version":"v1"}'); const loose = await state('{}', 0o640); expect(() => loadFreshRestoreState(duplicate)).toThrow(); expect(() => loadFreshRestoreState(loose)).toThrow(); });
});

const fingerprint = (value: Uint8Array) => createHash('sha256').update(value).digest('base64url');
const bytes = (n: number) => new Uint8Array(Buffer.alloc(32, n));
const ring = (active: string, entries: readonly [string, number][]): KeyRing => ({ active, keys: Object.fromEntries(entries.map(([id, n]) => [id, bytes(n)])) });
const signing = (kid: string): SigningJwk => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { ...(privateKey.export({ format: 'jwk' }) as Omit<SigningJwk, 'kid' | 'use' | 'alg'>), kid, use: 'sig', alg: 'RS256' };
};
const secrets = (offset: number, keys: readonly SigningJwk[]): OidcSecrets => ({ clientSecret: bytes(offset), cookieKeys: [bytes(offset + 1), bytes(offset + 2)], signingKeys: keys, publicJwks: { keys: keys.map(({ kty, n, e, kid, use, alg }) => ({ kty, n, e, kid, use, alg })) } });
const config = (adapter: KeyRing, index: KeyRing, floor: string): Config => ({
  APP_ENV: 'test', PORT: 1, DATABASE_URL: 'postgres://x', CONTROL_PLANE_RUNTIME_ROLE: 'runtime', PUBLIC_BASE_URL: '', FOUNDATION_BASE_URL: '', PWA_ORIGIN: '', OIDC_ISSUER: '', OIDC_SECTOR: '', OIDC_EPOCH: Buffer.alloc(16, 1).toString('base64url'), OIDC_TRUSTED_PROXY_ADDRESS: '', MAS_CLIENT_ID: '', MAS_REDIRECT_URI: '', OIDC_SIGNING_JWKS_PATH: '', MAS_CLIENT_SECRET_PATH: '', OIDC_COOKIE_KEYS_PATH: '', OIDC_RESTORE_FLOOR_DIR: floor, COOKIE_SECURE: true, COOKIE_KEY: bytes(3), SUBJECT_KEY_RING: ring('subject', [['subject', 4]]), ENVELOPE_KEY_RING: ring('envelope', [['envelope', 5]]), CHALLENGE_KEY_RING: ring('challenge', [['challenge', 6]]), SESSION_BINDING_KEY_RING: ring('binding', [['binding', 7]]), JTI_KEY_RING: ring('jti', [['jti', 8]]), IDEMPOTENCY_KEY_RING: ring('idem', [['idem', 9]]), REQUEST_FINGERPRINT_KEY_RING: ring('request', [['request', 10]]), OIDC_ADAPTER_KEY_RING: adapter, OIDC_INDEX_KEY_RING: index, REVOCATION_EVIDENCE_KEY_RING: ring('revocation', [['revocation', 11]]), ROOT_DIDS: [], AUTHORITY_POLICY_VERSION: 'v1', POLICY_MAX_STALENESS_SECONDS: 1, ROOT_PUBLIC_JWKS: {},
} as Config);

function fake(events: string[], failure?: string, rollbackFailure = false) {
  let released: Error | undefined;
  const client = {
    query: async (text: string, values?: unknown[]) => {
      events.push(text);
      if (failure === text) throw new Error(`failure: ${text}`);
      if (text === 'ROLLBACK' && rollbackFailure) throw new Error('rollback failure');
      if (text.startsWith('SELECT checksum')) return { rows: [{ checksum: Buffer.alloc(32, 12) }], rowCount: 1 };
      if (text === 'SELECT pg_advisory_xact_lock($1)') expect(values).toEqual([8_004]);
      return { rows: [], rowCount: 0 };
    },
    release: (error?: Error) => { released = error; events.push(error ? `release:${error.message}` : 'release'); },
  };
  return { pool: { connect: async () => client }, released: () => released };
}

async function activationSetup() {
  const floor = await mkdtemp(join(tmpdir(), 'oidc-activation-')); dirs.push(floor); await chmod(floor, 0o700);
  const currentAdapter = ring('a-z', [['a_z', 20], ['a-z', 21]]), currentIndex = ring('i-z', [['i_z', 22], ['i-z', 23]]);
  const currentSigning = signing('shared'); const currentSecrets = secrets(30, [currentSigning]); const current = config(currentAdapter, currentIndex, floor);
  const currentBinding = restoreActivation(current, currentSecrets);
  const base = await appendRestoreFloor(floor, new Date(0), currentBinding, { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD });
  const candidate: FreshRestoreState = { epoch: Buffer.alloc(16, 2).toString('base64url'), adapter: ring('a-z', [['a_z', 20], ['a-z', 21], ['new', 40]]), index: ring('i-z', [['i_z', 22], ['i-z', 23], ['new', 41]]) };
  const candidateSecrets = secrets(50, [currentSigning, signing('new')]);
  return { floor, current, currentSecrets, candidate, candidateSecrets, expectation: { expectedPreviousFloor: base.minimumIssuedAt, expectedNextSequence: 2, expectedHead: base.head } };
}

describe('OIDC activation key safety and transaction fence', () => {
  it('binds ASCII-sorted rings, preserved cookie and v3 signing order, and exact public JWK fingerprints', async () => {
    const { current, currentSecrets, candidate, candidateSecrets } = await activationSetup();
    const binding = restoreActivation({ ...current, OIDC_EPOCH: candidate.epoch, OIDC_ADAPTER_KEY_RING: candidate.adapter, OIDC_INDEX_KEY_RING: candidate.index }, candidateSecrets);
    expect(binding.adapter.keys.map(({ id }) => id)).toEqual(['a-z', 'a_z', 'new']);
    expect(binding.index.keys.map(({ id }) => id)).toEqual(['i-z', 'i_z', 'new']);
    expect(binding.cookieKeyFingerprints).toEqual(candidateSecrets.cookieKeys.map(fingerprint));
    expect(binding.signingKeys.map(({ kid }) => kid)).toEqual(['shared', 'new']);
    expect(binding.signingKeys[0]!.fingerprint).toBe(fingerprint(Buffer.from(JSON.stringify(candidateSecrets.publicJwks.keys[0]))));
    expect(restoreActivation(current, currentSecrets).signingKeys[0]!.kid).toBe('shared');
  });

  type ActivationMutation = Readonly<{ candidate?: FreshRestoreState; candidateSecrets?: OidcSecrets }>;
  type HistoricalMutation = Readonly<{ adapter?: KeyRing; index?: KeyRing; cookie?: readonly Uint8Array[]; client?: Uint8Array }>;
  it.each([
    ['changed shared adapter ID', (s: Awaited<ReturnType<typeof activationSetup>>) => ({ ...s.candidate, adapter: ring('a-z', [['a_z', 99]]) })],
    ['changed shared index ID', (s: Awaited<ReturnType<typeof activationSetup>>) => ({ ...s.candidate, index: ring('i-z', [['i_z', 99]]) })],
  ])('rejects %s before publication', async (_name, mutate) => {
    const setup = await activationSetup(); const f = fake([]); const candidate = mutate(setup);
    await expect(runOidcActivation({ ...f, runtimeRole: 'runtime', retentionRole: 'retention' } as never, setup.current, candidate, setup.currentSecrets, setup.candidateSecrets, setup.expectation)).rejects.toThrow('OIDC restore unavailable');
    expect(f.released()).toBeUndefined();
    expect(await readdir(setup.floor)).not.toContain('00000000000000000002');
  });

  it.each([
    ['removed adapter key renamed under a new adapter ID', (s: Awaited<ReturnType<typeof activationSetup>>) => ({ candidate: { ...s.candidate, adapter: ring('renamed', [['renamed', 20]]) } })],
    ['removed index key renamed under a new index ID', (s: Awaited<ReturnType<typeof activationSetup>>) => ({ candidate: { ...s.candidate, index: ring('renamed', [['renamed', 22]]) } })],
    ['adapter colliding with current index', (s: Awaited<ReturnType<typeof activationSetup>>) => ({ candidate: { ...s.candidate, adapter: ring('a-z', [['a_z', 20], ['a-z', 21], ['new', 22]]) } })],
    ['adapter colliding with current cookie', (s: Awaited<ReturnType<typeof activationSetup>>) => ({ candidate: { ...s.candidate, adapter: ring('a-z', [['a_z', 20], ['a-z', 21], ['new', 31]]) } })],
    ['index colliding with current client secret', (s: Awaited<ReturnType<typeof activationSetup>>) => ({ candidate: { ...s.candidate, index: ring('i-z', [['i_z', 22], ['i-z', 23], ['new', 30]]) } })],
    ['cookie colliding with current adapter', (s: Awaited<ReturnType<typeof activationSetup>>) => ({ candidateSecrets: { ...s.candidateSecrets, cookieKeys: [bytes(20), bytes(51)] } })],
    ['client secret colliding with current index', (s: Awaited<ReturnType<typeof activationSetup>>) => ({ candidateSecrets: { ...s.candidateSecrets, clientSecret: bytes(22) } })],
  ] as readonly [string, (setup: Awaited<ReturnType<typeof activationSetup>>) => ActivationMutation][])('rejects historical purpose/identity collision: %s', async (_name, mutate) => {
    const setup = await activationSetup(); const changed = mutate(setup);
    await expect(runOidcActivation({ ...fake([]), runtimeRole: 'runtime', retentionRole: 'retention' } as never, setup.current, changed.candidate ?? setup.candidate, setup.currentSecrets, changed.candidateSecrets ?? setup.candidateSecrets, setup.expectation)).rejects.toThrow('OIDC restore unavailable');
    expect(await readdir(setup.floor)).not.toContain('00000000000000000002');
  });

  it('allows current material only at the same symmetric purpose and ID', async () => {
    const setup = await activationSetup(); const result = await runOidcActivation({ ...fake([]), runtimeRole: 'runtime', retentionRole: 'retention', assertCatalog: async () => undefined, assertKeys: async () => undefined, expectedMigrationChecksum: async () => Buffer.alloc(32, 12) } as never, setup.current, setup.candidate, setup.currentSecrets, setup.candidateSecrets, setup.expectation);
    expect(result.sequence).toBe(2);
  });

  it.each([
    ['adapter ID renamed', () => ({ adapter: ring('renamed', [['renamed', 20]]) })],
    ['index ID renamed', () => ({ index: ring('renamed', [['renamed', 22]]) })],
    ['adapter moved to cookie', () => ({ cookie: [bytes(20), bytes(81)] })],
    ['adapter moved to client secret', () => ({ client: bytes(20) })],
  ] as readonly [string, (s: Awaited<ReturnType<typeof activationSetup>>) => HistoricalMutation][])('rejects material removed in an earlier activation and later reused: %s', async (_name, mutate) => {
    const setup = await activationSetup();
    const middleBinding = restoreActivation({ ...setup.current, OIDC_EPOCH: setup.candidate.epoch, OIDC_ADAPTER_KEY_RING: setup.candidate.adapter, OIDC_INDEX_KEY_RING: setup.candidate.index }, setup.candidateSecrets);
    const middle = await (await import('./restore-floor.js')).appendOidcActivation(setup.floor, middleBinding, setup.expectation);
    const current = { ...setup.current, OIDC_EPOCH: setup.candidate.epoch, OIDC_ADAPTER_KEY_RING: setup.candidate.adapter, OIDC_INDEX_KEY_RING: setup.candidate.index };
    const change = mutate(setup); const next: FreshRestoreState = { epoch: Buffer.alloc(16, 3).toString('base64url'), adapter: change.adapter ?? ring('next', [['next', 80]]), index: change.index ?? ring('next', [['next', 82]]) };
    const nextSecrets = secrets(83, [signing('later')]);
    const altered = { ...nextSecrets, ...(change.cookie && { cookieKeys: change.cookie }), ...(change.client && { clientSecret: change.client }) };
    await expect(runOidcActivation({ ...fake([]), runtimeRole: 'runtime', retentionRole: 'retention' } as never, current, next, setup.candidateSecrets, altered, { expectedPreviousFloor: middle.minimumIssuedAt, expectedNextSequence: 3, expectedHead: middle.head })).rejects.toThrow('OIDC restore unavailable');
  });

  it('rejects changed shared signing kid public key and candidate secret collisions without publication or secret disclosure', async () => {
    const setup = await activationSetup(); const changed = { ...setup.candidateSecrets, publicJwks: { keys: [{ ...setup.candidateSecrets.publicJwks.keys[0]!, n: 'changed' }, ...setup.candidateSecrets.publicJwks.keys.slice(1)] } };
    await expect(runOidcActivation({ ...fake([]), runtimeRole: 'runtime', retentionRole: 'retention' } as never, setup.current, setup.candidate, setup.currentSecrets, changed, setup.expectation)).rejects.toThrow('OIDC restore unavailable');
    const collision = { ...setup.candidateSecrets, clientSecret: setup.current.SUBJECT_KEY_RING.keys.subject! };
    await expect(runOidcActivation({ ...fake([]), runtimeRole: 'runtime', retentionRole: 'retention' } as never, setup.current, setup.candidate, setup.currentSecrets, collision, setup.expectation)).rejects.toThrow(/^OIDC restore unavailable$/);
    expect(await readdir(setup.floor)).not.toContain('00000000000000000002');
  });

  it('validates then executes the read-only fenced publication sequence with no mutation SQL', async () => {
    const setup = await activationSetup(); const events: string[] = []; const f = fake(events);
    const result = await runOidcActivation({ ...f, runtimeRole: 'runtime', retentionRole: 'retention', assertCatalog: async () => { events.push('catalog'); }, assertKeys: async () => { events.push('keys'); }, expectedMigrationChecksum: async () => { events.push('checksum'); return Buffer.alloc(32, 12); } } as never, setup.current, setup.candidate, setup.currentSecrets, setup.candidateSecrets, setup.expectation);
    expect(result.sequence).toBe(2);
    expect(events).toEqual(['BEGIN READ ONLY', 'SELECT pg_advisory_xact_lock($1)', 'catalog', "SELECT checksum FROM control_plane.schema_migrations WHERE id='0005_access_revocation_foundation'", 'checksum', 'keys', 'keys', 'COMMIT', 'release']);
    expect(events.join('\n')).not.toMatch(/\b(?:DELETE|INSERT|UPDATE|audit)\b/i);
  });

  it.each(['catalog', "SELECT checksum FROM control_plane.schema_migrations WHERE id='0005_access_revocation_foundation'", 'keys'])('rolls back and cleanly releases on %s failure', async (failure) => {
    const setup = await activationSetup(); const events: string[] = []; const f = fake(events, failure);
    await expect(runOidcActivation({ ...f, runtimeRole: 'runtime', retentionRole: 'retention', assertCatalog: async () => { if (failure === 'catalog') throw new Error('no'); }, assertKeys: async () => { if (failure === 'keys') throw new Error('no'); }, expectedMigrationChecksum: async () => Buffer.alloc(32, 12) } as never, setup.current, setup.candidate, setup.currentSecrets, setup.candidateSecrets, setup.expectation)).rejects.toThrow('OIDC restore unavailable');
    expect(events).toContain('ROLLBACK'); expect(f.released()).toBeUndefined();
  });

  it('rolls back and does not publish when append fails after both retained-key checks', async () => {
    const setup = await activationSetup(); const events: string[] = []; const f = fake(events);
    await expect(runOidcActivation({ ...f, runtimeRole: 'runtime', retentionRole: 'retention', assertCatalog: async () => undefined, assertKeys: async () => { await chmod(setup.floor, 0o500); }, expectedMigrationChecksum: async () => Buffer.alloc(32, 12) } as never, setup.current, setup.candidate, setup.currentSecrets, setup.candidateSecrets, setup.expectation)).rejects.toThrow('OIDC restore unavailable');
    await chmod(setup.floor, 0o700); expect(events).toContain('ROLLBACK'); expect(f.released()).toBeUndefined(); expect(await readdir(setup.floor)).not.toContain('00000000000000000002');
  });

  it('poisons on rollback failure and returns durable publication when commit fails; exact retry is recoverable', async () => {
    const setup = await activationSetup(); const rollbackEvents: string[] = []; const failed = fake(rollbackEvents, 'BEGIN READ ONLY', true); const checks = { assertCatalog: async () => undefined, assertKeys: async () => undefined, expectedMigrationChecksum: async () => Buffer.alloc(32, 12) };
    await expect(runOidcActivation({ ...failed, ...checks, runtimeRole: 'runtime', retentionRole: 'retention' } as never, setup.current, setup.candidate, setup.currentSecrets, setup.candidateSecrets, setup.expectation)).rejects.toThrow('OIDC restore unavailable');
    expect(failed.released()).toBeInstanceOf(Error);
    const events: string[] = []; const commit = fake(events, 'COMMIT'); const deps = { ...commit, ...checks, runtimeRole: 'runtime', retentionRole: 'retention' } as never;
    const published = await runOidcActivation(deps, setup.current, setup.candidate, setup.currentSecrets, setup.candidateSecrets, setup.expectation);
    expect(published.sequence).toBe(2); expect(commit.released()).toBeInstanceOf(Error);
    await expect(runOidcActivation({ ...fake([]), ...checks, runtimeRole: 'runtime', retentionRole: 'retention' } as never, setup.current, setup.candidate, setup.currentSecrets, setup.candidateSecrets, setup.expectation)).resolves.toEqual(published);
    await expect(runOidcActivation({ ...fake([]), ...checks, runtimeRole: 'runtime', retentionRole: 'retention' } as never, setup.current, setup.candidate, setup.currentSecrets, secrets(70, setup.candidateSecrets.signingKeys), setup.expectation)).rejects.toThrow('OIDC restore unavailable');
  });
});

describe('OIDC restore history and startup-equivalent secret separation', () => {
  const noSideEffects = () => {
    let connects = 0; let appends = 0;
    return { deps: { pool: { connect: async () => { connects += 1; throw new Error('DB access'); } }, runtimeRole: 'runtime', retentionRole: 'retention', appendFloor: async (...args: Parameters<typeof appendRestoreFloor>) => { appends += 1; return appendRestoreFloor(...args); } }, connects: () => connects, appends: () => appends };
  };

  it('rejects a key absent from current binding but present two records ago before append or purge', async () => {
    const floor = await mkdtemp(join(tmpdir(), 'oidc-restore-history-')); dirs.push(floor); await chmod(floor, 0o700);
    const old = config(ring('old', [['old', 70]]), ring('old-index', [['old-index', 71]]), floor); const oldSecrets = secrets(72, [signing('old')]);
    const first = await appendRestoreFloor(floor, new Date(0), restoreActivation(old, oldSecrets), { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD });
    const backup = { ...old, OIDC_EPOCH: Buffer.alloc(16, 2).toString('base64url'), OIDC_ADAPTER_KEY_RING: ring('current', [['current', 20]]), OIDC_INDEX_KEY_RING: ring('current-index', [['current-index', 21]]) }; const backupSecrets = secrets(30, [signing('current')]);
    const second = await (await import('./restore-floor.js')).appendOidcActivation(floor, restoreActivation(backup, backupSecrets), { expectedPreviousFloor: first.minimumIssuedAt, expectedNextSequence: 2, expectedHead: first.head });
    const fresh: FreshRestoreState = { epoch: Buffer.alloc(16, 3).toString('base64url'), adapter: ring('fresh', [['fresh', 70]]), index: ring('fresh-index', [['fresh-index', 40]]) }; const sideEffects = noSideEffects();
    await expect(runOidcRestore(sideEffects.deps as never, backup, fresh, backupSecrets, secrets(50, [signing('fresh')]), new Date(), { expectedPreviousFloor: second.minimumIssuedAt, expectedNextSequence: 3, expectedHead: second.head })).rejects.toThrow('OIDC restore unavailable');
    expect(sideEffects.appends()).toBe(0); expect(sideEffects.connects()).toBe(0);
  });

  it.each(['adapter ID', 'index ID', 'signing kid'] as const)('rejects a historically used %s with new material before append or purge', async (collision) => {
    const floor = await mkdtemp(join(tmpdir(), 'oidc-restore-history-id-')); dirs.push(floor); await chmod(floor, 0o700);
    const old = config(ring('old-adapter', [['old-adapter', 70]]), ring('old-index', [['old-index', 71]]), floor); const oldSecrets = secrets(72, [signing('old-signing')]);
    const first = await appendRestoreFloor(floor, new Date(0), restoreActivation(old, oldSecrets), { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD });
    const backup = { ...old, OIDC_EPOCH: Buffer.alloc(16, 2).toString('base64url'), OIDC_ADAPTER_KEY_RING: ring('current-adapter', [['current-adapter', 20]]), OIDC_INDEX_KEY_RING: ring('current-index', [['current-index', 21]]) }; const backupSecrets = secrets(30, [signing('current-signing')]);
    const second = await (await import('./restore-floor.js')).appendOidcActivation(floor, restoreActivation(backup, backupSecrets), { expectedPreviousFloor: first.minimumIssuedAt, expectedNextSequence: 2, expectedHead: first.head });
    const fresh: FreshRestoreState = { epoch: Buffer.alloc(16, 3).toString('base64url'), adapter: ring(collision === 'adapter ID' ? 'old-adapter' : 'fresh-adapter', [[collision === 'adapter ID' ? 'old-adapter' : 'fresh-adapter', 40]]), index: ring(collision === 'index ID' ? 'old-index' : 'fresh-index', [[collision === 'index ID' ? 'old-index' : 'fresh-index', 41]]) };
    const freshSecrets = secrets(50, [signing(collision === 'signing kid' ? 'old-signing' : 'fresh-signing')]); const sideEffects = noSideEffects();
    await expect(runOidcRestore(sideEffects.deps as never, backup, fresh, backupSecrets, freshSecrets, new Date(), { expectedPreviousFloor: second.minimumIssuedAt, expectedNextSequence: 3, expectedHead: second.head })).rejects.toThrow('OIDC restore unavailable');
    expect(sideEffects.appends()).toBe(0); expect(sideEffects.connects()).toBe(0);
  });

  it('rejects an epoch used two records ago before append or DB connection', async () => {
    const floor = await mkdtemp(join(tmpdir(), 'oidc-restore-history-epoch-')); dirs.push(floor); await chmod(floor, 0o700);
    const old = config(ring('old', [['old', 70]]), ring('old-index', [['old-index', 71]]), floor); const oldSecrets = secrets(72, [signing('old')]);
    const first = await appendRestoreFloor(floor, new Date(0), restoreActivation(old, oldSecrets), { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD });
    const backup = { ...old, OIDC_EPOCH: Buffer.alloc(16, 2).toString('base64url'), OIDC_ADAPTER_KEY_RING: ring('current', [['current', 20]]), OIDC_INDEX_KEY_RING: ring('current-index', [['current-index', 21]]) }; const backupSecrets = secrets(30, [signing('current')]);
    const second = await (await import('./restore-floor.js')).appendOidcActivation(floor, restoreActivation(backup, backupSecrets), { expectedPreviousFloor: first.minimumIssuedAt, expectedNextSequence: 2, expectedHead: first.head }); const sideEffects = noSideEffects();
    await expect(runOidcRestore(sideEffects.deps as never, backup, { epoch: old.OIDC_EPOCH, adapter: ring('fresh', [['fresh', 40]]), index: ring('fresh-index', [['fresh-index', 41]]) }, backupSecrets, secrets(50, [signing('fresh')]), new Date(), { expectedPreviousFloor: second.minimumIssuedAt, expectedNextSequence: 3, expectedHead: second.head })).rejects.toThrow('OIDC restore unavailable');
    expect(sideEffects.appends()).toBe(0); expect(sideEffects.connects()).toBe(0);
  });

  it.each(['adapter', 'index', 'signing'] as const)('rejects current %s identity with new material when the ledger is empty before append or DB connection', async (collision) => {
    const floor = await mkdtemp(join(tmpdir(), 'oidc-restore-current-id-')); dirs.push(floor); await chmod(floor, 0o700);
    const backup = config(ring('current-adapter', [['current-adapter', 20]]), ring('current-index', [['current-index', 21]]), floor); const backupSecrets = secrets(30, [signing('current-signing')]); const sideEffects = noSideEffects();
    const fresh: FreshRestoreState = { epoch: Buffer.alloc(16, 2).toString('base64url'), adapter: ring(collision === 'adapter' ? 'current-adapter' : 'fresh-adapter', [[collision === 'adapter' ? 'current-adapter' : 'fresh-adapter', 40]]), index: ring(collision === 'index' ? 'current-index' : 'fresh-index', [[collision === 'index' ? 'current-index' : 'fresh-index', 41]]) };
    await expect(runOidcRestore(sideEffects.deps as never, backup, fresh, backupSecrets, secrets(50, [signing(collision === 'signing' ? 'current-signing' : 'fresh-signing')]), new Date(), { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD })).rejects.toThrow('OIDC restore unavailable');
    expect(sideEffects.appends()).toBe(0); expect(sideEffects.connects()).toBe(0);
  });

  it('holds one exclusive transaction client through publication, purge, and verification', async () => {
    const floor = await mkdtemp(join(tmpdir(), 'oidc-restore-fence-')); dirs.push(floor); await chmod(floor, 0o700);
    const backup = config(ring('backup', [['backup', 20]]), ring('backup-index', [['backup-index', 21]]), floor); const backupSecrets = secrets(30, [signing('backup')]); const fresh: FreshRestoreState = { epoch: Buffer.alloc(16, 2).toString('base64url'), adapter: ring('fresh', [['fresh', 40]]), index: ring('fresh-index', [['fresh-index', 41]]) }; const freshSecrets = secrets(50, [signing('fresh')]);
    const events: string[] = []; let connects = 0; let catalogArgs: readonly unknown[] | undefined;
    const client = { query: async (text: string) => { if (text.startsWith('SELECT count')) events.push(`count:${text.slice(text.lastIndexOf(' ') + 1)}`); else if (text.startsWith('DELETE')) events.push(`delete:${text.slice('DELETE FROM '.length)}`); else events.push(text); if (text.startsWith('SELECT checksum')) return { rows: [{ checksum: Buffer.alloc(32, 12) }], rowCount: 1 }; return { rows: [{ count: 0 }], rowCount: 0 }; }, release: () => events.push('release') };
    const result = await runOidcRestore({ pool: { connect: async () => { connects += 1; return client; } }, runtimeRole: 'runtime', retentionRole: 'retention', claimantRole: 'configured_revocation', assertCatalog: async (...args: unknown[]) => { catalogArgs = args; events.push('catalog'); }, assertKeys: async () => { events.push('keys'); }, expectedMigrationChecksum: async () => { events.push('checksum'); return Buffer.alloc(32, 12); }, appendFloor: async (...args: Parameters<typeof appendRestoreFloor>) => { events.push('append'); return appendRestoreFloor(...args); } } as never, backup, fresh, backupSecrets, freshSecrets, new Date(0), { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD });
    expect(result.phase).toBe('committed'); expect(connects).toBe(1);
    expect(catalogArgs?.slice(1)).toEqual(['runtime', 'retention', LATEST_CONTROL_PLANE_CATALOG, 'configured_revocation']);
    expect(events).toEqual([
      'BEGIN', 'SELECT pg_advisory_xact_lock($1)', 'catalog', 'keys', "SELECT checksum FROM control_plane.schema_migrations WHERE id='0005_access_revocation_foundation'", 'checksum',
      'append',
      ...['oidc.interaction_csrf', 'oidc.authorization_contexts', 'oidc.provider_artifacts', 'control_plane.idempotency_key_aliases', 'control_plane.idempotency_results', 'control_plane.jti_key_aliases', 'control_plane.jti_uses', 'control_plane.proof_challenges', 'control_plane.login_states', 'control_plane.entitlement_evidence_aliases', 'control_plane.entitlements', 'control_plane.identity_sessions', 'control_plane.active_policy'].map(table => `delete:${table}`),
      ...['oidc.interaction_csrf', 'oidc.authorization_contexts', 'oidc.provider_artifacts', 'control_plane.idempotency_key_aliases', 'control_plane.idempotency_results', 'control_plane.jti_key_aliases', 'control_plane.jti_uses', 'control_plane.proof_challenges', 'control_plane.login_states', 'control_plane.entitlement_evidence_aliases', 'control_plane.entitlements', 'control_plane.identity_sessions', 'control_plane.active_policy'].map(table => `count:${table}`),
      ...[...['control_plane.security_audit_events', 'control_plane.did_mappings', 'control_plane.policy_snapshots', 'control_plane.encrypted_envelopes', 'control_plane.revocation_evidence_key_ids', 'control_plane.membership_access_states', 'control_plane.entitlement_evidence_aliases', 'control_plane.membership_access_sources', 'control_plane.membership_access_source_chunks', 'control_plane.membership_access_source_selector_aliases', 'control_plane.membership_access_source_cause_aliases', 'control_plane.membership_access_source_targets', 'control_plane.membership_access_operations', 'control_plane.membership_access_requests', 'control_plane.membership_access_request_operation_links', 'control_plane.membership_access_mas_targets', 'control_plane.membership_access_registry_snapshots', 'control_plane.membership_access_crypto_capabilities', 'control_plane.membership_access_room_targets', 'control_plane.membership_access_steps', 'control_plane.membership_access_step_attempts'], ...['control_plane.security_audit_events', 'control_plane.did_mappings', 'control_plane.policy_snapshots', 'control_plane.encrypted_envelopes', 'control_plane.revocation_evidence_key_ids', 'control_plane.membership_access_states', 'control_plane.entitlement_evidence_aliases', 'control_plane.membership_access_sources', 'control_plane.membership_access_source_chunks', 'control_plane.membership_access_source_selector_aliases', 'control_plane.membership_access_source_cause_aliases', 'control_plane.membership_access_source_targets', 'control_plane.membership_access_operations', 'control_plane.membership_access_requests', 'control_plane.membership_access_request_operation_links', 'control_plane.membership_access_mas_targets', 'control_plane.membership_access_registry_snapshots', 'control_plane.membership_access_crypto_capabilities', 'control_plane.membership_access_room_targets', 'control_plane.membership_access_steps', 'control_plane.membership_access_step_attempts']].map(table => `count:${table}`), 'keys', 'COMMIT', 'release',
    ]);
  });

  it('rolls back and poisons after a published append when commit fails, then exact retry recovers', async () => {
    const floor = await mkdtemp(join(tmpdir(), 'oidc-restore-commit-')); dirs.push(floor); await chmod(floor, 0o700);
    const backup = config(ring('backup', [['backup', 20]]), ring('backup-index', [['backup-index', 21]]), floor); const backupSecrets = secrets(30, [signing('backup')]); const fresh: FreshRestoreState = { epoch: Buffer.alloc(16, 2).toString('base64url'), adapter: ring('fresh', [['fresh', 40]]), index: ring('fresh-index', [['fresh-index', 41]]) }; const freshSecrets = secrets(50, [signing('fresh')]); const expectation = { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD };
    const releases: (Error | undefined)[] = []; let failCommit = true;
    const deps = { pool: { connect: async () => ({ query: async (text: string) => { if (text === 'COMMIT' && failCommit) throw new Error('commit lost'); if (text.startsWith('SELECT checksum')) return { rows: [{ checksum: Buffer.alloc(32, 12) }], rowCount: 1 }; return { rows: [{ count: 0 }], rowCount: 0 }; }, release: (error?: Error) => releases.push(error) }) }, runtimeRole: 'runtime', retentionRole: 'retention', assertCatalog: async () => undefined, assertKeys: async () => undefined, expectedMigrationChecksum: async () => Buffer.alloc(32, 12) };
    await expect(runOidcRestore(deps as never, backup, fresh, backupSecrets, freshSecrets, new Date(0), expectation)).rejects.toThrow('OIDC restore unavailable');
    expect(releases[0]).toBeInstanceOf(Error); expect((await readdir(floor)).filter(name => /^\d/.test(name))).toHaveLength(1);
    failCommit = false;
    await expect(runOidcRestore(deps as never, backup, fresh, backupSecrets, freshSecrets, new Date(0), expectation)).resolves.toMatchObject({ phase: 'committed', sequence: 1 });
  });

  it.each([
    ['subject', (backup: Config) => backup.SUBJECT_KEY_RING.keys.subject!], ['envelope', (backup: Config) => backup.ENVELOPE_KEY_RING.keys.envelope!], ['challenge', (backup: Config) => backup.CHALLENGE_KEY_RING.keys.challenge!], ['session binding', (backup: Config) => backup.SESSION_BINDING_KEY_RING.keys.binding!], ['JTI', (backup: Config) => backup.JTI_KEY_RING.keys.jti!], ['idempotency', (backup: Config) => backup.IDEMPOTENCY_KEY_RING.keys.idem!], ['request', (backup: Config) => backup.REQUEST_FINGERPRINT_KEY_RING.keys.request!], ['application cookie', (backup: Config) => backup.COOKIE_KEY],
  ] as const)('rejects fresh OIDC material colliding with %s before append or DB purge', async (_name, controlPlaneKey) => {
    const floor = await mkdtemp(join(tmpdir(), 'oidc-restore-separation-')); dirs.push(floor); await chmod(floor, 0o700);
    const backup = config(ring('backup', [['backup', 20]]), ring('backup-index', [['backup-index', 21]]), floor); const backupSecrets = secrets(30, [signing('backup')]); const fresh: FreshRestoreState = { epoch: Buffer.alloc(16, 2).toString('base64url'), adapter: ring('fresh', [['fresh', 40]]), index: ring('fresh-index', [['fresh-index', 41]]) }; const sideEffects = noSideEffects();
    await expect(runOidcRestore(sideEffects.deps as never, backup, fresh, backupSecrets, { ...secrets(50, [signing('fresh')]), clientSecret: controlPlaneKey(backup) }, new Date(), { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD })).rejects.toThrow('OIDC restore unavailable');
    expect(sideEffects.appends()).toBe(0); expect(sideEffects.connects()).toBe(0);
  });
});
