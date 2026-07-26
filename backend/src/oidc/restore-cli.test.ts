import { describe, expect, it, vi } from 'vitest';
import { main, type RestoreCliDependencies } from './restore-cli.js';

const head = Buffer.alloc(32, 9).toString('base64url');
const args = ['--fresh-state', '/fresh/state', '--fresh-cookie-keys', '/fresh/cookies', '--fresh-signing-jwks', '/fresh/jwks', '--fresh-mas-client-secret', '/fresh/secret', '--expected-previous-floor', '7', '--expected-next-sequence', '8', '--trusted-restore-time', '2026-01-01T00:00:00Z', '--expected-head', head] as const;
type Captured = { stdout: string; stderr: string };
const streams = (): [Captured, { write: (value: string) => boolean }, { write: (value: string) => boolean }] => { const captured: Captured = { stdout: '', stderr: '' }; return [captured, { write: value => (captured.stdout += value, true) }, { write: value => (captured.stderr += value, true) }]; };
const deps = (overrides: Record<string, unknown> = {}): RestoreCliDependencies => ({
  getConfig: vi.fn(() => ({ value: 'backup' })), getMigrationConfig: vi.fn(() => ({ MIGRATION_DATABASE_URL: 'postgres://secret/path', CONTROL_PLANE_RUNTIME_ROLE: 'runtime', CONTROL_PLANE_RETENTION_ROLE: 'retention', CONTROL_PLANE_REVOCATION_ROLE: 'revocation' })), loadFreshRestoreState: vi.fn(() => ({ value: 'fresh' })), loadOidcSecrets: vi.fn(() => ({ value: 'secrets' })), createPool: vi.fn(() => ({ end: vi.fn() })), runOidcRestore: vi.fn(async () => ({ phase: 'committed', sequence: 8, minimumIssuedAt: 9, head, purged: {} })), ...overrides,
} as unknown as RestoreCliDependencies);
const run = async (input: readonly string[], injected = deps()): Promise<{ code: number; captured: Captured }> => { const [captured, stdout, stderr] = streams(); return { code: await main(input, stdout, stderr, injected), captured }; };

describe('OIDC restore CLI', () => {
  it('is import-safe', async () => { await expect(import('./restore-cli.js')).resolves.toHaveProperty('main'); });
  it.each([args.slice(0, -2), args.map(value => value === '7' ? '07' : value), [...args.slice(0, 2), '--fresh-state', '/again', ...args.slice(2, -2)], args.map(value => value === '2026-01-01T00:00:00Z' ? '2026-01-01T00:00:00.000Z' : value)].map(input => [input] as const))('coarsens invalid input without loading configuration', async (input) => {
    const injected = deps(); const result = await run(input, injected); expect(result).toEqual({ code: 1, captured: { stdout: '', stderr: 'OIDC restore unavailable\n' } }); expect(injected.getConfig).not.toHaveBeenCalled();
  });
  it('forwards exact values and emits one JSON success line', async () => {
    const injected = deps(); const result = await run(args, injected); expect(result).toEqual({ code: 0, captured: { stdout: `{"phase":"committed","sequence":8,"minimumIssuedAt":9,"head":"${head}","purged":{}}\n`, stderr: '' } }); expect(injected.runOidcRestore).toHaveBeenCalledWith(expect.objectContaining({ runtimeRole: 'runtime', retentionRole: 'retention' }), { value: 'backup' }, { value: 'fresh' }, { value: 'secrets' }, { value: 'secrets' }, new Date('2026-01-01T00:00:00Z'), { expectedPreviousFloor: 7, expectedNextSequence: 8, expectedHead: head });
  });
  it.each(['getConfig', 'getMigrationConfig', 'loadFreshRestoreState', 'loadOidcSecrets', 'createPool', 'runOidcRestore'] as const)('coarsens %s and pool cleanup failures', async key => {
    expect(await run(args, deps({ [key]: vi.fn(() => { throw new Error('secret /path leaked'); }) }))).toEqual({ code: 1, captured: { stdout: '', stderr: 'OIDC restore unavailable\n' } });
    expect(await run(args, deps({ createPool: vi.fn(() => ({ end: vi.fn(async () => { throw new Error('db secret'); }) })) }))).toEqual({ code: 1, captured: { stdout: '', stderr: 'OIDC restore unavailable\n' } });
  });
});
