import { describe, expect, it, vi } from 'vitest';
import { main, type ActivationCliDependencies } from './activation-cli.js';

const head = Buffer.alloc(32, 9).toString('base64url');
const args = ['--candidate-state', '/candidate/state', '--candidate-cookie-keys', '/candidate/cookies', '--candidate-signing-jwks', '/candidate/jwks', '--candidate-mas-client-secret', '/candidate/secret', '--expected-previous-floor', '7', '--expected-next-sequence', '8', '--expected-head', head] as const;
type Captured = { stdout: string; stderr: string };
const streams = (): [Captured, { write: (value: string) => boolean }, { write: (value: string) => boolean }] => { const captured: Captured = { stdout: '', stderr: '' }; return [captured, { write: value => (captured.stdout += value, true) }, { write: value => (captured.stderr += value, true) }]; };
const deps = (overrides: Record<string, unknown> = {}): ActivationCliDependencies => ({
  getConfig: vi.fn(() => ({ value: 'current' })), getMigrationConfig: vi.fn(() => ({ MIGRATION_DATABASE_URL: 'postgres://secret/path', CONTROL_PLANE_RUNTIME_ROLE: 'runtime', CONTROL_PLANE_RETENTION_ROLE: 'retention', CONTROL_PLANE_REVOCATION_ROLE: 'revocation' })),
  loadFreshRestoreState: vi.fn(() => ({ value: 'candidate' })), loadOidcSecrets: vi.fn(() => ({ value: 'secrets' })), createPool: vi.fn(() => ({ end: vi.fn() })),
  runOidcActivation: vi.fn(async () => ({ sequence: 8, minimumIssuedAt: 7, head })), ...overrides,
} as unknown as ActivationCliDependencies);
const run = async (input: readonly string[], injected = deps()): Promise<{ code: number; captured: Captured; injected: ActivationCliDependencies }> => { const [captured, stdout, stderr] = streams(); return { code: await main(input, stdout, stderr, injected), captured, injected }; };

describe('OIDC activation CLI', () => {
  it('is import-safe', async () => { await expect(import('./activation-cli.js')).resolves.toHaveProperty('main'); });
  it.each([
    ['missing', args.slice(0, -2)], ['duplicate', [...args.slice(0, 2), '--candidate-state', '/again', ...args.slice(2, -2)]], ['unknown', [...args.slice(0, -2), '--unknown', 'x']], ['flag-as-value', [args[0], '--candidate-cookie-keys', ...args.slice(2)]], ['leading-zero', args.map(x => x === '7' ? '07' : x)], ['noncanonical decimal', args.map(x => x === '8' ? '+8' : x)], ['malformed head', args.map(x => x === head ? `${head}=` : x)],
  ])('rejects %s without dependencies or output leakage', async (_name, input) => {
    const injected = deps(); const { code, captured } = await run(input, injected);
    expect(code).toBe(1); expect(captured).toEqual({ stdout: '', stderr: 'OIDC activation unavailable\n' }); expect(injected.getConfig).not.toHaveBeenCalled();
  });
  it('forwards exact parsed inputs and emits one exact JSON object', async () => {
    const injected = deps(); const { code, captured } = await run(args, injected);
    expect(code).toBe(0); expect(captured).toEqual({ stdout: `{"sequence":8,"minimumIssuedAt":7,"head":"${head}"}\n`, stderr: '' });
    expect(injected.loadFreshRestoreState).toHaveBeenCalledWith('/candidate/state');
    expect(injected.runOidcActivation).toHaveBeenCalledWith(expect.objectContaining({ runtimeRole: 'runtime', retentionRole: 'retention' }), { value: 'current' }, { value: 'candidate' }, { value: 'secrets' }, { value: 'secrets' }, { expectedPreviousFloor: 7, expectedNextSequence: 8, expectedHead: head });
  });
  it.each(['getConfig', 'getMigrationConfig', 'loadFreshRestoreState', 'loadOidcSecrets', 'createPool', 'runOidcActivation'] as const)('coarsens %s failures and pool close failure without rejection', async key => {
    const injected = deps({ [key]: vi.fn(() => { throw new Error('secret /path SELECT leaked'); }) }); const result = await run(args, injected);
    expect(result).toMatchObject({ code: 1, captured: { stdout: '', stderr: 'OIDC activation unavailable\n' } });
    const closing = deps({ createPool: vi.fn(() => ({ end: vi.fn(async () => { throw new Error('db secret'); }) })) });
    await expect(run(args, closing)).resolves.toMatchObject({ code: 1, captured: { stdout: '', stderr: 'OIDC activation unavailable\n' } });
  });
});
