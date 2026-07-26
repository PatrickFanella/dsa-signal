import { Pool } from 'pg';
import { getConfig, getMigrationConfig } from '../config.js';
import { loadOidcSecrets } from './secrets.js';
import { loadFreshRestoreState, runOidcActivation } from './restore.js';

type Output = Pick<NodeJS.WriteStream, 'write'>;
export type ActivationCliDependencies = Readonly<{
  getConfig: typeof getConfig;
  getMigrationConfig: typeof getMigrationConfig;
  loadFreshRestoreState: typeof loadFreshRestoreState;
  loadOidcSecrets: typeof loadOidcSecrets;
  runOidcActivation: typeof runOidcActivation;
  createPool: (options: ConstructorParameters<typeof Pool>[0]) => Pool;
}>;
const dependencies: ActivationCliDependencies = { getConfig, getMigrationConfig, loadFreshRestoreState, loadOidcSecrets, runOidcActivation, createPool: options => new Pool(options) };
const fail = (): never => { throw new Error('OIDC activation unavailable'); };
const decimal = (value: string): number => { if (!/^(0|[1-9]\d*)$/.test(value)) fail(); const n = Number(value); if (!Number.isSafeInteger(n)) fail(); return n; };
const parse = (args: readonly string[]): Record<string, string> => {
  const known = new Set(['--candidate-state', '--candidate-cookie-keys', '--candidate-signing-jwks', '--candidate-mas-client-secret', '--expected-previous-floor', '--expected-next-sequence', '--expected-head']);
  if (args.length !== 14) fail(); const output: Record<string, string> = {};
  for (let i = 0; i < args.length; i += 2) { const key = args[i], value = args[i + 1]; if (!key || !value || !known.has(key) || Object.hasOwn(output, key) || value.startsWith('--')) fail(); output[key] = value; }
  if (Object.keys(output).length !== known.size) fail(); return output;
};
export async function main(args: readonly string[], stdout: Output = process.stdout, stderr: Output = process.stderr, deps: ActivationCliDependencies = dependencies): Promise<number> {
  let pool: Pool | undefined;
  let output: string | undefined;
  try {
    const values = parse(args); const previous = decimal(values['--expected-previous-floor']!), sequence = decimal(values['--expected-next-sequence']!), head = values['--expected-head']!;
    if (previous < 0 || sequence < 1 || !/^[A-Za-z0-9_-]{43}$/.test(head) || Buffer.from(head, 'base64url').length !== 32 || Buffer.from(head, 'base64url').toString('base64url') !== head) fail();
    const current = deps.getConfig(), migration = deps.getMigrationConfig(), candidate = deps.loadFreshRestoreState(values['--candidate-state']!);
    pool = deps.createPool({ connectionString: migration.MIGRATION_DATABASE_URL });
    const result = await deps.runOidcActivation({ pool, runtimeRole: migration.CONTROL_PLANE_RUNTIME_ROLE, retentionRole: migration.CONTROL_PLANE_RETENTION_ROLE, claimantRole: migration.CONTROL_PLANE_REVOCATION_ROLE }, current, candidate, deps.loadOidcSecrets(current), deps.loadOidcSecrets({ MAS_CLIENT_SECRET_PATH: values['--candidate-mas-client-secret']!, OIDC_COOKIE_KEYS_PATH: values['--candidate-cookie-keys']!, OIDC_SIGNING_JWKS_PATH: values['--candidate-signing-jwks']! }), { expectedPreviousFloor: previous, expectedNextSequence: sequence, expectedHead: head });
    output = `${JSON.stringify({ sequence: result.sequence, minimumIssuedAt: result.minimumIssuedAt, head: result.head })}\n`;
  } catch { /* reported after cleanup */ }
  try { await pool?.end(); } catch { output = undefined; }
  if (output === undefined) { stderr.write('OIDC activation unavailable\n'); return 1; }
  stdout.write(output); return 0;
}
