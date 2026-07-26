import { Pool } from 'pg';
import { getConfig, getMigrationConfig } from '../config.js';
import { loadOidcSecrets } from './secrets.js';
import { loadFreshRestoreState, runOidcRestore } from './restore.js';

type Output = Pick<NodeJS.WriteStream, 'write'>;
export type RestoreCliDependencies = Readonly<{ getConfig: typeof getConfig; getMigrationConfig: typeof getMigrationConfig; loadFreshRestoreState: typeof loadFreshRestoreState; loadOidcSecrets: typeof loadOidcSecrets; runOidcRestore: typeof runOidcRestore; createPool: (options: ConstructorParameters<typeof Pool>[0]) => Pool }>;
const dependencies: RestoreCliDependencies = { getConfig, getMigrationConfig, loadFreshRestoreState, loadOidcSecrets, runOidcRestore, createPool: options => new Pool(options) };
const fail = (): never => { throw new Error('OIDC restore unavailable'); };
const decimal = (value: string): number => { if (!/^(0|[1-9]\d*)$/.test(value)) fail(); const result = Number(value); if (!Number.isSafeInteger(result)) fail(); return result; };
const parse = (args: readonly string[]): Record<string, string> => {
  const known = new Set(['--fresh-state', '--fresh-cookie-keys', '--fresh-signing-jwks', '--fresh-mas-client-secret', '--expected-previous-floor', '--expected-next-sequence', '--trusted-restore-time', '--expected-head']);
  if (args.length !== 16) fail(); const values: Record<string, string> = {};
  for (let index = 0; index < args.length; index += 2) { const key = args[index], value = args[index + 1]; if (!key || !value || !known.has(key) || Object.hasOwn(values, key) || value.startsWith('--')) fail(); values[key] = value; }
  if (Object.keys(values).length !== known.size) fail(); return values;
};
export async function main(args: readonly string[], stdout: Output = process.stdout, stderr: Output = process.stderr, deps: RestoreCliDependencies = dependencies): Promise<number> {
  let pool: Pool | undefined; let output: string | undefined;
  try {
    const values = parse(args); const previous = decimal(values['--expected-previous-floor']!), sequence = decimal(values['--expected-next-sequence']!), head = values['--expected-head']!, trusted = values['--trusted-restore-time']!;
    if (previous < 0 || sequence < 1 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(trusted) || !/^[A-Za-z0-9_-]{43}$/.test(head) || Buffer.from(head, 'base64url').length !== 32 || Buffer.from(head, 'base64url').toString('base64url') !== head) fail();
    const clock = new Date(trusted); if (!Number.isFinite(clock.getTime()) || clock.toISOString() !== `${trusted.slice(0, -1)}.000Z`) fail();
    const backup = deps.getConfig(), migration = deps.getMigrationConfig(), fresh = deps.loadFreshRestoreState(values['--fresh-state']!);
    pool = deps.createPool({ connectionString: migration.MIGRATION_DATABASE_URL });
    const result = await deps.runOidcRestore({ pool, runtimeRole: migration.CONTROL_PLANE_RUNTIME_ROLE, retentionRole: migration.CONTROL_PLANE_RETENTION_ROLE, claimantRole: migration.CONTROL_PLANE_REVOCATION_ROLE }, backup, fresh, deps.loadOidcSecrets(backup), deps.loadOidcSecrets({ MAS_CLIENT_SECRET_PATH: values['--fresh-mas-client-secret']!, OIDC_COOKIE_KEYS_PATH: values['--fresh-cookie-keys']!, OIDC_SIGNING_JWKS_PATH: values['--fresh-signing-jwks']! }), clock, { expectedPreviousFloor: previous, expectedNextSequence: sequence, expectedHead: head });
    output = `${JSON.stringify(result)}\n`;
  } catch { /* reported after cleanup */ }
  try { await pool?.end(); } catch { output = undefined; }
  if (output === undefined) { stderr.write('OIDC restore unavailable\n'); return 1; }
  stdout.write(output); return 0;
}
