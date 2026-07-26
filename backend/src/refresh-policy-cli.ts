import { fileURLToPath } from 'node:url';
import { getConfig } from './config.js';
import { createComposition } from './composition.js';
import { createRuntimePool } from './db.js';
import { runRefreshPolicyCli } from './refresh-policy.js';
import { loadRestoreFloor } from './oidc/restore-floor.js';
import { assertOidcSecretSeparation, loadOidcSecrets } from './oidc/secrets.js';
import { restoreActivation } from './oidc/restore.js';

export async function main(args: readonly string[] = process.argv.slice(2), stderr: (message: string) => void = (message) => process.stderr.write(message)): Promise<number> {
  let pool: ReturnType<typeof createRuntimePool> | undefined;
  try {
    const config = getConfig(); pool = createRuntimePool(config);
    return await runRefreshPolicyCli(args, async () => {
      // Composition owns the same Foundation/policy configuration as the API.
      const secrets = loadOidcSecrets(config); assertOidcSecretSeparation(config, secrets); const floor = await loadRestoreFloor(config.OIDC_RESTORE_FLOOR_DIR!, config.OIDC_RESTORE_FLOOR_HEAD!, restoreActivation(config, secrets));
      const composed = createComposition(config, pool!, fetch, undefined, floor.minimumIssuedAt);
      return composed.policyRefresh;
    }, stderr);
  } catch { stderr('policy refresh failed\n'); return 1; }
  finally { await pool?.end(); }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) { process.exitCode = await main(); }
