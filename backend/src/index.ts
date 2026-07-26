import { createApp } from './server.js';
import { getConfig } from './config.js';
import { acquireRuntimeWriteFence, assertCatalogManifest, assertRetainedKeys, createRuntimePool, LATEST_CONTROL_PLANE_CATALOG } from './db.js';
import { createComposition } from './composition.js';
import { loadOidcSecrets } from './oidc/secrets.js';
import { loadRestoreFloor } from './oidc/restore-floor.js';
import { restoreActivation } from './oidc/restore.js';
import type { PoolClient } from 'pg';

const config = getConfig();
const retentionRole = process.env.CONTROL_PLANE_RETENTION_ROLE;
if (!retentionRole || !/^[a-z_][a-z0-9_]{0,62}$/.test(retentionRole) || retentionRole === config.CONTROL_PLANE_RUNTIME_ROLE) throw new Error('Invalid CONTROL_PLANE_RETENTION_ROLE');
const revocationRole = process.env.CONTROL_PLANE_REVOCATION_ROLE;
if (!revocationRole || !/^[a-z_][a-z0-9_]{0,62}$/.test(revocationRole) || revocationRole === config.CONTROL_PLANE_RUNTIME_ROLE || revocationRole === retentionRole) throw new Error('Invalid CONTROL_PLANE_REVOCATION_ROLE');
const pool = createRuntimePool(config);
const oidcSecrets = loadOidcSecrets(config);
const floor = await loadRestoreFloor(config.OIDC_RESTORE_FLOOR_DIR!, config.OIDC_RESTORE_FLOOR_HEAD!, restoreActivation(config, oidcSecrets));
const composition = createComposition(config, pool, fetch, oidcSecrets, floor.minimumIssuedAt);
let client: PoolClient | undefined;
let startupTransaction = false;
try {
  client = await pool.connect();
  await assertCatalogManifest(client, config.CONTROL_PLANE_RUNTIME_ROLE, retentionRole, LATEST_CONTROL_PLANE_CATALOG, revocationRole);
  await assertRetainedKeys(client, { subject: config.SUBJECT_KEY_RING.keys, envelope: config.ENVELOPE_KEY_RING.keys, challenge: Object.keys(config.CHALLENGE_KEY_RING.keys), binding: Object.keys(config.SESSION_BINDING_KEY_RING.keys), jti: { active: config.JTI_KEY_RING.active, retained: Object.keys(config.JTI_KEY_RING.keys) }, idempotency: { active: config.IDEMPOTENCY_KEY_RING.active, retained: Object.keys(config.IDEMPOTENCY_KEY_RING.keys) }, request: Object.keys(config.REQUEST_FINGERPRINT_KEY_RING.keys), evidence: Object.keys(config.REVOCATION_EVIDENCE_KEY_RING.keys), oidc: { epoch: config.OIDC_EPOCH, adapter: config.OIDC_ADAPTER_KEY_RING.keys, index: Object.keys(config.OIDC_INDEX_KEY_RING.keys) } });
  await client.query('BEGIN');
  startupTransaction = true;
  await acquireRuntimeWriteFence(client);
  await composition.policyRefresh.loadActive(client);
  await client.query('COMMIT');
  startupTransaction = false;
  client.release(); client = undefined;
  const server = createApp(composition).listen(config.PORT, () => console.log(`api listening on ${config.PORT}`));
  let closing = false;
  const shutdown = (): void => {
    if (closing) return; closing = true;
    server.close(() => { void pool.end().finally(() => { process.exitCode = 0; }); });
    setTimeout(() => { server.closeAllConnections(); }, 10_000).unref();
  };
  process.once('SIGTERM', shutdown); process.once('SIGINT', shutdown);
} catch (error) {
  if (client && startupTransaction) await client.query('ROLLBACK').catch((rollback) => { client?.release(rollback instanceof Error ? rollback : new Error('startup rollback failed')); client = undefined; });
  (client as PoolClient | undefined)?.release();
  await pool.end();
  throw error;
}
