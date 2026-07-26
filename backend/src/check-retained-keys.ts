import { fileURLToPath } from 'node:url';
import type { Pool, PoolClient } from 'pg';
import { getConfig, type Config } from './config.js';
import { assertRetainedKeys, createRuntimePool } from './db.js';

type RetainedKeys = Parameters<typeof assertRetainedKeys>[1];
type RunnerDependencies = Readonly<{
  getConfig: () => Config;
  createRuntimePool: (config: Config) => Pool;
  assertRetainedKeys: (client: PoolClient, keys: RetainedKeys) => Promise<void>;
}>;

const retainedKeys = (config: Config): RetainedKeys => ({
  subject: config.SUBJECT_KEY_RING.keys,
  envelope: config.ENVELOPE_KEY_RING.keys,
  challenge: Object.keys(config.CHALLENGE_KEY_RING.keys),
  binding: Object.keys(config.SESSION_BINDING_KEY_RING.keys),
  jti: { active: config.JTI_KEY_RING.active, retained: Object.keys(config.JTI_KEY_RING.keys) },
  idempotency: { active: config.IDEMPOTENCY_KEY_RING.active, retained: Object.keys(config.IDEMPOTENCY_KEY_RING.keys) },
  request: Object.keys(config.REQUEST_FINGERPRINT_KEY_RING.keys),
  evidence: Object.keys(config.REVOCATION_EVIDENCE_KEY_RING.keys),
  oidc: { epoch: config.OIDC_EPOCH, adapter: config.OIDC_ADAPTER_KEY_RING.keys, index: Object.keys(config.OIDC_INDEX_KEY_RING.keys) },
});

const defaults: RunnerDependencies = { getConfig, createRuntimePool, assertRetainedKeys };

/** Runs the read-only retained-key gate without exposing configuration or database detail. */
export async function runRetainedKeyPreflight(dependencies: RunnerDependencies = defaults, stdout: (message: string) => void = (message) => process.stdout.write(message), stderr: (message: string) => void = (message) => process.stderr.write(message)): Promise<number> {
  let pool: Pool | undefined;
  let client: PoolClient | undefined;
  let failed = false;
  try {
    const config = dependencies.getConfig();
    pool = dependencies.createRuntimePool(config);
    client = await pool.connect();
    await dependencies.assertRetainedKeys(client, retainedKeys(config));
    const checkedOut = client;
    client = undefined;
    checkedOut.release();
  } catch {
    failed = true;
    if (client) {
      const checkedOut = client;
      client = undefined;
      try { checkedOut.release(new Error('retained-key preflight failed')); } catch { /* pool shutdown still follows */ }
    }
  }
  try {
    await pool?.end();
  } catch {
    failed = true;
  }
  if (failed) { stderr('retained-key preflight failed\n'); return 1; }
  stdout('retained-key preflight ok\n');
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = await runRetainedKeyPreflight();
