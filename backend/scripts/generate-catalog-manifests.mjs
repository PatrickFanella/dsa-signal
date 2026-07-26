import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { URL } from 'node:url';
import { Pool } from 'pg';
import { captureCatalogManifest } from '../dist/db.js';

const root = new URL('../../', import.meta.url);
const catalog = new URL('migrations/catalog/', root);
const container = `dsa-signal-catalog-${process.pid}`;
const runtime = `catalog_runtime_${process.pid}`;
const retention = `catalog_retention_${process.pid}`;
const claimant = `catalog_claimant_${process.pid}`;
let pool;

const migration = async (name) => readFile(new URL(`migrations/${name}.sql`, root), 'utf8');
const ledger = async (client, id, source) => client.query('INSERT INTO control_plane.schema_migrations(id,checksum) VALUES($1,$2)', [id, createHash('sha256').update(source).digest()]);
const installAcls = async (client, includeOidc) => {
  for (const sql of [
    `REVOKE ALL ON SCHEMA control_plane FROM PUBLIC, "${runtime}", "${retention}"`,
    `REVOKE ALL ON ALL TABLES IN SCHEMA control_plane FROM PUBLIC, "${runtime}", "${retention}"`,
    `REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_plane FROM PUBLIC, "${runtime}", "${retention}"`,
    `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_plane FROM PUBLIC, "${runtime}", "${retention}"`,
    `GRANT USAGE ON SCHEMA control_plane TO "${runtime}", "${retention}"`,
    `GRANT SELECT, INSERT ON control_plane.encrypted_envelopes, control_plane.did_mappings, control_plane.login_states, control_plane.identity_sessions, control_plane.proof_challenges, control_plane.policy_snapshots, control_plane.active_policy, control_plane.jti_uses, control_plane.jti_key_aliases, control_plane.idempotency_results, control_plane.idempotency_key_aliases, control_plane.entitlements TO "${runtime}"`,
    `GRANT UPDATE ON control_plane.login_states, control_plane.identity_sessions, control_plane.proof_challenges, control_plane.active_policy, control_plane.entitlements TO "${runtime}"`,
    `GRANT INSERT ON control_plane.security_audit_events TO "${runtime}"`,
    `GRANT EXECUTE ON FUNCTION control_plane.is_canonical_origin(text) TO "${runtime}"`,
    `GRANT EXECUTE ON FUNCTION control_plane.cleanup_expired(timestamptz) TO "${retention}"`,
    ...(includeOidc ? [
      `REVOKE ALL ON SCHEMA oidc FROM PUBLIC, "${runtime}", "${retention}"`,
      `REVOKE ALL ON ALL TABLES IN SCHEMA oidc FROM PUBLIC, "${runtime}", "${retention}"`,
      `REVOKE ALL ON ALL SEQUENCES IN SCHEMA oidc FROM PUBLIC, "${runtime}", "${retention}"`,
      `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA oidc FROM PUBLIC, "${runtime}", "${retention}"`,
      `GRANT USAGE ON SCHEMA oidc TO "${runtime}", "${retention}"`,
      `GRANT SELECT, INSERT, UPDATE ON oidc.provider_artifacts, oidc.authorization_contexts, oidc.interaction_csrf TO "${runtime}"`,
      `GRANT EXECUTE ON FUNCTION oidc.cleanup_expired(timestamptz) TO "${retention}"`,
    ] : []),
  ]) await client.query(sql);
};

try {
  execFileSync('docker', ['run', '-d', '--rm', '--name', container, '-e', 'POSTGRES_PASSWORD=postgres', '-P', 'postgres:17'], { stdio: 'ignore' });
  const deadline = Date.now() + 30_000;
  let port;
  while (!port && Date.now() < deadline) {
    try {
      const output = execFileSync('docker', ['port', container, '5432/tcp'], { encoding: 'utf8' }).trim().split('\n')[0];
      port = Number(output.slice(output.lastIndexOf(':') + 1));
    } catch { await delay(100); }
  }
  if (!port) throw new Error('PostgreSQL port unavailable');
  pool = new Pool({ connectionString: `postgresql://postgres:postgres@127.0.0.1:${port}/postgres` });
  let client;
  while (!client && Date.now() < deadline) {
    try { client = await pool.connect(); } catch { await delay(100); }
  }
  if (!client) throw new Error('PostgreSQL unavailable');
  try {
    await client.query(`CREATE ROLE "${runtime}" LOGIN`);
    await client.query(`CREATE ROLE "${retention}" LOGIN`); await client.query(`CREATE ROLE "${claimant}" LOGIN`);
    const two = await migration('0002_identity_control_plane'); await client.query(two); await ledger(client, '0002_identity_control_plane', two);
    const three = await migration('0003_entitlement_session_binding'); await client.query(three); await ledger(client, '0003_entitlement_session_binding', three);
    await installAcls(client, false);
    const roles = { owner: 'postgres', runtime, retention, claimant };
    const pre = await captureCatalogManifest(client, '0003-pre', ['control_plane'], ['oidc'], roles);
    // Historical manifests are immutable witnesses; generation may only verify them.
    if (JSON.stringify(pre) !== JSON.stringify(JSON.parse(await readFile(new URL('0003-pre.json', catalog), 'utf8')))) throw new Error('0003-pre catalog drift');
    const four = await migration('0004_mas_upstream_oidc'); await client.query(four); await ledger(client, '0004_mas_upstream_oidc', four);
    await installAcls(client, true);
    const post = await captureCatalogManifest(client, '0004-post', ['control_plane', 'oidc'], [], roles);
    if (JSON.stringify(post) !== JSON.stringify(JSON.parse(await readFile(new URL('0004-post.json', catalog), 'utf8')))) throw new Error('0004-post catalog drift');
    const five = await migration('0005_access_revocation_foundation'); await client.query(`SET control_plane.revocation_role = '${claimant}'`); await client.query(five); await ledger(client, '0005_access_revocation_foundation', five);
    await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON control_plane.entitlement_evidence_aliases TO "${runtime}"; GRANT SELECT ON control_plane.revocation_evidence_key_ids, control_plane.membership_access_source_selector_aliases, control_plane.membership_access_source_cause_aliases TO "${runtime}"; GRANT SELECT, INSERT, UPDATE ON control_plane.membership_access_states TO "${runtime}"; GRANT EXECUTE ON FUNCTION control_plane.replace_entitlement_evidence_aliases(uuid,jsonb) TO "${runtime}"`);
    const foundation = await captureCatalogManifest(client, '0005-post', ['control_plane', 'oidc'], [], roles);
    if (JSON.stringify(foundation) !== JSON.stringify(JSON.parse(await readFile(new URL('0005-post.json', catalog), 'utf8')))) throw new Error('0005-post catalog drift');
    const six = await migration('0006_access_revocation_enforcement'); await client.query(six); await ledger(client, '0006_access_revocation_enforcement', six);
    await client.query(`GRANT EXECUTE ON FUNCTION control_plane.enforce_published_source_target(uuid,uuid) TO "${runtime}"`);
    const enforcement = await captureCatalogManifest(client, '0006-post', ['control_plane', 'oidc'], [], roles);
    if (JSON.stringify(enforcement) !== JSON.stringify(JSON.parse(await readFile(new URL('0006-post.json', catalog), 'utf8')))) throw new Error('0006-post catalog drift');
    const seven = await migration('0007_access_revocation_source_set_guard'); await client.query(seven); await ledger(client, '0007_access_revocation_source_set_guard', seven);
    const corrective = await captureCatalogManifest(client, '0007-post', ['control_plane', 'oidc'], [], roles);
    if (JSON.stringify(corrective) !== JSON.stringify(JSON.parse(await readFile(new URL('0007-post.json', catalog), 'utf8')))) throw new Error('0007-post catalog drift');
    const eight = await migration('0008_access_revocation_local_enforcement_fix'); await client.query(eight); await ledger(client, '0008_access_revocation_local_enforcement_fix', eight);
    await installAcls(client, true);
    await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON control_plane.entitlement_evidence_aliases TO "${runtime}"; GRANT SELECT ON control_plane.revocation_evidence_key_ids, control_plane.membership_access_source_selector_aliases, control_plane.membership_access_source_cause_aliases TO "${runtime}"; GRANT SELECT, INSERT, UPDATE ON control_plane.membership_access_states TO "${runtime}"; GRANT EXECUTE ON FUNCTION control_plane.replace_entitlement_evidence_aliases(uuid,jsonb), control_plane.membership_access_source_set_fence(boolean), control_plane.enforce_published_source_target(uuid,uuid) TO "${runtime}"`);
    const local = await captureCatalogManifest(client, '0008-post', ['control_plane', 'oidc'], [], roles);
    if (JSON.stringify(local) !== JSON.stringify(JSON.parse(await readFile(new URL('0008-post.json', catalog), 'utf8')))) throw new Error('0008-post catalog drift');
    const nine = await migration('0009_access_revocation_reconciliation_fix'); await client.query(nine); await ledger(client, '0009_access_revocation_reconciliation_fix', nine);
    const reconciliation = await captureCatalogManifest(client, '0009-post', ['control_plane', 'oidc'], [], roles);
    if (JSON.stringify(reconciliation) !== JSON.stringify(JSON.parse(await readFile(new URL('0009-post.json', catalog), 'utf8')))) throw new Error('0009-post catalog drift');
    const ten = await migration('0010_access_revocation_worker'); await client.query(`SET control_plane.revocation_role = '${claimant}'`); await client.query(ten); await ledger(client, '0010_access_revocation_worker', ten);
    const worker = await captureCatalogManifest(client, '0010-post', ['control_plane', 'oidc'], [], roles);
    await writeFile(new URL('0010-post.json', catalog), `${JSON.stringify(worker, null, 2)}\n`);
  } finally { client.release(); }
} finally {
  await pool?.end().catch(() => undefined);
  try { execFileSync('docker', ['rm', '-f', container], { stdio: 'ignore' }); } catch { /* already removed */ }
}
