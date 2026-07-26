import { execFile } from 'node:child_process';
import { createServer, request as httpRequest } from 'node:http';
import { createCipheriv, createHash, createHmac, randomBytes, randomUUID, webcrypto } from 'node:crypto';
import { chmod, mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Pool, type PoolClient } from 'pg';
import { CompactSign, exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { applyControlPlaneMigration, assertCatalogManifest, assertControlPlaneCatalog, assertRetainedKeys, expectedControlPlaneMigrationChecksum, LATEST_CONTROL_PLANE_CATALOG } from './db.js';
import { ChallengeRejectedError, createChallengeService } from './entitlements/challenge-service.js';
import { createVerificationService, jwkThumbprint, parsePublicJwk, VerificationRejectedError, VerificationUnavailableError } from './entitlements/verify-entitlement.js';
import { createSessionRepository } from './identity/session-repository.js';
import { readSessionCookie } from './identity/session-cookie.js';
import { FoundationService } from './foundation/foundation-service.js';
import { PolicyRefreshService } from './refresh-policy.js';
import { createApp } from './server.js';
import { createComposition } from './composition.js';
import type { Config } from './config.js';
import { getConfig } from './config.js';
import { createOidcAdapter } from './oidc/adapter.js';
import { createAuthorizationCodeClaim, createAuthorizationHooks, createResumePreflight, createTokenPreflight } from './oidc/authorization-decision.js';
import { createInteractionHandler } from './oidc/interaction.js';
import { createOidcProvider } from './oidc/provider.js';
import { createOidcDispatcher, createTransactionalProviderInvocation } from './routes/oidc.js';
import { makeSessionCookie } from './identity/session-cookie.js';
import { OidcIndeterminateCommitError, requireOidcRequestContext, runOidcTransaction, serializeOidcAdapterCall } from './oidc/request-context.js';
import { createLogoutService } from './routes/auth.js';
import { assertFreshMaterial, restoreActivation, runOidcRestore } from './oidc/restore.js';
import { INITIAL_RESTORE_FLOOR_HEAD, loadRestoreFloor } from './oidc/restore-floor.js';
import type { OidcSecrets } from './oidc/secrets.js';
import { derivePairwiseSubject } from './subjects/pairwise-subject.js';
import { createPostgresClaimantStore, createRevocationWorker } from './entitlements/revocation-worker.js';

const exec = promisify(execFile); const suffix = randomUUID().replaceAll('-', '').slice(0, 12);
const securityDrillRunId = process.env.DSA_SECURITY_DRILL_RUN_ID;
if (securityDrillRunId !== undefined && !/^[a-z0-9][a-z0-9_-]{0,47}$/.test(securityDrillRunId)) throw new Error('DSA_SECURITY_DRILL_RUN_ID must be a lowercase identifier of at most 48 characters');
const securityDrillOwner = process.env.DSA_SECURITY_DRILL_OWNER;
const securityDrillOwnerPid = process.env.DSA_SECURITY_DRILL_OWNER_PID;
const securityDrillOwnerStart = process.env.DSA_SECURITY_DRILL_OWNER_START;
if (securityDrillRunId && (!/^[a-f0-9]{32}$/.test(securityDrillOwner ?? '') || !/^[1-9][0-9]*$/.test(securityDrillOwnerPid ?? '') || !/^[1-9][0-9]*$/.test(securityDrillOwnerStart ?? ''))) throw new Error('security drill owner labels are missing or invalid');
const container = securityDrillRunId ? `dsa-signal-security-drill-${securityDrillRunId}` : `dsa-signal-test-${suffix}`; const runtime = `cp_runtime_${suffix}`; const retention = `cp_retain_${suffix}`; const revocation = `cp_revoke_${suffix}`;
const containerLabels = securityDrillRunId
  ? { 'dsa-signal.security-drill': securityDrillRunId, 'dsa-signal.security-drill-owner': securityDrillOwner!, 'dsa-signal.security-drill-owner-pid': securityDrillOwnerPid!, 'dsa-signal.security-drill-owner-start': securityDrillOwnerStart! }
  : { 'dsa-signal.integration-test': suffix, 'dsa-signal.integration-test-container': container };
const evidenceKeyIds = ['v1'] as const;
const frozenPreTask5Migration0002Checksum = '176cacc0b4a0972421bda9335e3b10ce8cfbb1b50d68147d3c076aca780bdb04';
let pool: Pool;
let postgresPort: string;
let containerId: string | undefined;
const bytes = (value = 1): Buffer => Buffer.alloc(32, value);
const envelopeKey = randomBytes(32);
const fixtureSubjectKey = randomBytes(32);
const quoteRole = (role: string): string => `"${role.replaceAll('"', '""')}"`;
const fixtureDid = (): string => `did:plc:${Array.from(randomBytes(24), byte => 'abcdefghijklmnopqrstuvwxyz234567'[byte & 31]).join('')}`;
const migration = async (name: string): Promise<string> => readFile(fileURLToPath(new URL(`../../migrations/${name}.sql`, import.meta.url)), 'utf8');
async function asRole(role: string, sql: string, values: unknown[] = []): Promise<void> { const client = await pool.connect(); try { await client.query(`SET ROLE ${role}`); await client.query(sql, values); } finally { await client.query('RESET ROLE').catch(() => undefined); client.release(); } }
async function queryAsRole<T extends Record<string, unknown>>(role: string, sql: string, values: unknown[] = []): Promise<T[]> { const client = await pool.connect(); try { await client.query(`SET ROLE ${role}`); return (await client.query<T>(sql, values)).rows; } finally { await client.query('RESET ROLE').catch(() => undefined); client.release(); } }
async function envelope(id: string, purpose: 'did' | 'policy', key: Uint8Array, extra: string, parentId = id, plaintext = 'fixture'): Promise<void> { const nonce = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(Buffer.from(`dsa-signal-${purpose === 'did' ? 'did-mapping' : 'policy-snapshot'}:v1\0${parentId}\0${extra}`)); const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]); await pool.query('INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose) VALUES($1,$2,$3,$4,$5)', [id, 'env1', nonce, ciphertext, purpose]); }
async function docker(...args: string[]): Promise<string> { return (await exec('docker', args)).stdout.trim(); }
function isExactContainerAbsence(error: unknown, id: string): boolean {
  const stderr = typeof error === 'object' && error !== null && 'stderr' in error ? String(error.stderr) : '';
  return [`Error response from daemon: No such object: ${id}`, `Error response from daemon: No such container: ${id}`, `error: no such object: ${id}`, `error: no such container: ${id}`].some(diagnostic => stderr === diagnostic || stderr === `${diagnostic}\n`);
}
async function approvedPostgresImage(): Promise<string> {
  const lock = await readFile(fileURLToPath(new URL('../../deploy/locks/images.env', import.meta.url)), 'utf8');
  const images = [...lock.matchAll(/^POSTGRES_IMAGE=(postgres@sha256:[a-f0-9]{64})$/gm)].map(match => match[1]!);
  if (images.length !== 1) throw new Error('deploy/locks/images.env must contain exactly one valid POSTGRES_IMAGE digest');
  return images[0]!;
}
async function removeOwnedContainer(): Promise<void> {
  if (!containerId) return;
  const id = containerId;
  const [actualId, name, ...labels] = (await docker('inspect', '--format', '{{.Id}}|{{.Name}}|{{range $key, $value := .Config.Labels}}{{$key}}={{$value}}|{{end}}', id)).split('|');
  const expectedLabels = Object.entries(containerLabels).map(([key, value]) => `${key}=${value}`).sort();
  if (actualId !== id || name !== `/${container}` || labels.filter(Boolean).sort().join('|') !== expectedLabels.join('|')) throw new Error(`refusing to remove container with unexpected ownership: ${id}`);
  await docker('rm', '-f', id);
  try { await docker('inspect', id); } catch (error: unknown) { if (isExactContainerAbsence(error, id)) { containerId = undefined; return; } throw error; }
  throw new Error(`container remains after cleanup: ${id}`);
}
const apmPackage = (name: string): boolean => name.startsWith('@opentelemetry/') || ['dd-trace', 'newrelic', 'elastic-apm-node', '@sentry/node'].includes(name);
async function productionTypeScriptFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  return (await Promise.all(entries.map(async (entry) => entry.isDirectory() && entry.name !== 'dist' ? productionTypeScriptFiles(`${directory}/${entry.name}`) : entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [`${directory}/${entry.name}`] : []))).flat();
}
async function ready(): Promise<void> { for (let i = 0; i < 120; i += 1) { try { await pool.query('SELECT 1'); return; } catch { await new Promise((resolve) => setTimeout(resolve, 250)); } } throw new Error('PostgreSQL test container did not become ready'); }
async function awaitEntitlementLockWait(pid: number): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const locks = await pool.query<{ count: number }>("SELECT count(*)::int AS count FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted", [pid]);
    if (locks.rows[0]!.count === 1) return;
    await new Promise<void>(resolve => setImmediate(resolve));
  }
  throw new Error('entitlement writer did not wait for the publishing source lock');
}
async function awaitBlockedQuery(fragment: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const waiting = await pool.query<{ count: number }>("SELECT count(*)::int AS count FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%'||$1||'%'", [fragment]);
    if (waiting.rows[0]!.count > 0) return;
    await new Promise<void>(resolve => setImmediate(resolve));
  }
  throw new Error(`query did not wait for its lock: ${fragment}`);
}
async function identityFixture(): Promise<{ mapping: string; policy: string; version: string }> {
  const mapping = randomUUID(); const policy = randomUUID(); const version = `v-${randomUUID().slice(0, 8)}`;
  const mappingEnvelope = randomUUID(); const policyEnvelope = randomUUID(); const did = fixtureDid();
  await envelope(mappingEnvelope, 'did', envelopeKey, 'https://chat.example', mapping, did);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO control_plane.did_mappings(id,sector,subject_key_id,subject,envelope_id) VALUES($1,$2,$3,$4,$5)', [mapping, 'https://chat.example', 'subject1', derivePairwiseSubject(fixtureSubjectKey, 'https://chat.example', did), mappingEnvelope]);
    await client.query("INSERT INTO control_plane.membership_access_states(mapping_id,barrier_state,revision,changed_at) VALUES($1,'active',0,clock_timestamp())", [mapping]);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  await envelope(policyEnvelope, 'policy', envelopeKey, version, policy);
  await pool.query("INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) VALUES($1,$2,$3,$4,clock_timestamp()-interval '2 seconds',clock_timestamp()-interval '1 second',clock_timestamp()+interval '1 hour',clock_timestamp())", [policy, randomBytes(32), policyEnvelope, version]);
  return { mapping, policy, version };
}
async function workerFixture(roomBans = 0): Promise<{ operation: string; steps: Record<string, string> }> {
  const { mapping } = await identityFixture(); const operation = randomUUID(); const source = randomUUID(); const mas = randomUUID(); const registry = randomUUID(); const crypto = randomUUID(); const rooms = Array.from({ length: roomBans }, () => ({ id: randomUUID(), room: `!${randomUUID()}:example`, moderator: '@moderator:example' })); const digest = roomBans ? createHash('sha256').update('dsa-signal-managed-room-targets:v1\0').update(Buffer.concat(rooms.map(({ room, moderator }) => Buffer.concat([Buffer.from([0, 0, 0, Buffer.byteLength(room)]), Buffer.from(room), Buffer.from([0, 0, 0, Buffer.byteLength(moderator)]), Buffer.from(moderator)])))).digest() : (await pool.query<{ digest: Buffer }>('SELECT control_plane.registry_target_digest($1) AS digest', [registry])).rows[0]!.digest; const now = (await pool.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now;
  const steps: Record<string, string> = { mas_lock: randomUUID(), mas_finish_sessions: randomUUID(), crypto_gate: randomUUID() };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("INSERT INTO control_plane.membership_access_sources(id,source_kind,reason,producer_id,source_event_id,source_event_digest,requested_at,source_effective_at,mapping_id) VALUES($1,'entitlement_expiry','entitlement_expired','worker-fixture',$2,$3,$4,$4,$5)", [source, randomUUID(), randomBytes(32), now, mapping]);
    await client.query("INSERT INTO control_plane.membership_access_source_selector_aliases(source_id,selector_kind,fingerprint_key_id,fingerprint) VALUES($1,'mapping','v1',$2)", [source, randomBytes(32)]);
    await client.query("INSERT INTO control_plane.membership_access_source_cause_aliases(source_id,fingerprint_key_id,fingerprint) VALUES($1,'v1',$2)", [source, randomBytes(32)]);
    await client.query("INSERT INTO control_plane.membership_access_operations(id,mapping_id,transition_revision,state,first_effective_at,local_enforced_at) VALUES($1,$2,1,'reconciling',$3,$3)", [operation, mapping, now]);
    await client.query("INSERT INTO control_plane.membership_access_mas_targets(id,operation_id,mapping_id,transition_revision,kind,mas_user_id,matrix_user_id) VALUES($1,$2,$3,1,'bound','mas-user','@user:example')", [mas, operation, mapping]);
    await client.query("INSERT INTO control_plane.membership_access_registry_snapshots(id,operation_id,mapping_id,transition_revision,kind,expected_room_count,target_digest) VALUES($1,$2,$3,1,'complete',$4,$5)", [registry, operation, mapping, rooms.length, digest]);
    await client.query("INSERT INTO control_plane.membership_access_crypto_capabilities(id,operation_id,mapping_id,transition_revision,kind,capability_version) VALUES($1,$2,$3,1,'supported','v1')", [crypto, operation, mapping]);
    await client.query("INSERT INTO control_plane.membership_access_steps(id,operation_id,mapping_id,transition_revision,step_kind,state,mas_target_id) VALUES($1,$2,$3,1,'mas_lock','pending',$4),($5,$2,$3,1,'mas_finish_sessions','pending',$4)", [steps.mas_lock, operation, mapping, mas, steps.mas_finish_sessions]);
    await client.query("INSERT INTO control_plane.membership_access_steps(id,operation_id,mapping_id,transition_revision,step_kind,state,crypto_capability_id) VALUES($1,$2,$3,1,'crypto_gate','pending',$4)", [steps.crypto_gate, operation, mapping, crypto]);
    for (const room of rooms) { const step = randomUUID(); steps[`room_ban_${room.id}`] = step; await client.query('INSERT INTO control_plane.membership_access_room_targets(id,operation_id,mapping_id,transition_revision,registry_snapshot_id,room_id,moderator_user_id) VALUES($1,$2,$3,1,$4,$5,$6)', [room.id, operation, mapping, registry, room.room, room.moderator]); await client.query("INSERT INTO control_plane.membership_access_steps(id,operation_id,mapping_id,transition_revision,step_kind,state,room_target_id) VALUES($1,$2,$3,1,'room_ban','pending',$4)", [step, operation, mapping, room.id]); }
    await client.query("UPDATE control_plane.membership_access_states SET barrier_state='suspended',revision=1,current_operation_id=$1,changed_at=$2 WHERE mapping_id=$3", [operation, now, mapping]);
    await client.query("INSERT INTO control_plane.security_audit_events(id,event_type,mapping_id,outcome,reason,occurred_at,source_id,operation_id) VALUES($1,'membership_access_local_enforced',$2,'success','entitlement_expired',$3,$4,$5)", [randomUUID(), mapping, now, source, operation]);
    await client.query('COMMIT'); return { operation, steps };
  } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
}
async function insertEntitlement(sql: string, values: unknown[], entitlementIds: readonly string[], database: Pick<Pool, 'connect'> = pool, aliases: Partial<Record<'issuer' | 'issuer_key' | 'policy', Buffer>> = {}): Promise<void> {
  const client = await database.connect();
  try {
    await client.query('BEGIN');
    await client.query(sql, values);
    for (const entitlementId of entitlementIds) for (const keyId of evidenceKeyIds) await client.query("INSERT INTO control_plane.entitlement_evidence_aliases(entitlement_id,evidence_kind,fingerprint_key_id,fingerprint) VALUES($1,'issuer',$2,$3),($1,'issuer_key',$2,$4),($1,'policy',$2,$5)", [entitlementId, keyId, aliases.issuer ?? randomBytes(32), aliases.issuer_key ?? randomBytes(32), aliases.policy ?? randomBytes(32)]);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
}
async function insertMapping(client: Pick<PoolClient, 'query'>, mapping: string, sector: string, subjectKeyId: string, subject: string, envelopeId: string): Promise<void> {
  await client.query('BEGIN');
  try {
    await client.query('INSERT INTO control_plane.did_mappings(id,sector,subject_key_id,subject,envelope_id) VALUES($1,$2,$3,$4,$5)', [mapping, sector, subjectKeyId, subject, envelopeId]);
    await client.query("INSERT INTO control_plane.membership_access_states(mapping_id,barrier_state,revision,changed_at) VALUES($1,'active',0,clock_timestamp())", [mapping]);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; }
}
async function legacyPool(database: string, through0003 = false): Promise<Pool> {
  await pool.query(`CREATE DATABASE ${database}`);
  const legacy = new Pool({ connectionString: `postgresql://postgres:test@127.0.0.1:${postgresPort}/${database}` });
  const source = await migration('0002_identity_control_plane');
  expect(createHash('sha256').update(source).digest('hex')).toBe(frozenPreTask5Migration0002Checksum);
  await legacy.query(source);
  await legacy.query('INSERT INTO control_plane.schema_migrations(id,checksum) VALUES($1,$2)', ['0002_identity_control_plane', createHash('sha256').update(source).digest()]);
  if (through0003) {
    const source3 = await migration('0003_entitlement_session_binding');
    await legacy.query(source3);
    await legacy.query('INSERT INTO control_plane.schema_migrations(id,checksum) VALUES($1,$2)', ['0003_entitlement_session_binding', createHash('sha256').update(source3).digest()]);
  }
  await legacy.query(`GRANT USAGE ON SCHEMA control_plane TO ${runtime}, ${retention}`);
  await legacy.query(`GRANT SELECT, INSERT ON control_plane.encrypted_envelopes, control_plane.did_mappings, control_plane.login_states, control_plane.identity_sessions, control_plane.proof_challenges, control_plane.policy_snapshots, control_plane.active_policy, control_plane.jti_uses, control_plane.jti_key_aliases, control_plane.idempotency_results, control_plane.idempotency_key_aliases, control_plane.entitlements TO ${runtime}`);
  await legacy.query(`GRANT UPDATE ON control_plane.login_states, control_plane.identity_sessions, control_plane.proof_challenges, control_plane.active_policy, control_plane.entitlements TO ${runtime}`);
  await legacy.query(`GRANT INSERT ON control_plane.security_audit_events TO ${runtime}`);
  await legacy.query(`GRANT EXECUTE ON FUNCTION control_plane.is_canonical_origin(text) TO ${runtime}`);
  await legacy.query(`GRANT EXECUTE ON FUNCTION control_plane.cleanup_expired(timestamptz) TO ${retention}`);
  return legacy;
}

async function install0009CatalogAcls(database: Pool): Promise<void> {
  await database.query(`REVOKE ALL ON SCHEMA control_plane FROM PUBLIC, ${runtime}, ${retention}`);
  await database.query(`REVOKE ALL ON ALL TABLES IN SCHEMA control_plane FROM PUBLIC, ${runtime}, ${retention}`);
  await database.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_plane FROM PUBLIC, ${runtime}, ${retention}`);
  await database.query(`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_plane FROM PUBLIC, ${runtime}, ${retention}`);
  await database.query(`GRANT USAGE ON SCHEMA control_plane TO ${runtime}, ${retention}`);
  await database.query(`GRANT SELECT, INSERT ON control_plane.encrypted_envelopes, control_plane.did_mappings, control_plane.login_states, control_plane.identity_sessions, control_plane.proof_challenges, control_plane.policy_snapshots, control_plane.active_policy, control_plane.jti_uses, control_plane.jti_key_aliases, control_plane.idempotency_results, control_plane.idempotency_key_aliases, control_plane.entitlements, control_plane.entitlement_evidence_aliases, control_plane.membership_access_states TO ${runtime}`);
  await database.query(`GRANT UPDATE ON control_plane.login_states, control_plane.identity_sessions, control_plane.proof_challenges, control_plane.active_policy, control_plane.entitlements, control_plane.membership_access_states TO ${runtime}`);
  await database.query(`GRANT UPDATE, DELETE ON control_plane.entitlement_evidence_aliases TO ${runtime}`);
  await database.query(`GRANT SELECT ON control_plane.revocation_evidence_key_ids, control_plane.membership_access_source_selector_aliases, control_plane.membership_access_source_cause_aliases TO ${runtime}`);
  await database.query(`GRANT EXECUTE ON FUNCTION control_plane.replace_entitlement_evidence_aliases(uuid,jsonb), control_plane.membership_access_source_set_fence(boolean), control_plane.enforce_published_source_target(uuid,uuid), control_plane.is_canonical_origin(text) TO ${runtime}`);
  await database.query(`GRANT INSERT ON control_plane.security_audit_events TO ${runtime}`);
  await database.query(`GRANT EXECUTE ON FUNCTION control_plane.cleanup_expired(timestamptz) TO ${retention}`);
  await database.query(`REVOKE ALL ON SCHEMA oidc FROM PUBLIC, ${runtime}, ${retention}`);
  await database.query(`REVOKE ALL ON ALL TABLES IN SCHEMA oidc FROM PUBLIC, ${runtime}, ${retention}`);
  await database.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA oidc FROM PUBLIC, ${runtime}, ${retention}`);
  await database.query(`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA oidc FROM PUBLIC, ${runtime}, ${retention}`);
  await database.query(`GRANT USAGE ON SCHEMA oidc TO ${runtime}, ${retention}`);
  await database.query(`GRANT SELECT, INSERT, UPDATE ON oidc.provider_artifacts, oidc.authorization_contexts, oidc.interaction_csrf TO ${runtime}`);
  await database.query(`GRANT EXECUTE ON FUNCTION oidc.cleanup_expired(timestamptz) TO ${retention}`);
}

async function poolAt0009(database: string): Promise<Pool> {
  await pool.query(`CREATE DATABASE ${database}`);
  const legacy = new Pool({ connectionString: `postgresql://postgres:test@127.0.0.1:${postgresPort}/${database}` });
  try {
    for (const id of ['0002_identity_control_plane', '0003_entitlement_session_binding', '0004_mas_upstream_oidc', '0005_access_revocation_foundation', '0006_access_revocation_enforcement', '0007_access_revocation_source_set_guard', '0008_access_revocation_local_enforcement_fix', '0009_access_revocation_reconciliation_fix'] as const) {
      const source = await migration(id);
      if (id === '0005_access_revocation_foundation') await legacy.query(`SET control_plane.revocation_role = '${revocation}'`);
      await legacy.query(source);
      if (id === '0005_access_revocation_foundation') await legacy.query('INSERT INTO control_plane.revocation_evidence_key_ids(key_id,enabled) SELECT key_id,true FROM unnest($1::text[]) AS key_id', [evidenceKeyIds]);
      await legacy.query('INSERT INTO control_plane.schema_migrations(id,checksum) VALUES($1,$2)', [id, createHash('sha256').update(source).digest()]);
    }
    await install0009CatalogAcls(legacy);
    return legacy;
  } catch (error) { await legacy.end(); await pool.query(`DROP DATABASE ${database}`); throw error; }
}

describe('control-plane migration', () => {
  beforeAll(async () => {
    try {
      const image = await approvedPostgresImage();
      await docker('image', 'inspect', image);
      containerId = await docker('create', '--name', container, ...Object.entries(containerLabels).flatMap(([key, value]) => ['--label', `${key}=${value}`]), '-e', 'POSTGRES_PASSWORD=test', '-e', 'POSTGRES_DB=test_control_plane', '-p', '127.0.0.1::5432', image);
      if (!/^[a-f0-9]{64}$/.test(containerId)) throw new Error('Docker returned an invalid PostgreSQL container ID');
      await docker('start', containerId);
      const port = (await docker('port', containerId, '5432/tcp')).match(/^127\.0\.0\.1:(\d+)$/m)?.[1]; if (!port) throw new Error('Could not discover loopback PostgreSQL test port'); postgresPort = port;
      pool = new Pool({ connectionString: `postgresql://postgres:test@127.0.0.1:${postgresPort}/test_control_plane` });
      await ready(); await pool.query(`CREATE ROLE ${runtime} LOGIN PASSWORD 'runtime-test-only'; CREATE ROLE ${retention} LOGIN PASSWORD 'retention-test-only'; CREATE ROLE ${revocation} LOGIN PASSWORD 'revocation-test-only'`); await applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds);
    } catch (error) { await pool?.end().catch(() => undefined); await removeOwnedContainer(); throw error; }
  }, 30_000);
  afterAll(async () => { await pool?.end().catch(() => undefined); await removeOwnedContainer(); });
  it('pins 0004 source to its immutable checksum rather than permitting an override', async () => {
    await expect(expectedControlPlaneMigrationChecksum('0004_mas_upstream_oidc')).resolves.toEqual(Buffer.from('bc44318b770e09f909243dd91732638a610f3fdf876e69b2b4f8f4a60d5bcc7a', 'hex'));
  });
  it('pins 0005 source to its immutable checksum', async () => {
    await expect(expectedControlPlaneMigrationChecksum('0005_access_revocation_foundation')).resolves.toEqual(Buffer.from('c6e012af98b2c7316937e9943dd7a50a2fe81bff2ed489c60bd1970e901a7153', 'hex'));
  });
  it.each([
    ['0007_access_revocation_source_set_guard', '5ae58b678817c16c6b52474fab300e58776316fe312f33353eb73cf1a4d432ba'],
    ['0008_access_revocation_local_enforcement_fix', 'aa05e9af63c1bde4fe97f7b48751b630c7a63ff3014deeb62ef9ad9cdb1fe87f'],
    ['0009_access_revocation_reconciliation_fix', '56a7444e0c95df564d9bfe957a9a30e29b518df6b807db5b8817ea8715e50559'],
  ] as const)('pins %s source to its immutable checksum', async (id, checksum) => {
    await expect(expectedControlPlaneMigrationChecksum(id)).resolves.toEqual(Buffer.from(checksum, 'hex'));
  });
  it('binds complete registry snapshots to an independently encoded canonical target digest', async () => {
    const { mapping } = await identityFixture(); const operation = randomUUID(); const snapshot = randomUUID(); const mas = randomUUID(); const crypto = randomUUID();
    const targets = [{ id: randomUUID(), room: '!z:example', moderator: '@zoe:example' }, { id: randomUUID(), room: '!a:example', moderator: '@adam:example' }];
    const record = ({ room, moderator }: typeof targets[number]) => Buffer.concat([Buffer.from([0, 0, 0, Buffer.byteLength(room)]), Buffer.from(room), Buffer.from([0, 0, 0, Buffer.byteLength(moderator)]), Buffer.from(moderator)]);
    // This test deliberately does not call registry_target_digest or duplicate its
    // SQL: the protocol bytes are constructed here as an external known answer.
    const expected = createHash('sha256').update('dsa-signal-managed-room-targets:v1\0', 'utf8').update(Buffer.concat(targets.map(record).sort(Buffer.compare))).digest();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("INSERT INTO control_plane.membership_access_operations(id,mapping_id,transition_revision,state,first_effective_at) VALUES($1,$2,1,'reconciling',clock_timestamp())", [operation, mapping]);
      await client.query("INSERT INTO control_plane.membership_access_mas_targets(id,operation_id,mapping_id,transition_revision,kind) VALUES($1,$2,$3,1,'missing')", [mas, operation, mapping]);
      await client.query("INSERT INTO control_plane.membership_access_registry_snapshots(id,operation_id,mapping_id,transition_revision,kind,expected_room_count,target_digest) VALUES($1,$2,$3,1,'complete',2,$4)", [snapshot, operation, mapping, expected]);
      await client.query("INSERT INTO control_plane.membership_access_crypto_capabilities(id,operation_id,mapping_id,transition_revision,kind) VALUES($1,$2,$3,1,'missing')", [crypto, operation, mapping]);
      for (const target of targets) await client.query('INSERT INTO control_plane.membership_access_room_targets(id,operation_id,mapping_id,transition_revision,registry_snapshot_id,room_id,moderator_user_id) VALUES($1,$2,$3,1,$4,$5,$6)', [target.id, operation, mapping, snapshot, target.room, target.moderator]);
      await client.query("INSERT INTO control_plane.membership_access_steps(id,operation_id,mapping_id,transition_revision,step_kind,state,mas_target_id) VALUES($1,$2,$3,1,'mas_prerequisite','pending',$4)", [randomUUID(), operation, mapping, mas]);
      await client.query("INSERT INTO control_plane.membership_access_steps(id,operation_id,mapping_id,transition_revision,step_kind,state,crypto_capability_id) VALUES($1,$2,$3,1,'crypto_prerequisite','pending',$4)", [randomUUID(), operation, mapping, crypto]);
      for (const target of targets) await client.query("INSERT INTO control_plane.membership_access_steps(id,operation_id,mapping_id,transition_revision,step_kind,state,room_target_id) VALUES($1,$2,$3,1,'room_ban','pending',$4)", [randomUUID(), operation, mapping, target.id]);
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
    expect((await pool.query<{ digest: Buffer }>('SELECT control_plane.registry_target_digest($1) AS digest', [snapshot])).rows[0]!.digest.equals(expected)).toBe(true);
    await expect(pool.query("UPDATE control_plane.membership_access_room_targets SET room_id='!changed:example' WHERE id=$1", [targets[0]!.id])).rejects.toThrow('registry targets are immutable');
    await expect(pool.query('DELETE FROM control_plane.membership_access_room_targets WHERE id=$1', [targets[0]!.id])).rejects.toThrow();
    await expect(pool.query('UPDATE control_plane.membership_access_registry_snapshots SET expected_room_count=3 WHERE id=$1', [snapshot])).rejects.toThrow();
    await expect(pool.query('DELETE FROM control_plane.membership_access_registry_snapshots WHERE id=$1', [snapshot])).rejects.toThrow();
    const steps = (await pool.query<{ id: string }>('SELECT id FROM control_plane.membership_access_steps WHERE operation_id=$1', [operation])).rows;
    const terminal = await pool.connect(); const operationAudit = randomUUID();
    try {
      await terminal.query('BEGIN');
      for (const step of steps) {
        await terminal.query("UPDATE control_plane.membership_access_steps SET state='succeeded',confirmed_at=clock_timestamp(),evidence_fingerprint=$2 WHERE id=$1", [step.id, randomBytes(32)]);
        await terminal.query("INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason,step_id,mapping_id) VALUES($1,'membership_access_step_succeeded','success','completed',$2,$3)", [randomUUID(), step.id, mapping]);
      }
      await terminal.query("UPDATE control_plane.membership_access_operations SET state='completed',completed_at=clock_timestamp() WHERE id=$1", [operation]);
      await terminal.query("INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason,operation_id,mapping_id) VALUES($1,'membership_access_operation_terminal','success','completed',$2,$3)", [operationAudit, operation, mapping]);
      await terminal.query('COMMIT');
    } catch (error) { await terminal.query('ROLLBACK').catch(() => undefined); throw error; } finally { terminal.release(); }
    await expect(pool.query("UPDATE control_plane.membership_access_operations SET state='reconciling',completed_at=NULL WHERE id=$1", [operation])).rejects.toThrow('completed operation is immutable');
    await expect(pool.query("UPDATE control_plane.membership_access_steps SET state='pending',confirmed_at=NULL,evidence_fingerprint=NULL WHERE id=$1", [steps[0]!.id])).rejects.toThrow('succeeded step is immutable');
    const rollback = await pool.connect();
    try {
      await rollback.query('BEGIN'); await rollback.query('DELETE FROM control_plane.security_audit_events WHERE id=$1', [operationAudit]);
      await expect(rollback.query("UPDATE control_plane.membership_access_operations SET state='reconciling',completed_at=NULL WHERE id=$1", [operation])).rejects.toThrow('completed operation is immutable');
    } finally { await rollback.query('ROLLBACK').catch(() => undefined); rollback.release(); }
  });
  it('serializes entitlement fanout behind a publishing source and rejects the post-lock missing target', async () => {
    const fixture = await identityFixture(); const source = randomUUID(); const policyFingerprint = randomBytes(32); const setup = await pool.connect();
    try {
      await setup.query('BEGIN');
      await setup.query("INSERT INTO control_plane.membership_access_sources(id,source_kind,reason,producer_id,source_event_id,source_event_digest,requested_at,source_effective_at) VALUES($1,'signed_policy_revocation','policy_revoked','fanout-race',$2,$3,clock_timestamp(),clock_timestamp()-interval '1 second')", [source, randomUUID(), randomBytes(32)]);
      await setup.query("INSERT INTO control_plane.membership_access_source_selector_aliases(source_id,selector_kind,fingerprint_key_id,fingerprint) VALUES($1,'policy','v1',$2)", [source, policyFingerprint]);
      await setup.query("INSERT INTO control_plane.membership_access_source_cause_aliases(source_id,fingerprint_key_id,fingerprint) VALUES($1,'v1',$2)", [source, randomBytes(32)]);
      await setup.query('COMMIT');
    } catch (error) { await setup.query('ROLLBACK').catch(() => undefined); throw error; } finally { setup.release(); }
    const publisher = await pool.connect(); const writer = await pool.connect();
    try {
      await publisher.query('BEGIN'); await publisher.query("UPDATE control_plane.membership_access_sources SET publication_state='publishing',cursor_digest=sha256('\\x'::bytea) WHERE id=$1", [source]);
      const writerPid = (await writer.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid;
      await writer.query('BEGIN'); const entitlement = randomUUID();
      const insert = writer.query("WITH t AS (SELECT clock_timestamp() AS authorized) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,$5,authorized,authorized+interval '15 minutes','membership_verified','AAAAAAAAAAAAAAAAAAAAAA','bind1',$6,1 FROM t", [entitlement, fixture.mapping, randomBytes(32), fixture.policy, fixture.version, randomBytes(32)]);
      await awaitEntitlementLockWait(writerPid);
      await publisher.query("UPDATE control_plane.membership_access_sources SET publication_state='published',finalized_at=clock_timestamp() WHERE id=$1", [source]);
      await publisher.query("INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason,source_id) VALUES($1,'membership_access_source_published','success','policy_revoked',$2)", [randomUUID(), source]); await publisher.query('COMMIT');
      await insert;
      expect((await pool.query<{ publication_state: string }>('SELECT publication_state FROM control_plane.membership_access_sources WHERE id=$1', [source])).rows[0]!.publication_state).toBe('published');
      await expect(writer.query("INSERT INTO control_plane.entitlement_evidence_aliases(entitlement_id,evidence_kind,fingerprint_key_id,fingerprint) VALUES($1,'policy','v1',$2)", [entitlement, policyFingerprint])).rejects.toThrow('entitlement alias would make published source fanout incomplete');
      await writer.query('ROLLBACK');
    } finally { await publisher.query('ROLLBACK').catch(() => undefined); await writer.query('ROLLBACK').catch(() => undefined); publisher.release(); writer.release(); }
  });
  it('applies the three local-enforcement branches without replay mutation', async () => {
    const fixture = await identityFixture(); const entitlement = randomUUID();
    await insertEntitlement("WITH t AS (SELECT clock_timestamp() AS now) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,$5,now,now+interval '15 minutes','membership_verified','AAAAAAAAAAAAAAAAAAAAAA','bind1',$6,1 FROM t", [entitlement, fixture.mapping, randomBytes(32), fixture.policy, fixture.version, randomBytes(32)], [entitlement]);
    const publish = async (): Promise<string> => {
      const source = randomUUID(); const client = await pool.connect();
      try {
        await client.query('BEGIN'); await client.query("INSERT INTO control_plane.membership_access_sources(id,source_kind,reason,producer_id,source_event_id,source_event_digest,requested_at,source_effective_at,mapping_id) VALUES($1,'entitlement_expiry','entitlement_expired','enforcement-branch',$2,$3,clock_timestamp(),clock_timestamp()-interval '1 second',$4)", [source, randomUUID(), randomBytes(32), fixture.mapping]);
        await client.query("INSERT INTO control_plane.membership_access_source_selector_aliases(source_id,selector_kind,fingerprint_key_id,fingerprint) VALUES($1,'mapping','v1',$2)", [source, randomBytes(32)]); await client.query("INSERT INTO control_plane.membership_access_source_cause_aliases(source_id,fingerprint_key_id,fingerprint) VALUES($1,'v1',$2)", [source, randomBytes(32)]); await client.query('COMMIT');
        await client.query('BEGIN'); await client.query("INSERT INTO control_plane.membership_access_source_chunks(source_id,chunk_no,target_count,chunk_digest,published_at) VALUES($1,0,1,sha256(convert_to($2,'UTF8')),clock_timestamp())", [source, fixture.mapping]); await client.query('INSERT INTO control_plane.membership_access_source_targets(source_id,mapping_id,chunk_no) VALUES($1,$2,0)', [source, fixture.mapping]); await client.query("UPDATE control_plane.membership_access_sources SET publication_state='publishing',chunk_count=1,cursor_digest=sha256(decode(encode((SELECT chunk_digest FROM control_plane.membership_access_source_chunks WHERE source_id=$1 AND chunk_no=0),'hex'),'hex')) WHERE id=$1", [source]); await client.query("UPDATE control_plane.membership_access_sources SET publication_state='published',finalized_at=clock_timestamp() WHERE id=$1", [source]); await client.query("INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason,source_id,mapping_id) VALUES($1,'membership_access_source_published','success','entitlement_expired',$2,$3)", [randomUUID(), source, fixture.mapping]); await client.query('COMMIT'); return source;
      } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
    };
    const first = await publish(); const applied = (await pool.query<{ operation_id: string; transition_revision: string }>('SELECT * FROM control_plane.enforce_published_source_target($1,$2)', [first, fixture.mapping])).rows[0]!;
    const replayBefore = await pool.query<{ requests: number; audits: number }>("SELECT (SELECT count(*)::int FROM control_plane.membership_access_requests) requests,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE event_type='membership_access_local_enforced') audits");
    expect((await pool.query('SELECT * FROM control_plane.enforce_published_source_target($1,$2)', [first, fixture.mapping])).rows[0]).toEqual(applied);
    expect(await pool.query("SELECT (SELECT count(*)::int FROM control_plane.membership_access_requests) requests,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE event_type='membership_access_local_enforced') audits")).toEqual(replayBefore);
    const later = await publish(); expect((await pool.query('SELECT * FROM control_plane.enforce_published_source_target($1,$2)', [later, fixture.mapping])).rows[0]).toEqual(applied);
    expect((await pool.query<{ link_kind: string }>('SELECT link_kind FROM control_plane.membership_access_request_operation_links l JOIN control_plane.membership_access_requests r ON r.id=l.request_id WHERE r.source_id=$1', [later])).rows[0]!.link_kind).toBe('reconciliation');
    const terminal = await pool.connect(); try { await terminal.query('BEGIN'); const steps = (await terminal.query<{ id: string }>('SELECT id FROM control_plane.membership_access_steps WHERE operation_id=$1', [applied.operation_id])).rows; for (const step of steps) { await terminal.query("UPDATE control_plane.membership_access_steps SET state='succeeded',confirmed_at=clock_timestamp(),evidence_fingerprint=$2 WHERE id=$1", [step.id, randomBytes(32)]); await terminal.query("INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason,step_id,mapping_id) VALUES($1,'membership_access_step_succeeded','success','completed',$2,$3)", [randomUUID(), step.id, fixture.mapping]); } await terminal.query("UPDATE control_plane.membership_access_operations SET state='completed',blocked_code=NULL,completed_at=clock_timestamp() WHERE id=$1", [applied.operation_id]); await terminal.query("INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason,operation_id,mapping_id) VALUES($1,'membership_access_operation_terminal','success','completed',$2,$3)", [randomUUID(), applied.operation_id, fixture.mapping]); await terminal.query('COMMIT'); } catch (error) { await terminal.query('ROLLBACK').catch(() => undefined); throw error; } finally { terminal.release(); }
    const next = await publish(); expect((await pool.query<{ transition_revision: string }>('SELECT * FROM control_plane.enforce_published_source_target($1,$2)', [next, fixture.mapping])).rows[0]!.transition_revision).toBe('2');
  });
  it.each([
    ['entitlement_expiry', 'entitlement_expired', 'mapping'],
    ['signed_policy_revocation', 'policy_revoked', 'policy'],
    ['authenticated_issuer_revocation', 'issuer_revoked', 'issuer'],
    ['authenticated_key_compromise', 'issuer_key_compromise', 'issuer_key'],
    ['authenticated_lost_device', 'lost_device', 'mapping'],
  ] as const)('enforces published-source lifecycle: %s / %s', async (sourceKind, reason, selectorKind) => {
    const runtimePool = new Pool({ connectionString: `postgresql://${runtime}:runtime-test-only@127.0.0.1:${postgresPort}/test_control_plane` });
    const subjectKeys = { active: 'subject1', keys: { subject1: fixtureSubjectKey } }; const envelopeKeys = { active: 'env1', keys: { env1: envelopeKey } }; const bindingKeys = { active: 'bind1', keys: { bind1: randomBytes(32) } };
    const sessions = createSessionRepository({ pool: runtimePool, pwaOrigin: 'https://lifecycle.example', sector: 'https://lifecycle-sector.example', subjectKeys, envelopeKeys, bindingKeys });
    const opaqueSession = randomBytes(32).toString('base64url'); const now = (await pool.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now;
    try {
      const established = await sessions.establishFromHandoff({ did: fixtureDid(), audience: 'https://lifecycle.example', authenticatedAt: now.toISOString(), expiresIn: 60 }, opaqueSession);
      expect(await sessions.authenticate(opaqueSession, 'https://lifecycle.example')).toMatchObject({ mappingId: established.mappingId, sessionId: opaqueSession });
      const controlSession = (await pool.query<{ binding_key_id: string; binding_fingerprint: Buffer }>('SELECT binding_key_id,binding_fingerprint FROM control_plane.identity_sessions WHERE mapping_id=$1', [established.mappingId])).rows[0]!;
      const policy = randomUUID(); const policyEnvelope = randomUUID(); await envelope(policyEnvelope, 'policy', envelopeKey, 'lifecycle-v1', policy);
      await pool.query("INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) VALUES($1,$2,$3,'lifecycle-v1',clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp())", [policy, randomBytes(32), policyEnvelope]);
      const entitlement = randomUUID(); const selector = randomBytes(32); const source = randomUUID(); const sourceMapping = sourceKind === 'entitlement_expiry' || sourceKind === 'authenticated_lost_device' ? established.mappingId : null;
      await insertEntitlement("WITH t AS (SELECT clock_timestamp() AS now) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,'lifecycle-v1',now,now+interval '15 minutes','membership_verified','AAAAAAAAAAAAAAAAAAAAAA',$5,$6,1 FROM t", [entitlement, established.mappingId, randomBytes(32), policy, controlSession.binding_key_id, controlSession.binding_fingerprint], [entitlement], pool, { [selectorKind]: selector });
      const authorizationContext = randomUUID(); const grantArtifact = randomUUID(); const unrelatedArtifact = randomUUID(); const grant = randomBytes(32);
      await pool.query("WITH t AS (SELECT clock_timestamp() AS now) INSERT INTO oidc.authorization_contexts(id,epoch,client_key_id,client_fingerprint,grant_key_id,grant_fingerprint,interaction_chain_key_id,interaction_chain_fingerprint,interaction_uid_key_id,interaction_uid_fingerprint,control_session_key_id,control_session_fingerprint,mapping_id,entitlement_id,generation,jkt,policy_snapshot_id,policy_version,created_at,expires_at,grant_expires_at,retained_until) SELECT $1,'AAAAAAAAAAAAAAAAAAAAAA','idx',$4,'idx',$5,'idx',$6,'idx',$7,$8,$9,$2,$3,1,$10,$11,'lifecycle-v1',now,now+interval '300 seconds',now+interval '900 seconds',now+interval '930 seconds' FROM t", [authorizationContext, established.mappingId, entitlement, randomBytes(32), grant, randomBytes(32), randomBytes(32), controlSession.binding_key_id, controlSession.binding_fingerprint, randomBytes(32).toString('base64url'), policy]);
      await pool.query("WITH t AS (SELECT clock_timestamp() AS now) INSERT INTO oidc.provider_artifacts(id,epoch,model,artifact_key_id,artifact_fingerprint,grant_key_id,grant_fingerprint,cipher_key_id,nonce,ciphertext,created_at,expires_at,retained_until) SELECT $1::uuid,'AAAAAAAAAAAAAAAAAAAAAA','Grant','idx',$3::bytea,'idx',$4::bytea,'aes',$5::bytea,$6::bytea,now,now+interval '900 seconds',now+interval '930 seconds' FROM t UNION ALL SELECT $2::uuid,'AAAAAAAAAAAAAAAAAAAAAA','Grant','idx',$7::bytea,'idx',$8::bytea,'aes',$9::bytea,$10::bytea,now,now+interval '900 seconds',now+interval '930 seconds' FROM t", [grantArtifact, unrelatedArtifact, randomBytes(32), grant, randomBytes(12), randomBytes(16), randomBytes(32), randomBytes(32), randomBytes(12), randomBytes(16)]);
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('INSERT INTO control_plane.membership_access_sources(id,source_kind,reason,producer_id,source_event_id,source_event_digest,requested_at,source_effective_at,mapping_id) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp(),clock_timestamp()-interval \'1 second\',$7)', [source, sourceKind, reason, 'owner-seeded-evidence', randomUUID(), randomBytes(32), sourceMapping]);
        await client.query('INSERT INTO control_plane.membership_access_source_selector_aliases(source_id,selector_kind,fingerprint_key_id,fingerprint) VALUES($1,$2,$3,$4)', [source, selectorKind, 'v1', selector]);
        await client.query('INSERT INTO control_plane.membership_access_source_cause_aliases(source_id,fingerprint_key_id,fingerprint) VALUES($1,$2,$3)', [source, 'v1', randomBytes(32)]);
        await client.query('COMMIT');
        await client.query('BEGIN');
        const digest = createHash('sha256').update(established.mappingId).digest();
        await client.query('INSERT INTO control_plane.membership_access_source_chunks(source_id,chunk_no,target_count,chunk_digest,published_at) VALUES($1,0,1,$2,clock_timestamp())', [source, digest]);
        await client.query('INSERT INTO control_plane.membership_access_source_targets(source_id,mapping_id,chunk_no) VALUES($1,$2,0)', [source, established.mappingId]);
        await client.query("UPDATE control_plane.membership_access_sources SET publication_state='publishing',chunk_count=1,cursor_digest=sha256($2) WHERE id=$1", [source, digest]);
        await client.query("UPDATE control_plane.membership_access_sources SET publication_state='published',finalized_at=clock_timestamp() WHERE id=$1", [source]);
        await client.query("INSERT INTO control_plane.security_audit_events(id,event_type,mapping_id,outcome,reason,occurred_at,source_id) VALUES($1,'membership_access_source_published',$2,'success',$3,clock_timestamp(),$4)", [randomUUID(), sourceMapping, reason, source]);
        await client.query('COMMIT');
      } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
      const applied = (await pool.query<{ operation_id: string; transition_revision: string }>('SELECT * FROM control_plane.enforce_published_source_target($1,$2)', [source, established.mappingId])).rows[0]!;
      expect(applied.transition_revision).toBe('1');
      expect(await sessions.authenticate(opaqueSession, 'https://lifecycle.example')).toBeUndefined();
      expect((await pool.query<{ barrier_state: string; current_operation_id: string }>('SELECT barrier_state,current_operation_id FROM control_plane.membership_access_states WHERE mapping_id=$1', [established.mappingId])).rows[0]).toEqual({ barrier_state: 'suspended', current_operation_id: applied.operation_id });
      expect((await pool.query<{ status: string; reason: string }>('SELECT status,reason FROM control_plane.entitlements WHERE id=$1', [entitlement])).rows[0]).toEqual({ status: 'revoked', reason: 'revoked' });
      expect((await pool.query<{ revoked: boolean }>('SELECT revoked_at IS NOT NULL AS revoked FROM control_plane.identity_sessions WHERE mapping_id=$1', [established.mappingId])).rows[0]!.revoked).toBe(true);
      expect((await pool.query<{ context: boolean; artifact: boolean; unrelated: boolean }>('SELECT (SELECT revoked_at IS NOT NULL FROM oidc.authorization_contexts WHERE id=$1) context,(SELECT revoked_at IS NOT NULL FROM oidc.provider_artifacts WHERE id=$2) artifact,(SELECT revoked_at IS NOT NULL FROM oidc.provider_artifacts WHERE id=$3) unrelated', [authorizationContext, grantArtifact, unrelatedArtifact])).rows[0]).toEqual({ context: true, artifact: true, unrelated: false });
      expect((await pool.query<{ event_type: string; outcome: string; reason: string }>("SELECT event_type,outcome,reason FROM control_plane.security_audit_events WHERE source_id=$1 AND event_type='membership_access_local_enforced'", [source])).rows).toEqual([{ event_type: 'membership_access_local_enforced', outcome: 'success', reason }]);
      expect((await pool.query<{ state: string; blocked_code: string }>('SELECT state,blocked_code FROM control_plane.membership_access_operations WHERE id=$1', [applied.operation_id])).rows[0]).toEqual({ state: 'blocked', blocked_code: 'missing_external_prerequisites' });
      expect((await pool.query<{ step_kind: string; error_code: string }>('SELECT step_kind,error_code FROM control_plane.membership_access_steps WHERE operation_id=$1 ORDER BY step_kind', [applied.operation_id])).rows).toEqual([{ step_kind: 'crypto_prerequisite', error_code: 'missing_crypto_enforcement' }, { step_kind: 'mas_prerequisite', error_code: 'missing_mas_binding' }, { step_kind: 'registry_prerequisite', error_code: 'missing_managed_room_registry' }]);
      expect((await pool.query<{ completed: number; external: number }>("SELECT count(*) FILTER(WHERE state='completed')::int completed,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE operation_id=$1 AND event_type IN ('membership_access_operation_terminal','membership_access_step_succeeded'))::int external FROM control_plane.membership_access_operations WHERE id=$1", [applied.operation_id])).rows[0]).toEqual({ completed: 0, external: 0 });
      await pool.query('DELETE FROM oidc.authorization_contexts WHERE id=$1', [authorizationContext]);
      await pool.query('DELETE FROM oidc.provider_artifacts WHERE id=ANY($1)', [[grantArtifact, unrelatedArtifact]]);
    } finally { await runtimePool.end(); }
  });
  type WorkerClaim = { disposition: string; claim_attempt_id: string; step_id: string; lease_generation: string; lease_token: Buffer };
  const claim = async (owner: string, kinds: string[]): Promise<WorkerClaim | undefined> => (await pool.query<WorkerClaim>('SELECT * FROM control_plane.claim_membership_access_step($1,$2)', [owner, kinds])).rows[0];
  const result = async (c: WorkerClaim, owner: string, outcome: 'succeeded' | 'retryable' | 'permanent', code: string | null = null): Promise<boolean> => (await pool.query<{ accepted: boolean }>('SELECT control_plane.record_membership_access_step_result($1,$2,$3,$4,$5,$6,$7,$8) accepted', [c.claim_attempt_id, c.step_id, c.lease_generation, c.lease_token, owner, outcome, code, outcome === 'succeeded' ? randomBytes(32) : null])).rows[0]!.accepted;
  const masKinds = ['mas_lock', 'mas_finish_sessions'];
  const clearWorkerQueue = async (): Promise<void> => { await pool.query("UPDATE control_plane.membership_access_steps SET state='blocked',next_attempt_at=NULL,lease_token=NULL,lease_owner=NULL,lease_expires_at=NULL,error_code='test_cleanup',confirmed_at=NULL,evidence_fingerprint=NULL WHERE state IN ('pending','retry_wait','leased')"); };

  it('limits claimants to claim/result execution and fences concurrent claims', async () => {
    await clearWorkerQueue();
    const { steps } = await workerFixture();
    await expect(queryAsRole(revocation, 'SELECT * FROM control_plane.membership_access_steps')).rejects.toThrow();
    await expect(queryAsRole(revocation, 'SELECT * FROM control_plane.membership_access_step_attempts')).rejects.toThrow();
    await expect(asRole(revocation, "UPDATE control_plane.membership_access_steps SET state='blocked' WHERE id=$1", [steps.mas_lock])).rejects.toThrow();
    await expect(asRole(revocation, "UPDATE control_plane.membership_access_step_attempts SET outcome='blocked' WHERE step_id=$1", [steps.mas_lock])).rejects.toThrow();
    await expect(asRole(revocation, 'SELECT control_plane.retry_membership_access_step($1,$2,$3)', [steps.mas_lock, randomUUID(), 1])).rejects.toThrow();
    await expect(asRole(revocation, 'SELECT * FROM control_plane.claim_membership_access_step($1,$2)', [null, masKinds])).rejects.toThrow('invalid worker capability');
    await expect(asRole(revocation, 'SELECT control_plane.record_membership_access_step_result($1,$2,$3,$4,$5,$6,$7,$8)', [randomUUID(), randomUUID(), 1, randomBytes(32), 'worker_a', 'succeeded', null, randomBytes(32)])).resolves.toBeUndefined();
    const [left, right] = await Promise.all([claim('worker_a', masKinds), claim('worker_b', masKinds)]);
    expect([left, right].filter(Boolean)).toHaveLength(1);
    expect((left ?? right)!.step_id).toBe(steps.mas_lock);
  });

  it('skips a locked candidate without waiting and claims it after the lock is released', async () => {
    await clearWorkerQueue();
    const { steps } = await workerFixture(); const holder = await pool.connect();
    try {
      await holder.query('BEGIN'); await holder.query('SELECT id FROM control_plane.membership_access_steps WHERE id=$1 FOR UPDATE', [steps.mas_lock]);
      const started = Date.now(); expect(await claim('worker_skip', masKinds)).toBeUndefined(); expect(Date.now() - started).toBeLessThan(1_000);
      await holder.query('ROLLBACK'); expect((await claim('worker_skip', masKinds))!.step_id).toBe(steps.mas_lock);
    } finally { await holder.query('ROLLBACK').catch(() => undefined); holder.release(); }
  });

  it('uses the final post-maintenance-lock clock for a claim lease', async () => {
    await clearWorkerQueue(); await workerFixture(); const holder = await pool.connect();
    try {
      await holder.query('BEGIN'); await holder.query('SELECT pg_advisory_xact_lock($1)', [8_004]);
      const pending = claim('worker_clock', masKinds); await awaitBlockedQuery('claim_membership_access_step');
      const released = (await pool.query<{ now: Date }>('SELECT clock_timestamp() now')).rows[0]!.now; await holder.query('COMMIT');
      const c = (await pending)!;
      const row = (await pool.query<{ claimed_at: Date; lease_expires_at: Date }>('SELECT claimed_at,lease_expires_at FROM control_plane.membership_access_step_attempts WHERE id=$1', [c.claim_attempt_id])).rows[0]!;
      expect(row.claimed_at.getTime()).toBeGreaterThanOrEqual(released.getTime()); expect(row.lease_expires_at.getTime() - row.claimed_at.getTime()).toBe(30_000);
    } finally { await holder.query('ROLLBACK').catch(() => undefined); holder.release(); }
  });

  it('rejects a result whose lease expires while its step lock is held', async () => {
    await clearWorkerQueue(); await workerFixture(); const c = (await claim('worker_late', masKinds))!; const holder = await pool.connect();
    try {
      await holder.query('BEGIN'); await holder.query("UPDATE control_plane.membership_access_steps SET lease_expires_at=clock_timestamp()+interval '100 milliseconds' WHERE id=$1", [c.step_id]);
      const pending = result(c, 'worker_late', 'succeeded'); await awaitBlockedQuery('record_membership_access_step_result');
      while (!(await holder.query<{ expired: boolean }>('SELECT clock_timestamp()>=lease_expires_at AS expired FROM control_plane.membership_access_steps WHERE id=$1', [c.step_id])).rows[0]!.expired) await new Promise<void>(resolve => setImmediate(resolve));
      await holder.query('COMMIT');
      expect(await pending).toBe(false);
      expect((await pool.query<{ state: string }>('SELECT state FROM control_plane.membership_access_steps WHERE id=$1', [c.step_id])).rows[0]!.state).toBe('leased');
    } finally { await holder.query('ROLLBACK').catch(() => undefined); holder.release(); }
  });

  it('enforces MAS and room-ban dependency ordering and blocked-prerequisite precedence', async () => {
    await clearWorkerQueue();
    const blocked = await workerFixture();
    // A real prerequisite blocks the aggregate but must not starve executable MAS work.
    const precedence = await pool.connect();
    try {
      await precedence.query('BEGIN');
      await precedence.query("UPDATE control_plane.membership_access_steps SET step_kind='crypto_prerequisite',state='blocked',error_code='missing_crypto_enforcement' WHERE id=$1", [blocked.steps.crypto_gate]);
      await precedence.query('SELECT control_plane.recompute_membership_access_operation($1)', [blocked.operation]);
      expect((await precedence.query<{ blocked_code: string }>('SELECT blocked_code FROM control_plane.membership_access_operations WHERE id=$1', [blocked.operation])).rows[0]!.blocked_code).toBe('missing_external_prerequisites');
      const available = (await precedence.query<WorkerClaim>('SELECT * FROM control_plane.claim_membership_access_step($1,$2)', ['worker_c', masKinds])).rows[0]!;
      expect(available).toMatchObject({ step_id: blocked.steps.mas_lock, operation_id: blocked.operation });
    } finally { await precedence.query('ROLLBACK').catch(() => undefined); precedence.release(); }
    await clearWorkerQueue();
    const ordered = await workerFixture(1);
    expect(await claim('worker_d', ['crypto_gate'])).toBeUndefined();
    const lock = (await claim('worker_d', masKinds))!; expect(await result(lock, 'worker_d', 'succeeded')).toBe(true);
    const finish = (await claim('worker_d', masKinds))!; expect(finish.step_id).toBe(ordered.steps.mas_finish_sessions);
    expect(await claim('worker_d', ['crypto_gate'])).toBeUndefined();
    const ban = (await claim('worker_d', ['room_ban']))!; expect(await result(ban, 'worker_d', 'succeeded')).toBe(true);
    expect((await claim('worker_d', ['crypto_gate']))!.step_id).toBe(ordered.steps.crypto_gate);
  });

  it('uses database backoff and rejects stale tokens, generations, owners, and late results', async () => {
    await clearWorkerQueue();
    const { steps } = await workerFixture(); const first = (await claim('worker_e', masKinds))!;
    expect(await result(first, 'worker_e', 'retryable', 'transient_failure')).toBe(true);
    const wait = (await pool.query<{ seconds: number }>("SELECT extract(epoch FROM next_attempt_at-created_at)::int seconds FROM control_plane.membership_access_steps s JOIN control_plane.membership_access_step_attempts a ON a.id=(SELECT id FROM control_plane.membership_access_step_attempts WHERE step_id=s.id AND event_kind='result' ORDER BY created_at DESC,id DESC LIMIT 1) WHERE s.id=$1", [steps.mas_lock])).rows[0]!.seconds;
    expect(wait).toBe(1);
    await pool.query("UPDATE control_plane.membership_access_steps SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE id=$1", [steps.mas_lock]);
    const second = (await claim('worker_e', masKinds))!;
    expect(second.lease_generation).toBe('2'); expect(second.lease_token.equals(first.lease_token)).toBe(false);
    expect(await result(first, 'worker_e', 'succeeded')).toBe(false);
    const beforeWrongToken = (await pool.query<{ step: string; attempts: number }>("SELECT to_jsonb(s)::text step,(SELECT count(*)::int FROM control_plane.membership_access_step_attempts WHERE step_id=s.id) attempts FROM control_plane.membership_access_steps s WHERE id=$1", [steps.mas_lock])).rows[0]!;
    const wrongToken = Buffer.alloc(32, second.lease_token[0] === 0 ? 1 : 0);
    expect(await result({ ...second, lease_token: wrongToken }, 'worker_e', 'succeeded')).toBe(false);
    expect((await pool.query<{ step: string; attempts: number }>("SELECT to_jsonb(s)::text step,(SELECT count(*)::int FROM control_plane.membership_access_step_attempts WHERE step_id=s.id) attempts FROM control_plane.membership_access_steps s WHERE id=$1", [steps.mas_lock])).rows[0]).toEqual(beforeWrongToken);
    expect(await result({ ...second, claim_attempt_id: randomUUID() }, 'worker_e', 'succeeded')).toBe(false);
    expect(await result(second, 'worker_f', 'succeeded')).toBe(false);
    await pool.query("UPDATE control_plane.membership_access_steps SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", [steps.mas_lock]);
    expect(await result(second, 'worker_e', 'succeeded')).toBe(false);
    const third = (await claim('worker_e', masKinds))!; expect(third.lease_generation).toBe('3'); expect(await result(third, 'worker_e', 'succeeded')).toBe(true);
    expect((await pool.query<{ claims: number; results: number }>("SELECT count(*) FILTER(WHERE event_kind='claim')::int claims,count(*) FILTER(WHERE event_kind='result')::int results FROM control_plane.membership_access_step_attempts WHERE step_id=$1", [steps.mas_lock])).rows[0]).toEqual({ claims: 3, results: 2 });
  });

  it('executes a real claimant store claim and result with pg bigint, bytea, and text values', async () => {
    await clearWorkerQueue();
    await workerFixture();
    const store = createPostgresClaimantStore(pool);
    const worker = createRevocationWorker(store, { kinds: ['mas_lock', 'mas_finish_sessions'] as const, execute: async () => ({ status: 'succeeded' as const, evidenceFingerprint: randomBytes(32) }) });
    expect(await worker.runOnce('worker_store')).toBe('succeeded');
  });

  it('blocks automatic and expired eighth attempts without a ninth claim', async () => {
    await clearWorkerQueue();
    for (const expired of [false, true]) {
      const { steps } = await workerFixture(); let last!: WorkerClaim;
      for (let attempt = 1; attempt <= 8; attempt += 1) { last = (await claim('worker_g', masKinds))!; if (attempt < 8) { expect(await result(last, 'worker_g', 'retryable', 'temporary')).toBe(true); await pool.query("UPDATE control_plane.membership_access_steps SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE id=$1", [steps.mas_lock]); } }
      if (expired) { await pool.query("UPDATE control_plane.membership_access_steps SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", [steps.mas_lock]); expect((await claim('worker_g', masKinds))!.disposition).toBe('exhausted'); } else expect(await result(last, 'worker_g', 'retryable', 'temporary')).toBe(true);
      expect((await pool.query<{ state: string; attempt_count: number; error_code: string; claims: number; blocked: number }>("SELECT s.state,s.attempt_count,s.error_code,(SELECT count(*)::int FROM control_plane.membership_access_step_attempts WHERE step_id=s.id AND event_kind='claim') claims,(SELECT count(*)::int FROM control_plane.membership_access_step_attempts WHERE step_id=s.id AND event_kind='result' AND outcome='blocked') blocked FROM control_plane.membership_access_steps s WHERE id=$1", [steps.mas_lock])).rows[0]).toEqual({ state: 'blocked', attempt_count: 8, error_code: 'retry_exhausted', claims: 8, blocked: 1 });
    }
  });

  it('accepts only the latest exact blocked result for an operator retry', async () => {
    await clearWorkerQueue();
    const { steps } = await workerFixture(); const first = (await claim('worker_h', masKinds))!; expect(await result(first, 'worker_h', 'permanent', 'failed')).toBe(true);
    const old = (await pool.query<{ id: string }>("SELECT id FROM control_plane.membership_access_step_attempts WHERE step_id=$1 AND event_kind='result'", [steps.mas_lock])).rows[0]!;
    expect((await pool.query<{ ok: boolean }>('SELECT control_plane.retry_membership_access_step($1,$2,$3) ok', [steps.mas_lock, old.id, first.lease_generation])).rows[0]!.ok).toBe(true);
    const second = (await claim('worker_h', masKinds))!; expect(await result(second, 'worker_h', 'permanent', 'failed_again')).toBe(true);
    expect((await pool.query<{ ok: boolean }>('SELECT control_plane.retry_membership_access_step($1,$2,$3) ok', [steps.mas_lock, old.id, first.lease_generation])).rows[0]!.ok).toBe(false);
    const latest = (await pool.query<{ id: string }>("SELECT id FROM control_plane.membership_access_step_attempts WHERE step_id=$1 AND event_kind='result' ORDER BY created_at DESC,id DESC LIMIT 1", [steps.mas_lock])).rows[0]!;
    expect((await pool.query<{ ok: boolean }>('SELECT control_plane.retry_membership_access_step($1,$2,$3) ok', [steps.mas_lock, latest.id, second.lease_generation])).rows[0]!.ok).toBe(true);
    expect((await pool.query<{ state: string; attempt_count: number; lease_token: Buffer | null; lease_owner: string | null; error_code: string | null }>('SELECT state,attempt_count,lease_token,lease_owner,error_code FROM control_plane.membership_access_steps WHERE id=$1', [steps.mas_lock])).rows[0]).toEqual({ state: 'retry_wait', attempt_count: 0, lease_token: null, lease_owner: null, error_code: null });
  });

  it('serializes final results on the operation row and writes one exact terminal audit', async () => {
    await clearWorkerQueue();
    const { operation } = await workerFixture(); const lock = (await claim('worker_i', masKinds))!; expect(await result(lock, 'worker_i', 'succeeded')).toBe(true); const finish = (await claim('worker_i', masKinds))!; const crypto = (await claim('worker_j', ['crypto_gate']))!;
    const holder = await pool.connect(); const left = await pool.connect(); const right = await pool.connect();
    try {
      await holder.query('BEGIN'); await holder.query('SELECT id FROM control_plane.membership_access_operations WHERE id=$1 FOR UPDATE', [operation]);
      await left.query('BEGIN'); await right.query('BEGIN');
      let leftDone = false; let rightDone = false;
      const submit = (client: PoolClient, c: WorkerClaim, owner: string): Promise<boolean> => client.query<{ accepted: boolean }>('SELECT control_plane.record_membership_access_step_result($1,$2,$3,$4,$5,$6,$7,$8) accepted', [c.claim_attempt_id, c.step_id, c.lease_generation, c.lease_token, owner, 'succeeded', null, randomBytes(32)]).then(async row => { await client.query('COMMIT'); return row.rows[0]!.accepted; });
      const leftResult = submit(left, finish, 'worker_i').then(value => { leftDone = true; return value; });
      const rightResult = submit(right, crypto, 'worker_j').then(value => { rightDone = true; return value; });
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline && !(await pool.query<{ count: number }>("SELECT count(*)::int count FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%record_membership_access_step_result%' ")).rows[0]!.count) await new Promise(resolve => setTimeout(resolve, 20));
      expect(leftDone || rightDone).toBe(false);
      expect((await pool.query<{ count: number }>("SELECT count(*)::int count FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%record_membership_access_step_result%' ")).rows[0]!.count).toBeGreaterThan(0);
      await holder.query('COMMIT');
      expect(await Promise.all([leftResult, rightResult])).toEqual([true, true]);
    } finally { await holder.query('ROLLBACK').catch(() => undefined); await left.query('ROLLBACK').catch(() => undefined); await right.query('ROLLBACK').catch(() => undefined); holder.release(); left.release(); right.release(); }
    const row = (await pool.query<{ state: string; step_audits: number; terminal_audits: number; exact_terminal: number }>("SELECT o.state,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE step_id IN (SELECT id FROM control_plane.membership_access_steps WHERE operation_id=o.id) AND event_type='membership_access_step_succeeded') step_audits,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE operation_id=o.id AND event_type='membership_access_operation_terminal') terminal_audits,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE operation_id=o.id AND event_type='membership_access_operation_terminal' AND occurred_at=o.completed_at) exact_terminal FROM control_plane.membership_access_operations o WHERE o.id=$1", [operation])).rows[0]!;
    expect(row).toEqual({ state: 'completed', step_audits: 3, terminal_audits: 1, exact_terminal: 1 });
  });
  it.each([
    ['control_plane.cleanup_expired(clock_timestamp()-interval \'90 days\')'],
    ['oidc.cleanup_expired(clock_timestamp())'],
  ])('structurally fences retention maintenance: %s', async (call) => {
    const holder = await pool.connect(); const worker = await pool.connect();
    try {
      await holder.query('BEGIN'); await holder.query('SELECT pg_advisory_xact_lock($1)', [8_004]);
      await worker.query(`SET ROLE ${retention}`); let complete = false;
      const pending = worker.query(`SELECT ${call}`).then(() => { complete = true; });
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const waiting = await pool.query<{ count: number }>("SELECT count(*)::int count FROM pg_locks WHERE locktype='advisory' AND objid=8004 AND NOT granted");
        if (waiting.rows[0]!.count) break;
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      expect(complete).toBe(false);
      expect((await pool.query<{ count: number }>("SELECT count(*)::int count FROM pg_locks WHERE locktype='advisory' AND objid=8004 AND NOT granted")).rows[0]!.count).toBeGreaterThan(0);
      await holder.query('COMMIT'); await pending; expect(complete).toBe(true);
    } finally { await worker.query('RESET ROLE').catch(() => undefined); worker.release(); await holder.query('ROLLBACK').catch(() => undefined); holder.release(); }
  });
  it('is checksum-idempotent, rejects catalog and ACL drift, and grants append-only access', async () => {
    await applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds); await applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds); await Promise.all([applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds), applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds)]);
    await expect(applyControlPlaneMigration(pool, runtime, retention, 'SELECT 1;', revocation, evidenceKeyIds)).rejects.toThrow('Immutable migration source changed');
    await pool.query('CREATE TABLE control_plane.unexpected_drift (id integer)');
    await expect(applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('Control-plane catalog drift');
    await pool.query('DROP TABLE control_plane.unexpected_drift');
    await pool.query('ALTER TABLE control_plane.login_states DROP CONSTRAINT login_states_lifecycle');
    await expect(applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('Control-plane catalog drift');
    await pool.query("ALTER TABLE control_plane.login_states ADD CONSTRAINT login_states_lifecycle CHECK(expires_at=created_at+interval '5 minutes' AND (consumed_at IS NULL OR consumed_at BETWEEN created_at AND expires_at))");
    await pool.query('DROP INDEX control_plane.login_states_expiry_idx');
    await expect(applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('Control-plane catalog drift');
    await pool.query('CREATE INDEX login_states_expiry_idx ON control_plane.login_states(expires_at)');
    await pool.query(`GRANT SELECT ON control_plane.security_audit_events TO ${runtime}`);
    const aclClient = await pool.connect();
    await expect(assertControlPlaneCatalog(aclClient, runtime, retention, revocation)).rejects.toThrow('Control-plane catalog drift');
    aclClient.release();
    await expect(applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('Control-plane catalog drift');
    await pool.query(`REVOKE SELECT ON control_plane.security_audit_events FROM ${runtime}`);
    await applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds);
    await pool.query(`GRANT EXECUTE ON FUNCTION control_plane.active_policy_guard() TO ${runtime}`);
    const client = await pool.connect();
    await expect(assertControlPlaneCatalog(client, runtime, retention, revocation)).rejects.toThrow('Control-plane catalog drift');
    client.release();
    await pool.query(`REVOKE EXECUTE ON FUNCTION control_plane.active_policy_guard() FROM ${runtime}`);
    await applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds);
    const runtimeClient = await pool.connect();
    try {
      await runtimeClient.query(`SET ROLE ${quoteRole(runtime)}`);
      await expect(assertCatalogManifest(runtimeClient, runtime, retention, LATEST_CONTROL_PLANE_CATALOG, revocation)).resolves.toBeUndefined();
      await expect(runtimeClient.query('SELECT * FROM control_plane.schema_migrations')).rejects.toThrow(/permission denied/i);
    } finally {
      await runtimeClient.query('RESET ROLE').catch(() => undefined);
      runtimeClient.release();
    }
    const acl = await pool.query<{ has_table_privilege: boolean }>("SELECT has_table_privilege($1,'control_plane.security_audit_events','DELETE')", [runtime]);
    expect(acl.rows[0].has_table_privilege).toBe(false);
  });
  it('serializes concurrent first application in a fresh database', async () => {
    const database = `cp_race_${suffix}`; await pool.query(`CREATE DATABASE ${database}`);
    const racePool = new Pool({ connectionString: `postgresql://postgres:test@127.0.0.1:${postgresPort}/${database}` });
    try {
      await Promise.all([applyControlPlaneMigration(racePool, runtime, retention, undefined, revocation, evidenceKeyIds), applyControlPlaneMigration(racePool, runtime, retention, undefined, revocation, evidenceKeyIds)]);
      expect((await racePool.query("SELECT count(*)::int AS count FROM control_plane.schema_migrations WHERE id='0002_identity_control_plane'")).rows[0].count).toBe(1);
      expect((await racePool.query("SELECT count(*)::int AS count FROM control_plane.schema_migrations WHERE id='0003_entitlement_session_binding'")).rows[0].count).toBe(1);
    } finally {
      await racePool.end(); await pool.query(`DROP DATABASE ${database}`);
    }
  });
  it('rejects an unconfigured evidence registry before it can create a control plane', async () => {
    const database = `cp_no_evidence_${suffix}`;
    await pool.query(`CREATE DATABASE ${database}`);
    const empty = new Pool({ connectionString: `postgresql://postgres:test@127.0.0.1:${postgresPort}/${database}` });
    try {
      await expect(applyControlPlaneMigration(empty, runtime, retention, undefined, revocation, [])).rejects.toThrow('Configured revocation evidence keys are required');
      expect((await empty.query("SELECT to_regnamespace('control_plane') IS NOT NULL AS exists")).rows[0]!.exists).toBe(false);
    } finally { await empty.end(); await pool.query(`DROP DATABASE ${database}`); }
  });
  it('rejects an entitlement commit that omits any configured evidence alias', async () => {
    const { mapping, policy, version } = await identityFixture();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("WITH t AS (SELECT clock_timestamp() AS authorized) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,$5,authorized,authorized+interval '15 minutes','membership_verified','AAAAAAAAAAAAAAAAAAAAAA','bind1',$6,1 FROM t", [randomUUID(), mapping, randomBytes(32), policy, version, randomBytes(32)]);
      await expect(client.query('COMMIT')).rejects.toThrow('entitlement requires every configured evidence alias');
    } finally { await client.query('ROLLBACK').catch(() => undefined); client.release(); }
  });
  it('replaces renewed entitlement aliases atomically while rejecting incomplete or mutable alias sets', async () => {
    const { mapping, policy, version } = await identityFixture(); const entitlement = randomUUID();
    const aliases = () => ['issuer', 'issuer_key', 'policy'].map(evidence_kind => ({ evidence_kind, fingerprint_key_id: 'v1', fingerprint: randomBytes(32).toString('hex') }));
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("WITH t AS (SELECT clock_timestamp() AS authorized) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,$5,authorized,authorized+interval '15 minutes','membership_verified','AAAAAAAAAAAAAAAAAAAAAA','bind1',$6,1 FROM t", [entitlement, mapping, randomBytes(32), policy, version, randomBytes(32)]);
      await client.query('SELECT control_plane.replace_entitlement_evidence_aliases($1,$2::jsonb)', [entitlement, JSON.stringify(aliases())]);
      await client.query('COMMIT');
      await expect(client.query("UPDATE control_plane.entitlement_evidence_aliases SET fingerprint=$2 WHERE entitlement_id=$1 AND evidence_kind='issuer'", [entitlement, randomBytes(32)])).rejects.toThrow('evidence alias identity is immutable');
      await client.query('BEGIN');
      await client.query('UPDATE control_plane.entitlements SET generation=generation+1 WHERE id=$1', [entitlement]);
      await client.query('SELECT control_plane.replace_entitlement_evidence_aliases($1,$2::jsonb)', [entitlement, JSON.stringify(aliases().slice(0, 2))]);
      await expect(client.query('COMMIT')).rejects.toThrow(/entitlement (requires every configured evidence alias|aliases must exactly match enabled evidence keys)/);
      await client.query('ROLLBACK');
      await client.query('BEGIN');
      await client.query('UPDATE control_plane.entitlements SET generation=generation+1 WHERE id=$1', [entitlement]);
      const renewed = aliases(); await client.query('SELECT control_plane.replace_entitlement_evidence_aliases($1,$2::jsonb)', [entitlement, JSON.stringify(renewed)]);
      await client.query('COMMIT');
      expect((await pool.query<{ valid: boolean; count: number }>('SELECT control_plane.revocation_aliases_valid($1,NULL) AS valid,(SELECT count(*)::int FROM control_plane.entitlement_evidence_aliases WHERE entitlement_id=$1) AS count', [entitlement])).rows[0]).toEqual({ valid: true, count: 3 });
    } finally { await client.query('ROLLBACK').catch(() => undefined); client.release(); }
  });
  it('upgrades a frozen pre-Task5 0002 ledger checksum without fabricating bindings', async () => {
    const database = `cp_legacy_expired_${suffix}`; const legacy = await legacyPool(database);
    try {
      const id = randomUUID();
      await legacy.query("WITH t AS (SELECT clock_timestamp()-interval '2 minutes' AS created) INSERT INTO control_plane.idempotency_results(id,request_key_id,request_fingerprint,response_status,result,error_code,created_at,expires_at) SELECT $1,'request1',$2,200,'authorized',NULL,created,created+interval '60 seconds' FROM t", [id, randomBytes(32)]);
      await legacy.query("INSERT INTO control_plane.idempotency_key_aliases(result_id,key_id,fingerprint) VALUES($1,'idem1',$2)", [id, randomBytes(32)]);
      await applyControlPlaneMigration(legacy, runtime, retention, undefined, revocation, evidenceKeyIds);
      const ledger = await legacy.query<{ id: string; checksum: Buffer }>('SELECT id,checksum FROM control_plane.schema_migrations ORDER BY id');
      expect(ledger.rows.map(row => row.id)).toEqual(['0002_identity_control_plane', '0003_entitlement_session_binding', '0004_mas_upstream_oidc', '0005_access_revocation_foundation', '0006_access_revocation_enforcement', '0007_access_revocation_source_set_guard', '0008_access_revocation_local_enforcement_fix', '0009_access_revocation_reconciliation_fix', '0010_access_revocation_worker']);
      expect(ledger.rows[0]!.checksum.toString('hex')).toBe(frozenPreTask5Migration0002Checksum);
      expect(ledger.rows[1]!.checksum.equals(createHash('sha256').update(await migration('0003_entitlement_session_binding')).digest())).toBe(true);
      expect(ledger.rows[2]!.checksum.equals(createHash('sha256').update(await migration('0004_mas_upstream_oidc')).digest())).toBe(true);
      expect(ledger.rows[3]!.checksum.equals(createHash('sha256').update(await migration('0005_access_revocation_foundation')).digest())).toBe(true);
      expect(ledger.rows[4]!.checksum.equals(createHash('sha256').update(await migration('0006_access_revocation_enforcement')).digest())).toBe(true);
      expect(ledger.rows[5]!.checksum.equals(createHash('sha256').update(await migration('0007_access_revocation_source_set_guard')).digest())).toBe(true);
      expect(ledger.rows[6]!.checksum.equals(createHash('sha256').update(await migration('0008_access_revocation_local_enforcement_fix')).digest())).toBe(true);
      expect(ledger.rows[7]!.checksum.equals(createHash('sha256').update(await migration('0009_access_revocation_reconciliation_fix')).digest())).toBe(true);
      expect(ledger.rows[8]!.checksum.equals(createHash('sha256').update(await migration('0010_access_revocation_worker')).digest())).toBe(true);
      expect((await legacy.query('SELECT count(*)::int AS count FROM control_plane.idempotency_results')).rows[0].count).toBe(0);
      expect((await legacy.query('SELECT count(*)::int AS count FROM control_plane.idempotency_key_aliases')).rows[0].count).toBe(0);
      const columns = await legacy.query<{ column_name: string; column_default: string | null; is_nullable: string }>("SELECT column_name,column_default,is_nullable FROM information_schema.columns WHERE table_schema='control_plane' AND table_name='idempotency_results' AND column_name IN ('binding_key_id','binding_fingerprint') ORDER BY column_name");
      expect(columns.rows).toEqual([{ column_name: 'binding_fingerprint', column_default: null, is_nullable: 'NO' }, { column_name: 'binding_key_id', column_default: null, is_nullable: 'NO' }]);
    } finally { await legacy.end(); await pool.query(`DROP DATABASE ${database}`); }
  });
  it('incrementally upgrades a checked-in 0009 catalog to 0010', async () => {
    const database = `cp_0009_incremental_${suffix}`; const legacy = await poolAt0009(database);
    try {
      const beforeClient = await legacy.connect(); try { await assertCatalogManifest(beforeClient, runtime, retention, '0009-post.json', revocation); } finally { beforeClient.release(); }
      const before = (await legacy.query<{ id: string }>('SELECT id FROM control_plane.schema_migrations ORDER BY id')).rows.map(row => row.id);
      expect(before).toEqual(['0002_identity_control_plane', '0003_entitlement_session_binding', '0004_mas_upstream_oidc', '0005_access_revocation_foundation', '0006_access_revocation_enforcement', '0007_access_revocation_source_set_guard', '0008_access_revocation_local_enforcement_fix', '0009_access_revocation_reconciliation_fix']);
      expect((await legacy.query<{ exists: boolean }>("SELECT to_regprocedure('control_plane.claim_membership_access_step(text,text[])') IS NOT NULL AS exists")).rows[0]!.exists).toBe(false);
      expect((await legacy.query<{ exists: boolean }>("SELECT to_regprocedure('control_plane.record_membership_access_step_result(uuid,uuid,bigint,bytea,text,text,text,bytea)') IS NOT NULL AS exists")).rows[0]!.exists).toBe(false);
      await applyControlPlaneMigration(legacy, runtime, retention, undefined, revocation, evidenceKeyIds);
      expect((await legacy.query<{ id: string }>('SELECT id FROM control_plane.schema_migrations ORDER BY id')).rows.map(row => row.id)).toEqual([...before, '0010_access_revocation_worker']);
      const client = await legacy.connect(); try { await assertCatalogManifest(client, runtime, retention, '0010-post.json', revocation); } finally { client.release(); }
      const privileges = (await legacy.query<{ schema: boolean; claim: boolean; result: boolean; table: boolean; retry: boolean }>("SELECT has_schema_privilege($1,'control_plane','USAGE') schema,has_function_privilege($1,'control_plane.claim_membership_access_step(text,text[])','EXECUTE') claim,has_function_privilege($1,'control_plane.record_membership_access_step_result(uuid,uuid,bigint,bytea,text,text,text,bytea)','EXECUTE') result,has_table_privilege($1,'control_plane.membership_access_steps','SELECT') table,has_function_privilege($1,'control_plane.retry_membership_access_step(uuid,uuid,bigint)','EXECUTE') retry", [revocation])).rows[0]!;
      expect(privileges).toEqual({ schema: true, claim: true, result: true, table: false, retry: false });
    } finally { await legacy.end(); await pool.query(`DROP DATABASE ${database}`); }
  });
  it('rejects live legacy idempotency rows and rolls the upgrade back', async () => {
    const database = `cp_legacy_live_${suffix}`; const legacy = await legacyPool(database);
    try {
      const id = randomUUID();
      await legacy.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.idempotency_results(id,request_key_id,request_fingerprint,response_status,result,error_code,created_at,expires_at) SELECT $1,'request1',$2,200,'authorized',NULL,created,created+interval '60 seconds' FROM t", [id, randomBytes(32)]);
      await expect(applyControlPlaneMigration(legacy, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('quiesce retries');
      expect((await legacy.query('SELECT count(*)::int AS count FROM control_plane.idempotency_results WHERE id=$1', [id])).rows[0].count).toBe(1);
      expect((await legacy.query("SELECT count(*)::int AS count FROM information_schema.columns WHERE table_schema='control_plane' AND table_name='idempotency_results' AND column_name='binding_key_id'")).rows[0].count).toBe(0);
      expect((await legacy.query("SELECT count(*)::int AS count FROM control_plane.schema_migrations WHERE id='0003_entitlement_session_binding'")).rows[0].count).toBe(0);
    } finally { await legacy.end(); await pool.query(`DROP DATABASE ${database}`); }
  });
  it('rolls back 0004 entirely when a frozen 0002+0003 database has a live entitlement', async () => {
    const database = `cp_0004_live_${suffix}`; const legacy = await legacyPool(database, true);
    try {
      const mapping = randomUUID(); const policy = randomUUID(); const mappingEnvelope = randomUUID(); const policyEnvelope = randomUUID(); const entitlement = randomUUID();
      await legacy.query("INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose) VALUES($1,'env1',$2,$3,'did'),($4,'env1',$5,$6,'policy')", [mappingEnvelope, randomBytes(12), bytes(1), policyEnvelope, randomBytes(12), bytes(2)]);
      await legacy.query("INSERT INTO control_plane.did_mappings(id,sector,subject_key_id,subject,envelope_id) VALUES($1,'https://chat.example','subject1',$2,$3)", [mapping, randomBytes(32).toString('base64url'), mappingEnvelope]);
      await legacy.query("INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) VALUES($1,$2,$3,'v1',clock_timestamp()-interval '2 seconds',clock_timestamp()-interval '1 second',clock_timestamp()+interval '1 hour',clock_timestamp())", [policy, randomBytes(32), policyEnvelope]);
      await legacy.query("WITH t AS (SELECT clock_timestamp() AS now) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason) SELECT $1,$2,$3,'chat','active',$4,'v1',now,now+interval '15 minutes','membership_verified' FROM t", [entitlement, mapping, randomBytes(32), policy]);
      await expect(applyControlPlaneMigration(legacy, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('cannot migrate live entitlements');
      expect((await legacy.query('SELECT count(*)::int AS count FROM control_plane.entitlements WHERE id=$1', [entitlement])).rows[0]!.count).toBe(1);
      expect((await legacy.query("SELECT count(*)::int AS count FROM control_plane.schema_migrations WHERE id='0004_mas_upstream_oidc'")).rows[0]!.count).toBe(0);
      expect((await legacy.query("SELECT count(*)::int AS count FROM information_schema.columns WHERE table_schema='control_plane' AND table_name='entitlements' AND column_name IN ('oidc_epoch','session_binding_key_id','session_binding_fingerprint','generation')")).rows[0]!.count).toBe(0);
      expect((await legacy.query("SELECT count(*)::int AS count FROM pg_constraint WHERE conrelid='control_plane.entitlements'::regclass AND conname='entitlements_mapping_jkt_kind_key'")).rows[0]!.count).toBe(1);
      expect((await legacy.query("SELECT count(*)::int AS count FROM pg_constraint WHERE conrelid='control_plane.entitlements'::regclass AND conname='entitlements_snapshot_fkey'")).rows[0]!.count).toBe(1);
    } finally { await legacy.end(); await pool.query(`DROP DATABASE ${database}`); }
  });
  it('deletes expired frozen-legacy entitlements and preserves the policy FK while applying 0004', async () => {
    const database = `cp_0004_expired_${suffix}`; const legacy = await legacyPool(database, true);
    try {
      const mapping = randomUUID(); const policy = randomUUID(); const mappingEnvelope = randomUUID(); const policyEnvelope = randomUUID();
      await legacy.query("INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose) VALUES($1,'env1',$2,$3,'did'),($4,'env1',$5,$6,'policy')", [mappingEnvelope, randomBytes(12), bytes(1), policyEnvelope, randomBytes(12), bytes(2)]);
      await legacy.query("INSERT INTO control_plane.did_mappings(id,sector,subject_key_id,subject,envelope_id) VALUES($1,'https://chat.example','subject1',$2,$3)", [mapping, randomBytes(32).toString('base64url'), mappingEnvelope]);
      await legacy.query("INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) VALUES($1,$2,$3,'v1',clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour',clock_timestamp())", [policy, randomBytes(32), policyEnvelope]);
      await legacy.query("WITH t AS (SELECT clock_timestamp()-interval '16 minutes' AS now) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason) SELECT $1,$2,$3,'chat','active',$4,'v1',now,now+interval '15 minutes','membership_verified' FROM t", [randomUUID(), mapping, randomBytes(32), policy]);
      await applyControlPlaneMigration(legacy, runtime, retention, undefined, revocation, evidenceKeyIds);
      expect((await legacy.query('SELECT count(*)::int AS count FROM control_plane.entitlements')).rows[0]!.count).toBe(0);
      expect((await legacy.query<{ checksum: Buffer }>("SELECT checksum FROM control_plane.schema_migrations WHERE id='0004_mas_upstream_oidc'")).rows[0]!.checksum.equals(createHash('sha256').update(await migration('0004_mas_upstream_oidc')).digest())).toBe(true);
      expect((await legacy.query("SELECT confrelid::regclass::text AS target FROM pg_constraint WHERE conrelid='control_plane.entitlements'::regclass AND conname='entitlements_snapshot_fkey'")).rows[0]!.target).toBe('control_plane.policy_snapshots');
      expect((await legacy.query("SELECT count(*)::int AS count FROM pg_constraint WHERE conrelid='control_plane.entitlements'::regclass AND conname='entitlements_mapping_jkt_kind_key'")).rows[0]!.count).toBe(0);
      expect((await legacy.query("SELECT count(*)::int AS count FROM pg_constraint WHERE conrelid='control_plane.entitlements'::regclass AND conname='entitlements_session_binding_entitlement_key'")).rows[0]!.count).toBe(1);
      expect((await legacy.query("SELECT count(*)::int AS count FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='control_plane.entitlements'::regclass AND i.indpred IS NOT NULL")).rows[0]!.count).toBe(0);
    } finally { await legacy.end(); await pool.query(`DROP DATABASE ${database}`); }
  });
  it('rejects frozen 0003 catalog drift before executing 0004', async () => {
    const database = `cp_0003_drift_${suffix}`; const legacy = await legacyPool(database, true);
    try {
      await legacy.query('ALTER TABLE control_plane.login_states ADD COLUMN unexpected text');
      await expect(applyControlPlaneMigration(legacy, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('Control-plane catalog drift');
      expect((await legacy.query("SELECT to_regnamespace('oidc') IS NOT NULL AS exists")).rows[0]!.exists).toBe(false);
      expect((await legacy.query("SELECT count(*)::int AS count FROM control_plane.schema_migrations WHERE id='0004_mas_upstream_oidc'")).rows[0]!.count).toBe(0);
    } finally { await legacy.end(); await pool.query(`DROP DATABASE ${database}`); }
  });
  it('allows refreshed snapshots with the same version and validates migration artifacts', async () => {
    const { version } = await identityFixture(); const second = randomUUID(); const envelopeId = randomUUID();
    await envelope(envelopeId, 'policy', envelopeKey, version, second);
    await pool.query("INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) VALUES($1,$2,$3,$4,clock_timestamp()-interval '2 seconds',clock_timestamp()-interval '1 second',clock_timestamp()+interval '1 hour',clock_timestamp())", [second, randomBytes(32), envelopeId, version]);
    await pool.query('INSERT INTO control_plane.active_policy(singleton,snapshot_id,activated_at) VALUES(true,$1,clock_timestamp())', [second]);
    expect((await pool.query('SELECT snapshot_id FROM control_plane.active_policy')).rows[0].snapshot_id).toBe(second);
    const source2 = await migration('0002_identity_control_plane'); const source3 = await migration('0003_entitlement_session_binding');
    expect((await pool.query<{ checksum: Buffer }>("SELECT checksum FROM control_plane.schema_migrations WHERE id='0002_identity_control_plane'")).rows[0].checksum.equals(createHash('sha256').update(source2).digest())).toBe(true);
    await pool.query("UPDATE control_plane.schema_migrations SET checksum=decode(repeat('00',32),'hex') WHERE id='0003_entitlement_session_binding'");
    await expect(applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('Migration checksum mismatch');
    await pool.query("UPDATE control_plane.schema_migrations SET checksum=$1 WHERE id='0003_entitlement_session_binding'", [createHash('sha256').update(source3).digest()]);
    await exec('node', ['scripts/copy-migration.mjs'], { cwd: fileURLToPath(new URL('../', import.meta.url)) });
    for (const name of ['0002_identity_control_plane', '0003_entitlement_session_binding', '0004_mas_upstream_oidc', '0005_access_revocation_foundation', '0006_access_revocation_enforcement', '0007_access_revocation_source_set_guard', '0008_access_revocation_local_enforcement_fix', '0009_access_revocation_reconciliation_fix', '0010_access_revocation_worker']) expect(await readFile(fileURLToPath(new URL(`../dist/migrations/${name}.sql`, import.meta.url)), 'utf8')).toBe(await migration(name));
    for (const name of ['0003-pre.json', '0004-post.json', '0005-post.json', '0006-post.json', '0007-post.json', '0008-post.json', '0009-post.json', '0010-post.json']) expect(await readFile(fileURLToPath(new URL(`../dist/migrations/catalog/${name}`, import.meta.url)), 'utf8')).toBe(await readFile(fileURLToPath(new URL(`../../migrations/catalog/${name}`, import.meta.url)), 'utf8'));
    await pool.query('DELETE FROM control_plane.active_policy');
  });
  it('accepts only canonical origins and requires policy freshness beyond activation', async () => {
    const origin255 = `https://${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(55)}`;
    const origin256 = `${origin255}d`;
    expect(Buffer.byteLength(origin255)).toBe(255); expect(Buffer.byteLength(origin256)).toBe(256);
    for (const value of ['https://chat.example1', 'https://chat.example:1', 'https://chat.example:65535', origin255]) {
      expect((await pool.query<{ ok: boolean }>('SELECT control_plane.is_canonical_origin($1) AS ok', [value])).rows[0].ok).toBe(true);
    }
    for (const value of ['https://foo.1', 'https://chat.example:443', 'https://chat.example:0', 'https://chat.example:0001', 'https://chat.example:65536', `https://chat.example:${'9'.repeat(100)}`, 'https://127.1', 'https://2130706433', 'https://0177.0.0.1', 'https://0x7f.1', 'https://0x7f000001', 'https://127.0x1', 'https://chat.example\n', 'https://chat.example\u2028', 'https://chat.example\u2029', origin256]) {
      expect((await pool.query<{ ok: boolean }>('SELECT control_plane.is_canonical_origin($1) AS ok', [value])).rows[0].ok).toBe(false);
    }
  });
  it('keeps a newer root-signed policy active when older or equal fresh refreshes replay', async () => {
    const [root, issuer] = await Promise.all([generateKeyPair('ES256'), generateKeyPair('ES256')]);
    const [rootJwk, issuerJwk] = await Promise.all([exportJWK(root.publicKey), exportJWK(issuer.publicKey)]);
    const rootDid = 'did:plc:dddddddddddddddddddddddd'; const issuerDid = 'did:plc:eeeeeeeeeeeeeeeeeeeeeeee'; const version = `anti-${suffix}`; const policyUri = `at://${rootDid}/us.dsaslate.temp.dsaPolicy/rollback`;
    const key = randomBytes(32); const roots = { [`${rootDid}#root`]: parsePublicJwk(rootJwk) };
    const compact = async (issuedAt: number): Promise<string> => new CompactSign(Buffer.from(JSON.stringify({ version: 'v1', policyVersion: version, policyUri, rootDid, issuedAt, freshUntil: issuedAt + 300, issuers: [{ did: issuerDid, policies: [{ version, state: 'active', transitionedAt: issuedAt }], keys: [{ kid: `${issuerDid}#key`, state: 'active', transitionedAt: issuedAt, publicJwk: parsePublicJwk(issuerJwk) }] }] }))).setProtectedHeader({ alg: 'ES256', typ: 'dsa-signal-issuer-policy+jws', kid: `${rootDid}#root` }).sign(root.privateKey);
    const clock = Math.floor((await pool.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now.getTime() / 1000);
    const foundation = new FoundationService({ resolveAuthority: async () => ({ uri: policyUri, provenance: { uri: policyUri, cid: 'bafy-rollback', repoDid: rootDid, repoRev: 'rollback', sequence: 0, observedAt: new Date(clock * 1000).toISOString(), status: 'verified' as const }, authority: { status: 'official' as const, policyUri, policyVersion: version, rootDid, evaluatedAt: new Date(clock * 1000).toISOString() } }) } as never);
    const refresh = new PolicyRefreshService(pool, foundation, roots, version, { active: { id: 'rollback', key }, keys: [{ id: 'rollback', key }] });
    const newer = await compact(clock - 1); const older = await compact(clock - 2);
    const active = await refresh.refresh(newer);
    const before = await pool.query<{ snapshots: number; envelopes: number; audits: number }>("SELECT (SELECT count(*)::int FROM control_plane.policy_snapshots WHERE version=$1) AS snapshots,(SELECT count(*)::int FROM control_plane.encrypted_envelopes WHERE envelope_key_id='rollback') AS envelopes,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE snapshot_id=$2) AS audits", [version, active]);
    for (const replay of [older, newer]) await expect(refresh.refresh(replay)).rejects.toThrow('policy unavailable');
    expect((await pool.query<{ snapshot_id: string }>('SELECT snapshot_id FROM control_plane.active_policy WHERE singleton')).rows[0]!.snapshot_id).toBe(active);
    expect(await pool.query("SELECT (SELECT count(*)::int FROM control_plane.policy_snapshots WHERE version=$1) AS snapshots,(SELECT count(*)::int FROM control_plane.encrypted_envelopes WHERE envelope_key_id='rollback') AS envelopes,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE snapshot_id=$2) AS audits", [version, active])).toEqual(before);
    const equal = randomUUID(); const equalEnvelope = randomUUID(); await envelope(equalEnvelope, 'policy', envelopeKey, `${version}-equal`, equal);
    await pool.query("INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) SELECT $1,$2,$3,$4,signed_at,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp() FROM control_plane.policy_snapshots WHERE id=$5", [equal, randomBytes(32), equalEnvelope, `${version}-equal`, active]);
    await expect(pool.query('UPDATE control_plane.active_policy SET snapshot_id=$1,activated_at=clock_timestamp() WHERE singleton', [equal])).rejects.toThrow('signed_at must increase');
    await pool.query('DELETE FROM control_plane.policy_snapshots WHERE id=$1', [equal]); await pool.query('DELETE FROM control_plane.encrypted_envelopes WHERE id=$1', [equalEnvelope]);
    await pool.query('DELETE FROM control_plane.active_policy WHERE snapshot_id=$1', [active]);
    await pool.query('DELETE FROM control_plane.security_audit_events WHERE snapshot_id=$1', [active]);
    await pool.query('DELETE FROM control_plane.policy_snapshots WHERE version=$1', [version]);
    await pool.query("DELETE FROM control_plane.encrypted_envelopes WHERE envelope_key_id='rollback'");
  });
  it('enforces runtime and retention effective privileges', async () => {
    await asRole(runtime, "INSERT INTO control_plane.encrypted_envelopes VALUES($1,'env1',decode(repeat('01',12),'hex'),decode(repeat('01',16),'hex'),'did',clock_timestamp())", [randomUUID()]);
    await asRole(runtime, "INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason) VALUES($1,'login_state_consumed','success','completed')", [randomUUID()]);
    expect((await pool.query<{ has_table_privilege: boolean }>("SELECT has_table_privilege($1,'control_plane.did_mappings','UPDATE')", [runtime])).rows[0]!.has_table_privilege).toBe(false);
    for (const sql of ['UPDATE control_plane.did_mappings SET erased_at=clock_timestamp()', 'SELECT * FROM control_plane.security_audit_events', 'UPDATE control_plane.security_audit_events SET reason=reason', 'DELETE FROM control_plane.security_audit_events', 'TRUNCATE control_plane.security_audit_events', 'DELETE FROM control_plane.encrypted_envelopes', 'SELECT * FROM control_plane.schema_migrations']) await expect(asRole(runtime, sql)).rejects.toThrow();
    for (const sql of ['SELECT * FROM control_plane.login_states', 'UPDATE control_plane.login_states SET consumed_at=clock_timestamp()', 'TRUNCATE control_plane.login_states']) await expect(asRole(retention, sql)).rejects.toThrow();
    for (const sql of ['SELECT * FROM control_plane.revocation_evidence_key_ids', 'INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason) VALUES(gen_random_uuid(),\'login_state_consumed\',\'success\',\'completed\')', 'SELECT control_plane.cleanup_expired(clock_timestamp()-interval \'90 days\')']) await expect(asRole(revocation, sql)).rejects.toThrow();
  });
  it('detects defaults, function bodies, and third-role grants as drift', async () => {
    const client = await pool.connect(); try {
      for (const mutation of [
        "ALTER TABLE control_plane.login_states ALTER COLUMN created_at SET DEFAULT now()",
        "CREATE OR REPLACE FUNCTION control_plane.is_canonical_origin(value text) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT true'",
        "CREATE OR REPLACE FUNCTION control_plane.active_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
        'CREATE MATERIALIZED VIEW control_plane.unexpected_materialized AS SELECT event_type FROM control_plane.security_audit_events',
        "CREATE TYPE control_plane.unexpected_status AS ENUM ('unexpected')",
        'ALTER TABLE control_plane.login_states ENABLE ROW LEVEL SECURITY',
        'ALTER TABLE control_plane.login_states SET UNLOGGED',
        'ALTER TABLE control_plane.active_policy DISABLE TRIGGER active_policy_activation',
        'ALTER FUNCTION control_plane.is_canonical_origin(text) CALLED ON NULL INPUT',
        'ALTER FUNCTION control_plane.is_canonical_origin(text) PARALLEL SAFE',
        `GRANT SELECT(event_type) ON control_plane.security_audit_events TO ${runtime}`,
        `GRANT SELECT ON control_plane.login_states TO ${runtime} WITH GRANT OPTION`,
      ]) {
        await client.query('BEGIN'); await client.query(mutation); await expect(assertControlPlaneCatalog(client, runtime, retention, revocation)).rejects.toThrow('catalog drift'); await client.query('ROLLBACK');
      }
    } finally { client.release(); }
    const third = `cp_other_${suffix}`; await pool.query(`CREATE ROLE ${third}; GRANT SELECT ON control_plane.login_states TO ${third}`); const grantClient = await pool.connect(); await expect(assertControlPlaneCatalog(grantClient, runtime, retention, revocation)).rejects.toThrow('catalog drift'); grantClient.release(); await pool.query(`REVOKE ALL ON control_plane.login_states FROM ${third}; DROP ROLE ${third}`);
    await pool.query('CREATE ROLE runtime; GRANT SELECT ON control_plane.login_states TO runtime'); const collisionClient = await pool.connect(); await expect(assertControlPlaneCatalog(collisionClient, runtime, retention, revocation)).rejects.toThrow('catalog drift'); collisionClient.release(); await pool.query('REVOKE ALL ON control_plane.login_states FROM runtime; DROP ROLE runtime');
  });
  it('detects every OIDC catalog and privilege class as drift before repair', async () => {
    const client = await pool.connect();
    try {
      for (const mutation of [
        'CREATE MATERIALIZED VIEW oidc.unexpected_materialized AS SELECT model FROM oidc.provider_artifacts',
        "CREATE TYPE oidc.unexpected_status AS ENUM ('unexpected')",
        'ALTER TABLE oidc.provider_artifacts ALTER COLUMN epoch TYPE character(23)',
        'ALTER TABLE oidc.provider_artifacts ALTER COLUMN created_at SET DEFAULT now()',
        'ALTER TABLE oidc.provider_artifacts DROP CONSTRAINT provider_artifacts_model_check',
        'DROP INDEX oidc.authorization_context_code; CREATE UNIQUE INDEX authorization_context_code ON oidc.authorization_contexts(epoch,authorization_code_key_id,authorization_code_fingerprint) WHERE authorization_code_fingerprint IS NOT NULL',
        'CREATE TRIGGER unexpected_trigger BEFORE UPDATE ON oidc.provider_artifacts FOR EACH ROW EXECUTE FUNCTION control_plane.audit_mutation_guard()',
        "CREATE OR REPLACE FUNCTION oidc.cleanup_expired(p_now timestamptz) RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,oidc AS 'SELECT 0::bigint'",
        'ALTER FUNCTION oidc.cleanup_expired(timestamptz) SECURITY INVOKER',
        'ALTER FUNCTION oidc.cleanup_expired(timestamptz) STRICT',
        'ALTER FUNCTION oidc.cleanup_expired(timestamptz) PARALLEL SAFE',
        'ALTER TABLE oidc.provider_artifacts ENABLE ROW LEVEL SECURITY',
        'CREATE POLICY unexpected_policy ON oidc.provider_artifacts USING (true)',
        'ALTER TABLE oidc.provider_artifacts SET UNLOGGED',
        `GRANT SELECT(ciphertext) ON oidc.provider_artifacts TO ${runtime}`,
        `GRANT SELECT ON oidc.provider_artifacts TO ${runtime} WITH GRANT OPTION`,
        `GRANT EXECUTE ON FUNCTION oidc.cleanup_expired(timestamptz) TO ${runtime}`,
        `ALTER DEFAULT PRIVILEGES IN SCHEMA oidc GRANT SELECT ON TABLES TO ${runtime}`,
      ]) {
        await client.query('BEGIN');
        await client.query(mutation);
        await expect(assertControlPlaneCatalog(client, runtime, retention, revocation)).rejects.toThrow('catalog drift');
        await client.query('ROLLBACK');
      }
      const third = `oidc_owner_${suffix}`;
      await pool.query(`CREATE ROLE ${third}`);
      await client.query('BEGIN'); await client.query(`ALTER SCHEMA oidc OWNER TO ${third}`); await expect(assertControlPlaneCatalog(client, runtime, retention, revocation)).rejects.toThrow('catalog drift'); await client.query('ROLLBACK');
      await pool.query(`GRANT SELECT ON oidc.provider_artifacts TO ${third}`); await expect(assertControlPlaneCatalog(client, runtime, retention, revocation)).rejects.toThrow('catalog drift'); await pool.query(`REVOKE ALL ON oidc.provider_artifacts FROM ${third}; DROP ROLE ${third}`);
    } finally { client.release(); }
  });
  it('rejects elevated role attributes and membership paths', async () => {
    await pool.query(`ALTER ROLE ${runtime} CREATEDB`); await expect(applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('role separation'); await pool.query(`ALTER ROLE ${runtime} NOCREATEDB`);
    const member = `cp_member_${suffix}`; await pool.query(`CREATE ROLE ${member}; GRANT ${runtime} TO ${member}`); await expect(applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds)).rejects.toThrow('role separation'); await pool.query(`REVOKE ${runtime} FROM ${member}; DROP ROLE ${member}`);
    await applyControlPlaneMigration(pool, runtime, retention, undefined, revocation, evidenceKeyIds);
  });
  it('enforces lifecycle, response, envelope, policy, and replay constraints', async () => {
    const { mapping, policy } = await identityFixture();
    const session = randomUUID();
    await expect(pool.query("WITH t AS (SELECT clock_timestamp()-interval '14 minutes' AS created) INSERT INTO control_plane.identity_sessions(id,binding_key_id,binding_fingerprint,mapping_id,origin,created_at,last_seen_at,idle_expires_at,absolute_expires_at) SELECT $1,'bind1',$2,$3,'https://chat.example',created,created+interval '13 minutes',created+interval '15 minutes',created+interval '15 minutes' FROM t", [session, bytes(2), mapping])).resolves.toBeDefined();
    await expect(pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.login_states(id,state_digest,binding_key_id,binding_fingerprint,return_origin,created_at,expires_at) SELECT $1,$2,'bind1',$3,'https://chat.example',created,created+interval '4 minutes' FROM t", [randomUUID(), randomBytes(32), bytes(3)])).rejects.toThrow();
    await expect(pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.proof_challenges(id,challenge_key_id,challenge_fingerprint,binding_key_id,binding_fingerprint,mapping_id,jkt,audience,origin,created_at,expires_at) SELECT $1,'challenge1',$2,'bind1',$3,$4,$5,'dsa-signal','https://chat.example',created,created+interval '121 seconds' FROM t", [randomUUID(), randomBytes(32), bytes(4), mapping, bytes(5)])).rejects.toThrow();
    const validResponses: ReadonlyArray<readonly [number, 'authorized' | 'rejected', string | null]> = [[200, 'authorized', null], [400, 'rejected', 'invalid_request'], [406, 'rejected', 'invalid_request'], [413, 'rejected', 'invalid_request'], [415, 'rejected', 'invalid_request'], [401, 'rejected', 'rejected'], [409, 'rejected', 'conflict'], [503, 'rejected', 'unavailable']];
    for (const [status, result, error] of validResponses) await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.idempotency_results(id,request_key_id,request_fingerprint,binding_key_id,binding_fingerprint,response_status,result,error_code,created_at,expires_at) SELECT $1,'request1',$2,'bind1',$3,$4,$5,$6,created,created+interval '60 seconds' FROM t", [randomUUID(), randomBytes(32), randomBytes(32), status, result, error]);
    await expect(pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.idempotency_results(id,request_key_id,request_fingerprint,response_status,result,error_code,created_at,expires_at) SELECT $1,'request1',$2,201,'authorized',NULL,created,created+interval '60 seconds' FROM t", [randomUUID(), randomBytes(32)])).rejects.toThrow();
    const firstResult = randomUUID(); const secondResult = randomUUID();
    for (const id of [firstResult, secondResult]) await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.idempotency_results(id,request_key_id,request_fingerprint,binding_key_id,binding_fingerprint,response_status,result,error_code,created_at,expires_at) SELECT $1,'request1',$2,'bind1',$3,200,'authorized',NULL,created,created+interval '60 seconds' FROM t", [id, randomBytes(32), randomBytes(32)]);
    const replay = randomBytes(32); await pool.query("INSERT INTO control_plane.idempotency_key_aliases(result_id,key_id,fingerprint) VALUES($1,'idem1',$2)", [firstResult, replay]);
    await expect(pool.query("INSERT INTO control_plane.idempotency_key_aliases(result_id,key_id,fingerprint) VALUES($1,'idem1',$2)", [secondResult, replay])).rejects.toThrow();
    const firstJti = randomUUID(); const secondJti = randomUUID();
    for (const id of [firstJti, secondJti]) await pool.query("WITH t AS (SELECT clock_timestamp() AS decision) INSERT INTO control_plane.jti_uses(id,policy_snapshot_id,credential_expires_at,retained_until,decision_clock,decision,created_at) SELECT $1,$2,decision+interval '10 minutes',decision+interval '10 minutes 30 seconds',decision,'authorized',decision FROM t", [id, policy]);
    const jtiReplay = randomBytes(32); await pool.query("INSERT INTO control_plane.jti_key_aliases(jti_use_id,key_id,fingerprint) VALUES($1,'jti1',$2)", [firstJti, jtiReplay]);
    await expect(pool.query("INSERT INTO control_plane.jti_key_aliases(jti_use_id,key_id,fingerprint) VALUES($1,'jti1',$2)", [secondJti, jtiReplay])).rejects.toThrow();
    const wrongEnvelope = randomUUID(); await envelope(wrongEnvelope, 'policy', envelopeKey, 'wrong-purpose');
    await expect(pool.query("INSERT INTO control_plane.did_mappings(id,sector,subject_key_id,subject,envelope_id) VALUES($1,'https://chat.example','subject1',$2,$1)", [wrongEnvelope, randomBytes(32).toString('base64url')])).rejects.toThrow('envelope purpose');
    const nonce = randomBytes(12); await pool.query("INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose) VALUES($1,'env1',$2,$3,'did')", [randomUUID(), nonce, bytes(6)]);
    await expect(pool.query("INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose) VALUES($1,'env1',$2,$3,'policy')", [randomUUID(), nonce, bytes(7)])).rejects.toThrow();
    const staleEnvelope = randomUUID(); const stalePolicy = randomUUID(); await envelope(staleEnvelope, 'policy', envelopeKey, 'stale', stalePolicy);
    await pool.query("INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) VALUES($1,$2,$3,'stale',clock_timestamp()-interval '3 minutes',clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute',clock_timestamp()-interval '2 minutes')", [stalePolicy, randomBytes(32), staleEnvelope]);
    await expect(pool.query('INSERT INTO control_plane.active_policy(singleton,snapshot_id,activated_at) VALUES(true,$1,clock_timestamp())', [stalePolicy])).rejects.toThrow('fresh');
    await pool.query('DELETE FROM control_plane.idempotency_results');
    await pool.query('DELETE FROM control_plane.jti_uses');
    await pool.query('DELETE FROM control_plane.identity_sessions WHERE id=$1', [session]);
  });
  it('allows only expiry-guarded cleanup through the retention function', async () => {
    const { mapping, policy, version } = await identityFixture();
    const liveState = randomUUID();
    await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.login_states(id,state_digest,binding_key_id,binding_fingerprint,return_origin,created_at,expires_at) SELECT $1,$2,'bind1',$3,'https://chat.example',created,created+interval '5 minutes' FROM t", [liveState, randomBytes(32), randomBytes(32)]);
    const liveSession = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.identity_sessions(id,binding_key_id,binding_fingerprint,mapping_id,origin,created_at,last_seen_at,idle_expires_at,absolute_expires_at) SELECT $1,'bind1',$2,$3,'https://chat.example',created,created,created+interval '5 minutes',created+interval '15 minutes' FROM t", [liveSession, randomBytes(32), mapping]);
    const liveChallenge = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.proof_challenges(id,challenge_key_id,challenge_fingerprint,binding_key_id,binding_fingerprint,mapping_id,jkt,audience,origin,created_at,expires_at) SELECT $1,'challenge1',$2,'bind1',$3,$4,$5,'dsa-signal','https://chat.example',created,created+interval '120 seconds' FROM t", [liveChallenge, randomBytes(32), randomBytes(32), mapping, randomBytes(32)]);
    const liveJti = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp() AS decision) INSERT INTO control_plane.jti_uses(id,policy_snapshot_id,credential_expires_at,retained_until,decision_clock,decision,created_at) SELECT $1,$2,decision+interval '10 minutes',decision+interval '10 minutes 30 seconds',decision,'authorized',decision FROM t", [liveJti, policy]); await pool.query("INSERT INTO control_plane.jti_key_aliases(jti_use_id,key_id,fingerprint) VALUES($1,'jti1',$2)", [liveJti, randomBytes(32)]);
    const liveIdem = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.idempotency_results(id,request_key_id,request_fingerprint,binding_key_id,binding_fingerprint,response_status,result,error_code,created_at,expires_at) SELECT $1,'request1',$2,'bind1',$3,200,'authorized',NULL,created,created+interval '60 seconds' FROM t", [liveIdem, randomBytes(32), randomBytes(32)]); await pool.query("INSERT INTO control_plane.idempotency_key_aliases(result_id,key_id,fingerprint) VALUES($1,'idem1',$2)", [liveIdem, randomBytes(32)]);
    const liveEntitlement = randomUUID(); await insertEntitlement("WITH t AS (SELECT clock_timestamp() AS authorized) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,$5,authorized,authorized+interval '15 minutes','membership_verified','AAAAAAAAAAAAAAAAAAAAAA','bind1',$6,1 FROM t", [liveEntitlement, mapping, randomBytes(32), policy, version, randomBytes(32)], [liveEntitlement]);
    const liveAudit = randomUUID(); await pool.query("INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason,occurred_at) VALUES($1,'login_state_consumed','success','completed',clock_timestamp()-interval '89 days')", [liveAudit]);
    const expiredState = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp()-interval '6 minutes' AS created) INSERT INTO control_plane.login_states(id,state_digest,binding_key_id,binding_fingerprint,return_origin,created_at,expires_at) SELECT $1,$2,'bind1',$3,'https://chat.example',created,created+interval '5 minutes' FROM t", [expiredState, randomBytes(32), randomBytes(32)]);
    const expiredSession = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp()-interval '16 minutes' AS created) INSERT INTO control_plane.identity_sessions(id,binding_key_id,binding_fingerprint,mapping_id,origin,created_at,last_seen_at,idle_expires_at,absolute_expires_at) SELECT $1,'bind1',$2,$3,'https://chat.example',created,created,created+interval '5 minutes',created+interval '15 minutes' FROM t", [expiredSession, randomBytes(32), mapping]);
    const expiredChallenge = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp()-interval '3 minutes' AS created) INSERT INTO control_plane.proof_challenges(id,challenge_key_id,challenge_fingerprint,binding_key_id,binding_fingerprint,mapping_id,jkt,audience,origin,created_at,expires_at) SELECT $1,'challenge1',$2,'bind1',$3,$4,$5,'dsa-signal','https://chat.example',created,created+interval '120 seconds' FROM t", [expiredChallenge, randomBytes(32), randomBytes(32), mapping, randomBytes(32)]);
    const expiredJti = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp()-interval '20 minutes' AS decision) INSERT INTO control_plane.jti_uses(id,policy_snapshot_id,credential_expires_at,retained_until,decision_clock,decision,created_at) SELECT $1,$2,decision+interval '14 minutes',decision+interval '14 minutes 30 seconds',decision,'authorized',decision FROM t", [expiredJti, policy]); await pool.query("INSERT INTO control_plane.jti_key_aliases(jti_use_id,key_id,fingerprint) VALUES($1,'jti1',$2)", [expiredJti, randomBytes(32)]);
    const expiredIdem = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp()-interval '2 minutes' AS created) INSERT INTO control_plane.idempotency_results(id,request_key_id,request_fingerprint,binding_key_id,binding_fingerprint,response_status,result,error_code,created_at,expires_at) SELECT $1,'request1',$2,'bind1',$3,200,'authorized',NULL,created,created+interval '60 seconds' FROM t", [expiredIdem, randomBytes(32), randomBytes(32)]); await pool.query("INSERT INTO control_plane.idempotency_key_aliases(result_id,key_id,fingerprint) VALUES($1,'idem1',$2)", [expiredIdem, randomBytes(32)]);
    // An expired entitlement is retained until an expiry source has published its
    // complete fanout and the access barrier is actually suspended.
    const blockedEntitlement = randomUUID(); await insertEntitlement("WITH t AS (SELECT clock_timestamp()-interval '16 minutes' AS authorized) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,$5,authorized,authorized+interval '15 minutes','membership_verified','AAAAAAAAAAAAAAAAAAAAAA','bind1',$6,1 FROM t", [blockedEntitlement, mapping, randomBytes(32), policy, version, randomBytes(32)], [blockedEntitlement]);
    const permitted = await identityFixture(); const permittedEntitlement = randomUUID(); await insertEntitlement("WITH t AS (SELECT clock_timestamp()-interval '16 minutes' AS authorized) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,$5,authorized,authorized+interval '15 minutes','membership_verified','AAAAAAAAAAAAAAAAAAAAAA','bind1',$6,1 FROM t", [permittedEntitlement, permitted.mapping, randomBytes(32), permitted.policy, permitted.version, randomBytes(32)], [permittedEntitlement]);
    const source = randomUUID(); let sourceAudit = ''; const sourceClient = await pool.connect(); try {
      await sourceClient.query('BEGIN');
      await sourceClient.query("INSERT INTO control_plane.membership_access_sources(id,source_kind,reason,producer_id,source_event_id,source_event_digest,requested_at,source_effective_at,mapping_id) VALUES($1,'entitlement_expiry','entitlement_expired','cleanup-test',$2,$3,clock_timestamp(),clock_timestamp()-interval '1 second',$4)", [source, randomUUID(), randomBytes(32), permitted.mapping]);
      await sourceClient.query("INSERT INTO control_plane.membership_access_source_selector_aliases(source_id,selector_kind,fingerprint_key_id,fingerprint) VALUES($1,'mapping','v1',$2)", [source, randomBytes(32)]);
      await sourceClient.query("INSERT INTO control_plane.membership_access_source_cause_aliases(source_id,fingerprint_key_id,fingerprint) VALUES($1,'v1',$2)", [source, randomBytes(32)]);
      await sourceClient.query('COMMIT');
      await sourceClient.query('BEGIN');
      await sourceClient.query("INSERT INTO control_plane.membership_access_source_chunks(source_id,chunk_no,target_count,chunk_digest,published_at) VALUES($1,0,1,sha256(convert_to($2,'UTF8')),clock_timestamp())", [source, permitted.mapping]);
      await sourceClient.query('INSERT INTO control_plane.membership_access_source_targets(source_id,mapping_id,chunk_no) VALUES($1,$2,0)', [source, permitted.mapping]);
      await sourceClient.query("UPDATE control_plane.membership_access_sources SET publication_state='publishing',chunk_count=1,cursor_digest=sha256(decode(encode((SELECT chunk_digest FROM control_plane.membership_access_source_chunks WHERE source_id=$1 AND chunk_no=0),'hex'),'hex')) WHERE id=$1", [source]);
      await sourceClient.query("UPDATE control_plane.membership_access_sources SET publication_state='published',finalized_at=clock_timestamp() WHERE id=$1", [source]);
      sourceAudit = randomUUID(); await sourceClient.query("INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason,source_id,mapping_id,occurred_at) VALUES($1,'membership_access_source_published','success','entitlement_expired',$2,$3,clock_timestamp()-interval '91 days')", [sourceAudit, source, permitted.mapping]);
      await sourceClient.query("UPDATE control_plane.membership_access_states SET barrier_state='suspended',revision=1,changed_at=clock_timestamp() WHERE mapping_id=$1", [permitted.mapping]);
      await sourceClient.query('COMMIT');
    } catch (error) { await sourceClient.query('ROLLBACK').catch(() => undefined); throw error; } finally { sourceClient.release(); }
    const oldAudit = randomUUID(); await pool.query("INSERT INTO control_plane.security_audit_events(id,event_type,outcome,reason,occurred_at) VALUES($1,'login_state_consumed','success','completed',clock_timestamp()-interval '91 days')", [oldAudit]);
    await expect(asRole(retention, "SELECT control_plane.cleanup_expired(clock_timestamp()-interval '89 days')")).rejects.toThrow('90 days');
    await asRole(retention, "SELECT control_plane.cleanup_expired(clock_timestamp()-interval '90 days')");
    for (const [table, id] of [['login_states', expiredState], ['identity_sessions', expiredSession], ['proof_challenges', expiredChallenge], ['jti_uses', expiredJti], ['idempotency_results', expiredIdem], ['entitlements', permittedEntitlement]] as const) expect((await pool.query(`SELECT count(*)::int AS count FROM control_plane.${table} WHERE id=$1`, [id])).rows[0].count).toBe(0);
    for (const [table, id] of [['login_states', liveState], ['identity_sessions', liveSession], ['proof_challenges', liveChallenge], ['jti_uses', liveJti], ['idempotency_results', liveIdem], ['entitlements', liveEntitlement], ['entitlements', blockedEntitlement], ['security_audit_events', oldAudit], ['security_audit_events', liveAudit], ['security_audit_events', sourceAudit]] as const) expect((await pool.query(`SELECT count(*)::int AS count FROM control_plane.${table} WHERE id=$1`, [id])).rows[0].count).toBe(1);
  });
  it('allows retention to remove only deadline-expired OIDC rows with guarded time', async () => {
    const { mapping, policy, version } = await identityFixture();
    const epoch = 'AAAAAAAAAAAAAAAAAAAAAA';
    const expiredEntitlement = randomUUID(); const liveEntitlement = randomUUID();
    await insertEntitlement("WITH t AS (SELECT clock_timestamp()-interval '20 minutes' old,clock_timestamp() fresh) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1::uuid,$3::uuid,$5::bytea,'chat','active',$4::uuid,$7,old,old+interval '15 minutes','membership_verified',$8,'bind1',$6::bytea,1 FROM t UNION ALL SELECT $2::uuid,$3::uuid,$9::bytea,'chat','active',$4::uuid,$7,fresh,fresh+interval '15 minutes','membership_verified',$8,'bind1',$10::bytea,1 FROM t", [expiredEntitlement, liveEntitlement, mapping, policy, randomBytes(32), randomBytes(32), version, epoch, randomBytes(32), randomBytes(32)], [expiredEntitlement, liveEntitlement]);
    const expiredArtifact = randomUUID(); const liveArtifact = randomUUID(); const expiredGrant = randomBytes(32); const liveGrant = randomBytes(32);
    await pool.query("WITH t AS (SELECT clock_timestamp()-interval '1000 seconds' old,clock_timestamp() fresh) INSERT INTO oidc.provider_artifacts(id,epoch,model,artifact_key_id,artifact_fingerprint,grant_key_id,grant_fingerprint,cipher_key_id,nonce,ciphertext,created_at,expires_at,retained_until) SELECT $1::uuid,$3,'Grant','idx',$4::bytea,'idx',$5::bytea,'aes',$6::bytea,$7::bytea,old,old+interval '900 seconds',old+interval '930 seconds' FROM t UNION ALL SELECT $2::uuid,$3,'Grant','idx',$8::bytea,'idx',$9::bytea,'aes',$10::bytea,$11::bytea,fresh,fresh+interval '900 seconds',fresh+interval '930 seconds' FROM t", [expiredArtifact, liveArtifact, epoch, randomBytes(32), expiredGrant, randomBytes(12), randomBytes(16), randomBytes(32), liveGrant, randomBytes(12), randomBytes(16)]);
    const expiredContext = randomUUID(); const liveContext = randomUUID();
    await pool.query("WITH t AS (SELECT clock_timestamp()-interval '1000 seconds' old,clock_timestamp() fresh) INSERT INTO oidc.authorization_contexts(id,epoch,client_key_id,client_fingerprint,grant_key_id,grant_fingerprint,interaction_chain_key_id,interaction_chain_fingerprint,interaction_uid_key_id,interaction_uid_fingerprint,control_session_key_id,control_session_fingerprint,mapping_id,entitlement_id,generation,jkt,policy_snapshot_id,policy_version,created_at,expires_at,grant_expires_at,retained_until) SELECT $1::uuid,$7,'idx',$8::bytea,'idx',$9::bytea,'idx',$10::bytea,'idx',$11::bytea,'bind1',$12::bytea,$3::uuid,$5::uuid,1,$13,$4::uuid,$14,old,old+interval '300 seconds',old+interval '900 seconds',old+interval '930 seconds' FROM t UNION ALL SELECT $2::uuid,$7,'idx',$15::bytea,'idx',$16::bytea,'idx',$17::bytea,'idx',$18::bytea,'bind1',$19::bytea,$3::uuid,$6::uuid,1,$20,$4::uuid,$14,fresh,fresh+interval '300 seconds',fresh+interval '900 seconds',fresh+interval '930 seconds' FROM t", [expiredContext, liveContext, mapping, policy, expiredEntitlement, liveEntitlement, epoch, randomBytes(32), expiredGrant, randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32).toString('base64url'), version, randomBytes(32), liveGrant, randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32).toString('base64url')]);
    const expiredCsrf = randomUUID(); const liveCsrf = randomUUID();
    await pool.query("WITH t AS (SELECT clock_timestamp()-interval '400 seconds' old,clock_timestamp() fresh) INSERT INTO oidc.interaction_csrf(id,epoch,csrf_key_id,csrf_fingerprint,client_key_id,client_fingerprint,interaction_chain_key_id,interaction_chain_fingerprint,interaction_uid_key_id,interaction_uid_fingerprint,created_at,expires_at,retained_until) SELECT $1::uuid,$3,'idx',$4::bytea,'idx',$5::bytea,'idx',$6::bytea,'idx',$7::bytea,old,old+interval '300 seconds',old+interval '330 seconds' FROM t UNION ALL SELECT $2::uuid,$3,'idx',$8::bytea,'idx',$9::bytea,'idx',$10::bytea,'idx',$11::bytea,fresh,fresh+interval '300 seconds',fresh+interval '330 seconds' FROM t", [expiredCsrf, liveCsrf, epoch, randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32)]);
    for (const cutoff of ['NULL', "'infinity'::timestamptz", "clock_timestamp()+interval '1 second'"]) await expect(asRole(retention, `SELECT oidc.cleanup_expired(${cutoff})`)).rejects.toThrow('invalid cleanup cutoff');
    await expect(asRole(retention, 'SELECT * FROM oidc.provider_artifacts')).rejects.toThrow();
    await asRole(retention, 'SELECT oidc.cleanup_expired(clock_timestamp())');
    for (const [table, expired, live] of [['interaction_csrf', expiredCsrf, liveCsrf], ['authorization_contexts', expiredContext, liveContext], ['provider_artifacts', expiredArtifact, liveArtifact]] as const) {
      expect((await pool.query(`SELECT count(*)::int count FROM oidc.${table} WHERE id=$1`, [expired])).rows[0]!.count).toBe(0);
      expect((await pool.query(`SELECT count(*)::int count FROM oidc.${table} WHERE id=$1`, [live])).rows[0]!.count).toBe(1);
    }
    await pool.query('DELETE FROM oidc.interaction_csrf WHERE id=$1', [liveCsrf]); await pool.query('DELETE FROM oidc.authorization_contexts WHERE id=$1', [liveContext]); await pool.query('DELETE FROM oidc.provider_artifacts WHERE id=$1', [liveArtifact]); await pool.query('DELETE FROM control_plane.entitlements WHERE id=ANY($1)', [[expiredEntitlement, liveEntitlement]]);
  });
  it('authenticates live DID and policy envelopes and fails closed for wrong or missing keys', async () => {
    // This fixture must be the only live decryptable material: earlier catalog
    // fixtures intentionally use opaque placeholder envelopes.
    await pool.query('UPDATE control_plane.did_mappings SET erased_at=clock_timestamp() WHERE erased_at IS NULL');
    const did = fixtureDid(); const mapping = randomUUID(); const policy = randomUUID(); const didEnvelope = randomUUID(); const policyEnvelope = randomUUID(); const mappedSubject = derivePairwiseSubject(fixtureSubjectKey, 'https://chat.example', did); await envelope(didEnvelope, 'did', envelopeKey, 'https://chat.example', mapping, did); const mappingClient = await pool.connect(); try { await mappingClient.query('BEGIN'); await mappingClient.query('INSERT INTO control_plane.did_mappings(id,sector,subject_key_id,subject,envelope_id) VALUES($1,$2,$3,$4,$5)', [mapping, 'https://chat.example', 'subject1', mappedSubject, didEnvelope]); await mappingClient.query("INSERT INTO control_plane.membership_access_states(mapping_id,barrier_state,revision,changed_at) VALUES($1,'active',0,clock_timestamp())", [mapping]); await mappingClient.query('COMMIT'); } finally { mappingClient.release(); } await envelope(policyEnvelope, 'policy', envelopeKey, 'v1', policy); await pool.query("INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) VALUES($1,$2,$3,'v1',clock_timestamp()-interval '2 seconds',clock_timestamp()-interval '1 second',clock_timestamp()+interval '1 hour',clock_timestamp())", [policy, bytes(9), policyEnvelope]);
    await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.login_states(id,state_digest,binding_key_id,binding_fingerprint,return_origin,created_at,expires_at) SELECT $1,$2,'bind1',$3,'https://chat.example',created,created+interval '5 minutes' FROM t", [randomUUID(), randomBytes(32), randomBytes(32)]);
    await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.identity_sessions(id,binding_key_id,binding_fingerprint,mapping_id,origin,created_at,last_seen_at,idle_expires_at,absolute_expires_at) SELECT $1,'bind1',$2,$3,'https://chat.example',created,created,created+interval '5 minutes',created+interval '15 minutes' FROM t", [randomUUID(), randomBytes(32), mapping]);
    await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.proof_challenges(id,challenge_key_id,challenge_fingerprint,binding_key_id,binding_fingerprint,mapping_id,jkt,audience,origin,created_at,expires_at) SELECT $1,'challenge1',$2,'bind1',$3,$4,$5,'dsa-signal','https://chat.example',created,created+interval '120 seconds' FROM t", [randomUUID(), randomBytes(32), randomBytes(32), mapping, randomBytes(32)]);
    const jti = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp() AS decision) INSERT INTO control_plane.jti_uses(id,policy_snapshot_id,credential_expires_at,retained_until,decision_clock,decision,created_at) SELECT $1,$2,decision+interval '10 minutes',decision+interval '10 minutes 30 seconds',decision,'authorized',decision FROM t", [jti, policy]);
    await pool.query("INSERT INTO control_plane.jti_key_aliases(jti_use_id,key_id,fingerprint) VALUES($1,'jti1',$2),($1,'jti2',$3)", [jti, randomBytes(32), randomBytes(32)]);
    const idem = randomUUID(); await pool.query("WITH t AS (SELECT clock_timestamp() AS created) INSERT INTO control_plane.idempotency_results(id,request_key_id,request_fingerprint,binding_key_id,binding_fingerprint,response_status,result,error_code,created_at,expires_at) SELECT $1,'request1',$2,'bind1',$3,200,'authorized',NULL,created,created+interval '60 seconds' FROM t", [idem, randomBytes(32), randomBytes(32)]);
    await pool.query("INSERT INTO control_plane.idempotency_key_aliases(result_id,key_id,fingerprint) VALUES($1,'idem1',$2),($1,'idem2',$3)", [idem, randomBytes(32), randomBytes(32)]);
    const rings = { subject: { subject1: fixtureSubjectKey }, envelope: { env1: envelopeKey }, challenge: ['challenge1'], binding: ['bind1'], jti: { active: 'jti1', retained: ['jti1', 'jti2'] }, idempotency: { active: 'idem1', retained: ['idem1', 'idem2'] }, request: ['request1'], evidence: evidenceKeyIds, oidc: { epoch: 'AAAAAAAAAAAAAAAAAAAAAA', adapter: {}, index: [] } };
    const client = await pool.connect(); try {
      await expect(assertRetainedKeys(client, rings)).resolves.toBeUndefined();
      await expect(assertRetainedKeys(client, { ...rings, envelope: { env1: randomBytes(32) } })).rejects.toThrow('Required retained key is unavailable');
      await expect(assertRetainedKeys(client, { ...rings, envelope: {} })).rejects.toThrow('Required retained key is unavailable');
      for (const change of [{ subject: {} }, { challenge: [] }, { binding: [] }, { request: [] }]) await expect(assertRetainedKeys(client, { ...rings, ...change })).rejects.toThrow('Required retained key is unavailable');
      await expect(assertRetainedKeys(client, { ...rings, subject: { subject1: randomBytes(32) } })).rejects.toThrow('Required retained key is unavailable');
      await client.query('BEGIN');
      try {
        await client.query('UPDATE control_plane.did_mappings SET erased_at=clock_timestamp() WHERE id=$1', [mapping]);
        await expect(assertRetainedKeys(client, { ...rings, subject: {} })).rejects.toThrow('Required retained key is unavailable');
        await expect(assertRetainedKeys(client, { ...rings, envelope: {} })).rejects.toThrow('Required retained key is unavailable');
      } finally { await client.query('ROLLBACK'); }
      await pool.query("UPDATE control_plane.jti_key_aliases SET key_id='unknown' WHERE jti_use_id=$1 AND key_id='jti2'", [jti]);
      await expect(assertRetainedKeys(client, rings)).rejects.toThrow('Required retained key is unavailable');
      await pool.query("UPDATE control_plane.jti_key_aliases SET key_id='jti2' WHERE jti_use_id=$1 AND key_id='unknown'", [jti]);
      await pool.query("DELETE FROM control_plane.idempotency_key_aliases WHERE result_id=$1 AND key_id='idem1'", [idem]);
      await expect(assertRetainedKeys(client, rings)).rejects.toThrow('Required retained key is unavailable');
      await pool.query("INSERT INTO control_plane.idempotency_key_aliases(result_id,key_id,fingerprint) VALUES($1,'idem1',$2)", [idem, randomBytes(32)]);
      await expect(assertRetainedKeys(client, rings)).resolves.toBeUndefined();
      await expect(assertRetainedKeys(client, { ...rings, jti: { active: 'jti1', retained: ['jti1', 'jti2', 'jti3'] } })).resolves.toBeUndefined();
      await expect(assertRetainedKeys(client, { ...rings, jti: { active: 'jti2', retained: ['jti1', 'jti2'] } })).rejects.toThrow('Required retained key is unavailable');
      await expect(assertRetainedKeys(client, { ...rings, jti: { active: 'jti3', retained: ['jti1', 'jti2', 'jti3'] } })).rejects.toThrow('Required retained key is unavailable');
      const retainedBindingEntitlement = randomUUID();
      await insertEntitlement("WITH t AS (SELECT clock_timestamp()-interval '16 minutes' AS authorized) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,'v1',authorized,authorized+interval '15 minutes','membership_verified','AAAAAAAAAAAAAAAAAAAAAA','bind-retained',$5,1 FROM t", [retainedBindingEntitlement, mapping, randomBytes(32), policy, randomBytes(32)], [retainedBindingEntitlement]);
      const withRetainedBinding = { ...rings, binding: ['bind1', 'bind-retained'] };
      await expect(assertRetainedKeys(client, withRetainedBinding)).resolves.toBeUndefined();
      await expect(assertRetainedKeys(client, rings)).rejects.toThrow('Required retained key is unavailable');
      await pool.query('DELETE FROM control_plane.entitlements WHERE id=$1', [retainedBindingEntitlement]);
      await expect(assertRetainedKeys(client, rings)).resolves.toBeUndefined();
      const artifactId = randomUUID(); const artifactFingerprint = randomBytes(32); const oidcKey = randomBytes(32); const oidcNonce = randomBytes(12); const oidcPlaintext = Buffer.from('{"kind":"fixture"}');
      const oidcCipher = createCipheriv('aes-256-gcm', oidcKey, oidcNonce); oidcCipher.setAAD(Buffer.from(`dsa-signal-oidc-adapter:v1\0${artifactId}\0Interaction\0${artifactFingerprint.toString('base64url')}\0AAAAAAAAAAAAAAAAAAAAAA`)); const oidcCiphertext = Buffer.concat([oidcCipher.update(oidcPlaintext), oidcCipher.final(), oidcCipher.getAuthTag()]); oidcPlaintext.fill(0);
      await pool.query("WITH t AS (SELECT clock_timestamp() created) INSERT INTO oidc.provider_artifacts(id,epoch,model,artifact_key_id,artifact_fingerprint,cipher_key_id,nonce,ciphertext,created_at,expires_at,retained_until) SELECT $1,'AAAAAAAAAAAAAAAAAAAAAA','Interaction','idx1',$2,'aes1',$3,$4,created,created+interval '300 seconds',created+interval '330 seconds' FROM t", [artifactId, artifactFingerprint, oidcNonce, oidcCiphertext]);
      const withOidc = { ...rings, oidc: { epoch: 'AAAAAAAAAAAAAAAAAAAAAA', adapter: { aes1: oidcKey }, index: ['idx1'] } };
      await expect(assertRetainedKeys(client, withOidc)).resolves.toBeUndefined();
      await expect(assertRetainedKeys(client, { ...withOidc, oidc: { ...withOidc.oidc, adapter: {} } })).rejects.toThrow('Required retained key is unavailable');
      await expect(assertRetainedKeys(client, { ...withOidc, oidc: { ...withOidc.oidc, adapter: { aes1: randomBytes(32) } } })).rejects.toThrow('Required retained key is unavailable');
      await expect(assertRetainedKeys(client, { ...withOidc, oidc: { ...withOidc.oidc, index: [] } })).rejects.toThrow('Required retained key is unavailable');
      await expect(assertRetainedKeys(client, { ...withOidc, oidc: { ...withOidc.oidc, epoch: 'AQAAAAAAAAAAAAAAAAAAAA' } })).rejects.toThrow('Required retained key is unavailable');
      await pool.query('DELETE FROM oidc.provider_artifacts WHERE id=$1', [artifactId]); oidcKey.fill(0); artifactFingerprint.fill(0); oidcNonce.fill(0); oidcCiphertext.fill(0);
    } finally { client.release(); }
  });
  it('keeps production dependencies and sources free of APM sinks', async () => {
    const backend = fileURLToPath(new URL('../', import.meta.url));
    const manifest = JSON.parse(await readFile(`${backend}/package.json`, 'utf8')) as { dependencies?: Record<string, string> };
    const offenders = Object.keys(manifest.dependencies ?? {}).filter(apmPackage);
    for (const file of await productionTypeScriptFiles(`${backend}/src`)) {
      const source = await readFile(file, 'utf8');
      for (const match of source.matchAll(/(?:from\s*|import\s*\(|require\s*\()['"]([^'"]+)['"]/g)) if (apmPackage(match[1]!)) offenders.push(`${file}: ${match[1]}`);
    }
    expect(offenders, 'APM/tracing dependency or import found; scrubbed sink tests are required if one appears.').toEqual([]);
  });
  it('runs the Task 5 real PostgreSQL golden path without retaining request secrets', async () => {
    const database = `cp_task5_${suffix}`;
    await pool.query(`CREATE DATABASE ${database}`);
    const golden = new Pool({ connectionString: `postgresql://postgres:test@127.0.0.1:${postgresPort}/${database}` });
    const runtimeApplicationName = `task5-runtime-${suffix}`;
    const runtimePool = new Pool({ connectionString: `postgresql://${runtime}:runtime-test-only@127.0.0.1:${postgresPort}/${database}`, application_name: runtimeApplicationName });
    try {
      await applyControlPlaneMigration(golden, runtime, retention, undefined, revocation, ['test']);
      const [root, issuer, holder] = await Promise.all([generateKeyPair('ES256'), generateKeyPair('ES256'), generateKeyPair('ES256')]);
      const [rootJwk, issuerJwk, holderJwk] = await Promise.all([exportJWK(root.publicKey), exportJWK(issuer.publicKey), exportJWK(holder.publicKey)]);
      const rootDid = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa'; const issuerDid = 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb'; const holderDid = 'did:plc:cccccccccccccccccccccccc';
      const rootKey = parsePublicJwk(rootJwk); const issuerKey = parsePublicJwk(issuerJwk); const publicJwk = parsePublicJwk(holderJwk);
      const pwaOrigin = 'https://pwa.example'; const sector = 'https://oidc.example'; const version = '2026.07-1'; const policyUri = `at://${rootDid}/us.dsaslate.temp.dsaPolicy/rkey`;
      const rings = { active: 'test', keys: { test: randomBytes(32) } };
      const policyNow = (await golden.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now;
      const policyPayload = { version: 'v1', policyVersion: version, policyUri, rootDid, issuedAt: Math.floor(policyNow.getTime() / 1000) - 1, freshUntil: Math.floor(policyNow.getTime() / 1000) + 300, issuers: [{ did: issuerDid, policies: [{ version, state: 'active', transitionedAt: 0 }], keys: [{ kid: `${issuerDid}#key`, state: 'active', transitionedAt: 0, publicJwk: issuerKey }] }] };
      const compactPolicy = await new CompactSign(Buffer.from(JSON.stringify(policyPayload))).setProtectedHeader({ alg: 'ES256', typ: 'dsa-signal-issuer-policy+jws', kid: `${rootDid}#root` }).sign(root.privateKey);
      const foundation = new FoundationService({ resolveAuthority: async () => ({ uri: policyUri, provenance: { uri: policyUri, cid: 'bafy-task5', repoDid: rootDid, repoRev: 'task5', sequence: 0, observedAt: policyNow.toISOString(), status: 'verified' as const }, authority: { status: 'official' as const, policyUri, policyVersion: version, rootDid, evaluatedAt: policyNow.toISOString() } }) } as never);
      const refresh = new PolicyRefreshService(golden, foundation, { [`${rootDid}#root`]: rootKey }, version, { active: { id: 'test', key: rings.keys.test }, keys: [{ id: 'test', key: rings.keys.test }] });
      const snapshotId = await refresh.refresh(compactPolicy);
      const runtimeRefresh = new PolicyRefreshService(runtimePool, foundation, { [`${rootDid}#root`]: rootKey }, version, { active: { id: 'test', key: rings.keys.test }, keys: [{ id: 'test', key: rings.keys.test }] });
      const runtimeClient = await runtimePool.connect();
      try { await expect(runtimeRefresh.loadActive(runtimeClient)).resolves.toMatchObject({ snapshotId, policy: { policyVersion: version, rootDid, policyUri } }); }
      finally { runtimeClient.release(); }
      const sessions = createSessionRepository({ pool: runtimePool, pwaOrigin, sector, subjectKeys: rings, envelopeKeys: rings, bindingKeys: rings });
      const waitUntilBlocked = async (blockerPid: number, applicationName: string): Promise<void> => {
        for (let attempt = 0; attempt < 200; attempt += 1) {
          const blocked = await golden.query<{ blocked: boolean }>('SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$2 AND $1=ANY(pg_blocking_pids(pid))) AS blocked', [blockerPid, applicationName]);
          if (blocked.rows[0]?.blocked) return;
          await new Promise<void>(resolve => setImmediate(resolve));
        }
        throw new Error(`runtime application ${applicationName} did not block on backend ${blockerPid}`);
      };
      const sessionRow = async (opaqueSessionId: string) => {
        const binding = createHmac('sha256', rings.keys.test).update('dsa-signal-session-fingerprint:v1\0').update(opaqueSessionId, 'utf8').digest();
        try {
          const result = await golden.query<{ id: string; last_seen_at: Date; idle_expires_at: Date; revoked_at: Date | null }>('SELECT id,last_seen_at,idle_expires_at,revoked_at FROM control_plane.identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2', [rings.active, binding]);
          expect(result.rows).toHaveLength(1);
          return result.rows[0]!;
        } finally { binding.fill(0); }
      };
      const sessionId = randomBytes(32).toString('base64url');
      const handoffNow = (await golden.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now;
      const established = await sessions.establishFromHandoff({ did: holderDid, audience: pwaOrigin, authenticatedAt: handoffNow.toISOString(), expiresIn: 60 }, sessionId);
      const jkt = jwkThumbprint(publicJwk);
      const challenges = createChallengeService({ pool: runtimePool, challengeKeys: rings, bindingKeys: rings, pwaOrigin, policyRefresh: runtimeRefresh });
      const signedInputs: { input: { version: string; idempotencyKey: string; challenge: string; signature: string; publicJwk: typeof publicJwk; credential: string }; rawBody: Buffer; jti: string; idempotencyKey: string; signature: string; credential: string; challenge: string }[] = [];
      const signValidInput = async (challenge: string, overrides: { jti?: string; idempotencyKey?: string } = {}) => {
        const verifyNow = (await golden.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now;
        const jti = overrides.jti ?? randomBytes(32).toString('base64url'); const idempotencyKey = overrides.idempotencyKey ?? randomBytes(32).toString('base64url');
        const credentialClaims = { iss: issuerDid, sub: holderDid, aud: 'dsa-signal', iat: Math.floor(verifyNow.getTime() / 1000) - 1, exp: Math.floor(verifyNow.getTime() / 1000) + 120, jti, cnf: { jkt }, entitlement: 'chat', policyVersion: version };
        const credential = await new CompactSign(Buffer.from(JSON.stringify(credentialClaims))).setProtectedHeader({ alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: `${issuerDid}#key` }).sign(issuer.privateKey);
        const proof = `dsa-signal-proof:v1\n${challenge}\n${pwaOrigin}\ndsa-signal\n${holderDid}\n${jkt}\n${jti}`;
        const signature = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holder.privateKey, Buffer.from(proof))).toString('base64url');
        const input = { version: 'v1', idempotencyKey, challenge, signature, publicJwk, credential }; const rawBody = Buffer.from(JSON.stringify(input));
        const signed = { input, rawBody, jti, idempotencyKey, signature, credential, challenge }; signedInputs.push(signed); return signed;
      };
      const verification = createVerificationService({ pool: runtimePool, envelopeKeys: rings, challengeKeys: rings, bindingKeys: rings, jtiKeys: rings, idempotencyKeys: rings, requestKeys: rings, revocationEvidenceKeys: rings, oidcEpoch: 'AAAAAAAAAAAAAAAAAAAAAA', pwaOrigin, sector, policyRefresh: runtimeRefresh });
      const revocationChallengeSession = randomBytes(32).toString('base64url');
      const revocationChallengeNow = (await golden.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now;
      await sessions.establishFromHandoff({ did: holderDid, audience: pwaOrigin, authenticatedAt: revocationChallengeNow.toISOString(), expiresIn: 60 }, revocationChallengeSession);
      const challengeSessionBefore = await sessionRow(revocationChallengeSession);
      const challengesBefore = (await golden.query<{ count: number }>('SELECT count(*)::int AS count FROM control_plane.proof_challenges')).rows[0]!.count;
      const challengeLock = await golden.connect(); let challengeOperation: Promise<unknown> | undefined;
      try {
        await challengeLock.query('BEGIN');
        await challengeLock.query('SELECT id FROM control_plane.identity_sessions WHERE id=$1 FOR UPDATE', [challengeSessionBefore.id]);
        const blockerPid = (await challengeLock.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid;
        challengeOperation = challenges.issue(revocationChallengeSession, pwaOrigin, jkt);
        await waitUntilBlocked(blockerPid, runtimeApplicationName);
        await challengeLock.query('UPDATE control_plane.identity_sessions SET revoked_at=clock_timestamp() WHERE id=$1', [challengeSessionBefore.id]);
        await challengeLock.query('COMMIT');
        await expect(challengeOperation).rejects.toBeInstanceOf(ChallengeRejectedError);
      } finally {
        await challengeLock.query('ROLLBACK').catch(() => undefined); challengeLock.release();
        await challengeOperation?.catch(() => undefined);
      }
      const challengeSessionAfter = await sessionRow(revocationChallengeSession);
      expect((await golden.query<{ count: number }>('SELECT count(*)::int AS count FROM control_plane.proof_challenges')).rows[0]!.count).toBe(challengesBefore);
      expect(challengeSessionAfter.last_seen_at).toEqual(challengeSessionBefore.last_seen_at);
      expect(challengeSessionAfter.idle_expires_at).toEqual(challengeSessionBefore.idle_expires_at);
      expect(challengeSessionAfter.revoked_at).toBeInstanceOf(Date);

      const revocationVerificationSession = randomBytes(32).toString('base64url');
      const revocationVerificationNow = (await golden.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now;
      await sessions.establishFromHandoff({ did: holderDid, audience: pwaOrigin, authenticatedAt: revocationVerificationNow.toISOString(), expiresIn: 60 }, revocationVerificationSession);
      const revocationVerificationChallenge = await challenges.issue(revocationVerificationSession, pwaOrigin, jkt);
      const revocationVerificationInput = await signValidInput(revocationVerificationChallenge.challenge);
      const verificationSessionBefore = await sessionRow(revocationVerificationSession);
      const verificationChallengeBefore = (await golden.query<{ consumed_at: Date | null }>('SELECT consumed_at FROM control_plane.proof_challenges WHERE challenge_key_id=$1 AND challenge_fingerprint=$2', [rings.active, createHmac('sha256', rings.keys.test).update('dsa-signal-challenge-fingerprint:v1\0').update(Buffer.from(revocationVerificationChallenge.challenge, 'base64url')).digest()])).rows[0]!;
      expect(verificationChallengeBefore.consumed_at).toBeNull();
      const verificationCountsBefore = (await golden.query<{ jti: number; idempotency: number; success_audit: number; authorized_entitlements: number }>("SELECT (SELECT count(*)::int FROM control_plane.jti_uses) AS jti,(SELECT count(*)::int FROM control_plane.idempotency_results) AS idempotency,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE event_type='entitlement_decided' AND outcome='success') AS success_audit,(SELECT count(*)::int FROM control_plane.entitlements WHERE status='active') AS authorized_entitlements")).rows[0]!;
      const verificationLock = await golden.connect(); let verificationOperation: Promise<unknown> | undefined;
      try {
        await verificationLock.query('BEGIN');
        await verificationLock.query('SELECT id FROM control_plane.identity_sessions WHERE id=$1 FOR UPDATE', [verificationSessionBefore.id]);
        const blockerPid = (await verificationLock.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid;
        verificationOperation = verification.verify(revocationVerificationSession, pwaOrigin, revocationVerificationInput.rawBody);
        await waitUntilBlocked(blockerPid, runtimeApplicationName);
        await verificationLock.query('UPDATE control_plane.identity_sessions SET revoked_at=clock_timestamp() WHERE id=$1', [verificationSessionBefore.id]);
        await verificationLock.query('COMMIT');
        await expect(verificationOperation).rejects.toBeInstanceOf(VerificationRejectedError);
      } finally {
        await verificationLock.query('ROLLBACK').catch(() => undefined); verificationLock.release();
        await verificationOperation?.catch(() => undefined);
      }
      const verificationSessionAfter = await sessionRow(revocationVerificationSession);
      const verificationChallengeAfter = (await golden.query<{ consumed_at: Date | null }>('SELECT consumed_at FROM control_plane.proof_challenges WHERE challenge_key_id=$1 AND challenge_fingerprint=$2', [rings.active, createHmac('sha256', rings.keys.test).update('dsa-signal-challenge-fingerprint:v1\0').update(Buffer.from(revocationVerificationChallenge.challenge, 'base64url')).digest()])).rows[0]!;
      const verificationCountsAfter = (await golden.query<{ jti: number; idempotency: number; success_audit: number; authorized_entitlements: number }>("SELECT (SELECT count(*)::int FROM control_plane.jti_uses) AS jti,(SELECT count(*)::int FROM control_plane.idempotency_results) AS idempotency,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE event_type='entitlement_decided' AND outcome='success') AS success_audit,(SELECT count(*)::int FROM control_plane.entitlements WHERE status='active') AS authorized_entitlements")).rows[0]!;
      expect(verificationChallengeAfter.consumed_at).toBeNull();
      expect(verificationCountsAfter).toEqual(verificationCountsBefore);
      expect(verificationSessionAfter.last_seen_at).toEqual(verificationSessionBefore.last_seen_at);
      expect(verificationSessionAfter.idle_expires_at).toEqual(verificationSessionBefore.idle_expires_at);
      expect(verificationSessionAfter.revoked_at).toBeInstanceOf(Date);
      const issued = await challenges.issue(sessionId, pwaOrigin, jkt); const first = await signValidInput(issued.challenge); const { input, rawBody } = first;
      const identical = await Promise.all([verification.verify(sessionId, pwaOrigin, rawBody), verification.verify(sessionId, pwaOrigin, rawBody)]);
      expect(identical).toEqual([{ status: 200, body: { version: 'v1', result: 'authorized' } }, { status: 200, body: { version: 'v1', result: 'authorized' } }]);
      const firstEntitlement = (await golden.query<{ id: string; generation: string; oidc_epoch: string; jkt: Buffer; policy_snapshot_id: string; status: string; reason: string; session_binding_fingerprint: Buffer }>('SELECT id,generation,oidc_epoch,jkt,policy_snapshot_id,status,reason,session_binding_fingerprint FROM control_plane.entitlements')).rows[0]!;
      expect(firstEntitlement).toMatchObject({ generation: '1', oidc_epoch: 'AAAAAAAAAAAAAAAAAAAAAA', policy_snapshot_id: snapshotId, status: 'active', reason: 'membership_verified' });
      expect(firstEntitlement.jkt.toString('base64url')).toBe(jkt);
      for (const [table, count] of [['proof_challenges', 2], ['jti_uses', 1], ['idempotency_results', 1], ['entitlements', 1]] as const) expect((await golden.query<{ count: number }>(`SELECT count(*)::int AS count FROM control_plane.${table}`)).rows[0]!.count).toBe(count);
      expect((await golden.query<{ count: number }>('SELECT count(*)::int AS count FROM control_plane.proof_challenges WHERE consumed_at IS NOT NULL')).rows[0]!.count).toBe(1);
      expect((await golden.query<{ count: number }>("SELECT count(*)::int AS count FROM control_plane.security_audit_events WHERE event_type='challenge_consumed' AND outcome='success'")).rows[0]!.count).toBe(1);
      expect((await golden.query<{ count: number }>("SELECT count(*)::int AS count FROM control_plane.security_audit_events WHERE event_type='entitlement_decided' AND outcome='success'")).rows[0]!.count).toBe(1);
      expect(await verification.verify(sessionId, pwaOrigin, Buffer.from(JSON.stringify(input, null, 1)))).toMatchObject({ status: 409 });
      const otherSession = randomBytes(32).toString('base64url'); const otherNow = (await golden.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now;
      await sessions.establishFromHandoff({ did: holderDid, audience: pwaOrigin, authenticatedAt: otherNow.toISOString(), expiresIn: 60 }, otherSession);
      expect(await verification.verify(otherSession, pwaOrigin, rawBody)).toMatchObject({ status: 409 });
      const secondChallenge = await challenges.issue(sessionId, pwaOrigin, jkt); const second = await signValidInput(secondChallenge.challenge);
      expect(await verification.verify(sessionId, pwaOrigin, second.rawBody)).toMatchObject({ status: 200 });
      expect((await golden.query<{ id: string; generation: string }>('SELECT id,generation FROM control_plane.entitlements WHERE session_binding_fingerprint=$1', [firstEntitlement.session_binding_fingerprint])).rows[0]).toEqual({ id: firstEntitlement.id, generation: '2' });
      const rejectedChallenge = await challenges.issue(sessionId, pwaOrigin, jkt); const rejectedInput = await signValidInput(rejectedChallenge.challenge); const rejectedBody = Buffer.from(JSON.stringify({ ...rejectedInput.input, signature: `${rejectedInput.signature[0] === 'A' ? 'B' : 'A'}${rejectedInput.signature.slice(1)}` }));
      expect(await verification.verify(sessionId, pwaOrigin, rejectedBody)).toMatchObject({ status: 401 });
      expect((await golden.query<{ generation: string }>('SELECT generation FROM control_plane.entitlements WHERE id=$1', [firstEntitlement.id])).rows[0]!.generation).toBe('2');
      const controlChallenge = await challenges.issue(otherSession, pwaOrigin, jkt); const control = await signValidInput(controlChallenge.challenge);
      expect(await verification.verify(otherSession, pwaOrigin, control.rawBody)).toMatchObject({ status: 200 });
      expect((await golden.query<{ generation: string }>('SELECT generation FROM control_plane.entitlements WHERE session_binding_fingerprint<>$1', [firstEntitlement.session_binding_fingerprint])).rows[0]!.generation).toBe('1');

      const sharedChallenge = await challenges.issue(sessionId, pwaOrigin, jkt); const [challengeLeft, challengeRight] = await Promise.all([signValidInput(sharedChallenge.challenge), signValidInput(sharedChallenge.challenge)]);
      expect(challengeLeft.jti).not.toBe(challengeRight.jti); expect(challengeLeft.idempotencyKey).not.toBe(challengeRight.idempotencyKey); expect(challengeLeft.signature).not.toBe(challengeRight.signature);
      const sharedChallengeFingerprint = createHmac('sha256', rings.keys.test).update('dsa-signal-challenge-fingerprint:v1\0').update(Buffer.from(sharedChallenge.challenge, 'base64url')).digest();
      const sharedJtiFingerprints = [challengeLeft, challengeRight].map(({ jti }) => createHmac('sha256', rings.keys.test).update('dsa-signal-jti-fingerprint:v1\0').update(issuerDid).update('\0').update(Buffer.from(jti, 'base64url')).digest());
      const sharedIdempotencyFingerprints = [challengeLeft, challengeRight].map(({ idempotencyKey }) => createHmac('sha256', rings.keys.test).update('dsa-signal-idempotency-fingerprint:v1\0').update(Buffer.from(idempotencyKey, 'base64url')).digest());
      const sharedRaceAuditBefore = (await golden.query<{ successes: number; denials: number }>("SELECT count(*) FILTER (WHERE outcome='success')::int AS successes,count(*) FILTER (WHERE outcome='denied')::int AS denials FROM control_plane.security_audit_events WHERE event_type='entitlement_decided'")).rows[0]!;
      const challengeRace = await Promise.all([verification.verify(sessionId, pwaOrigin, challengeLeft.rawBody), verification.verify(sessionId, pwaOrigin, challengeRight.rawBody)]);
      expect(challengeRace.map(result => result.status).sort()).toEqual([200, 401]);
      expect((await golden.query<{ consumed: number }>('SELECT count(*) FILTER (WHERE consumed_at IS NOT NULL)::int AS consumed FROM control_plane.proof_challenges WHERE challenge_fingerprint=$1', [sharedChallengeFingerprint])).rows[0]).toEqual({ consumed: 1 });
      expect((await golden.query<{ count: number }>('SELECT count(*)::int AS count FROM control_plane.jti_key_aliases WHERE fingerprint=ANY($1)', [sharedJtiFingerprints])).rows[0]).toEqual({ count: 1 });
      expect((await golden.query<{ count: number }>('SELECT count(*)::int AS count FROM control_plane.idempotency_key_aliases WHERE fingerprint=ANY($1)', [sharedIdempotencyFingerprints])).rows[0]).toEqual({ count: 2 });
      expect((await golden.query<{ generation: string }>('SELECT generation FROM control_plane.entitlements WHERE id=$1', [firstEntitlement.id])).rows[0]).toEqual({ generation: '3' });
      const sharedRaceAuditAfter = (await golden.query<{ successes: number; denials: number }>("SELECT count(*) FILTER (WHERE outcome='success')::int AS successes,count(*) FILTER (WHERE outcome='denied')::int AS denials FROM control_plane.security_audit_events WHERE event_type='entitlement_decided'")).rows[0]!;
      expect(sharedRaceAuditAfter).toEqual({ successes: sharedRaceAuditBefore.successes + 1, denials: sharedRaceAuditBefore.denials + 1 });

      const [jtiChallengeLeft, jtiChallengeRight] = await Promise.all([challenges.issue(sessionId, pwaOrigin, jkt), challenges.issue(sessionId, pwaOrigin, jkt)]); const sharedJti = randomBytes(32).toString('base64url');
      const [jtiLeft, jtiRight] = await Promise.all([signValidInput(jtiChallengeLeft.challenge, { jti: sharedJti }), signValidInput(jtiChallengeRight.challenge, { jti: sharedJti })]);
      expect(jtiLeft.jti).toBe(jtiRight.jti); expect(jtiLeft.challenge).not.toBe(jtiRight.challenge); expect(jtiLeft.idempotencyKey).not.toBe(jtiRight.idempotencyKey); expect(jtiLeft.signature).not.toBe(jtiRight.signature);
      const jtiChallengeFingerprints = [jtiChallengeLeft, jtiChallengeRight].map(({ challenge }) => createHmac('sha256', rings.keys.test).update('dsa-signal-challenge-fingerprint:v1\0').update(Buffer.from(challenge, 'base64url')).digest());
      const sharedJtiFingerprint = createHmac('sha256', rings.keys.test).update('dsa-signal-jti-fingerprint:v1\0').update(issuerDid).update('\0').update(Buffer.from(sharedJti, 'base64url')).digest();
      const jtiIdempotencyFingerprints = [jtiLeft, jtiRight].map(({ idempotencyKey }) => createHmac('sha256', rings.keys.test).update('dsa-signal-idempotency-fingerprint:v1\0').update(Buffer.from(idempotencyKey, 'base64url')).digest());
      const jtiRaceAuditBefore = (await golden.query<{ successes: number; denials: number }>("SELECT count(*) FILTER (WHERE outcome='success')::int AS successes,count(*) FILTER (WHERE outcome='denied')::int AS denials FROM control_plane.security_audit_events WHERE event_type='entitlement_decided'")).rows[0]!;
      const jtiRace = await Promise.all([verification.verify(sessionId, pwaOrigin, jtiLeft.rawBody), verification.verify(sessionId, pwaOrigin, jtiRight.rawBody)]);
      expect(jtiRace.map(result => result.status).sort()).toEqual([200, 401]);
      expect((await golden.query<{ consumed: number; unconsumed: number }>('SELECT count(*) FILTER (WHERE consumed_at IS NOT NULL)::int AS consumed,count(*) FILTER (WHERE consumed_at IS NULL)::int AS unconsumed FROM control_plane.proof_challenges WHERE challenge_fingerprint=ANY($1)', [jtiChallengeFingerprints])).rows[0]).toEqual({ consumed: 1, unconsumed: 1 });
      expect((await golden.query<{ count: number }>('SELECT count(*)::int AS count FROM control_plane.jti_key_aliases WHERE fingerprint=$1', [sharedJtiFingerprint])).rows[0]).toEqual({ count: 1 });
      expect((await golden.query<{ count: number }>('SELECT count(*)::int AS count FROM control_plane.idempotency_key_aliases WHERE fingerprint=ANY($1)', [jtiIdempotencyFingerprints])).rows[0]).toEqual({ count: 2 });
      expect((await golden.query<{ generation: string }>('SELECT generation FROM control_plane.entitlements WHERE id=$1', [firstEntitlement.id])).rows[0]).toEqual({ generation: '4' });
      const jtiRaceAuditAfter = (await golden.query<{ successes: number; denials: number }>("SELECT count(*) FILTER (WHERE outcome='success')::int AS successes,count(*) FILTER (WHERE outcome='denied')::int AS denials FROM control_plane.security_audit_events WHERE event_type='entitlement_decided'")).rows[0]!;
      expect(jtiRaceAuditAfter).toEqual({ successes: jtiRaceAuditBefore.successes + 1, denials: jtiRaceAuditBefore.denials + 1 });
      await golden.query('UPDATE control_plane.entitlements SET generation=9223372036854775807 WHERE id=$1', [firstEntitlement.id]);
      try {
        const overflowChallenge = await challenges.issue(sessionId, pwaOrigin, jkt); const overflow = await signValidInput(overflowChallenge.challenge);
        const overflowChallengeFingerprint = createHmac('sha256', rings.keys.test).update('dsa-signal-challenge-fingerprint:v1\0').update(Buffer.from(overflowChallenge.challenge, 'base64url')).digest();
        const overflowJtiFingerprint = createHmac('sha256', rings.keys.test).update('dsa-signal-jti-fingerprint:v1\0').update(issuerDid).update('\0').update(Buffer.from(overflow.jti, 'base64url')).digest();
        const overflowIdempotencyFingerprint = createHmac('sha256', rings.keys.test).update('dsa-signal-idempotency-fingerprint:v1\0').update(Buffer.from(overflow.idempotencyKey, 'base64url')).digest();
        const overflowBefore = (await golden.query<{ last_seen_at: Date; idle_expires_at: Date; consumed: number; jti_uses: number; jti_aliases: number; idempotency_results: number; idempotency_aliases: number; challenge_audit: number; success_audit: number }>("SELECT s.last_seen_at,s.idle_expires_at,(SELECT count(*)::int FROM control_plane.proof_challenges WHERE challenge_fingerprint=$2 AND consumed_at IS NOT NULL) AS consumed,(SELECT count(*)::int FROM control_plane.jti_uses) AS jti_uses,(SELECT count(*)::int FROM control_plane.jti_key_aliases WHERE key_id=$3 AND fingerprint=$4) AS jti_aliases,(SELECT count(*)::int FROM control_plane.idempotency_results) AS idempotency_results,(SELECT count(*)::int FROM control_plane.idempotency_key_aliases WHERE key_id=$5 AND fingerprint=$6) AS idempotency_aliases,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE event_type='challenge_consumed' AND outcome='success' AND mapping_id=$7 AND snapshot_id=$8) AS challenge_audit,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE event_type='entitlement_decided' AND outcome='success' AND mapping_id=$7 AND snapshot_id=$8) AS success_audit FROM control_plane.identity_sessions s WHERE s.binding_fingerprint=$1", [firstEntitlement.session_binding_fingerprint, overflowChallengeFingerprint, rings.active, overflowJtiFingerprint, rings.active, overflowIdempotencyFingerprint, established.mappingId, snapshotId])).rows[0]!;
        await expect(verification.verify(sessionId, pwaOrigin, overflow.rawBody)).rejects.toBeInstanceOf(VerificationUnavailableError);
        const overflowAfter = (await golden.query<{ last_seen_at: Date; idle_expires_at: Date; consumed: number; jti_uses: number; jti_aliases: number; idempotency_results: number; idempotency_aliases: number; challenge_audit: number; success_audit: number; generation: string }>("SELECT s.last_seen_at,s.idle_expires_at,e.generation,(SELECT count(*)::int FROM control_plane.proof_challenges WHERE challenge_fingerprint=$2 AND consumed_at IS NOT NULL) AS consumed,(SELECT count(*)::int FROM control_plane.jti_uses) AS jti_uses,(SELECT count(*)::int FROM control_plane.jti_key_aliases WHERE key_id=$3 AND fingerprint=$4) AS jti_aliases,(SELECT count(*)::int FROM control_plane.idempotency_results) AS idempotency_results,(SELECT count(*)::int FROM control_plane.idempotency_key_aliases WHERE key_id=$5 AND fingerprint=$6) AS idempotency_aliases,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE event_type='challenge_consumed' AND outcome='success' AND mapping_id=$7 AND snapshot_id=$8) AS challenge_audit,(SELECT count(*)::int FROM control_plane.security_audit_events WHERE event_type='entitlement_decided' AND outcome='success' AND mapping_id=$7 AND snapshot_id=$8) AS success_audit FROM control_plane.identity_sessions s CROSS JOIN control_plane.entitlements e WHERE s.binding_fingerprint=$1 AND e.id=$9", [firstEntitlement.session_binding_fingerprint, overflowChallengeFingerprint, rings.active, overflowJtiFingerprint, rings.active, overflowIdempotencyFingerprint, established.mappingId, snapshotId, firstEntitlement.id])).rows[0]!;
        expect(overflowAfter).toEqual({ ...overflowBefore, generation: '9223372036854775807' });
      } finally { await golden.query("UPDATE control_plane.entitlements SET generation=4 WHERE id=$1", [firstEntitlement.id]); }
      const ids = (await golden.query<{ mapping_id: string; mapping_envelope: string; snapshot_id: string; policy_envelope: string }>('SELECT m.id mapping_id,m.envelope_id mapping_envelope,p.id snapshot_id,p.envelope_id policy_envelope FROM control_plane.did_mappings m CROSS JOIN control_plane.policy_snapshots p')).rows[0]!;
      expect(ids.mapping_id).toBe(established.mappingId); expect(ids.snapshot_id).toBe(snapshotId); expect(ids.mapping_id).not.toBe(ids.mapping_envelope); expect(ids.snapshot_id).not.toBe(ids.policy_envelope);
      const timing = (await golden.query<{ seconds: number; idle_capped: boolean }>("SELECT extract(epoch FROM expires_at-created_at)::int AS seconds, (SELECT idle_expires_at<=absolute_expires_at FROM control_plane.identity_sessions ORDER BY created_at LIMIT 1) AS idle_capped FROM control_plane.idempotency_results")).rows[0]!;
      expect(timing).toEqual({ seconds: 60, idle_capped: true });
      const cookieKey = randomBytes(32); const consoleMessages: string[] = []; const captureConsole = (...values: unknown[]) => { consoleMessages.push(values.map(String).join(' ')); };
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(captureConsole); const warnSpy = vi.spyOn(console, 'warn').mockImplementation(captureConsole); const logSpy = vi.spyOn(console, 'log').mockImplementation(captureConsole);
      const api = createApp({ config: { PWA_ORIGIN: pwaOrigin, COOKIE_KEY: cookieKey }, foundation: { exchangeIdentityHandoff: async () => ({ did: holderDid, audience: pwaOrigin, authenticatedAt: policyNow.toISOString(), expiresIn: 60 }) }, sessions, challenges, verifications: verification, logout: { logout: async () => undefined } });
      const extraTextCanaries: string[] = []; let originalPolicyCiphertext: Buffer | undefined; let policyCiphertextCorrupted = false;
      await new Promise<void>(resolve => api.listen(0, '127.0.0.1', resolve));
      try {
        const address = api.address(); if (!address || typeof address === 'string') throw new Error('no API address'); const base = `http://127.0.0.1:${address.port}`; const headers = { accept: 'application/json', 'content-type': 'application/json', origin: pwaOrigin };
        const handoff = await fetch(`${base}/v1/identity/sessions`, { method: 'POST', headers, body: JSON.stringify({ version: 'v1', code: 'A'.repeat(43), verifier: 'B'.repeat(43), audience: pwaOrigin }) }); expect(handoff.status).toBe(201); const cookie = handoff.headers.get('set-cookie')?.split(';')[0]; expect(cookie).toBeTruthy();
        const recoveredSession = readSessionCookie(cookie, cookieKey); expect(recoveredSession.duplicate).toBe(false); expect(recoveredSession.id).toMatch(/^[A-Za-z0-9_-]{43}$/); const rawHttpSessionId = recoveredSession.id!; extraTextCanaries.push(cookie!, rawHttpSessionId);
        const issuedHttp = await fetch(`${base}/v1/entitlements/challenges`, { method: 'POST', headers: { ...headers, cookie: cookie! }, body: JSON.stringify({ version: 'v1', jkt }) }); expect(issuedHttp.status).toBe(201); const challengeHttp = (await issuedHttp.json() as { challenge: string }).challenge;
        const httpInput = await signValidInput(challengeHttp); const verifiedHttp = await fetch(`${base}/v1/entitlements/verifications`, { method: 'POST', headers: { ...headers, cookie: cookie! }, body: httpInput.rawBody }); expect(verifiedHttp.status).toBe(200); expect(await verifiedHttp.json()).toEqual({ version: 'v1', result: 'authorized' });
        const exactRetry = await fetch(`${base}/v1/entitlements/verifications`, { method: 'POST', headers: { ...headers, cookie: cookie! }, body: httpInput.rawBody }); expect(exactRetry.status).toBe(200); expect(await exactRetry.json()).toEqual({ version: 'v1', result: 'authorized' });
        const changedRawBody = Buffer.from(JSON.stringify(httpInput.input, null, 1)); extraTextCanaries.push(changedRawBody.toString()); const changedRetry = await fetch(`${base}/v1/entitlements/verifications`, { method: 'POST', headers: { ...headers, cookie: cookie! }, body: changedRawBody }); expect(changedRetry.status).toBe(409); expect(await changedRetry.json()).toEqual({ version: 'v1', result: 'rejected', error: 'conflict' });

        const invalidChallengeResponse = await fetch(`${base}/v1/entitlements/challenges`, { method: 'POST', headers: { ...headers, cookie: cookie! }, body: JSON.stringify({ version: 'v1', jkt }) }); expect(invalidChallengeResponse.status).toBe(201); const invalidChallenge = (await invalidChallengeResponse.json() as { challenge: string }).challenge;
        const invalidSigned = await signValidInput(invalidChallenge); const invalidSignature = `${invalidSigned.signature[0] === 'A' ? 'B' : 'A'}${invalidSigned.signature.slice(1)}`; const invalidRawBody = Buffer.from(JSON.stringify({ ...invalidSigned.input, signature: invalidSignature })); extraTextCanaries.push(invalidSignature, invalidRawBody.toString());
        const invalidResponse = await fetch(`${base}/v1/entitlements/verifications`, { method: 'POST', headers: { ...headers, cookie: cookie! }, body: invalidRawBody }); expect(invalidResponse.status).toBe(401); expect(await invalidResponse.json()).toEqual({ version: 'v1', result: 'rejected', error: 'rejected' });

        const unavailableChallengeResponse = await fetch(`${base}/v1/entitlements/challenges`, { method: 'POST', headers: { ...headers, cookie: cookie! }, body: JSON.stringify({ version: 'v1', jkt }) }); expect(unavailableChallengeResponse.status).toBe(201); const unavailableChallenge = (await unavailableChallengeResponse.json() as { challenge: string }).challenge; const unavailableSigned = await signValidInput(unavailableChallenge);
        originalPolicyCiphertext = Buffer.from((await golden.query<{ ciphertext: Buffer }>('SELECT ciphertext FROM control_plane.encrypted_envelopes WHERE id=$1', [ids.policy_envelope])).rows[0]!.ciphertext); const corruptedPolicyCiphertext = Buffer.from(originalPolicyCiphertext); corruptedPolicyCiphertext[0] ^= 1;
        await golden.query('UPDATE control_plane.encrypted_envelopes SET ciphertext=$1 WHERE id=$2', [corruptedPolicyCiphertext, ids.policy_envelope]); policyCiphertextCorrupted = true;
        const unavailableResponse = await fetch(`${base}/v1/entitlements/verifications`, { method: 'POST', headers: { ...headers, cookie: cookie! }, body: unavailableSigned.rawBody }); expect(unavailableResponse.status).toBe(503); expect(await unavailableResponse.json()).toEqual({ version: 'v1', result: 'rejected', error: 'unavailable' });
        await golden.query('UPDATE control_plane.encrypted_envelopes SET ciphertext=$1 WHERE id=$2', [originalPolicyCiphertext, ids.policy_envelope]); policyCiphertextCorrupted = false;
        const recoveredResponse = await fetch(`${base}/v1/entitlements/verifications`, { method: 'POST', headers: { ...headers, cookie: cookie! }, body: unavailableSigned.rawBody }); expect(recoveredResponse.status).toBe(200); expect(await recoveredResponse.json()).toEqual({ version: 'v1', result: 'authorized' });
      } finally {
        if (policyCiphertextCorrupted && originalPolicyCiphertext) await golden.query('UPDATE control_plane.encrypted_envelopes SET ciphertext=$1 WHERE id=$2', [originalPolicyCiphertext, ids.policy_envelope]);
        errorSpy.mockRestore(); warnSpy.mockRestore(); logSpy.mockRestore();
        api.closeAllConnections(); if (api.listening) await new Promise<void>((resolve, reject) => api.close(error => error ? reject(error) : resolve()));
      }
      const policyPlaintext = JSON.stringify({ compact: compactPolicy, provenance: { uri: policyUri, cid: 'bafy-task5', repoDid: rootDid, repoRev: 'task5', sequence: 0, observedAt: policyNow.toISOString(), status: 'verified', authority: { status: 'official', policyUri, policyVersion: version, rootDid, evaluatedAt: policyNow.toISOString() } } });
      const canaries = [holderDid, issuerDid, rootDid, publicJwk.x, publicJwk.y, `${issuerDid}#issuer-key`, compactPolicy, Buffer.from(compactPolicy.split('.')[1]!, 'base64url').toString(), JSON.stringify(policyPayload), policyPlaintext, JSON.stringify(publicJwk), ...extraTextCanaries, ...signedInputs.flatMap(signed => [signed.credential, Buffer.from(signed.credential.split('.')[1]!, 'base64url').toString(), signed.challenge, signed.jti, signed.idempotencyKey, signed.signature, signed.rawBody.toString(), `dsa-signal-proof:v1\n${signed.challenge}\n${pwaOrigin}\ndsa-signal\n${holderDid}\n${jkt}\n${signed.jti}`])];
      const rawAtoms = [Buffer.from(extraTextCanaries[1]!, 'base64url'), Buffer.from(publicJwk.x, 'base64url'), Buffer.from(publicJwk.y, 'base64url'), Buffer.from('A'.repeat(43)), Buffer.from('B'.repeat(43)), ...signedInputs.flatMap(signed => [signed.challenge, signed.jti, signed.idempotencyKey, signed.signature, signed.credential.split('.')[2]!].map(value => Buffer.from(value, 'base64url'))), Buffer.from(compactPolicy.split('.')[2]!, 'base64url')]; for (const atom of rawAtoms) expect(atom.length).toBeGreaterThanOrEqual(16);
      for (const canary of canaries) expect(consoleMessages.join('\n')).not.toContain(canary);
      const columns = await golden.query<{ table_name: string; column_name: string; data_type: 'text' | 'bytea' }>("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='control_plane' AND table_name<>'encrypted_envelopes' AND data_type IN ('text','bytea')");
      for (const column of columns.rows) for (const canary of canaries) expect((await golden.query<{ count: number }>(`SELECT count(*)::int AS count FROM control_plane.${column.table_name} WHERE position($1${column.data_type === 'bytea' ? '::bytea' : ''} in ${column.column_name})>0`, [column.data_type === 'bytea' ? Buffer.from(canary) : canary])).rows[0]!.count).toBe(0);
      for (const column of columns.rows.filter(column => column.data_type === 'bytea')) for (const atom of rawAtoms) expect((await golden.query<{ count: number }>(`SELECT count(*)::int AS count FROM control_plane.${column.table_name} WHERE position($1::bytea in ${column.column_name})>0`, [atom])).rows[0]!.count).toBe(0);
       for (const canary of canaries.filter(canary => Buffer.byteLength(canary, 'utf8') >= 16)) expect((await golden.query<{ count: number }>('SELECT count(*)::int AS count FROM control_plane.encrypted_envelopes WHERE position($1::bytea in ciphertext)>0', [Buffer.from(canary)])).rows[0]!.count).toBe(0);
       for (const atom of rawAtoms) expect((await golden.query<{ count: number }>('SELECT count(*)::int AS count FROM control_plane.encrypted_envelopes WHERE position($1::bytea in ciphertext)>0', [atom])).rows[0]!.count).toBe(0);
    } finally { await runtimePool.end(); await golden.end(); await pool.query(`DROP DATABASE ${database}`); }
  }, 30_000);

  it('runs createComposition through the published Foundation transport as the runtime role', async () => {
    const database = `cp_composition_${suffix}`;
    await pool.query(`CREATE DATABASE ${database}`);
    const ownerPool = new Pool({ connectionString: `postgresql://postgres:test@127.0.0.1:${postgresPort}/${database}` });
    const runtimePool = new Pool({ connectionString: `postgresql://${runtime}:runtime-test-only@127.0.0.1:${postgresPort}/${database}`, application_name: `composition-runtime-${suffix}` });
    let foundationServer: ReturnType<typeof createServer> | undefined;
    let api: ReturnType<typeof createApp> | undefined;
    const output: string[] = []; const capture = (...values: unknown[]) => output.push(values.map(String).join(' '));
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(capture); const warnSpy = vi.spyOn(console, 'warn').mockImplementation(capture); const logSpy = vi.spyOn(console, 'log').mockImplementation(capture);
    try {
      await applyControlPlaneMigration(ownerPool, runtime, retention, undefined, revocation, ['test']);
      const [root, issuer, holder] = await Promise.all([generateKeyPair('ES256'), generateKeyPair('ES256'), generateKeyPair('ES256')]);
      const [rootJwk, issuerJwk, holderJwk] = await Promise.all([exportJWK(root.publicKey), exportJWK(issuer.publicKey), exportJWK(holder.publicKey)]);
      const rootDid = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa'; const issuerDid = 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb'; const holderDid = 'did:plc:cccccccccccccccccccccccc';
      const pwaOrigin = 'https://pwa.example'; const version = '2026.07-1'; const policyUri = `at://${rootDid}/us.dsaslate.temp.dsaPolicy/rkey`;
      const ring = (): Config['SUBJECT_KEY_RING'] => ({ active: 'test', keys: { test: randomBytes(32) } });
      const config: Config = { APP_ENV: 'test', PORT: 8080, DATABASE_URL: `postgresql://${runtime}:runtime-test-only@127.0.0.1:${postgresPort}/${database}`, CONTROL_PLANE_RUNTIME_ROLE: runtime, PUBLIC_BASE_URL: pwaOrigin, FOUNDATION_BASE_URL: 'https://foundation.example', PWA_ORIGIN: pwaOrigin, OIDC_ISSUER: `${pwaOrigin}/oidc`, OIDC_SECTOR: 'https://oidc.example', OIDC_EPOCH: 'AAAAAAAAAAAAAAAAAAAAAA', OIDC_TRUSTED_PROXY_ADDRESS: '127.0.0.1', MAS_CLIENT_ID: 'dsa-signal', MAS_REDIRECT_URI: 'https://oidc.example/upstream/callback/01J00000000000000000000000', OIDC_SIGNING_JWKS_PATH: '/run/secrets/signing', MAS_CLIENT_SECRET_PATH: '/run/secrets/client', OIDC_COOKIE_KEYS_PATH: '/run/secrets/cookies', COOKIE_SECURE: true, COOKIE_KEY: randomBytes(32), SUBJECT_KEY_RING: ring(), ENVELOPE_KEY_RING: ring(), CHALLENGE_KEY_RING: ring(), SESSION_BINDING_KEY_RING: ring(), JTI_KEY_RING: ring(), IDEMPOTENCY_KEY_RING: ring(), REQUEST_FINGERPRINT_KEY_RING: ring(), OIDC_ADAPTER_KEY_RING: ring(), OIDC_INDEX_KEY_RING: ring(), REVOCATION_EVIDENCE_KEY_RING: ring(), ROOT_DIDS: [rootDid], AUTHORITY_POLICY_VERSION: version, POLICY_MAX_STALENESS_SECONDS: 300, ROOT_PUBLIC_JWKS: { [`${rootDid}#root`]: parsePublicJwk(rootJwk) } };
      const now = (await ownerPool.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]!.now;
      const policy = { version: 'v1', policyVersion: version, policyUri, rootDid, issuedAt: Math.floor(now.getTime() / 1000) - 1, freshUntil: Math.floor(now.getTime() / 1000) + 299, issuers: [{ did: issuerDid, policies: [{ version, state: 'active', transitionedAt: 0 }], keys: [{ kid: `${issuerDid}#key`, state: 'active', transitionedAt: 0, publicJwk: parsePublicJwk(issuerJwk) }] }] };
      const compactPolicy = await new CompactSign(Buffer.from(JSON.stringify(policy))).setProtectedHeader({ alg: 'ES256', typ: 'dsa-signal-issuer-policy+jws', kid: `${rootDid}#root` }).sign(root.privateKey);
      const requests: { method: string; path: string; query: URLSearchParams; body: unknown }[] = [];
      foundationServer = createServer(async (req, res) => {
        const url = new URL(req.url ?? '/', 'http://localhost'); const chunks: Buffer[] = []; for await (const chunk of req) chunks.push(Buffer.from(chunk));
        const body = chunks.length === 0 ? undefined : JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
        requests.push({ method: req.method ?? '', path: url.pathname, query: url.searchParams, body });
        res.setHeader('content-type', 'application/json');
        if (req.method === 'POST' && url.pathname === '/oauth/identity/v1/exchange') { expect(body).toEqual({ code: 'A'.repeat(43), verifier: 'B'.repeat(43), audience: pwaOrigin }); res.end(JSON.stringify({ did: holderDid, audience: pwaOrigin, authenticatedAt: now.toISOString(), expiresIn: 60 })); return; }
        if (req.method === 'GET' && url.pathname === '/xrpc/us.dsaslate.temp.resolveAuthority') { expect(url.searchParams.get('uri')).toBe(policyUri); expect(url.searchParams.get('depth')).toBe('16'); res.end(JSON.stringify({ uri: policyUri, provenance: { uri: policyUri, cid: 'bafy-composition', repoDid: rootDid, repoRev: 'composition', sequence: 0, observedAt: now.toISOString(), status: 'verified', ignored: 'extension' }, authority: { status: 'official', policyUri, policyVersion: version, rootDid, chain: [], reasons: [], evaluatedAt: now.toISOString(), ignored: 'extension' }, ignored: 'extension' })); return; }
        res.statusCode = 404; res.end(JSON.stringify({ error: 'not_found' }));
      });
      await new Promise<void>(resolve => foundationServer!.listen(0, '127.0.0.1', resolve));
      const address = foundationServer.address(); if (!address || typeof address === 'string') throw new Error('no Foundation address');
      const rewritingFetch: typeof fetch = (input, init) => { const original = new URL(input instanceof Request ? input.url : input instanceof URL ? input.href : input); original.protocol = 'http:'; original.hostname = '127.0.0.1'; original.port = String(address.port); return fetch(original, init); };
      const retained = await runtimePool.connect(); try { await assertRetainedKeys(retained, { subject: config.SUBJECT_KEY_RING.keys, envelope: config.ENVELOPE_KEY_RING.keys, challenge: Object.keys(config.CHALLENGE_KEY_RING.keys), binding: Object.keys(config.SESSION_BINDING_KEY_RING.keys), jti: { active: config.JTI_KEY_RING.active, retained: Object.keys(config.JTI_KEY_RING.keys) }, idempotency: { active: config.IDEMPOTENCY_KEY_RING.active, retained: Object.keys(config.IDEMPOTENCY_KEY_RING.keys) }, request: Object.keys(config.REQUEST_FINGERPRINT_KEY_RING.keys), evidence: Object.keys(config.REVOCATION_EVIDENCE_KEY_RING.keys), oidc: { epoch: config.OIDC_EPOCH, adapter: config.OIDC_ADAPTER_KEY_RING.keys, index: Object.keys(config.OIDC_INDEX_KEY_RING.keys) } }); } finally { retained.release(); }
      const composition = createComposition(config, runtimePool, rewritingFetch);
      await composition.policyRefresh.refresh(compactPolicy);
      expect((await ownerPool.query('SELECT * FROM control_plane.active_policy')).rowCount).toBe(1);
      api = createApp(composition); await new Promise<void>(resolve => api!.listen(0, '127.0.0.1', resolve));
      const apiAddress = api.address(); if (!apiAddress || typeof apiAddress === 'string') throw new Error('no API address'); const base = `http://127.0.0.1:${apiAddress.port}`; const headers = { accept: 'application/json', 'content-type': 'application/json', origin: pwaOrigin };
      const identity = await fetch(`${base}/v1/identity/sessions`, { method: 'POST', headers, body: JSON.stringify({ version: 'v1', code: 'A'.repeat(43), verifier: 'B'.repeat(43), audience: pwaOrigin }) }); expect(identity.status).toBe(201); const cookie = identity.headers.get('set-cookie')!.split(';')[0]!;
      const publicJwk = parsePublicJwk(holderJwk); const jkt = jwkThumbprint(publicJwk); const challengeResponse = await fetch(`${base}/v1/entitlements/challenges`, { method: 'POST', headers: { ...headers, cookie }, body: JSON.stringify({ version: 'v1', jkt }) }); expect(challengeResponse.status).toBe(201); const challenge = (await challengeResponse.json() as { challenge: string }).challenge;
      const jti = randomBytes(32).toString('base64url'); const credential = await new CompactSign(Buffer.from(JSON.stringify({ iss: issuerDid, sub: holderDid, aud: 'dsa-signal', iat: Math.floor(now.getTime() / 1000) - 1, exp: Math.floor(now.getTime() / 1000) + 120, jti, cnf: { jkt }, entitlement: 'chat', policyVersion: version }))).setProtectedHeader({ alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: `${issuerDid}#key` }).sign(issuer.privateKey);
      const proof = `dsa-signal-proof:v1\n${challenge}\n${pwaOrigin}\ndsa-signal\n${holderDid}\n${jkt}\n${jti}`; const signature = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holder.privateKey, Buffer.from(proof))).toString('base64url'); const input = { version: 'v1', idempotencyKey: randomBytes(32).toString('base64url'), challenge, signature, publicJwk, credential }; const raw = Buffer.from(JSON.stringify(input));
      for (const expected of [200, 200]) expect((await fetch(`${base}/v1/entitlements/verifications`, { method: 'POST', headers: { ...headers, cookie }, body: raw })).status).toBe(expected);
      expect((await fetch(`${base}/v1/entitlements/verifications`, { method: 'POST', headers: { ...headers, cookie }, body: Buffer.from(JSON.stringify(input, null, 1)) })).status).toBe(409);
      const badChallengeResponse = await fetch(`${base}/v1/entitlements/challenges`, { method: 'POST', headers: { ...headers, cookie }, body: JSON.stringify({ version: 'v1', jkt }) }); expect(badChallengeResponse.status).toBe(201); const badChallenge = (await badChallengeResponse.json() as { challenge: string }).challenge;
      const bad = Buffer.from(JSON.stringify({ ...input, challenge: badChallenge, idempotencyKey: randomBytes(32).toString('base64url'), signature: `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}` })); expect((await fetch(`${base}/v1/entitlements/verifications`, { method: 'POST', headers: { ...headers, cookie }, body: bad })).status).toBe(401);
      expect(requests.map(request => `${request.method} ${request.path}`)).toEqual(['GET /xrpc/us.dsaslate.temp.resolveAuthority', 'POST /oauth/identity/v1/exchange']);
      for (const secret of [compactPolicy, credential, signature, challenge, cookie]) expect(output.join('\n')).not.toContain(secret);
    } finally { errorSpy.mockRestore(); warnSpy.mockRestore(); logSpy.mockRestore(); api?.closeAllConnections(); if (api?.listening) await new Promise<void>((resolve, reject) => api!.close(error => error ? reject(error) : resolve())); if (foundationServer?.listening) await new Promise<void>((resolve, reject) => foundationServer!.close(error => error ? reject(error) : resolve())); await runtimePool.end(); await ownerPool.end(); await pool.query(`DROP DATABASE ${database}`); }
  }, 30_000);

  it('runs Slice 5 transaction disposition paths against a checked-out PostgreSQL client', async () => {
    const real = await pool.connect();
    let released = false;
    let releasePoison: Error | undefined;
    let indeterminateRollbacks = 0;
    try {
      await real.query('CREATE TEMPORARY TABLE oidc_transaction_probe (marker text PRIMARY KEY)');
      const transaction = async (fault: { rollbackToSavepoint?: boolean; commit?: 'definite' | 'indeterminate' } = {}, work: (context: import('./oidc/request-context.js').OidcRequestContext) => Promise<void>): Promise<void> => {
        let rollbackToSavepointAttempts = 0;
        const client = new Proxy(real, { get(target, property, receiver) {
          if (property === 'query') return async (...args: Parameters<PoolClient['query']>) => {
            const sql = args[0];
            if (fault.rollbackToSavepoint && /^ROLLBACK TO SAVEPOINT /i.test(sql)) { rollbackToSavepointAttempts += 1; throw new Error('injected savepoint rollback failure'); }
            if (fault.commit === 'definite' && sql === 'COMMIT') { await target.query('ROLLBACK'); throw Object.assign(new Error('injected serialization failure'), { code: '40001' }); }
            if (fault.commit === 'indeterminate' && sql === 'COMMIT') { await target.query('COMMIT'); throw new Error('injected connection reset'); }
            if (fault.commit === 'indeterminate' && sql === 'ROLLBACK') indeterminateRollbacks += 1;
            return target.query(...args);
          };
          if (property === 'release') return (poison?: Error) => { released = true; releasePoison = poison; };
          return Reflect.get(target, property, receiver);
        } }) as PoolClient;
        const wrappedPool = { connect: async () => client } as Pick<Pool, 'connect'>;
        try { await runOidcTransaction(wrappedPool, work); }
        finally { if (fault.rollbackToSavepoint) expect(rollbackToSavepointAttempts).toBe(1); }
      };
      const markers = async (): Promise<string[]> => (await real.query<{ marker: string }>('SELECT marker FROM oidc_transaction_probe ORDER BY marker')).rows.map(row => row.marker);

      await transaction({}, async context => { await context.client.query("INSERT INTO oidc_transaction_probe VALUES ('success')"); });
      expect(await markers()).toEqual(['success']);
      await expect(transaction({}, async context => { await context.client.query("INSERT INTO oidc_transaction_probe VALUES ('pre-error')"); throw new Error('before consume'); })).rejects.toThrow('before consume');
      expect(await markers()).toEqual(['success']);
      await expect(transaction({}, async context => { await context.client.query("INSERT INTO oidc_transaction_probe VALUES ('consumed')"); await context.client.query('SAVEPOINT oidc_after_code_consume'); context.tokenConsumeSavepoint = 'oidc_after_code_consume'; await context.client.query("INSERT INTO oidc_transaction_probe VALUES ('after-consume')"); throw new Error('after consume'); })).rejects.toThrow('after consume');
      expect(await markers()).toEqual(['consumed', 'success']);
      await expect(transaction({}, async context => { void serializeOidcAdapterCall(async () => { throw new Error('queued failure'); }).catch(() => undefined); void serializeOidcAdapterCall(async () => { await context.client.query("INSERT INTO oidc_transaction_probe VALUES ('queued')"); }).catch(() => undefined); })).rejects.toThrow('queued failure');
      expect(await markers()).toEqual(['consumed', 'success']);
      await expect(transaction({ rollbackToSavepoint: true }, async context => { await context.client.query("INSERT INTO oidc_transaction_probe VALUES ('failed-consume')"); await context.client.query('SAVEPOINT oidc_after_code_consume'); context.tokenConsumeSavepoint = 'oidc_after_code_consume'; await context.client.query("INSERT INTO oidc_transaction_probe VALUES ('failed-later')"); throw new Error('after consume with broken savepoint'); })).rejects.toThrow('after consume with broken savepoint');
      expect(await markers()).toEqual(['consumed', 'success']);
      const definiteCommit = transaction({ commit: 'definite' }, async context => { await context.client.query("INSERT INTO oidc_transaction_probe VALUES ('definite-commit')"); });
      await expect(definiteCommit).rejects.toMatchObject({ code: '40001' });
      await expect(definiteCommit).rejects.not.toBeInstanceOf(OidcIndeterminateCommitError);
      expect(await markers()).toEqual(['consumed', 'success']);
      await expect(transaction({ commit: 'indeterminate' }, async context => { await context.client.query("INSERT INTO oidc_transaction_probe VALUES ('indeterminate-commit')"); })).rejects.toBeInstanceOf(OidcIndeterminateCommitError);
      expect(await markers()).toEqual(['consumed', 'indeterminate-commit', 'success']);
      expect(indeterminateRollbacks).toBe(0);
      expect(released).toBe(true);
      expect(releasePoison).toBeInstanceOf(OidcIndeterminateCommitError);
    } finally {
      await real.query('DROP TABLE IF EXISTS oidc_transaction_probe').catch(() => undefined);
      real.release();
    }
  });

  it('runs isolated OIDC restore against PostgreSQL 17', async () => {
    const database = `cp_oidc_restore_${suffix}`;
    const floor = await mkdtemp(join(tmpdir(), 'dsa-signal-restore-'));
    let owner: Pool | undefined;
    let runtimePool: Pool | undefined;
    try {
      await chmod(floor, 0o700);
      owner = await legacyPool(database, true);
      await applyControlPlaneMigration(owner, runtime, retention, undefined, revocation, evidenceKeyIds);
      runtimePool = new Pool({ connectionString: `postgresql://${runtime}:runtime-test-only@127.0.0.1:${postgresPort}/${database}` });
      const backup = getConfig({ APP_ENV: 'test', DATABASE_URL: `postgresql://${runtime}:runtime-test-only@127.0.0.1:${postgresPort}/${database}`, CONTROL_PLANE_RUNTIME_ROLE: runtime, OIDC_RESTORE_FLOOR_DIR: floor });
      const did = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa'; const mapping = randomUUID(); const snapshot = randomUUID(); const session = randomUUID(); const entitlement = randomUUID();
      const didEnvelope = randomUUID(); const policyEnvelope = randomUUID(); const policyVersion = 'restore-canary';
      const seal = async (id: string, purpose: 'did' | 'policy', parent: string, extra: string, plaintext: string): Promise<void> => {
        const nonce = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', backup.ENVELOPE_KEY_RING.keys[backup.ENVELOPE_KEY_RING.active]!, nonce);
        cipher.setAAD(Buffer.from(`dsa-signal-${purpose === 'did' ? 'did-mapping' : 'policy-snapshot'}:v1\0${parent}\0${extra}`));
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
        await owner!.query('INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose) VALUES($1,$2,$3,$4,$5)', [id, backup.ENVELOPE_KEY_RING.active, nonce, ciphertext, purpose]);
      };
      const subject = derivePairwiseSubject(backup.SUBJECT_KEY_RING.keys[backup.SUBJECT_KEY_RING.active]!, backup.OIDC_SECTOR, did);
      await seal(didEnvelope, 'did', mapping, backup.OIDC_SECTOR, did);
      await insertMapping(owner, mapping, backup.OIDC_SECTOR, backup.SUBJECT_KEY_RING.active, subject, didEnvelope);
      await seal(policyEnvelope, 'policy', snapshot, policyVersion, 'stale-policy-canary');
      await owner.query("INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) VALUES($1,$2,$3,$4,clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour',clock_timestamp())", [snapshot, randomBytes(32), policyEnvelope, policyVersion]);
      await owner.query("INSERT INTO control_plane.security_audit_events(id,event_type,mapping_id,snapshot_id,outcome,reason,occurred_at) VALUES($1,'policy_activated',$2,$3,'success','policy',clock_timestamp())", [randomUUID(), mapping, snapshot]);
      const binding = createHmac('sha256', backup.SESSION_BINDING_KEY_RING.keys[backup.SESSION_BINDING_KEY_RING.active]!).update('dsa-signal-session-fingerprint:v1\0restore-session-canary').digest();
      await owner.query("WITH t AS (SELECT clock_timestamp() now) INSERT INTO control_plane.identity_sessions(id,binding_key_id,binding_fingerprint,mapping_id,origin,created_at,last_seen_at,idle_expires_at,absolute_expires_at) SELECT $1,$2,$3,$4,$5,now,now,now+interval '5 minutes',now+interval '15 minutes' FROM t", [session, backup.SESSION_BINDING_KEY_RING.active, binding, mapping, backup.PWA_ORIGIN]);
      await insertEntitlement("WITH t AS (SELECT clock_timestamp() now) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,$5,now,now+interval '15 minutes','membership_verified',$6,$7,$8,1 FROM t", [entitlement, mapping, randomBytes(32), snapshot, policyVersion, backup.OIDC_EPOCH, backup.SESSION_BINDING_KEY_RING.active, binding], [entitlement], owner);
      const grantId = 'restore-grant-canary'; const interactionId = 'restore-interaction-canary'; const grantPayload = { jti: 'restore-payload-canary', accountId: mapping, clientId: backup.MAS_CLIENT_ID };
      const Adapter = createOidcAdapter({ epoch: backup.OIDC_EPOCH, adapter: backup.OIDC_ADAPTER_KEY_RING, index: backup.OIDC_INDEX_KEY_RING });
      await runOidcTransaction(runtimePool, async () => { await new Adapter('Grant').upsert(grantId, grantPayload, 900); await new Adapter('Interaction').upsert(interactionId, { uid: 'restore-interaction-payload-canary' }, 300); });
      const indexKey = backup.OIDC_INDEX_KEY_RING.keys[backup.OIDC_INDEX_KEY_RING.active]!;
      const grant = createHmac('sha256', indexKey).update(`dsa-signal-oidc-grant-id:v1\0${backup.OIDC_EPOCH}\0`).update(grantId).digest();
      const fp = (name: string): Buffer => createHmac('sha256', indexKey).update(`restore-${name}\0`).update('restore-raw-canary').digest();
      await owner.query("WITH t AS (SELECT clock_timestamp() now) INSERT INTO oidc.authorization_contexts(id,epoch,client_key_id,client_fingerprint,grant_key_id,grant_fingerprint,interaction_chain_key_id,interaction_chain_fingerprint,interaction_uid_key_id,interaction_uid_fingerprint,control_session_key_id,control_session_fingerprint,mapping_id,entitlement_id,generation,jkt,policy_snapshot_id,policy_version,created_at,expires_at,grant_expires_at,retained_until) SELECT $1,$2,$3,$4,$3,$5,$3,$6,$3,$7,$8,$9,$10,$11,1,$12,$13,$14,now,now+interval '300 seconds',now+interval '900 seconds',now+interval '930 seconds' FROM t", [randomUUID(), backup.OIDC_EPOCH, backup.OIDC_INDEX_KEY_RING.active, fp('client'), grant, fp('chain'), fp('interaction'), backup.SESSION_BINDING_KEY_RING.active, binding, mapping, entitlement, randomBytes(32).toString('base64url'), snapshot, policyVersion]);
      await owner.query("WITH t AS (SELECT clock_timestamp() now) INSERT INTO oidc.interaction_csrf(id,epoch,csrf_key_id,csrf_fingerprint,client_key_id,client_fingerprint,interaction_chain_key_id,interaction_chain_fingerprint,interaction_uid_key_id,interaction_uid_fingerprint,created_at,expires_at,retained_until) SELECT $1,$2,$3,$4,$3,$5,$3,$6,$3,$7,now,now+interval '300 seconds',now+interval '330 seconds' FROM t", [randomUUID(), backup.OIDC_EPOCH, backup.OIDC_INDEX_KEY_RING.active, fp('csrf'), fp('client'), fp('chain'), fp('interaction')]);
      const secrets = async (kid: string, cookie: Uint8Array, clientSecret: Uint8Array): Promise<OidcSecrets> => { const pair = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true }); const privateKey = { ...await exportJWK(pair.privateKey), kid, use: 'sig' as const, alg: 'RS256' as const } as OidcSecrets['signingKeys'][number]; return { clientSecret, cookieKeys: [cookie], signingKeys: [privateKey], publicJwks: { keys: [{ kty: 'RSA', n: privateKey.n!, e: privateKey.e!, kid, use: 'sig', alg: 'RS256' }] } }; };
      const backupSecrets = await secrets('restore-old', randomBytes(32), randomBytes(32)); const freshSecrets = await secrets('restore-new', randomBytes(32), randomBytes(32));
      const fresh = { epoch: randomBytes(16).toString('base64url'), adapter: { active: 'new', keys: { new: randomBytes(32) } }, index: { active: 'new', keys: { new: randomBytes(32) } } };
      expect(() => assertFreshMaterial(backup, { ...fresh, epoch: backup.OIDC_EPOCH }, freshSecrets, backupSecrets)).toThrow('OIDC restore unavailable');
      expect(() => assertFreshMaterial(backup, { ...fresh, index: { active: 'new', keys: { new: fresh.adapter.keys.new } } }, freshSecrets, backupSecrets)).toThrow('OIDC restore unavailable');
      expect(() => assertFreshMaterial(backup, fresh, { ...freshSecrets, cookieKeys: backupSecrets.cookieKeys }, backupSecrets)).toThrow('OIDC restore unavailable');
      expect(() => assertFreshMaterial(backup, fresh, { ...freshSecrets, clientSecret: backupSecrets.clientSecret }, backupSecrets)).toThrow('OIDC restore unavailable');
      expect(() => assertFreshMaterial(backup, fresh, { ...freshSecrets, signingKeys: freshSecrets.signingKeys.map(key => ({ ...key, kid: 'restore-old' })), publicJwks: { keys: freshSecrets.publicJwks.keys.map(key => ({ ...key, kid: 'restore-old' })) } }, backupSecrets)).toThrow('OIDC restore unavailable');
      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE position($1::bytea in ciphertext)>0", [Buffer.from('restore-payload-canary')])).rows[0]!.count).toBe(0);
      const trusted = new Date(Math.floor(Date.now() / 1000) * 1000);
      const deps = { pool: owner, runtimeRole: runtime, retentionRole: retention, claimantRole: revocation };
      const result = await runOidcRestore(deps, backup, fresh, backupSecrets, freshSecrets, trusted, { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD });
      expect(result.phase).toBe('committed'); expect(result.minimumIssuedAt).toBe(Math.floor(trusted.getTime() / 1000) + 1);
      for (const table of ['control_plane.identity_sessions', 'control_plane.entitlements', 'oidc.provider_artifacts', 'oidc.authorization_contexts', 'oidc.interaction_csrf']) { expect(result.purged[table]).toBeGreaterThan(0); expect((await owner.query<{ count: number }>(`SELECT count(*)::int count FROM ${table}`)).rows[0]!.count).toBe(0); }
      const activation = restoreActivation({ OIDC_EPOCH: fresh.epoch, OIDC_ADAPTER_KEY_RING: fresh.adapter, OIDC_INDEX_KEY_RING: fresh.index }, freshSecrets);
      expect(await loadRestoreFloor(floor, result.head, activation)).toEqual({ minimumIssuedAt: result.minimumIssuedAt, sequence: result.sequence, head: result.head });
      expect((await owner.query('SELECT id FROM control_plane.did_mappings WHERE id=$1', [mapping])).rowCount).toBe(1); expect((await owner.query('SELECT id FROM control_plane.policy_snapshots WHERE id=$1', [snapshot])).rowCount).toBe(1); expect((await owner.query('SELECT id FROM control_plane.encrypted_envelopes WHERE id=ANY($1)', [[didEnvelope, policyEnvelope]])).rowCount).toBe(2); expect((await owner.query('SELECT * FROM control_plane.security_audit_events WHERE mapping_id=$1 AND snapshot_id=$2', [mapping, snapshot])).rowCount).toBe(1);
      const retained = await owner.connect(); try { await assertRetainedKeys(retained, { subject: backup.SUBJECT_KEY_RING.keys, envelope: backup.ENVELOPE_KEY_RING.keys, challenge: Object.keys(backup.CHALLENGE_KEY_RING.keys), binding: Object.keys(backup.SESSION_BINDING_KEY_RING.keys), jti: { active: backup.JTI_KEY_RING.active, retained: Object.keys(backup.JTI_KEY_RING.keys) }, idempotency: { active: backup.IDEMPOTENCY_KEY_RING.active, retained: Object.keys(backup.IDEMPOTENCY_KEY_RING.keys) }, request: Object.keys(backup.REQUEST_FINGERPRINT_KEY_RING.keys), evidence: Object.keys(backup.REVOCATION_EVIDENCE_KEY_RING.keys), oidc: { epoch: fresh.epoch, adapter: fresh.adapter.keys, index: Object.keys(fresh.index.keys) } }); } finally { retained.release(); }
      expect((await owner.query("SELECT count(*)::int count FROM control_plane.schema_migrations WHERE id='0004_mas_upstream_oidc'")).rows[0]!.count).toBe(1);
      await expect(runOidcTransaction(runtimePool, async () => new Adapter('Grant').find(grantId))).resolves.toBeUndefined(); await expect(runOidcTransaction(runtimePool, async () => new Adapter('Interaction').find(interactionId))).resolves.toBeUndefined();
      const retry = await runOidcRestore(deps, backup, fresh, backupSecrets, freshSecrets, trusted, { expectedPreviousFloor: 0, expectedNextSequence: 1, expectedHead: INITIAL_RESTORE_FLOOR_HEAD });
      expect(retry.minimumIssuedAt).toBe(result.minimumIssuedAt); expect(Object.values(retry.purged).every(count => count === 0)).toBe(true); expect(await loadRestoreFloor(floor, retry.head, activation)).toEqual({ minimumIssuedAt: retry.minimumIssuedAt, sequence: retry.sequence, head: retry.head });
      expect((await owner.query('SELECT count(*)::int count FROM oidc.provider_artifacts WHERE position($1::bytea in ciphertext)>0', [Buffer.from('restore-payload-canary')])).rows[0]!.count).toBe(0);
    } finally { await runtimePool?.end(); await owner?.end(); await pool.query(`DROP DATABASE IF EXISTS ${database}`); await rm(floor, { recursive: true, force: true }); }
  }, 30_000);

  it('rolls back post-consume storage, signing, and rendering failures through an isolated real OIDC stack', async () => {
    type Stage = 'storage' | 'signing' | 'rendering';
    const runCase = async (stage: Stage): Promise<void> => {
      const database = `cp_post_consume_${stage}_${randomUUID().replaceAll('-', '').slice(0, 8)}`;
      await pool.query(`CREATE DATABASE ${database}`);
      const owner = new Pool({ connectionString: `postgresql://postgres:test@127.0.0.1:${postgresPort}/${database}` });
      const runtimePool = new Pool({ connectionString: `postgresql://${runtime}:runtime-test-only@127.0.0.1:${postgresPort}/${database}` });
      let server: ReturnType<typeof createServer> | undefined;
      try {
        await applyControlPlaneMigration(owner, runtime, retention, undefined, revocation, evidenceKeyIds);
        const epoch = randomBytes(16).toString('base64url'); const origin = 'https://oidc.example'; const clientId = 'dsa-signal'; const redirect = 'https://mas.example/callback';
        const ring = { active: 'test', keys: { test: randomBytes(32) } }; const bindingRing = { active: 'test', keys: { test: randomBytes(32) } }; const controlKey = randomBytes(32); const controlId = randomBytes(32).toString('base64url');
        const mapping = randomUUID(); const policy = randomUUID(); const entitlement = randomUUID(); const subject = randomBytes(32).toString('base64url');
        const binding = createHmac('sha256', bindingRing.keys.test).update('dsa-signal-session-fingerprint:v1\0').update(controlId).digest();
        const mappingEnvelope = randomUUID(); const policyEnvelope = randomUUID();
        await owner.query("INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose) VALUES($1,'test',$2,$3,'did'),($4,'test',$5,$6,'policy')", [mappingEnvelope, randomBytes(12), randomBytes(32), policyEnvelope, randomBytes(12), randomBytes(32)]);
        await insertMapping(owner, mapping, origin, 'test', subject, mappingEnvelope);
        await owner.query("WITH t AS (SELECT clock_timestamp() now) INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) SELECT $1,$2,$3,'post-consume',now-interval '2 seconds',now-interval '1 second',now+interval '1 hour',now FROM t", [policy, randomBytes(32), policyEnvelope]);
        await owner.query('INSERT INTO control_plane.active_policy(singleton,snapshot_id,activated_at) VALUES(true,$1,clock_timestamp())', [policy]);
        await owner.query("WITH t AS (SELECT clock_timestamp() now) INSERT INTO control_plane.identity_sessions(id,binding_key_id,binding_fingerprint,mapping_id,origin,created_at,last_seen_at,idle_expires_at,absolute_expires_at) SELECT $1,'test',$2,$3,$4,now,now,now+interval '5 minutes',now+interval '15 minutes' FROM t", [randomUUID(), binding, mapping, origin]);
        await insertEntitlement("WITH t AS (SELECT clock_timestamp() now) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,'post-consume',now,now+interval '15 minutes','membership_verified',$5,'test',$6,1 FROM t", [entitlement, mapping, randomBytes(32), policy, epoch, binding], [entitlement], owner);
        const pair = await generateKeyPair('RS256', { extractable: true }); const privateJwk = await exportJWK(pair.privateKey); const clientSecret = randomBytes(32);
        const seamOrder: string[] = []; let accessTokenUpsertCount = 0; let accessTokenPostSavepointCount = 0; let storageSuperCompleted = false; let storageFailureCount = 0; let throwStorage = stage === 'storage';
        const BaseAdapter = createOidcAdapter({ epoch, adapter: ring, index: ring }, createAuthorizationCodeClaim(epoch, ring), createTokenPreflight(epoch, clientId, ring));
        const adapter = class extends BaseAdapter {
          override async upsert(id: string, payload: Record<string, unknown>, expiresIn: number): Promise<void> {
            await super.upsert(id, payload, expiresIn);
            if (this.model !== 'AccessToken') return;
            accessTokenUpsertCount += 1;
            const requestContext = requireOidcRequestContext();
            expect(requestContext.tokenConsumeSavepoint).toBe('oidc_after_code_consume');
            accessTokenPostSavepointCount += 1; seamOrder.push('access-token-after-savepoint');
            const written = await requestContext.client.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken'");
            storageSuperCompleted = written.rows[0]!.count > 0;
            if (throwStorage) { throwStorage = false; storageFailureCount += 1; seamOrder.push('storage-failure'); throw new Error('injected AccessToken persistence failure after super.upsert'); }
          }
        };
        const signingKey = stage === 'signing' ? { ...privateJwk, kid: 'signing-failure', use: 'sig', alg: 'RS256', key_ops: ['verify'] } : { ...privateJwk, kid: 'test', use: 'sig', alg: 'RS256' };
        const provider = createOidcProvider({ OIDC_ISSUER: `${origin}/oidc`, MAS_CLIENT_ID: clientId, MAS_REDIRECT_URI: redirect }, { clientSecret, cookieKeys: [randomBytes(32)], signingKeys: [signingKey as never], publicJwks: { keys: [] } }, adapter, createAuthorizationHooks(epoch, ring));
        const providerErrors: { name: string; message: string }[] = []; let signingErrorCount = 0; let signingEventSavepoint: string | undefined; let signingEventLackedAls = false;
        (provider as unknown as { on(name: string, listener: (_context: unknown, error: Error) => void): void }).on('server_error', (_context, error) => {
          providerErrors.push({ name: error.name, message: error.message });
          if (stage !== 'signing' || error.name !== 'TypeError' || error.message !== "Cannot read properties of undefined (reading 'kty')") return;
          signingErrorCount += 1; seamOrder.push('signing-error');
          try { signingEventSavepoint = requireOidcRequestContext().tokenConsumeSavepoint; } catch { signingEventLackedAls = true; }
          if (!signingEventLackedAls) expect(signingEventSavepoint).toBe('oidc_after_code_consume');
        });
        const renderingErrors: { name: string; message: string }[] = [];
        (provider as unknown as { on(name: string, listener: (error: Error) => void): void }).on('error', error => { if (stage === 'rendering') renderingErrors.push({ name: error.name, message: error.message }); });
        let originalTokenBodyObserved = false; let renderingToJsonCalls = 0; let renderingInjectionCount = 0; let renderingInjected = false; let renderingSavepoint: string | undefined;
        if (stage === 'rendering') provider.use(async (context, next) => {
          await next();
          const koa = context as unknown as { body?: unknown };
          const body = koa.body as { access_token?: unknown; id_token?: unknown };
          const originalBody = typeof body?.access_token === 'string' && typeof body?.id_token === 'string';
          if (!originalBody || renderingInjected) return;
          originalTokenBodyObserved = true; renderingInjected = true; renderingInjectionCount += 1;
          renderingSavepoint = requireOidcRequestContext().tokenConsumeSavepoint;
          expect(renderingSavepoint).toBe('oidc_after_code_consume');
          seamOrder.push('rendering-before-body-replacement');
          koa.body = { toJSON: () => { renderingToJsonCalls += 1; if (renderingToJsonCalls === 1) throw new Error('injected token rendering failure'); return {}; } };
        });
        const interaction = createInteractionHandler({ pool: runtimePool, provider, epoch, clientId, redirectUri: redirect, origin, cookieKey: controlKey, indexKeys: ring, bindingKeys: bindingRing });
        const dispatcher = createOidcDispatcher({ issuer: `${origin}/oidc`, trustedProxyAddress: '127.0.0.1' }, provider, interaction, createTransactionalProviderInvocation(runtimePool, provider, createResumePreflight(epoch, ring, adapter)));
        server = createApp({ config: { PWA_ORIGIN: origin, COOKIE_KEY: controlKey }, foundation: { exchangeIdentityHandoff: async () => { throw new Error('unused'); } }, sessions: { establishFromHandoff: async () => { throw new Error('unused'); }, authenticate: async () => undefined, renew: async () => false, revoke: async () => false }, challenges: { issue: async () => { throw new Error('unused'); } }, verifications: { verify: async () => { throw new Error('unused'); } }, logout: createLogoutService({ pool: runtimePool, oidcEpoch: epoch, bindingKeys: bindingRing }), oidcDispatcher: dispatcher });
        await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve)); const address = server.address(); if (!address || typeof address === 'string') throw new Error('server missing address');
        const forward = { host: 'oidc.example', 'x-forwarded-host': 'oidc.example', 'x-forwarded-proto': 'https' };
        const request = (path: string, method = 'GET', headers: Record<string, string> = forward, body?: string): Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: string }> => new Promise((resolve, reject) => { const req = httpRequest({ host: '127.0.0.1', port: address.port, path, method, headers }, response => { const chunks: Buffer[] = []; response.on('data', chunk => chunks.push(Buffer.from(chunk))); response.on('end', () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString() })); }); req.on('error', reject); req.end(body); });
        const cookies = new Map<string, { value: string; path: string }>(); const absorb = (response: { headers: import('node:http').IncomingHttpHeaders }) => { for (const value of response.headers['set-cookie'] ?? []) { const first = value.split(';')[0]!; cookies.set(first.split('=')[0]!, { value: first, path: /;\s*Path=([^;]+)/i.exec(value)?.[1] ?? '/' }); } }; const cookie = (path: string, control = false) => [...cookies.values()].filter(entry => path.startsWith(entry.path)).map(entry => entry.value).concat(control ? [makeSessionCookie(controlId, controlKey).split(';')[0]!] : []).join('; ');
        const verifier = randomBytes(32).toString('base64url'); const challenge = createHash('sha256').update(verifier).digest('base64url');
        const auth = await request(`/oidc/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=openid%20dsa_signal_entitlement&state=${stage}&nonce=${stage}&code_challenge=${challenge}&code_challenge_method=S256`); expect(auth.status).toBe(303); absorb(auth);
        const page = await request('/oidc/interaction', 'GET', { ...forward, cookie: cookie('/oidc/interaction') }); const csrf = /name="csrf" value="([A-Za-z0-9_-]{43})"/.exec(page.body)?.[1]; expect(page.status).toBe(200); expect(csrf).toBeTruthy();
        const postBody = `csrf=${csrf}`; const post = await request('/oidc/interaction', 'POST', { ...forward, origin, cookie: cookie('/oidc/interaction', true), 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(postBody.length) }, postBody); expect(post.status).toBe(303); absorb(post);
        const resumePath = new URL(post.headers.location!).pathname; const resume = await request(resumePath, 'GET', { ...forward, cookie: cookie(resumePath) }); expect(resume.status).toBe(303); const code = new URL(resume.headers.location!, origin).searchParams.get('code')!;
        const artifactSnapshot = (await owner.query<{ count: number }>('SELECT count(*)::int count FROM oidc.provider_artifacts')).rows[0]!.count; const accessSnapshot = (await owner.query<{ count: number }>("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken'")).rows[0]!.count;
        const codeGrant = await owner.query<{ grant_key_id: string; grant_fingerprint: Buffer }>(`SELECT c.grant_key_id,c.grant_fingerprint FROM oidc.authorization_contexts c JOIN oidc.provider_artifacts a ON a.epoch=c.epoch AND a.model='AuthorizationCode' AND a.artifact_key_id=c.authorization_code_key_id AND a.artifact_fingerprint=c.authorization_code_fingerprint WHERE c.epoch=$1`, [epoch]); expect(codeGrant.rowCount).toBe(1); const grant = codeGrant.rows[0]!;
        const lifecycle = async () => owner.query<{ consumed: boolean; codeRevoked: boolean; grantRevoked: boolean; access: number }>(`SELECT (SELECT consumed_at IS NOT NULL FROM oidc.provider_artifacts WHERE epoch=$1 AND model='AuthorizationCode' AND grant_key_id=$2 AND grant_fingerprint=$3) consumed,(SELECT revoked_at IS NOT NULL FROM oidc.provider_artifacts WHERE epoch=$1 AND model='AuthorizationCode' AND grant_key_id=$2 AND grant_fingerprint=$3) "codeRevoked",(SELECT revoked_at IS NOT NULL FROM oidc.provider_artifacts WHERE epoch=$1 AND model='Grant' AND grant_key_id=$2 AND grant_fingerprint=$3) "grantRevoked",(SELECT count(*)::int FROM oidc.provider_artifacts WHERE epoch=$1 AND model='AccessToken' AND grant_key_id=$2 AND grant_fingerprint=$3) access`, [epoch, grant.grant_key_id, grant.grant_fingerprint]);
        expect((await lifecycle()).rows[0]).toEqual({ consumed: false, codeRevoked: false, grantRevoked: false, access: 0 });
        const exchange = () => { const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirect, code_verifier: verifier }).toString(); return request('/oidc/token', 'POST', { ...forward, authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret.toString('base64url')}`).toString('base64')}`, 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(Buffer.byteLength(body)) }, body); };
        const failed = await exchange(); expect(failed.status).toBe(500); expect(failed.body).toBe('{"error":"server_error"}'); expect(failed.headers['content-type']).toMatch(/^application\/json/); expect(failed.headers['cache-control']).toBe('no-store'); expect(failed.headers['referrer-policy']).toBe('no-referrer'); expect(failed.headers.location).toBeUndefined(); expect(failed.headers['set-cookie']).toBeUndefined(); expect(failed.headers['www-authenticate']).toBeUndefined();
        expect((await owner.query<{ count: number }>('SELECT count(*)::int count FROM oidc.provider_artifacts')).rows[0]!.count).toBe(artifactSnapshot); expect((await owner.query<{ count: number }>("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken'")).rows[0]!.count).toBe(accessSnapshot); expect((await lifecycle()).rows[0]).toEqual({ consumed: true, codeRevoked: false, grantRevoked: false, access: 0 });
        const replay = await exchange(); expect(replay.status).toBe(400); expect(JSON.parse(replay.body)).toMatchObject({ error: 'invalid_grant' }); expect((await owner.query<{ count: number }>('SELECT count(*)::int count FROM oidc.provider_artifacts')).rows[0]!.count).toBe(artifactSnapshot); expect((await owner.query<{ count: number }>("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken'")).rows[0]!.count).toBe(accessSnapshot); expect((await lifecycle()).rows[0]).toEqual({ consumed: true, codeRevoked: true, grantRevoked: true, access: 0 });
        expect(accessTokenUpsertCount).toBe(1); expect(accessTokenPostSavepointCount).toBe(1);
        if (stage === 'storage') {
          expect(storageSuperCompleted).toBe(true); expect(storageFailureCount).toBe(1); expect(signingErrorCount).toBe(0); expect(renderingInjectionCount).toBe(0); expect(renderingToJsonCalls).toBe(0); expect(seamOrder).toEqual(['access-token-after-savepoint', 'storage-failure']);
          expect(providerErrors).toEqual([{ name: 'Error', message: 'injected AccessToken persistence failure after super.upsert' }]); expect(renderingErrors).toEqual([]);
        }
        if (stage === 'signing') {
          expect(storageFailureCount).toBe(0); expect(renderingInjectionCount).toBe(0); expect(renderingToJsonCalls).toBe(0); expect(signingErrorCount).toBe(1); expect(seamOrder).toEqual(['access-token-after-savepoint', 'signing-error']);
          // oidc-provider emits this event outside ALS in some releases; ordering then rests on the completed post-savepoint AccessToken seam and this exact lazy-JWK error.
          if (signingEventLackedAls) expect(seamOrder).toEqual(['access-token-after-savepoint', 'signing-error']); else expect(signingEventSavepoint).toBe('oidc_after_code_consume');
          expect(providerErrors).toEqual([{ name: 'TypeError', message: "Cannot read properties of undefined (reading 'kty')" }]); expect(renderingErrors).toEqual([]);
          expect(providerErrors.map(error => error.message)).not.toContain('injected AccessToken persistence failure after super.upsert'); expect(providerErrors.map(error => error.message)).not.toContain('injected token rendering failure');
        }
        if (stage === 'rendering') {
          expect(storageFailureCount).toBe(0); expect(signingErrorCount).toBe(0); expect(originalTokenBodyObserved, 'token response body was not observed').toBe(true); expect(renderingInjectionCount).toBe(1); expect(renderingSavepoint).toBe('oidc_after_code_consume'); expect(renderingToJsonCalls, 'token response toJSON was not invoked').toBe(1); expect(seamOrder).toEqual(['access-token-after-savepoint', 'rendering-before-body-replacement']);
          expect(providerErrors).toEqual([]); expect(renderingErrors).toEqual([{ name: 'Error', message: 'injected token rendering failure' }]);
        }
      } finally { server?.closeAllConnections(); if (server?.listening) await new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve())); await runtimePool.end(); await owner.end(); await pool.query(`DROP DATABASE ${database}`); }
    };
    await runCase('storage'); await runCase('signing'); await runCase('rendering');
  }, 60_000);

  it('runs Slice 3 through PostgreSQL, the real provider, and a bound HTTP server', async () => {
    const database = `cp_slice3_${suffix}`;
    await pool.query(`CREATE DATABASE ${database}`);
    const owner = new Pool({ connectionString: `postgresql://postgres:test@127.0.0.1:${postgresPort}/${database}` });
    const runtimePool = new Pool({ connectionString: `postgresql://${runtime}:runtime-test-only@127.0.0.1:${postgresPort}/${database}` });
    let server: ReturnType<typeof createServer> | undefined;
    try {
      await applyControlPlaneMigration(owner, runtime, retention, undefined, revocation, evidenceKeyIds);
      const epoch = 'AAAAAAAAAAAAAAAAAAAAAA'; const origin = 'https://oidc.example'; const clientId = 'dsa-signal'; const redirect = 'https://mas.example/callback';
      const ring = { active: 'old', keys: { old: randomBytes(32), next: randomBytes(32) } }; const bindingRing = { active: 'next', keys: { old: randomBytes(32), next: randomBytes(32) } }; const controlKey = randomBytes(32); const controlId = randomBytes(32).toString('base64url');
      const mapping = randomUUID(); const policy = randomUUID(); const entitlement = randomUUID(); const mappingSubject = randomBytes(32).toString('base64url');
      const binding = createHmac('sha256', bindingRing.keys.old).update('dsa-signal-session-fingerprint:v1\0').update(controlId).digest();
      const mappingEnvelope = randomUUID(); const policyEnvelope = randomUUID();
      await owner.query("INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose) VALUES($1,'test',$2,$3,'did')", [mappingEnvelope, randomBytes(12), randomBytes(32)]);
      await insertMapping(owner, mapping, origin, 'test', mappingSubject, mappingEnvelope);
      await owner.query("INSERT INTO control_plane.encrypted_envelopes(id,envelope_key_id,nonce,ciphertext,purpose) VALUES($1,'test',$2,$3,'policy')", [policyEnvelope, randomBytes(12), randomBytes(32)]);
      await owner.query("WITH t AS (SELECT clock_timestamp() now) INSERT INTO control_plane.policy_snapshots(id,digest,envelope_id,version,signed_at,verified_at,fresh_until,created_at) SELECT $1,$2,$3,'slice3',now-interval '2 seconds',now-interval '1 second',now+interval '1 hour',now FROM t", [policy, randomBytes(32), policyEnvelope]);
      await owner.query('INSERT INTO control_plane.active_policy(singleton,snapshot_id,activated_at) VALUES(true,$1,clock_timestamp())', [policy]);
      await owner.query("WITH t AS (SELECT clock_timestamp() now) INSERT INTO control_plane.identity_sessions(id,binding_key_id,binding_fingerprint,mapping_id,origin,created_at,last_seen_at,idle_expires_at,absolute_expires_at) SELECT $1,'old',$2,$3,$4,now,now,now+interval '5 minutes',now+interval '15 minutes' FROM t", [randomUUID(), binding, mapping, origin]);
      await insertEntitlement("WITH t AS (SELECT clock_timestamp() now) INSERT INTO control_plane.entitlements(id,mapping_id,jkt,entitlement,status,policy_snapshot_id,policy_version,authorized_at,expires_at,reason,oidc_epoch,session_binding_key_id,session_binding_fingerprint,generation) SELECT $1,$2,$3,'chat','active',$4,'slice3',now,now+interval '15 minutes','membership_verified',$5,'old',$6,1 FROM t", [entitlement, mapping, randomBytes(32), policy, epoch, binding], [entitlement], owner);
      const rsa = await generateKeyPair('RS256', { extractable: true }); const jwk = await exportJWK(rsa.privateKey); const clientSecret = randomBytes(32);
      const BaseAdapter = createOidcAdapter({ epoch, adapter: ring, index: ring }, createAuthorizationCodeClaim(epoch, ring), createTokenPreflight(epoch, clientId, ring));
      let failNextSessionUpsert = false;
      const adapter = class extends BaseAdapter {
        override async upsert(id: string, payload: Record<string, unknown>, expiresIn: number): Promise<void> {
          if (this.model === 'Session' && failNextSessionUpsert) {
            failNextSessionUpsert = false;
            throw new Error('injected session persistence failure');
          }
          await super.upsert(id, payload, expiresIn);
        }
      };
      const provider = createOidcProvider({ OIDC_ISSUER: `${origin}/oidc`, MAS_CLIENT_ID: clientId, MAS_REDIRECT_URI: redirect }, { clientSecret, cookieKeys: [randomBytes(32)], signingKeys: [{ ...jwk, kid: 'test', use: 'sig', alg: 'RS256' } as never], publicJwks: { keys: [] } }, adapter, createAuthorizationHooks(epoch, ring));
      const providerErrors: string[] = [];
      (provider as unknown as { on(name: string, listener: (_context: unknown, error: Error) => void): void }).on('server_error', (_context, error) => providerErrors.push(error.stack ?? error.message));
      const interaction = createInteractionHandler({ pool: runtimePool, provider, epoch, clientId, redirectUri: redirect, origin, cookieKey: controlKey, indexKeys: ring, bindingKeys: bindingRing });
      const dispatcher = createOidcDispatcher({ issuer: `${origin}/oidc`, trustedProxyAddress: '127.0.0.1' }, provider, interaction, createTransactionalProviderInvocation(runtimePool, provider, createResumePreflight(epoch, ring, adapter)));
      server = createApp({
        config: { PWA_ORIGIN: origin, COOKIE_KEY: controlKey },
        foundation: { exchangeIdentityHandoff: async () => { throw new Error('unused'); } },
        sessions: { establishFromHandoff: async () => { throw new Error('unused'); }, authenticate: async () => undefined, renew: async () => false, revoke: async () => false },
        challenges: { issue: async () => { throw new Error('unused'); } },
        verifications: { verify: async () => { throw new Error('unused'); } },
        logout: createLogoutService({ pool: runtimePool, oidcEpoch: epoch, bindingKeys: bindingRing }),
        oidcDispatcher: dispatcher,
      });
      await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve)); const address = server.address(); if (!address || typeof address === 'string') throw new Error('server missing address');
      const forward = { host: 'oidc.example', 'x-forwarded-host': 'oidc.example', 'x-forwarded-proto': 'https' };
      const request = (path: string, method = 'GET', headers: Record<string, string> = forward, body?: string): Promise<{ status: number; headers: import('node:http').IncomingHttpHeaders; body: string }> => new Promise((resolve, reject) => { const req = httpRequest({ host: '127.0.0.1', port: address.port, path, method, headers }, res => { const chunks: Buffer[] = []; res.on('data', chunk => chunks.push(Buffer.from(chunk))); res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString() })); }); req.on('error', reject); req.end(body); });
      const cookies = new Map<string, { value: string; path: string }>();
      const cookie = (path: string, control = false) => [...cookies.values()].filter(entry => path.startsWith(entry.path)).map(entry => entry.value).concat(control ? [makeSessionCookie(controlId, controlKey).split(';')[0]!] : []).join('; ');
      const verifier = randomBytes(32).toString('base64url'); const challenge = createHash('sha256').update(verifier).digest('base64url');
      const auth = await request(`/oidc/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=openid%20dsa_signal_entitlement&state=state&nonce=nonce&code_challenge=${challenge}&code_challenge_method=S256`);
      const absorbHttp = (response: { headers: import('node:http').IncomingHttpHeaders }) => { for (const value of response.headers['set-cookie'] ?? []) { const first = value.split(';')[0]!; cookies.set(first.split('=')[0]!, { value: first, path: /;\s*Path=([^;]+)/i.exec(value)?.[1] ?? '/' }); } }; expect(auth.status, `${auth.body}\n${providerErrors.join('\n')}`).toBe(303); absorbHttp(auth); expect(auth.headers.location).toBe('/oidc/interaction');
      const page = await request('/oidc/interaction', 'GET', { ...forward, cookie: cookie('/oidc/interaction') }); expect(page.status).toBe(200); const csrf = /name="csrf" value="([A-Za-z0-9_-]{43})"/.exec(page.body)?.[1]; expect(csrf).toBeTruthy();
      expect((await owner.query('SELECT * FROM oidc.interaction_csrf')).rowCount).toBe(1);
      const replacementPage = await request('/oidc/interaction', 'GET', { ...forward, cookie: cookie('/oidc/interaction') }); expect(replacementPage.status).toBe(200); const replacementCsrf = /name="csrf" value="([A-Za-z0-9_-]{43})"/.exec(replacementPage.body)?.[1]; expect(replacementCsrf).toBeTruthy(); expect(replacementCsrf).not.toBe(csrf); expect((await owner.query('SELECT * FROM oidc.interaction_csrf')).rowCount).toBe(1);
      ring.active = 'next';
      const staleBody = `csrf=${csrf}`; const stale = await request('/oidc/interaction', 'POST', { ...forward, origin, cookie: cookie('/oidc/interaction', true), 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(staleBody.length) }, staleBody); expect(stale.status).toBe(400);
      const postBody = `csrf=${replacementCsrf}`; const preSuccessCookieHeader = cookie('/oidc/interaction', true); const postHeaders = { ...forward, origin, cookie: preSuccessCookieHeader, 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(postBody.length) };
      const post = await request('/oidc/interaction', 'POST', postHeaders, postBody); expect(post.status, `${post.body}\n${providerErrors.join('\n')}`).toBe(303);
      const authorizationContextCount = (await owner.query('SELECT * FROM oidc.authorization_contexts WHERE mapping_id=$1 AND entitlement_id=$2 AND generation=1 AND policy_snapshot_id=$3', [mapping, entitlement, policy])).rowCount; expect(authorizationContextCount).toBe(1);
      const replay = await request('/oidc/interaction', 'POST', postHeaders, postBody); expect(replay.status).toBe(400);
      expect((await owner.query('SELECT * FROM oidc.authorization_contexts WHERE mapping_id=$1 AND entitlement_id=$2 AND generation=1 AND policy_snapshot_id=$3', [mapping, entitlement, policy])).rowCount).toBe(authorizationContextCount);
      absorbHttp(post);
      ring.active = 'old';
      const resumePath = new URL(post.headers.location!).pathname;
      const resume = await request(resumePath, 'GET', { ...forward, cookie: cookie(resumePath) }); expect(resume.status, `${resume.body}\n${providerErrors.join('\n')}`).toBe(303); absorbHttp(resume); expect(resume.headers.location).toBeDefined(); const callback = new URL(resume.headers.location!, origin); expect(callback.searchParams.getAll('code')).toHaveLength(1);
      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AuthorizationCode'", [])).rows[0]!.count).toBe(1); expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='Session'", [])).rows[0]!.count).toBe(1); expect((await owner.query('SELECT count(*)::int count FROM oidc.authorization_contexts WHERE authorization_code_fingerprint IS NOT NULL AND provider_session_uid_fingerprint IS NOT NULL')).rows[0]!.count).toBe(1);
      expect((await owner.query(`SELECT count(*)::int count FROM oidc.authorization_contexts c
        JOIN oidc.provider_artifacts a ON a.epoch=c.epoch AND a.model='AuthorizationCode' AND a.artifact_key_id=c.authorization_code_key_id AND a.artifact_fingerprint=c.authorization_code_fingerprint
        JOIN oidc.provider_artifacts s ON s.epoch=c.epoch AND s.model='Session' AND s.session_uid_key_id=c.provider_session_uid_key_id AND s.session_uid_fingerprint=c.provider_session_uid_fingerprint`)).rows[0]!.count).toBe(1);
      const exchange = (code: string, codeVerifier: string) => {
        const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirect, code_verifier: codeVerifier }).toString();
        return request('/oidc/token', 'POST', { ...forward, authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret.toString('base64url')}`).toString('base64')}`, 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(Buffer.byteLength(body)) }, body);
      };
      const code1 = callback.searchParams.get('code')!; const token1 = await exchange(code1, verifier); expect(token1.status, `${token1.body}\n${providerErrors.join('\n')}`).toBe(200);
      const tokenPayload1 = JSON.parse(token1.body) as { access_token: string; id_token: string; expires_in: number; token_type: string };
      expect(tokenPayload1.access_token).toMatch(/^[A-Za-z0-9_-]{43}$/); expect(tokenPayload1.token_type).toBe('Bearer'); expect(tokenPayload1.expires_in).toBeGreaterThan(0); expect(tokenPayload1.expires_in).toBeLessThanOrEqual(300);
      const verifiedIdToken1 = await jwtVerify(tokenPayload1.id_token, rsa.publicKey, { algorithms: ['RS256'], issuer: `${origin}/oidc`, audience: clientId });
      expect(Object.keys(verifiedIdToken1.payload).sort()).toEqual(['aud', 'auth_time', 'dsa_signal_entitlement_policy_version', 'exp', 'iat', 'iss', 'nonce', 'sub'].sort());
      expect(verifiedIdToken1.payload.nonce).toBe('nonce'); expect(verifiedIdToken1.payload.sub).toBe(mappingSubject); expect(verifiedIdToken1.payload.dsa_signal_entitlement_policy_version).toBe('slice3'); expect(verifiedIdToken1.payload.exp! - verifiedIdToken1.payload.iat!).toBe(tokenPayload1.expires_in);
      ring.active = 'next';
      const verifier2 = randomBytes(32).toString('base64url'); const challenge2 = createHash('sha256').update(verifier2).digest('base64url');
      const auth2 = await request(`/oidc/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=openid%20dsa_signal_entitlement&state=state2&nonce=nonce2&code_challenge=${challenge2}&code_challenge_method=S256`, 'GET', { ...forward, cookie: cookie('/oidc/auth') }); expect(auth2.status, `${auth2.body}\n${providerErrors.join('\n')}`).toBe(303); absorbHttp(auth2);
      const page2 = await request('/oidc/interaction', 'GET', { ...forward, cookie: cookie('/oidc/interaction') }); expect(page2.status).toBe(200); const csrf2 = /name="csrf" value="([A-Za-z0-9_-]{43})"/.exec(page2.body)?.[1]; expect(csrf2).toBeTruthy();
      const postBody2 = `csrf=${csrf2}`; const post2 = await request('/oidc/interaction', 'POST', { ...forward, origin, cookie: cookie('/oidc/interaction', true), 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(postBody2.length) }, postBody2); expect(post2.status, `${post2.body}\n${providerErrors.join('\n')}`).toBe(303); absorbHttp(post2);
      const resumePath2 = new URL(post2.headers.location!).pathname; const resume2 = await request(resumePath2, 'GET', { ...forward, cookie: cookie(resumePath2) }); expect(resume2.status, `${resume2.body}\n${providerErrors.join('\n')}`).toBe(303); absorbHttp(resume2); const callback2 = new URL(resume2.headers.location!, origin); expect(callback2.searchParams.getAll('code')).toHaveLength(1); expect(callback2.searchParams.get('code')).not.toBe(callback.searchParams.get('code'));
      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='Session' AND session_uid_key_id='next'", [])).rows[0]!.count).toBe(1); expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='Grant'", [])).rows[0]!.count).toBe(2); expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AuthorizationCode'", [])).rows[0]!.count).toBe(2); expect((await owner.query('SELECT count(DISTINCT grant_fingerprint)::int count FROM oidc.authorization_contexts')).rows[0]!.count).toBe(2); expect(providerErrors).toEqual([]);
      expect((await owner.query(`SELECT count(*)::int count
        FROM oidc.authorization_contexts c
        JOIN oidc.provider_artifacts a ON a.epoch=c.epoch AND a.model='AuthorizationCode'
          AND a.artifact_key_id=c.authorization_code_key_id AND a.artifact_fingerprint=c.authorization_code_fingerprint`)).rows[0]!.count).toBe(2);
      expect((await owner.query(`SELECT count(*)::int count FROM oidc.authorization_contexts c
        JOIN oidc.provider_artifacts s ON s.epoch=c.epoch AND s.model='Session'
          AND s.session_uid_key_id=c.provider_session_uid_key_id AND s.session_uid_fingerprint=c.provider_session_uid_fingerprint
        WHERE c.provider_session_uid_key_id='next'`)).rows[0]!.count).toBe(1);
      expect((await owner.query("SELECT count(*)::int count FROM oidc.authorization_contexts WHERE provider_session_uid_key_id='old'", [])).rows[0]!.count).toBe(1);

      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='Grant' AND revoked_at IS NULL")).rows[0]!.count).toBe(2);
      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AuthorizationCode' AND consumed_at IS NULL AND revoked_at IS NULL")).rows[0]!.count).toBe(1);
      const code2 = callback2.searchParams.get('code')!;
      const raceBlocker = await owner.connect();
      let raced: Awaited<ReturnType<typeof exchange>>[];
      try {
        await raceBlocker.query('BEGIN');
        await raceBlocker.query('SELECT id FROM control_plane.identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2 FOR UPDATE', ['old', binding]);
        const blockerPid = (await raceBlocker.query<{ pid: number }>('SELECT pg_backend_pid() pid')).rows[0]!.pid;
        const racedPromise = Promise.all([exchange(code2, verifier2), exchange(code2, verifier2)]);
        let lockChainReady = false;
        for (let attempt = 0; attempt < 200 && !lockChainReady; attempt += 1) {
          const waiting = await owner.query<{ pid: number; blockers: number[]; query: string }>(`SELECT pid,pg_blocking_pids(pid) blockers,query
            FROM pg_stat_activity
            WHERE datname=current_database() AND usename=$1 AND state='active' AND wait_event_type='Lock'`, [runtime]);
          const first = waiting.rows.find(row => row.blockers.includes(blockerPid) && row.query.includes('control_plane.identity_sessions'));
          const second = first && waiting.rows.find(row => row.blockers.includes(first.pid) && row.query.includes('pg_advisory_xact_lock'));
          lockChainReady = Boolean(first && second);
          if (!lockChainReady) await new Promise<void>(resolve => setImmediate(resolve));
        }
        expect(lockChainReady).toBe(true);
        await raceBlocker.query('COMMIT');
        raced = await racedPromise;
        expect(raced.map(result => result.status).sort(), `${raced.map(result => result.body).join('\n')}\n${providerErrors.join('\n')}`).toEqual([200, 400]);
      } finally { await raceBlocker.query('ROLLBACK').catch(() => undefined); raceBlocker.release(); }
      const winner = JSON.parse(raced.find(result => result.status === 200)!.body) as { access_token: string; id_token: string }; expect(winner.access_token).toMatch(/^[A-Za-z0-9_-]{43}$/); await expect(jwtVerify(winner.id_token, rsa.publicKey, { algorithms: ['RS256'], issuer: `${origin}/oidc`, audience: clientId })).resolves.toBeDefined();
      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AuthorizationCode' AND consumed_at IS NOT NULL")).rows[0]!.count).toBe(2);
      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken'")).rows[0]!.count).toBe(2);
      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken' AND revoked_at IS NOT NULL")).rows[0]!.count).toBe(1);
      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='Grant' AND revoked_at IS NOT NULL")).rows[0]!.count).toBe(1);
      const code2Fingerprint = createHmac('sha256', ring.keys.next).update(`dsa-signal-oidc-artifact-id:v1\0${epoch}\0AuthorizationCode\0`).update(code2).digest();
      const revokedCode2Grant = await owner.query<{ count: number }>(`SELECT count(*)::int count
        FROM oidc.authorization_contexts c
        JOIN oidc.provider_artifacts g ON g.epoch=c.epoch AND g.model='Grant'
          AND g.grant_key_id=c.grant_key_id AND g.grant_fingerprint=c.grant_fingerprint
        WHERE c.authorization_code_key_id='next' AND c.authorization_code_fingerprint=$1 AND g.revoked_at IS NOT NULL`, [code2Fingerprint]);
      code2Fingerprint.fill(0);
      expect(revokedCode2Grant.rows[0]!.count).toBe(1);

      const verifier3 = randomBytes(32).toString('base64url'); const challenge3 = createHash('sha256').update(verifier3).digest('base64url');
      const auth3 = await request(`/oidc/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=openid%20dsa_signal_entitlement&state=state3&nonce=nonce3&code_challenge=${challenge3}&code_challenge_method=S256`, 'GET', { ...forward, cookie: cookie('/oidc/auth') }); expect(auth3.status).toBe(303); absorbHttp(auth3);
      const page3 = await request('/oidc/interaction', 'GET', { ...forward, cookie: cookie('/oidc/interaction') }); const csrf3 = /name="csrf" value="([A-Za-z0-9_-]{43})"/.exec(page3.body)?.[1]; expect(page3.status).toBe(200); expect(csrf3).toBeTruthy();
      const postBody3 = `csrf=${csrf3}`; const post3 = await request('/oidc/interaction', 'POST', { ...forward, origin, cookie: cookie('/oidc/interaction', true), 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(postBody3.length) }, postBody3); expect(post3.status).toBe(303); absorbHttp(post3);
      const artifactCountsBeforeFailure = (await owner.query<{ model: string; count: number }>("SELECT model,count(*)::int count FROM oidc.provider_artifacts WHERE model IN ('AuthorizationCode','Session') GROUP BY model ORDER BY model")).rows;
      failNextSessionUpsert = true;
      const failedResumePath = new URL(post3.headers.location!).pathname; const failedResume = await request(failedResumePath, 'GET', { ...forward, cookie: cookie(failedResumePath) }); expect(failedResume.status).toBe(500); expect(failedResume.body).toBe('{"error":"server_error"}');
      expect((await owner.query<{ model: string; count: number }>("SELECT model,count(*)::int count FROM oidc.provider_artifacts WHERE model IN ('AuthorizationCode','Session') GROUP BY model ORDER BY model")).rows).toEqual(artifactCountsBeforeFailure);
      expect((await owner.query('SELECT count(*)::int count FROM oidc.authorization_contexts WHERE authorization_code_fingerprint IS NOT NULL')).rows[0]!.count).toBe(2);
      const recoveredResume = await request(failedResumePath, 'GET', { ...forward, cookie: cookie(failedResumePath) }); expect(recoveredResume.status).toBe(303); const callback3 = new URL(recoveredResume.headers.location!, origin); const code3 = callback3.searchParams.get('code'); expect(code3).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AuthorizationCode'")).rows[0]!.count).toBe(3);
      let csrfAfterLogout: string | undefined;
      let verifier4 = '';
      let code4: string | null = null;
      const blocker = await owner.connect();
      try {
        await blocker.query('BEGIN');
        await blocker.query('SELECT id FROM control_plane.identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2 FOR UPDATE', ['old', binding]);
        const blockerPid = (await blocker.query<{ pid: number }>('SELECT pg_backend_pid() pid')).rows[0]!.pid;
        const retry = exchange(code3!, verifier3);
        let blocked = false;
        for (let attempt = 0; attempt < 100 && !blocked; attempt += 1) {
          blocked = (await owner.query<{ blocked: boolean }>('SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))) blocked', [blockerPid])).rows[0]!.blocked;
          if (!blocked) await new Promise<void>(resolve => setImmediate(resolve));
        }
        expect(blocked).toBe(true);
        await blocker.query('UPDATE control_plane.entitlements SET expires_at=clock_timestamp() WHERE id=$1', [entitlement]);
        await blocker.query('COMMIT');
        const rejectedRetry = await retry; expect(rejectedRetry.status).toBe(500); expect(rejectedRetry.body).toBe('{"error":"server_error"}');
        expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AuthorizationCode' AND consumed_at IS NOT NULL", [])).rows[0]!.count).toBe(2);
        expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken'", [])).rows[0]!.count).toBe(2);
        await owner.query("UPDATE control_plane.entitlements SET expires_at=authorized_at+interval '15 minutes' WHERE id=$1", [entitlement]);
        const token3 = await exchange(code3!, verifier3); expect(token3.status).toBe(200);
        verifier4 = randomBytes(32).toString('base64url'); const challenge4 = createHash('sha256').update(verifier4).digest('base64url');
        const auth4 = await request(`/oidc/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=openid%20dsa_signal_entitlement&state=state4&nonce=nonce4&code_challenge=${challenge4}&code_challenge_method=S256`, 'GET', { ...forward, cookie: cookie('/oidc/auth') }); expect(auth4.status).toBe(303); absorbHttp(auth4);
        const page4 = await request('/oidc/interaction', 'GET', { ...forward, cookie: cookie('/oidc/interaction') }); const csrf4 = /name="csrf" value="([A-Za-z0-9_-]{43})"/.exec(page4.body)?.[1]; expect(page4.status).toBe(200); expect(csrf4).toBeTruthy();
        const postBody4 = `csrf=${csrf4}`; const post4 = await request('/oidc/interaction', 'POST', { ...forward, origin, cookie: cookie('/oidc/interaction', true), 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(postBody4.length) }, postBody4); expect(post4.status).toBe(303); absorbHttp(post4);
        const resumePath4 = new URL(post4.headers.location!).pathname; const resume4 = await request(resumePath4, 'GET', { ...forward, cookie: cookie(resumePath4) }); expect(resume4.status).toBe(303); absorbHttp(resume4); code4 = new URL(resume4.headers.location!, origin).searchParams.get('code'); expect(code4).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect((await owner.query(`SELECT count(*)::int count FROM oidc.provider_artifacts a JOIN oidc.authorization_contexts c
          ON c.epoch=a.epoch AND c.grant_key_id=a.grant_key_id AND c.grant_fingerprint=a.grant_fingerprint
          WHERE a.model='AuthorizationCode'`)).rows[0]!.count).toBe(4);
        expect((await owner.query(`SELECT count(*)::int count FROM oidc.provider_artifacts a JOIN oidc.authorization_contexts c
          ON c.epoch=a.epoch AND c.grant_key_id=a.grant_key_id AND c.grant_fingerprint=a.grant_fingerprint
          WHERE a.model='AccessToken'`)).rows[0]!.count).toBe(3);
        await owner.query("UPDATE oidc.authorization_contexts SET expires_at=created_at+interval '1 second' WHERE id=(SELECT id FROM oidc.authorization_contexts ORDER BY created_at LIMIT 1)");
        const retainedAccessFingerprint = createHmac('sha256', ring.keys.old).update(`dsa-signal-oidc-artifact-id:v1\0${epoch}\0AccessToken\0`).update(tokenPayload1.access_token).digest();
        await owner.query("WITH t AS (SELECT clock_timestamp() now) UPDATE oidc.provider_artifacts SET created_at=t.now-interval '310 seconds',expires_at=t.now-interval '10 seconds',retained_until=t.now+interval '20 seconds' FROM t WHERE model='AccessToken' AND artifact_key_id='old' AND artifact_fingerprint=$1", [retainedAccessFingerprint]);
        const contextsBeforeLogout = (await owner.query<{ count: number }>('SELECT count(*)::int count FROM oidc.authorization_contexts WHERE grant_expires_at>clock_timestamp()')).rows[0]!.count;
        const logoutBody = '{"version":"v1"}';
        await blocker.query('BEGIN'); await blocker.query('SELECT id FROM control_plane.identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2 FOR UPDATE', ['old', binding]);
        const logoutBlockerPid = (await blocker.query<{ pid: number }>('SELECT pg_backend_pid() pid')).rows[0]!.pid;
        const logoutPromise = request('/v1/identity/logout', 'POST', { ...forward, origin, accept: 'application/json', cookie: makeSessionCookie(controlId, controlKey).split(';')[0]!, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(logoutBody)) }, logoutBody);
        let logoutPid: number | undefined;
        for (let attempt = 0; attempt < 200 && logoutPid === undefined; attempt += 1) {
          const waiting = await owner.query<{ pid: number; blockers: number[]; query: string }>(`SELECT pid,pg_blocking_pids(pid) blockers,query FROM pg_stat_activity
            WHERE datname=current_database() AND usename=$1 AND state='active' AND wait_event_type='Lock'`, [runtime]);
          logoutPid = waiting.rows.find(row => row.blockers.includes(logoutBlockerPid) && row.query.includes('control_plane.identity_sessions'))?.pid;
          if (logoutPid === undefined) await new Promise<void>(resolve => setImmediate(resolve));
        }
        expect(logoutPid).toBeDefined();
        const consumedReplayPromise = exchange(code3!, verifier3);
        let replayWaitsOnLogout = false;
        for (let attempt = 0; attempt < 200 && !replayWaitsOnLogout; attempt += 1) {
          const waiting = await owner.query<{ blockers: number[]; query: string }>(`SELECT pg_blocking_pids(pid) blockers,query FROM pg_stat_activity
            WHERE datname=current_database() AND usename=$1 AND state='active' AND wait_event_type='Lock'`, [runtime]);
          replayWaitsOnLogout = waiting.rows.some(row => row.blockers.includes(logoutPid!) && row.query.includes('pg_advisory_xact_lock'));
          if (!replayWaitsOnLogout) await new Promise<void>(resolve => setImmediate(resolve));
        }
        expect(replayWaitsOnLogout).toBe(true); await blocker.query('COMMIT');
        const [logout, consumedReplay] = await Promise.all([logoutPromise, consumedReplayPromise]);
        expect(logout.status).toBe(200); expect(logout.body).toBe('{"version":"v1","result":"logged_out"}'); expect(logout.headers['set-cookie']).toContain('__Host-dsa_signal_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
        expect(consumedReplay.status).toBe(400); expect(consumedReplay.body).toContain('invalid_grant');
        expect((await owner.query('SELECT count(*)::int count FROM control_plane.identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2 AND revoked_at IS NOT NULL', ['old', binding])).rows[0]!.count).toBe(1);
        expect((await owner.query('SELECT count(*)::int count FROM oidc.authorization_contexts WHERE grant_expires_at>clock_timestamp() AND revoked_at IS NOT NULL')).rows[0]!.count).toBe(contextsBeforeLogout);
        expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='Grant' AND revoked_at IS NOT NULL")).rows[0]!.count).toBe(4);
        expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken' AND artifact_key_id='old' AND artifact_fingerprint=$1 AND expires_at<clock_timestamp() AND retained_until>clock_timestamp() AND revoked_at IS NOT NULL", [retainedAccessFingerprint])).rows[0]!.count).toBe(1);
        retainedAccessFingerprint.fill(0);
        const unrevokedAccess = (await owner.query(`SELECT a.id,a.grant_key_id,encode(a.grant_fingerprint,'hex') grant_fingerprint,
          EXISTS(SELECT 1 FROM oidc.authorization_contexts c WHERE c.grant_key_id=a.grant_key_id AND c.grant_fingerprint=a.grant_fingerprint) has_context
          FROM oidc.provider_artifacts a WHERE a.model='AccessToken' AND a.revoked_at IS NULL`)).rows;
        expect(unrevokedAccess, JSON.stringify(unrevokedAccess)).toHaveLength(0);
        const accessCountAfterLogout = (await owner.query<{ count: number }>("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken'")).rows[0]!.count;
        const unconsumedAfterLogout = await exchange(code4!, verifier4); expect(unconsumedAfterLogout.status).toBe(400); expect(unconsumedAfterLogout.body).toContain('invalid_grant');
        expect((await owner.query<{ count: number }>("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken'")).rows[0]!.count).toBe(accessCountAfterLogout);
        expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='AccessToken' AND revoked_at IS NOT NULL", [])).rows[0]!.count).toBe(3);
        const retainedContext = (await owner.query<{ id: string; grant_key_id: string; grant_fingerprint: Buffer }>('SELECT id,grant_key_id,grant_fingerprint FROM oidc.authorization_contexts WHERE grant_expires_at>clock_timestamp() ORDER BY created_at DESC LIMIT 1')).rows[0]!;
        await owner.query('UPDATE oidc.authorization_contexts SET revoked_at=NULL WHERE id=$1', [retainedContext.id]);
        await owner.query("UPDATE oidc.provider_artifacts SET revoked_at=NULL WHERE model='Grant' AND grant_key_id=$1 AND grant_fingerprint=$2", [retainedContext.grant_key_id, retainedContext.grant_fingerprint]);
        await owner.query('DELETE FROM control_plane.identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2', ['old', binding]);
        const secondLogout = await request('/v1/identity/logout', 'POST', { ...forward, origin, accept: 'application/json', cookie: makeSessionCookie(controlId, controlKey).split(';')[0]!, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(logoutBody)) }, logoutBody);
        expect(secondLogout.status).toBe(200); expect(secondLogout.body).toBe('{"version":"v1","result":"logged_out"}');
        expect((await owner.query('SELECT count(*)::int count FROM oidc.authorization_contexts WHERE id=$1 AND revoked_at IS NOT NULL', [retainedContext.id])).rows[0]!.count).toBe(1);
        expect((await owner.query("SELECT count(*)::int count FROM oidc.provider_artifacts WHERE model='Grant' AND grant_key_id=$1 AND grant_fingerprint=$2 AND revoked_at IS NOT NULL", [retainedContext.grant_key_id, retainedContext.grant_fingerprint])).rows[0]!.count).toBe(1);
        const contextCountAfterLogout = (await owner.query<{ count: number }>('SELECT count(*)::int count FROM oidc.authorization_contexts')).rows[0]!.count;
        cookies.delete('__Host-dsa_signal_oidc_session'); cookies.delete('__Host-dsa_signal_oidc_session.sig');
        const verifier5 = randomBytes(32).toString('base64url'); const challenge5 = createHash('sha256').update(verifier5).digest('base64url');
        const auth5 = await request(`/oidc/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&scope=openid%20dsa_signal_entitlement&state=state5&nonce=nonce5&code_challenge=${challenge5}&code_challenge_method=S256`, 'GET', { ...forward, cookie: cookie('/oidc/auth') }); expect(auth5.status).toBe(303); absorbHttp(auth5);
        const page5 = await request('/oidc/interaction', 'GET', { ...forward, cookie: cookie('/oidc/interaction') }); csrfAfterLogout = /name="csrf" value="([A-Za-z0-9_-]{43})"/.exec(page5.body)?.[1]; expect(page5.status).toBe(200); expect(csrfAfterLogout).toBeTruthy();
        const postBody5 = `csrf=${csrfAfterLogout}`; const post5 = await request('/oidc/interaction', 'POST', { ...forward, origin, cookie: cookie('/oidc/interaction', true), 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(postBody5.length) }, postBody5); expect(post5.status).toBe(303); absorbHttp(post5);
        const resumePath5 = new URL(post5.headers.location!).pathname; const resume5 = await request(resumePath5, 'GET', { ...forward, cookie: cookie(resumePath5) }); expect(resume5.status).toBe(303); absorbHttp(resume5); const callback5 = new URL(resume5.headers.location!, origin); expect(callback5.origin).toBe(new URL(redirect).origin); expect(callback5.pathname).toBe(new URL(redirect).pathname); expect(callback5.searchParams.get('error')).toBe('access_denied'); expect(callback5.searchParams.get('state')).toBe('state5'); expect(callback5.searchParams.has('code')).toBe(false);
        expect((await owner.query<{ count: number }>('SELECT count(*)::int count FROM oidc.authorization_contexts')).rows[0]!.count).toBe(contextCountAfterLogout);
      } finally { await blocker.query('ROLLBACK').catch(() => undefined); blocker.release(); }
      expect((await owner.query('SELECT subject FROM control_plane.did_mappings WHERE id=$1', [mapping])).rows[0]!.subject).toBe(mappingSubject);
      for (const value of [csrf!, replacementCsrf!, csrf2!, csrf3!, csrfAfterLogout!, clientId, controlId, code1, code2, code3!, code4!, verifier, verifier2, verifier3, verifier4, tokenPayload1.access_token, tokenPayload1.id_token, winner.access_token, winner.id_token, 'state1', 'state2', 'state3', 'state4', 'nonce1', 'nonce2', 'nonce3', 'nonce4']) for (const column of (await owner.query<{ table_schema: string; table_name: string; column_name: string; data_type: string }>("SELECT table_schema,table_name,column_name,data_type FROM information_schema.columns WHERE table_schema IN ('oidc','control_plane') AND data_type IN ('text','bytea')")).rows) expect((await owner.query(`SELECT count(*)::int count FROM ${column.table_schema}.${column.table_name} WHERE position($1${column.data_type === 'bytea' ? '::bytea' : ''} in ${column.column_name})>0`, [column.data_type === 'bytea' ? Buffer.from(value) : value])).rows[0]!.count).toBe(0);
    } finally { server?.closeAllConnections(); if (server?.listening) await new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve())); await runtimePool.end(); await owner.end(); await pool.query(`DROP DATABASE ${database}`); }
  }, 30_000);
});
