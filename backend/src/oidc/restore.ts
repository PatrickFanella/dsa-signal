import { createHash, createPrivateKey, createPublicKey, createSign, createVerify, timingSafeEqual } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { assertCatalogManifest, assertRetainedKeys, expectedControlPlaneMigrationChecksum, LATEST_CONTROL_PLANE_CATALOG, type RetainedKeys } from '../db.js';
import type { Config, KeyRing } from '../config.js';
import { parseStrictJson } from '../http/strict-json.js';
import { assertOidcSecretSeparation, readSecretFile, type OidcSecrets } from './secrets.js';
import { appendOidcActivation, appendRestoreFloor, loadPublishedOidcActivation, loadPublishedRestoreFloor, loadRestoreFloorHistory, loadRestoreFloorLedger, type RestoreActivation, type RestoreFloorExpectation, type RestoreFloorResult } from './restore-floor.js';

const fail = (): never => { throw new Error('OIDC restore unavailable'); };
const PURGED_TABLES = [
  'oidc.interaction_csrf',
  'oidc.authorization_contexts',
  'oidc.provider_artifacts',
  'control_plane.idempotency_key_aliases',
  'control_plane.idempotency_results',
  'control_plane.jti_key_aliases',
  'control_plane.jti_uses',
  'control_plane.proof_challenges',
  'control_plane.login_states',
  'control_plane.entitlement_evidence_aliases',
  'control_plane.entitlements',
  'control_plane.identity_sessions',
  'control_plane.active_policy',
] as const;
const RETAINED_TABLES = ['control_plane.security_audit_events', 'control_plane.did_mappings', 'control_plane.policy_snapshots', 'control_plane.encrypted_envelopes', 'control_plane.revocation_evidence_key_ids', 'control_plane.membership_access_states', 'control_plane.entitlement_evidence_aliases', 'control_plane.membership_access_sources', 'control_plane.membership_access_source_chunks', 'control_plane.membership_access_source_selector_aliases', 'control_plane.membership_access_source_cause_aliases', 'control_plane.membership_access_source_targets', 'control_plane.membership_access_operations', 'control_plane.membership_access_requests', 'control_plane.membership_access_request_operation_links', 'control_plane.membership_access_mas_targets', 'control_plane.membership_access_registry_snapshots', 'control_plane.membership_access_crypto_capabilities', 'control_plane.membership_access_room_targets', 'control_plane.membership_access_steps', 'control_plane.membership_access_step_attempts'] as const;

export type FreshRestoreState = Readonly<{ epoch: string; adapter: KeyRing; index: KeyRing }>;
export type RestoreDeps = Readonly<{
  pool: Pick<Pool, 'connect'>;
  runtimeRole: string;
  retentionRole: string;
  claimantRole: string;
  assertCatalog?: typeof assertCatalogManifest;
  assertKeys?: typeof assertRetainedKeys;
  appendFloor?: typeof appendRestoreFloor;
  expectedMigrationChecksum?: typeof expectedControlPlaneMigrationChecksum;
}>;
export type RestoreResult = Readonly<{ phase: 'committed'; minimumIssuedAt: number; sequence: number; head: string; purged: Readonly<Record<string, number>> }>;
const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('base64url');
/** Produces the non-secret, canonical material binding stored in a floor record. */
export function restoreActivation(config: Pick<Config, 'OIDC_EPOCH' | 'OIDC_ADAPTER_KEY_RING' | 'OIDC_INDEX_KEY_RING'>, secrets: OidcSecrets): RestoreActivation {
  const ring = (value: KeyRing) => ({ active: value.active, keys: Object.entries(value.keys).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([id, key]) => ({ id, fingerprint: sha256(key) })) });
  // The first provider key is active: v3 binds this order exactly.
  return { epoch: config.OIDC_EPOCH, adapter: ring(config.OIDC_ADAPTER_KEY_RING), index: ring(config.OIDC_INDEX_KEY_RING), cookieKeyFingerprints: secrets.cookieKeys.map(sha256), clientSecretFingerprint: sha256(secrets.clientSecret), signingKeys: secrets.publicJwks.keys.map(key => ({ kid: key.kid, fingerprint: sha256(Buffer.from(JSON.stringify(key), 'utf8')) })) };
}

function decodeKey(value: unknown): Uint8Array {
  if (typeof value !== 'string') return fail();
  const encoded = value;
  if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) return fail();
  const bytes = Buffer.from(encoded, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== encoded) fail();
  return new Uint8Array(bytes);
}

function parseRing(value: unknown): KeyRing {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const source = value as Record<string, unknown>;
  if (Object.keys(source).sort().join(',') !== 'active,keys' || typeof source.active !== 'string' || !source.keys || typeof source.keys !== 'object' || Array.isArray(source.keys)) return fail();
  const active = source.active;
  if (!/^[a-z][a-z0-9_-]{0,31}$/.test(active)) return fail();
  const rawKeys = source.keys as Record<string, unknown>;
  const pairs = Object.entries(rawKeys);
  if (!pairs.length || !Object.hasOwn(rawKeys, active) || pairs.some(([id]) => !/^[a-z][a-z0-9_-]{0,31}$/.test(id))) fail();
  const keys = Object.fromEntries(pairs.map(([id, item]) => [id, decodeKey(item)]));
  if (new Set(Object.values(keys).map((item) => Buffer.from(item).toString('base64url'))).size !== pairs.length) fail();
  return { active, keys };
}

export function loadFreshRestoreState(path: string): FreshRestoreState {
  const bytes = readSecretFile(path);
  try {
    const value = parseStrictJson(bytes);
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
    const state = value as Record<string, unknown>;
    if (Object.keys(state).sort().join(',') !== 'adapter,epoch,index,version' || state.version !== 'v1' || typeof state.epoch !== 'string') return fail();
    const encodedEpoch = state.epoch;
    if (!/^[A-Za-z0-9_-]{22}$/.test(encodedEpoch)) return fail();
    const epoch = Buffer.from(encodedEpoch, 'base64url');
    if (epoch.length !== 16 || epoch.toString('base64url') !== encodedEpoch) fail();
    return { epoch: encodedEpoch, adapter: parseRing(state.adapter), index: parseRing(state.index) };
  } catch {
    return fail();
  } finally {
    bytes.fill(0);
  }
}

const equal = (left: Uint8Array, right: Uint8Array): boolean => left.length === right.length && timingSafeEqual(left, right);
const values = (ring: KeyRing): readonly Uint8Array[] => Object.values(ring.keys);

/** Proves every replacement OIDC secret purpose is fresh and signing trust is fresh-only. */
export function assertFreshMaterial(backup: Config, fresh: FreshRestoreState, freshSecrets: OidcSecrets, backupSecrets: OidcSecrets): void {
  if (fresh.epoch === backup.OIDC_EPOCH) fail();
  const oldSymmetric = [...values(backup.OIDC_ADAPTER_KEY_RING), ...values(backup.OIDC_INDEX_KEY_RING), ...backupSecrets.cookieKeys, backupSecrets.clientSecret];
  const newPurposes = [...values(fresh.adapter), ...values(fresh.index), ...freshSecrets.cookieKeys, freshSecrets.clientSecret];
  for (let index = 0; index < newPurposes.length; index += 1) {
    if (oldSymmetric.some((old) => equal(newPurposes[index]!, old)) || newPurposes.slice(index + 1).some((other) => equal(newPurposes[index]!, other))) fail();
  }
  const oldKids = new Set(backupSecrets.signingKeys.map((item) => item.kid));
  if (freshSecrets.signingKeys.some((item) => oldKids.has(item.kid)) || freshSecrets.publicJwks.keys.length !== freshSecrets.signingKeys.length) fail();
  const message = Buffer.from('dsa-signal isolated restore signing proof');
  const active = freshSecrets.signingKeys[0];
  if (!active) fail();
  const sign = createSign('sha256'); sign.update(message); sign.end();
  const signature = sign.sign(createPrivateKey({ key: active, format: 'jwk' }));
  const verify = createVerify('sha256'); verify.update(message); verify.end();
  if (!verify.verify(createPublicKey({ key: { kty: active.kty, n: active.n, e: active.e }, format: 'jwk' }), signature)) fail();
  for (const old of backupSecrets.signingKeys) {
    const oldSign = createSign('sha256'); oldSign.update(message); oldSign.end();
    const oldSignature = oldSign.sign(createPrivateKey({ key: old, format: 'jwk' }));
    if (freshSecrets.publicJwks.keys.some((publicKey) => {
      const check = createVerify('sha256'); check.update(message); check.end();
      return check.verify(createPublicKey({ key: publicKey, format: 'jwk' }), oldSignature);
    })) fail();
  }
}

const symmetricBindings = (activation: RestoreActivation) => [
  ...activation.adapter.keys.map(key => ({ purpose: 'adapter', id: key.id, fingerprint: key.fingerprint })),
  ...activation.index.keys.map(key => ({ purpose: 'index', id: key.id, fingerprint: key.fingerprint })),
  ...activation.cookieKeyFingerprints.map(fingerprint => ({ purpose: 'cookie', fingerprint })),
  { purpose: 'client', fingerprint: activation.clientSecretFingerprint },
] as const;
function assertActivationHistory(candidate: RestoreActivation, history: readonly RestoreActivation[]): void {
  for (const item of symmetricBindings(candidate)) for (const activation of history) for (const prior of symmetricBindings(activation)) {
    if ('id' in item && 'id' in prior && item.id === prior.id && item.purpose === prior.purpose && item.fingerprint !== prior.fingerprint) fail();
    if (item.fingerprint === prior.fingerprint && (item.purpose !== prior.purpose || ('id' in item ? item.id : undefined) !== ('id' in prior ? prior.id : undefined))) fail();
  }
  for (const item of candidate.signingKeys) for (const activation of history) for (const prior of activation.signingKeys) {
    if (item.kid === prior.kid && item.fingerprint !== prior.fingerprint) fail();
    if (item.fingerprint === prior.fingerprint && item.kid !== prior.kid) fail();
  }
}
function assertHistoricallyFresh(candidate: RestoreActivation, history: readonly RestoreActivation[]): void {
  if (history.some(activation => activation.epoch === candidate.epoch)) fail();
  const fingerprints = new Set([...symmetricBindings(candidate).map(item => item.fingerprint), ...candidate.signingKeys.map(item => item.fingerprint)]);
  if (history.some(activation => [...symmetricBindings(activation).map(item => item.fingerprint), ...activation.signingKeys.map(item => item.fingerprint)].some(fingerprint => fingerprints.has(fingerprint)))) fail();
  const adapterIds = new Set(candidate.adapter.keys.map(key => key.id)), indexIds = new Set(candidate.index.keys.map(key => key.id)), signingKids = new Set(candidate.signingKeys.map(key => key.kid));
  if (history.some(activation => activation.adapter.keys.some(key => adapterIds.has(key.id)) || activation.index.keys.some(key => indexIds.has(key.id)) || activation.signingKeys.some(key => signingKids.has(key.kid)))) fail();
}

function retained(config: Config, oidc: FreshRestoreState): RetainedKeys {
  return {
    subject: config.SUBJECT_KEY_RING.keys,
    envelope: config.ENVELOPE_KEY_RING.keys,
    challenge: Object.keys(config.CHALLENGE_KEY_RING.keys),
    binding: Object.keys(config.SESSION_BINDING_KEY_RING.keys),
    jti: { active: config.JTI_KEY_RING.active, retained: Object.keys(config.JTI_KEY_RING.keys) },
    idempotency: { active: config.IDEMPOTENCY_KEY_RING.active, retained: Object.keys(config.IDEMPOTENCY_KEY_RING.keys) },
    request: Object.keys(config.REQUEST_FINGERPRINT_KEY_RING.keys),
    evidence: Object.keys(config.REVOCATION_EVIDENCE_KEY_RING.keys),
    oidc: { epoch: oidc.epoch, adapter: oidc.adapter.keys, index: Object.keys(oidc.index.keys) },
  };
}

async function counts(client: PoolClient, tables: readonly string[]): Promise<Record<string, number>> {
  const result: Record<string, number> = {};
  for (const table of tables) result[table] = (await client.query<{ count: number }>(`SELECT count(*)::int count FROM ${table}`)).rows[0]?.count ?? -1;
  return result;
}

const sameCounts = (left: Readonly<Record<string, number>>, right: Readonly<Record<string, number>>): boolean => Object.keys(left).every((key) => left[key] === right[key]);

/** Runs the fail-closed isolated restore purge. It never installs or emits secrets. */
export async function runOidcRestore(deps: RestoreDeps, backup: Config, fresh: FreshRestoreState, backupSecrets: OidcSecrets, freshSecrets: OidcSecrets, trustedClock: Date, expectation: RestoreFloorExpectation): Promise<RestoreResult> {
  try {
    assertFreshMaterial(backup, fresh, freshSecrets, backupSecrets);
    const candidateConfig: Config = { ...backup, OIDC_EPOCH: fresh.epoch, OIDC_ADAPTER_KEY_RING: fresh.adapter, OIDC_INDEX_KEY_RING: fresh.index };
    assertOidcSecretSeparation(candidateConfig, freshSecrets);
    const freshBinding = restoreActivation({ OIDC_EPOCH: fresh.epoch, OIDC_ADAPTER_KEY_RING: fresh.adapter, OIDC_INDEX_KEY_RING: fresh.index }, freshSecrets);
    let predecessorHistory: readonly RestoreActivation[]; let exactRetry = false; let published: RestoreFloorResult | undefined;
    try {
      predecessorHistory = (await loadRestoreFloorHistory(backup.OIDC_RESTORE_FLOOR_DIR!, expectation.expectedHead)).activations;
    } catch {
      const retry: RestoreFloorResult = (await loadPublishedRestoreFloor(backup.OIDC_RESTORE_FLOOR_DIR!, trustedClock, freshBinding, expectation)) ?? fail();
      published = retry;
      predecessorHistory = (await loadRestoreFloorHistory(backup.OIDC_RESTORE_FLOOR_DIR!, retry.head)).activations.slice(0, -1);
      exactRetry = true;
    }
    // A restored backup is binding material too, including before the ledger exists.
    // On an exact retry the just-published candidate was removed from predecessorHistory.
    assertHistoricallyFresh(freshBinding, [restoreActivation(backup, backupSecrets), ...predecessorHistory]);
    const catalog = deps.assertCatalog ?? assertCatalogManifest;
    const keys = deps.assertKeys ?? assertRetainedKeys;
    const append = deps.appendFloor ?? appendRestoreFloor;
    const expectedChecksum = deps.expectedMigrationChecksum ?? expectedControlPlaneMigrationChecksum;

    const client = await deps.pool.connect();
    let commitAttempted = false;
    let poison: Error | undefined;
    const purged: Record<string, number> = {};
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1)', [8_004]);
      await catalog(client, deps.runtimeRole, deps.retentionRole, LATEST_CONTROL_PLANE_CATALOG, deps.claimantRole);
      await keys(client, retained(backup, { epoch: backup.OIDC_EPOCH, adapter: backup.OIDC_ADAPTER_KEY_RING, index: backup.OIDC_INDEX_KEY_RING }));
      const ledger = (await client.query<{ checksum: Buffer }>("SELECT checksum FROM control_plane.schema_migrations WHERE id='0005_access_revocation_foundation'")).rows[0]?.checksum;
      const checksum = await expectedChecksum('0005_access_revocation_foundation');
      if (!Buffer.isBuffer(ledger) || ledger.length !== checksum.length || !timingSafeEqual(ledger, checksum)) fail();
      const appended = exactRetry ? published! : await append(backup.OIDC_RESTORE_FLOOR_DIR!, trustedClock, freshBinding, expectation);
      // Alias rows are entitlement-derived and must be purged before their
      // parent; all independent 0005 evidence remains part of the snapshot.
      for (const table of PURGED_TABLES) purged[table] = (await client.query(`DELETE FROM ${table}`)).rowCount ?? 0;
      if (Object.values(await counts(client, PURGED_TABLES)).some((count) => count !== 0)) fail();
      const retainedBefore = await counts(client, RETAINED_TABLES);
      if (!sameCounts(retainedBefore, await counts(client, RETAINED_TABLES))) fail();
      await keys(client, retained(backup, fresh));
      commitAttempted = true;
      await client.query('COMMIT');
      return { phase: 'committed', ...appended, purged };
    } catch (error) {
      const failure = error instanceof Error ? error : new Error('OIDC restore unavailable');
      if (commitAttempted) {
        poison = failure;
      } else {
        try { await client.query('ROLLBACK'); } catch (rollback) { poison = rollback instanceof Error ? rollback : failure; }
      }
      throw failure;
    } finally {
      client.release(poison);
    }

  } catch {
    return fail();
  }
}

/** Fenced, non-destructive material activation. Operators must keep traffic blocked through head publication and deployment. */
export async function runOidcActivation(deps: RestoreDeps, current: Config, candidate: FreshRestoreState, currentSecrets: OidcSecrets, candidateSecrets: OidcSecrets, expectation: RestoreFloorExpectation): Promise<RestoreFloorResult> {
  try {
    const catalog = deps.assertCatalog ?? assertCatalogManifest;
    const keys = deps.assertKeys ?? assertRetainedKeys;
    const checksum = deps.expectedMigrationChecksum ?? expectedControlPlaneMigrationChecksum;
    const candidateConfig: Config = { ...current, OIDC_EPOCH: candidate.epoch, OIDC_ADAPTER_KEY_RING: candidate.adapter, OIDC_INDEX_KEY_RING: candidate.index };
    assertOidcSecretSeparation(candidateConfig, candidateSecrets);
    const currentBinding = restoreActivation(current, currentSecrets);
    const candidateBinding = restoreActivation({ OIDC_EPOCH: candidate.epoch, OIDC_ADAPTER_KEY_RING: candidate.adapter, OIDC_INDEX_KEY_RING: candidate.index }, candidateSecrets);
    const retry = await loadPublishedOidcActivation(current.OIDC_RESTORE_FLOOR_DIR!, candidateBinding, expectation);
    const floor = await loadRestoreFloorLedger(current.OIDC_RESTORE_FLOOR_DIR!, retry?.head ?? expectation.expectedHead, retry ? candidateBinding : currentBinding);
    assertActivationHistory(candidateBinding, floor.activations);
    if (!retry) {
      if (floor.minimumIssuedAt !== expectation.expectedPreviousFloor || floor.sequence !== expectation.expectedNextSequence - 1 || floor.head !== expectation.expectedHead) fail();
    }
    const client = await deps.pool.connect(); let committed = false; let poison: Error | undefined; let published: RestoreFloorResult | undefined;
    try {
      await client.query('BEGIN READ ONLY');
      await client.query('SELECT pg_advisory_xact_lock($1)', [8_004]);
      await catalog(client, deps.runtimeRole, deps.retentionRole, LATEST_CONTROL_PLANE_CATALOG, deps.claimantRole);
      const ledger = (await client.query<{ checksum: Buffer }>("SELECT checksum FROM control_plane.schema_migrations WHERE id='0005_access_revocation_foundation'")).rows[0]?.checksum;
      const expected = await checksum('0005_access_revocation_foundation');
      if (!Buffer.isBuffer(ledger) || ledger.length !== expected.length || !timingSafeEqual(ledger, expected)) fail();
      await keys(client, retained(current, { epoch: current.OIDC_EPOCH, adapter: current.OIDC_ADAPTER_KEY_RING, index: current.OIDC_INDEX_KEY_RING }));
      await keys(client, retained(current, candidate));
      const result = await appendOidcActivation(current.OIDC_RESTORE_FLOOR_DIR!, candidateBinding, expectation);
      published = result;
      committed = true;
      try { await client.query('COMMIT'); } catch (error) { poison = error instanceof Error ? error : new Error('OIDC restore unavailable'); return result; }
      return result;
    } catch (error) {
      const failure = error instanceof Error ? error : new Error('OIDC restore unavailable');
      if (committed && published) { poison = failure; return published; } else { try { await client.query('ROLLBACK'); } catch (rollback) { poison = rollback instanceof Error ? rollback : failure; } }
      throw failure;
    } finally { client.release(poison); }
  } catch { return fail(); }
}
