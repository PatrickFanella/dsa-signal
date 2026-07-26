import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import type { KeyRing } from '../config.js';
import { refreshOidcDecisionNow, requireOidcRequestContext } from './request-context.js';
import type { OidcHooks } from './provider.js';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { lockMappingAccess, lockSourceSet } from '../entitlements/runtime-locks.js';
export type OidcFingerprints = Readonly<{ keyId: string; client: Buffer; interactionChain: Buffer; interactionUid: Buffer; csrf?: Buffer }>;
export type AuthorizationDecision = Readonly<{ mappingId: string; entitlementId: string; generation: bigint; jkt: string; policySnapshotId: string; policyVersion: string; subject: string; expiresAt: Date; sessionIdleExpiresAt: Date; sessionAbsoluteExpiresAt: Date }>;
const mac = (key: Uint8Array, prefix: string, value: string | Uint8Array): Buffer => { const h = createHmac('sha256', key).update(prefix).update('\0'); if (typeof value === 'string') h.update(value, 'utf8'); else h.update(value); return h.digest(); };
export function oidcFingerprintsForKey(ring: KeyRing, keyId: string, epoch: string, clientId: string, chain: string, interaction: string, csrf?: Uint8Array): OidcFingerprints { const key = ring.keys[keyId]; if (!key) throw new Error('OIDC index key unavailable'); return { keyId, client: mac(key, `dsa-signal-oidc-client:v1\0${epoch}`, clientId), interactionChain: mac(key, `dsa-signal-oidc-interaction-chain:v1\0${epoch}`, chain), interactionUid: mac(key, `dsa-signal-oidc-interaction-uid:v1\0${epoch}`, interaction), ...(csrf ? { csrf: mac(key, `dsa-signal-oidc-csrf:v1\0${epoch}`, csrf) } : {}) }; }
export function oidcFingerprints(ring: KeyRing, epoch: string, clientId: string, chain: string, interaction: string, csrf?: Uint8Array): OidcFingerprints { return oidcFingerprintsForKey(ring, ring.active, epoch, clientId, chain, interaction, csrf); }
export const advisoryLock = async (fingerprint: Uint8Array): Promise<void> => { if (fingerprint.length !== 32) throw new Error('invalid control binding'); await requireOidcRequestContext().client.query("SELECT pg_advisory_xact_lock(('x' || encode($1::bytea, 'hex'))::bit(64)::bigint)", [Buffer.from(fingerprint.subarray(0, 8))]); };
export class OidcAuthorizationRejectedError extends Error {}
/**
 * The lock order shared by token redemption and product logout. Policy snapshots
 * are immutable and therefore cannot be UPDATE-locked at runtime; active_policy
 * is the mutable serialization boundary for a snapshot change.
 */
export type ControlSessionLockOptions = Readonly<{
  /** Only product logout may resolve a retained context from this exact epoch. */
  logoutEpoch?: string;
  allowSuspendedMapping?: boolean;
}>;
export async function lockControlSessionEntitlementsAndPolicy(bindingKeyId: string, bindingFingerprint: Uint8Array, options: ControlSessionLockOptions = {}): Promise<void> {
  const { client } = requireOidcRequestContext();
  const candidates = async (decisionNow: Date): Promise<string[]> => (await client.query<{ mapping_id: string }>(`SELECT DISTINCT mapping_id FROM (SELECT mapping_id FROM control_plane.identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2${options.logoutEpoch ? ' UNION ALL SELECT mapping_id FROM oidc.authorization_contexts WHERE control_session_key_id=$1 AND control_session_fingerprint=$2 AND epoch=$3 AND grant_expires_at>$4' : ''}) candidate`, options.logoutEpoch ? [bindingKeyId, Buffer.from(bindingFingerprint), options.logoutEpoch, decisionNow] : [bindingKeyId, Buffer.from(bindingFingerprint)])).rows.map(row => row.mapping_id);
  await lockSourceSet(client);
  const before = await candidates(requireOidcRequestContext().decisionNow);
  if (before.length !== 1) throw new OidcAuthorizationRejectedError('authorization rejected');
  const active = await lockMappingAccess(client, before[0]!);
  if (!options.allowSuspendedMapping && !active) throw new OidcAuthorizationRejectedError('authorization rejected');
  await advisoryLock(bindingFingerprint);
  // Exact-key locks must not be filtered by time: an otherwise stale row still
  // has to be serialized before the authoritative clock is sampled.
  await client.query('SELECT binding_key_id FROM control_plane.identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2 FOR UPDATE', [bindingKeyId, Buffer.from(bindingFingerprint)]);
  await client.query('SELECT id FROM control_plane.entitlements WHERE session_binding_key_id=$1 AND session_binding_fingerprint=$2 ORDER BY id FOR UPDATE', [bindingKeyId, Buffer.from(bindingFingerprint)]);
  await client.query('SELECT singleton FROM control_plane.active_policy WHERE singleton=true FOR UPDATE');
  const decisionNow = await refreshOidcDecisionNow();
  const after = await candidates(decisionNow);
  if (after.length !== 1 || after[0] !== before[0]) throw new OidcAuthorizationRejectedError('authorization rejected');
}
/** Query authorization only after the common locks have already been acquired. */
export async function queryLiveAuthorizationDecision(epoch: string, bindingKeyId: string, bindingFingerprint: Uint8Array, minimumIssuedAt = 0): Promise<AuthorizationDecision> { const context = requireOidcRequestContext(); const floor = await context.client.query('SELECT 1 FROM control_plane.active_policy a JOIN control_plane.policy_snapshots p ON p.id=a.snapshot_id WHERE a.singleton=true AND p.signed_at>=to_timestamp($1)', [minimumIssuedAt]); if (floor.rowCount !== 1) throw new OidcAuthorizationRejectedError('authorization rejected'); const result = await context.client.query<{ mapping_id: string; entitlement_id: string; generation: string; jkt: Buffer; policy_snapshot_id: string; policy_version: string; subject: string; expires_at: Date; idle_expires_at: Date; absolute_expires_at: Date }>(`SELECT s.mapping_id,e.id AS entitlement_id,e.generation,e.jkt,e.policy_snapshot_id,e.policy_version,m.subject,e.expires_at,s.idle_expires_at,s.absolute_expires_at FROM control_plane.identity_sessions s JOIN control_plane.entitlements e ON e.session_binding_key_id=s.binding_key_id AND e.session_binding_fingerprint=s.binding_fingerprint JOIN control_plane.did_mappings m ON m.id=s.mapping_id AND m.erased_at IS NULL JOIN control_plane.active_policy a ON a.singleton=true AND a.snapshot_id=e.policy_snapshot_id JOIN control_plane.policy_snapshots p ON p.id=a.snapshot_id AND p.version=e.policy_version AND p.fresh_until>$4 WHERE s.binding_key_id=$1 AND s.binding_fingerprint=$2 AND s.revoked_at IS NULL AND s.idle_expires_at>$4 AND s.absolute_expires_at>$4 AND e.oidc_epoch=$3 AND e.entitlement='chat' AND e.status='active' AND e.expires_at>$4`, [bindingKeyId, Buffer.from(bindingFingerprint), epoch, context.decisionNow]); if (result.rowCount !== 1) throw new OidcAuthorizationRejectedError('authorization rejected'); const row = result.rows[0]!; return { mappingId: row.mapping_id, entitlementId: row.entitlement_id, generation: BigInt(row.generation), jkt: row.jkt.toString('base64url'), policySnapshotId: row.policy_snapshot_id, policyVersion: row.policy_version, subject: row.subject, expiresAt: row.expires_at, sessionIdleExpiresAt: row.idle_expires_at, sessionAbsoluteExpiresAt: row.absolute_expires_at }; }
export async function loadLiveAuthorizationDecision(epoch: string, bindingKeyId: string, bindingFingerprint: Uint8Array, minimumIssuedAt = 0): Promise<AuthorizationDecision> { await lockControlSessionEntitlementsAndPolicy(bindingKeyId, bindingFingerprint); return queryLiveAuthorizationDecision(epoch, bindingKeyId, bindingFingerprint, minimumIssuedAt); }
export async function saveAuthorizationContext(epoch: string, fp: OidcFingerprints, controlKeyId: string, controlFingerprint: Uint8Array, grantId: string, index: KeyRing, decision: AuthorizationDecision): Promise<void> { const { client, decisionNow } = requireOidcRequestContext(); const key = index.keys[index.active]; if (!key) throw new Error('OIDC index key unavailable'); const grant = mac(key, `dsa-signal-oidc-grant-id:v1\0${epoch}`, grantId); try { const result = await client.query(`INSERT INTO oidc.authorization_contexts(id,epoch,client_key_id,client_fingerprint,grant_key_id,grant_fingerprint,interaction_chain_key_id,interaction_chain_fingerprint,interaction_uid_key_id,interaction_uid_fingerprint,control_session_key_id,control_session_fingerprint,mapping_id,entitlement_id,generation,jkt,policy_snapshot_id,policy_version,created_at,expires_at,grant_expires_at,retained_until) VALUES($1,$2,$3,$4,$3,$5,$3,$6,$3,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::timestamptz,$16::timestamptz+interval '300 seconds',$16::timestamptz+interval '900 seconds',$16::timestamptz+interval '930 seconds')`, [randomUUID(), epoch, fp.keyId, fp.client, grant, fp.interactionChain, fp.interactionUid, controlKeyId, Buffer.from(controlFingerprint), decision.mappingId, decision.entitlementId, decision.generation.toString(), decision.jkt, decision.policySnapshotId, decision.policyVersion, decisionNow]); if (result.rowCount !== 1) throw new Error('authorization context missing'); } finally { grant.fill(0); } }
/** Stage the cross-model claim.  The provider can still fail after storing its code. */
export function createAuthorizationCodeClaim(epoch: string, index: KeyRing): (code: string, payload: Readonly<Record<string, unknown>>) => Promise<void> {
  return async (code, payload) => {
    const grantId = payload.grantId; const sessionUid = payload.sessionUid;
    if (typeof grantId !== 'string' || typeof sessionUid !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(sessionUid)) throw new Error('authorization code binding missing');
    const request = requireOidcRequestContext();
    if (request.pendingCodeClaim) throw new Error('multiple authorization code claims');
    request.pendingCodeClaim = { code, grantId, sessionUid, finalize: async () => {
      const key = index.keys[index.active]; if (!key) throw new Error('OIDC index key unavailable');
      const resume = request.pendingResume;
      if (!resume || resume.grantId !== grantId) throw new Error('authorization resume unavailable');
      const contextKey = index.keys[resume.indexKeyId]; if (!contextKey) throw new Error('OIDC retained index key unavailable');
      const grant = mac(contextKey, `dsa-signal-oidc-grant-id:v1\0${epoch}`, grantId);
      const codeFingerprint = mac(key, `dsa-signal-oidc-artifact-id:v1\0${epoch}\0AuthorizationCode`, code);
      const sessionFingerprint = mac(key, `dsa-signal-oidc-session-uid:v1\0${epoch}`, sessionUid);
      try {
        const codeArtifact = await request.client.query<{ expires_at: Date; revoked_at: Date | null }>('SELECT expires_at,revoked_at FROM oidc.provider_artifacts WHERE epoch=$1 AND model=\'AuthorizationCode\' AND artifact_key_id=$2 AND artifact_fingerprint=$3 FOR UPDATE', [epoch, index.active, codeFingerprint]);
        const sessionArtifact = await request.client.query<{ expires_at: Date; revoked_at: Date | null }>('SELECT expires_at,revoked_at FROM oidc.provider_artifacts WHERE epoch=$1 AND model=\'Session\' AND session_uid_key_id=$2 AND session_uid_fingerprint=$3 FOR UPDATE', [epoch, index.active, sessionFingerprint]);
        if (codeArtifact.rowCount !== 1 || sessionArtifact.rowCount !== 1) throw new Error('authorization artifacts unavailable');
        await refreshOidcDecisionNow();
        if (codeArtifact.rows[0]!.revoked_at || codeArtifact.rows[0]!.expires_at <= request.decisionNow || sessionArtifact.rows[0]!.revoked_at || sessionArtifact.rows[0]!.expires_at <= request.decisionNow) throw new Error('authorization artifacts unavailable');
        const finalLive = await queryLiveAuthorizationDecision(epoch, resume.controlSessionKeyId, resume.controlSessionFingerprint, resume.minimumIssuedAt);
        if (finalLive.mappingId !== resume.mappingId || finalLive.entitlementId !== resume.entitlementId || finalLive.generation !== resume.generation || finalLive.jkt !== resume.jkt || finalLive.policySnapshotId !== resume.policySnapshotId || finalLive.policyVersion !== resume.policyVersion) throw new Error('authorization decision changed');
        const claimed = await request.client.query('UPDATE oidc.authorization_contexts SET authorization_code_key_id=$1,authorization_code_fingerprint=$2,provider_session_uid_key_id=$1,provider_session_uid_fingerprint=$3 WHERE id=$4 AND epoch=$5 AND grant_key_id=$6 AND grant_fingerprint=$7 AND authorization_code_key_id IS NULL AND provider_session_uid_key_id IS NULL AND mapping_id=$8 AND entitlement_id=$9 AND generation=$10 AND jkt=$11 AND policy_snapshot_id=$12 AND policy_version=$13 AND revoked_at IS NULL AND expires_at>$14', [index.active, codeFingerprint, sessionFingerprint, resume.contextId, epoch, resume.indexKeyId, grant, finalLive.mappingId, finalLive.entitlementId, finalLive.generation.toString(), finalLive.jkt, finalLive.policySnapshotId, finalLive.policyVersion, request.decisionNow]);
        if (claimed.rowCount !== 1) throw new Error('authorization context claim missing');
      } finally { grant.fill(0); codeFingerprint.fill(0); sessionFingerprint.fill(0); }
    } };
  };
}

type ProviderHookContext = Readonly<{ oidc?: { result?: { consent?: { grantId?: unknown } } } }>;
type StoredInteraction = Readonly<{ jti?: unknown; cid?: unknown; result?: unknown; grantId?: unknown }>;
type InteractionReader = new (model: string) => { find(id: string): Promise<StoredInteraction | undefined> };
type TokenContextRow = { id: string; client_key_id: string; client_fingerprint: Buffer; grant_key_id: string; grant_fingerprint: Buffer; provider_session_uid_key_id: string; provider_session_uid_fingerprint: Buffer; control_session_key_id: string; control_session_fingerprint: Buffer; mapping_id: string; entitlement_id: string; generation: string; jkt: string; policy_snapshot_id: string; policy_version: string };

/**
 * Runs before oidc-provider's token handler after the host has bounded and
 * pre-read the raw token form; it is neither copied into ALS nor persisted.
 */
export function createTokenPreflight(epoch: string, clientId: string, index: KeyRing, minimumIssuedAt = 0): (code: string, payload: Readonly<Record<string, unknown>>, match: Readonly<{ keyId: string; fingerprint: Buffer; consumedAt: Date | null }>) => Promise<Date | undefined> {
  return async (code, payload, match) => {
    if (!/^[A-Za-z0-9_-]{43}$/.test(code)) throw new Error('token rejected');
    const request = requireOidcRequestContext();
    const grantId = payload.grantId; const sessionUid = payload.sessionUid;
    if (payload.clientId !== clientId || typeof grantId !== 'string' || typeof sessionUid !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(sessionUid)) throw new Error('token binding unavailable');
    // Pre-resolve only enough context to derive the common session lock. Every
    // value is revalidated after the advisory lock and refreshed DB clock.
    const context = await request.client.query<TokenContextRow>('SELECT id,client_key_id,client_fingerprint,grant_key_id,grant_fingerprint,provider_session_uid_key_id,provider_session_uid_fingerprint,control_session_key_id,control_session_fingerprint,mapping_id,entitlement_id,generation,jkt,policy_snapshot_id,policy_version FROM oidc.authorization_contexts WHERE epoch=$1 AND authorization_code_key_id=$2 AND authorization_code_fingerprint=$3', [epoch, match.keyId, match.fingerprint]);
    if (context.rowCount !== 1) throw new Error('token context unavailable');
    const row = context.rows[0]!;
    const clientKey = index.keys[row.client_key_id]; const grantKey = index.keys[row.grant_key_id]; const sessionKey = index.keys[row.provider_session_uid_key_id];
    if (!clientKey || !grantKey || !sessionKey) throw new Error('token retained key unavailable');
    const client = mac(clientKey, `dsa-signal-oidc-client:v1\0${epoch}`, clientId); const grant = mac(grantKey, `dsa-signal-oidc-grant-id:v1\0${epoch}`, grantId); const uid = mac(sessionKey, `dsa-signal-oidc-session-uid:v1\0${epoch}`, sessionUid);
    try {
      if (!timingSafeEqual(client, row.client_fingerprint) || !timingSafeEqual(grant, row.grant_fingerprint) || !timingSafeEqual(uid, row.provider_session_uid_fingerprint)) throw new Error('token artifact binding changed');
      await lockControlSessionEntitlementsAndPolicy(row.control_session_key_id, row.control_session_fingerprint);
      const lockedContext = await request.client.query('SELECT id,revoked_at,expires_at FROM oidc.authorization_contexts WHERE id=$1 AND epoch=$2 AND authorization_code_key_id=$3 AND authorization_code_fingerprint=$4 FOR UPDATE', [row.id, epoch, match.keyId, match.fingerprint]);
      if (lockedContext.rowCount !== 1) throw new Error('token context unavailable');
      const lockedCode = await request.client.query<{ consumed_at: Date | null; expires_at: Date; revoked_at: Date | null }>('SELECT consumed_at,expires_at,revoked_at FROM oidc.provider_artifacts WHERE epoch=$1 AND model=\'AuthorizationCode\' AND artifact_key_id=$2 AND artifact_fingerprint=$3 FOR UPDATE', [epoch, match.keyId, match.fingerprint]);
      if (lockedCode.rowCount !== 1) throw new Error('token code unavailable');
      if (lockedCode.rows[0]!.consumed_at) return lockedCode.rows[0]!.consumed_at!;
      if (lockedCode.rows[0]!.revoked_at || lockedCode.rows[0]!.expires_at <= request.decisionNow) throw new Error('token code unavailable');
      const live = await queryLiveAuthorizationDecision(epoch, row.control_session_key_id, row.control_session_fingerprint, minimumIssuedAt);
      if (live.mappingId !== row.mapping_id || live.entitlementId !== row.entitlement_id || live.generation !== BigInt(row.generation) || live.jkt !== row.jkt || live.policySnapshotId !== row.policy_snapshot_id || live.policyVersion !== row.policy_version) throw new Error('token decision changed');
      const exactContext = await request.client.query('SELECT id FROM oidc.authorization_contexts WHERE id=$1 AND epoch=$2 AND client_key_id=$3 AND client_fingerprint=$4 AND authorization_code_key_id=$5 AND authorization_code_fingerprint=$6 AND grant_key_id=$7 AND grant_fingerprint=$8 AND provider_session_uid_key_id=$9 AND provider_session_uid_fingerprint=$10 AND mapping_id=$11 AND entitlement_id=$12 AND generation=$13 AND jkt=$14 AND policy_snapshot_id=$15 AND policy_version=$16 AND expires_at>$17 AND revoked_at IS NULL', [row.id, epoch, row.client_key_id, client, match.keyId, match.fingerprint, row.grant_key_id, grant, row.provider_session_uid_key_id, uid, live.mappingId, live.entitlementId, live.generation.toString(), live.jkt, live.policySnapshotId, live.policyVersion, request.decisionNow]);
      if (exactContext.rowCount !== 1) throw new Error('token artifacts unavailable');
      const grantArtifact = await request.client.query<{ id: string; expires_at: Date; revoked_at: Date | null }>('SELECT id,expires_at,revoked_at FROM oidc.provider_artifacts WHERE epoch=$1 AND model=\'Grant\' AND grant_key_id=$2 AND grant_fingerprint=$3 FOR UPDATE', [epoch, row.grant_key_id, grant]);
      const sessionRows = new Map<string, { expires_at: Date; revoked_at: Date | null }>();
      for (const [sessionKeyId, retainedKey] of Object.entries(index.keys)) {
        const retainedUid = mac(retainedKey, `dsa-signal-oidc-session-uid:v1\0${epoch}`, sessionUid);
        try {
          const found = await request.client.query<{ id: string; expires_at: Date; revoked_at: Date | null }>('SELECT id,expires_at,revoked_at FROM oidc.provider_artifacts WHERE epoch=$1 AND model=\'Session\' AND session_uid_key_id=$2 AND session_uid_fingerprint=$3 FOR UPDATE', [epoch, sessionKeyId, retainedUid]);
          if (found.rows[0]) sessionRows.set(found.rows[0].id, found.rows[0]);
        } finally { retainedUid.fill(0); }
      }
      if (grantArtifact.rowCount !== 1 || sessionRows.size !== 1) throw new Error('token artifacts unavailable');
      // Grant and provider Session locks may have waited.  Do not calculate a
      // token TTL or authorize the already-locked code/context on their old
      // clock.
      await refreshOidcDecisionNow();
      const finalLive = await queryLiveAuthorizationDecision(epoch, row.control_session_key_id, row.control_session_fingerprint, minimumIssuedAt);
      if (finalLive.mappingId !== live.mappingId || finalLive.entitlementId !== live.entitlementId || finalLive.generation !== live.generation || finalLive.jkt !== live.jkt || finalLive.policySnapshotId !== live.policySnapshotId || finalLive.policyVersion !== live.policyVersion) throw new Error('token decision changed');
      if (lockedCode.rows[0]!.revoked_at || lockedCode.rows[0]!.expires_at <= request.decisionNow) throw new Error('token code unavailable');
      if (grantArtifact.rows[0]!.revoked_at || grantArtifact.rows[0]!.expires_at <= request.decisionNow || [...sessionRows.values()].some(session => session.revoked_at || session.expires_at <= request.decisionNow)) throw new Error('token artifacts unavailable');
      const finalContext = await request.client.query('SELECT id FROM oidc.authorization_contexts WHERE id=$1 AND epoch=$2 AND client_key_id=$3 AND client_fingerprint=$4 AND authorization_code_key_id=$5 AND authorization_code_fingerprint=$6 AND grant_key_id=$7 AND grant_fingerprint=$8 AND provider_session_uid_key_id=$9 AND provider_session_uid_fingerprint=$10 AND mapping_id=$11 AND entitlement_id=$12 AND generation=$13 AND jkt=$14 AND policy_snapshot_id=$15 AND policy_version=$16 AND expires_at>$17 AND revoked_at IS NULL', [row.id, epoch, row.client_key_id, client, match.keyId, match.fingerprint, row.grant_key_id, grant, row.provider_session_uid_key_id, uid, finalLive.mappingId, finalLive.entitlementId, finalLive.generation.toString(), finalLive.jkt, finalLive.policySnapshotId, finalLive.policyVersion, request.decisionNow]);
      if (finalContext.rowCount !== 1) throw new Error('token artifacts unavailable');
      const ttl = Math.floor(Math.min(300, (finalLive.sessionIdleExpiresAt.getTime() - request.decisionNow.getTime()) / 1000, (finalLive.sessionAbsoluteExpiresAt.getTime() - request.decisionNow.getTime()) / 1000, (finalLive.expiresAt.getTime() - request.decisionNow.getTime()) / 1000));
      if (ttl < 1) throw new Error('token expired');
      request.pendingTokenRedemption = { mappingId: finalLive.mappingId, subject: finalLive.subject, policyVersion: finalLive.policyVersion, ttl };
      return undefined;
    } finally { client.fill(0); grant.fill(0); uid.fill(0); }
  };
}

/** Resolve and bind an exact provider resume before it is allowed to mutate artifacts. */
export function createResumePreflight(epoch: string, index: KeyRing, Adapter: InteractionReader, minimumIssuedAt = 0): (request: IncomingMessage, _response: ServerResponse) => Promise<void> {
  return async (request) => {
    const matched = /^\/auth\/([A-Za-z0-9_-]{43})$/.exec(request.url ?? '');
    if (!matched) return;
    const details = await new Adapter('Interaction').find(matched[1]!) as StoredInteraction | undefined;
    const result = details?.result;
    const terminalDenial = result !== null && typeof result === 'object' && !Array.isArray(result) && Object.getPrototypeOf(result) === Object.prototype && Object.keys(result).sort().join(',') === 'error,error_description' && (result as Record<string, unknown>).error === 'access_denied' && (result as Record<string, unknown>).error_description === 'Access denied';
    if (details && details.jti === matched[1] && typeof details.cid === 'string' && /^[A-Za-z0-9_-]{43}$/.test(details.cid) && !Object.hasOwn(details, 'grantId') && terminalDenial) return;
    const consent = result !== null && typeof result === 'object' && !Array.isArray(result) ? (result as Record<string, unknown>).consent : undefined;
    const grantId = consent !== null && typeof consent === 'object' && !Array.isArray(consent) ? (consent as Record<string, unknown>).grantId : undefined;
    if (typeof grantId !== 'string' || details?.jti !== matched[1] || typeof details.cid !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(details.cid)) throw new Error('resume binding unavailable');
    const current = requireOidcRequestContext();
    type ContextRow = { id: string; control_session_key_id: string; control_session_fingerprint: Buffer; mapping_id: string; entitlement_id: string; generation: string; jkt: string; policy_snapshot_id: string; policy_version: string };
    let selected: { keyId: string; grant: Buffer; chain: Buffer; interaction: Buffer; row: ContextRow } | undefined;
    try {
      for (const [keyId, key] of Object.entries(index.keys)) {
        const grant = mac(key, `dsa-signal-oidc-grant-id:v1\0${epoch}`, grantId); const chain = mac(key, `dsa-signal-oidc-interaction-chain:v1\0${epoch}`, details.cid); const interaction = mac(key, `dsa-signal-oidc-interaction-uid:v1\0${epoch}`, details.jti);
        const found = await current.client.query<ContextRow>('SELECT id,control_session_key_id,control_session_fingerprint,mapping_id,entitlement_id,generation,jkt,policy_snapshot_id,policy_version FROM oidc.authorization_contexts WHERE epoch=$1 AND grant_key_id=$2 AND grant_fingerprint=$3 AND interaction_chain_key_id=$2 AND interaction_chain_fingerprint=$4 AND interaction_uid_key_id=$2 AND interaction_uid_fingerprint=$5 AND expires_at>$6 AND revoked_at IS NULL', [epoch, keyId, grant, chain, interaction, current.decisionNow]);
        if (found.rowCount === 1) {
          if (selected) { grant.fill(0); chain.fill(0); interaction.fill(0); throw new Error('resume context ambiguous'); }
          selected = { keyId, grant, chain, interaction, row: found.rows[0]! };
        } else { grant.fill(0); chain.fill(0); interaction.fill(0); }
      }
      if (!selected) throw new Error('resume context unavailable');
      const live = await loadLiveAuthorizationDecision(epoch, selected.row.control_session_key_id, selected.row.control_session_fingerprint, minimumIssuedAt);
      if (live.mappingId !== selected.row.mapping_id || live.entitlementId !== selected.row.entitlement_id || live.generation !== BigInt(selected.row.generation) || live.jkt !== selected.row.jkt || live.policySnapshotId !== selected.row.policy_snapshot_id || live.policyVersion !== selected.row.policy_version) throw new Error('authorization decision changed');
      const locked = await current.client.query('SELECT id,revoked_at,expires_at,mapping_id,entitlement_id,generation,jkt,policy_snapshot_id,policy_version FROM oidc.authorization_contexts WHERE id=$1 AND epoch=$2 AND grant_key_id=$3 AND grant_fingerprint=$4 AND interaction_chain_key_id=$3 AND interaction_chain_fingerprint=$5 AND interaction_uid_key_id=$3 AND interaction_uid_fingerprint=$6 FOR UPDATE', [selected.row.id, epoch, selected.keyId, selected.grant, selected.chain, selected.interaction]);
      if (locked.rowCount !== 1) throw new Error('resume context changed');
      await refreshOidcDecisionNow();
      const finalLive = await queryLiveAuthorizationDecision(epoch, selected.row.control_session_key_id, selected.row.control_session_fingerprint, minimumIssuedAt);
      if (finalLive.mappingId !== live.mappingId || finalLive.entitlementId !== live.entitlementId || finalLive.generation !== live.generation || finalLive.jkt !== live.jkt || finalLive.policySnapshotId !== live.policySnapshotId || finalLive.policyVersion !== live.policyVersion) throw new Error('authorization decision changed');
      const finalContext = locked.rows[0]! as { revoked_at: Date | null; expires_at: Date; mapping_id: string; entitlement_id: string; generation: string; jkt: string; policy_snapshot_id: string; policy_version: string };
      if (finalContext.revoked_at || finalContext.expires_at <= current.decisionNow || finalContext.mapping_id !== finalLive.mappingId || finalContext.entitlement_id !== finalLive.entitlementId || BigInt(finalContext.generation) !== finalLive.generation || finalContext.jkt !== finalLive.jkt || finalContext.policy_snapshot_id !== finalLive.policySnapshotId || finalContext.policy_version !== finalLive.policyVersion) throw new Error('resume context changed');
      current.authorizedAccount = { mappingId: finalLive.mappingId, subject: finalLive.subject, policyVersion: finalLive.policyVersion };
      current.pendingResume = { contextId: selected.row.id, grantId, interactionChain: details.cid, interactionUid: details.jti, indexKeyId: selected.keyId, mappingId: finalLive.mappingId, entitlementId: finalLive.entitlementId, generation: finalLive.generation, jkt: finalLive.jkt, policySnapshotId: finalLive.policySnapshotId, policyVersion: finalLive.policyVersion, minimumIssuedAt, controlSessionKeyId: selected.row.control_session_key_id, controlSessionFingerprint: selected.row.control_session_fingerprint };
    } finally { selected?.grant.fill(0); selected?.chain.fill(0); selected?.interaction.fill(0); }
  };
}

/** Live authorization hooks for the resume phase. Token redemption adds its code path in Slice 4. */
export function createAuthorizationHooks(epoch: string, index: KeyRing): Pick<OidcHooks, 'findAccount' | 'pairwiseIdentifier'> {
  return {
    async findAccount(context: unknown, accountId: string) {
      const grantId = (context as ProviderHookContext).oidc?.result?.consent?.grantId;
      const redemption = requireOidcRequestContext().pendingTokenRedemption;
      if (redemption) {
        if (accountId !== redemption.mappingId) throw new Error('token account changed');
        return { accountId: redemption.mappingId, claims: () => ({ dsa_signal_entitlement_policy_version: redemption.policyVersion }) };
      }
      // A remembered provider Session causes oidc-provider to load the account
      // before evaluating the mandatory fresh-entitlement prompt. This return
      // permits prompt evaluation only; claims stay unavailable until resume
      // revalidates the control session and entitlement under the common lock.
      if (typeof grantId !== 'string') {
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(accountId)) {
          throw new Error('authorization context unavailable');
        }
        return {
          accountId,
          claims: () => { throw new Error('fresh entitlement required'); },
        };
      }
      const request = requireOidcRequestContext();
      const resume = request.pendingResume;
      if (!resume || resume.grantId !== grantId) throw new Error('resume binding unavailable');
      const key = index.keys[resume.indexKeyId];
      if (!key) throw new Error('OIDC index key unavailable');
      const grant = mac(key, `dsa-signal-oidc-grant-id:v1\0${epoch}`, grantId);
      try {
        const stored = await request.client.query<{
          mapping_id: string;
          entitlement_id: string;
          generation: string;
          jkt: string;
          policy_snapshot_id: string;
          policy_version: string;
          expires_at: Date;
          revoked_at: Date | null;
          control_session_key_id: string;
          control_session_fingerprint: Buffer;
        }>(`SELECT mapping_id,entitlement_id,generation,jkt,policy_snapshot_id,policy_version,expires_at,revoked_at,
                   control_session_key_id,control_session_fingerprint
              FROM oidc.authorization_contexts
             WHERE id=$4 AND epoch=$1 AND grant_key_id=$2 AND grant_fingerprint=$3
             `, [epoch, resume.indexKeyId, grant, resume.contextId]);
        if (stored.rowCount !== 1) throw new Error('authorization context unavailable');
        const row = stored.rows[0]!;
        await refreshOidcDecisionNow();
        const finalLive = await queryLiveAuthorizationDecision(epoch, resume.controlSessionKeyId, resume.controlSessionFingerprint, resume.minimumIssuedAt);
        const authorized = request.authorizedAccount;
        if (!authorized || row.mapping_id !== accountId || authorized.mappingId !== row.mapping_id || row.revoked_at || row.expires_at <= request.decisionNow ||
          row.mapping_id !== resume.mappingId || row.entitlement_id !== resume.entitlementId ||
          BigInt(row.generation) !== resume.generation || row.jkt !== resume.jkt ||
          row.policy_snapshot_id !== resume.policySnapshotId || row.policy_version !== resume.policyVersion ||
          finalLive.mappingId !== resume.mappingId || finalLive.entitlementId !== resume.entitlementId || finalLive.generation !== resume.generation || finalLive.jkt !== resume.jkt || finalLive.policySnapshotId !== resume.policySnapshotId || finalLive.policyVersion !== resume.policyVersion) {
          throw new Error('authorization decision changed');
        }
        return {
          accountId: authorized.mappingId,
          claims: () => ({ dsa_signal_entitlement_policy_version: authorized.policyVersion }),
        };
      } finally {
        grant.fill(0);
      }
    },
    async pairwiseIdentifier(_context: unknown, accountId: string) {
      const current = requireOidcRequestContext();
      const redemption = current.pendingTokenRedemption;
      if (redemption) { if (redemption.mappingId !== accountId) throw new Error('token account unavailable'); return redemption.subject; }
      const account = current.authorizedAccount;
      if (!account || account.mappingId !== accountId) throw new Error('authorization account unavailable');
      return account.subject;
    },
  };
}
