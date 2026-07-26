import type { Pool } from 'pg';
import type { KeyRing } from '../config.js';
import { sessionBindingFingerprint } from '../identity/session-repository.js';
import { OidcIndeterminateCommitError, refreshOidcDecisionNow, runOidcTransaction } from '../oidc/request-context.js';
import { lockControlSessionEntitlementsAndPolicy } from '../oidc/authorization-decision.js';

export class LogoutUnavailableError extends Error { constructor() { super('logout unavailable'); this.name = 'LogoutUnavailableError'; } }
export type LogoutService = Readonly<{ logout(sessionId: string): Promise<void> }>;
const validSessionId = (id: string): boolean => /^[A-Za-z0-9_-]{43}$/.test(id) && Buffer.from(id, 'base64url').length === 32;
const RETAINED_BINDING = `
  SELECT binding_key_id,binding_fingerprint FROM control_plane.identity_sessions
   WHERE (binding_key_id,binding_fingerprint) IN (SELECT * FROM unnest($1::text[],$2::bytea[]))
     AND absolute_expires_at+interval '30 seconds'>$3
  UNION
  SELECT control_session_key_id,control_session_fingerprint FROM oidc.authorization_contexts
   WHERE epoch=$4 AND (control_session_key_id,control_session_fingerprint) IN (SELECT * FROM unnest($1::text[],$2::bytea[]))
     AND grant_expires_at>$3`;
const LIVE_CONTEXTS = 'SELECT grant_key_id,grant_fingerprint,grant_expires_at,revoked_at FROM oidc.authorization_contexts WHERE control_session_key_id=$1 AND control_session_fingerprint=$2 AND epoch=$3 FOR UPDATE';
const LOCK_ARTIFACTS = "SELECT id FROM oidc.provider_artifacts WHERE epoch=$1 AND (grant_key_id,grant_fingerprint) IN (SELECT * FROM unnest($2::text[],$3::bytea[])) FOR UPDATE";
const REVOKE_ARTIFACTS = 'UPDATE oidc.provider_artifacts SET revoked_at=$4 WHERE epoch=$1 AND (grant_key_id,grant_fingerprint) IN (SELECT * FROM unnest($2::text[],$3::bytea[])) AND retained_until>=$4 AND revoked_at IS NULL';

/** Product-session revocation; OIDC protocol endpoints remain owned by oidc-provider. */
export function createLogoutService(options: Readonly<{ pool: Pick<Pool, 'connect'>; oidcEpoch: string; bindingKeys: KeyRing }>): LogoutService {
  return { async logout(sessionId: string): Promise<void> {
    if (!validSessionId(sessionId)) throw new LogoutUnavailableError();
    const ids = Object.keys(options.bindingKeys.keys);
    const prints = Object.values(options.bindingKeys.keys).map(key => sessionBindingFingerprint(sessionId, key));
    try {
      await runOidcTransaction(options.pool, async ({ client, decisionNow }) => {
        const matched = await client.query<{ binding_key_id: string; binding_fingerprint: Buffer }>(RETAINED_BINDING, [ids, prints, decisionNow, options.oidcEpoch]);
        if (matched.rowCount === 0) return;
        if (matched.rowCount !== 1) throw new LogoutUnavailableError();
        const binding = new Uint8Array(matched.rows[0]!.binding_fingerprint);
        try {
            await lockControlSessionEntitlementsAndPolicy(matched.rows[0]!.binding_key_id, binding, { allowSuspendedMapping: true, logoutEpoch: options.oidcEpoch });
            const contexts = await client.query<{ grant_key_id: string; grant_fingerprint: Buffer; grant_expires_at: Date; revoked_at: Date | null }>(
              LIVE_CONTEXTS, [matched.rows[0]!.binding_key_id, binding, options.oidcEpoch]);
            const grantIds = contexts.rows.map(row => row.grant_key_id); const grants = contexts.rows.map(row => row.grant_fingerprint);
            if (grantIds.length) {
              await client.query(LOCK_ARTIFACTS, [options.oidcEpoch, grantIds, grants]);
            }
            // Context and artifact locks can block after the common helper.
            // All mutation predicates below must use this final clock.
            const now = await refreshOidcDecisionNow();
            // A context-only candidate may have crossed grant_expires_at while
            // waiting for its exact artifact locks.  Never revoke its provider
            // artifacts unless the binding is still eligible at this clock.
            const eligible = await client.query('SELECT 1 FROM control_plane.identity_sessions WHERE binding_key_id=$1 AND binding_fingerprint=$2 AND absolute_expires_at+interval \'30 seconds\'>$3 UNION ALL SELECT 1 FROM oidc.authorization_contexts WHERE control_session_key_id=$1 AND control_session_fingerprint=$2 AND epoch=$4 AND grant_expires_at>$3 LIMIT 1', [matched.rows[0]!.binding_key_id, binding, now, options.oidcEpoch]);
            if (eligible.rowCount !== 1) return;
            await client.query("UPDATE control_plane.identity_sessions SET revoked_at=$3 WHERE binding_key_id=$1 AND binding_fingerprint=$2 AND revoked_at IS NULL AND absolute_expires_at>$3 AND $3<=absolute_expires_at+interval '30 seconds'", [matched.rows[0]!.binding_key_id, binding, now]);
            await client.query('UPDATE oidc.authorization_contexts SET revoked_at=$4 WHERE control_session_key_id=$1 AND control_session_fingerprint=$2 AND epoch=$3 AND grant_expires_at>$4 AND revoked_at IS NULL', [matched.rows[0]!.binding_key_id, binding, options.oidcEpoch, now]);
            const liveArtifactContexts = contexts.rows.filter(row => row.grant_expires_at > now && row.revoked_at === null);
            const liveGrantIds = liveArtifactContexts.map(row => row.grant_key_id);
            const liveGrants = liveArtifactContexts.map(row => row.grant_fingerprint);
            if (liveGrantIds.length) await client.query(REVOKE_ARTIFACTS, [options.oidcEpoch, liveGrantIds, liveGrants, now]);
        } finally { binding.fill(0); }
      });
    } catch (error) {
      if (error instanceof OidcIndeterminateCommitError) throw error;
      if (error instanceof LogoutUnavailableError) throw error;
      throw new LogoutUnavailableError();
    } finally { for (const print of prints) print.fill(0); }
  } };
}
