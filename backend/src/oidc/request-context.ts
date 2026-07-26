import { AsyncLocalStorage } from 'node:async_hooks';
import type { PoolClient } from 'pg';
import { acquireRuntimeWriteFence } from '../db.js';

export type OidcAuthorizedAccount = Readonly<{ mappingId: string; subject: string; policyVersion: string }>;
export type PendingAuthorizationCodeClaim = Readonly<{
  code: string;
  grantId: string;
  sessionUid: string;
  finalize: () => Promise<void>;
}>;
export type PendingOidcResume = Readonly<{
  contextId: string;
  grantId: string;
  interactionUid: string;
  interactionChain: string;
  indexKeyId: string;
  mappingId: string;
  entitlementId: string;
  generation: bigint;
  jkt: string;
  policySnapshotId: string;
  policyVersion: string;
  minimumIssuedAt: number;
  controlSessionKeyId: string;
  controlSessionFingerprint: Buffer;
}>;
/** Values decided under the token redemption locks. Provider TTL callbacks must
 * only read this object; doing database I/O from a callback is racy. */
export type PendingTokenRedemption = Readonly<{
  mappingId: string;
  subject: string;
  policyVersion: string;
  ttl: number;
}>;
/** The only database capability available to provider adapter calls. */
export type OidcRequestContext = { readonly client: PoolClient; decisionNow: Date; authorizedAccount?: OidcAuthorizedAccount; pendingCodeClaim?: PendingAuthorizationCodeClaim; pendingResume?: PendingOidcResume; pendingTokenRedemption?: PendingTokenRedemption; tokenConsumeSavepoint?: string; adapterQueue?: Promise<void>; adapterQueueError?: unknown; adapterQueueFailed?: boolean; providerResponseStatus?: number; requestCancelled?: boolean; consumptionRecoveryAttempted?: boolean; commitAttempted?: boolean; dispositionComplete?: boolean; commitCleanupError?: Error };
const storage = new AsyncLocalStorage<OidcRequestContext>();
export const oidcRequestContext = storage;
export function requireOidcRequestContext(): OidcRequestContext {
  const context = storage.getStore();
  if (!context) throw new Error('OIDC adapter called outside request transaction');
  return context;
}
/** oidc-provider may revoke several artifact models concurrently; pg clients
 * permit only one in-flight query, so serialize those public adapter calls. */
export function serializeOidcAdapterCall<T>(work: () => Promise<T>): Promise<T> {
  const context = requireOidcRequestContext();
  const run = (context.adapterQueue ?? Promise.resolve()).then(work, work);
  context.adapterQueue = run.then(() => undefined, (error: unknown) => {
    if (!context.adapterQueueFailed) { context.adapterQueueFailed = true; context.adapterQueueError = error; }
  });
  return run;
}
/** Wait for every adapter operation queued by this request, including work
 * appended while waiting, and surface the first failure once all have settled. */
export async function drainOidcAdapterQueue(): Promise<void> {
  const context = requireOidcRequestContext();
  for (;;) {
    const queue = context.adapterQueue;
    if (!queue) break;
    await queue;
    if (queue === context.adapterQueue) break;
  }
  if (context.adapterQueueFailed) throw context.adapterQueueError;
}

/** A COMMIT whose outcome is unknown must never be followed by more SQL. */
export class OidcIndeterminateCommitError extends Error {
  constructor(cause: unknown) { super('OIDC transaction commit outcome is indeterminate', { cause }); this.name = 'OidcIndeterminateCommitError'; }
}
export class OidcRequestCancelledError extends Error {
  constructor() { super('OIDC request cancelled'); this.name = 'OidcRequestCancelledError'; }
}
const commitIsIndeterminate = (error: unknown): boolean => {
  const code = error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
  if (code && ['ECONNRESET', 'EPIPE', 'ETIMEDOUT', 'ECONNREFUSED', 'ERR_STREAM_PREMATURE_CLOSE'].includes(code)) return true;
  if (!code || !/^[0-9A-Z]{5}$/.test(code)) return true;
  return code === '40003' || code.startsWith('08') || ['57P01', '57P02', '57P03'].includes(code);
};
export async function refreshOidcDecisionNow(): Promise<Date> {
  const context = requireOidcRequestContext();
  const clock = await context.client.query<{ decision_now: Date }>('SELECT clock_timestamp() AS decision_now');
  const decisionNow = clock.rows[0]?.decision_now;
  if (!(decisionNow instanceof Date) || !Number.isFinite(decisionNow.valueOf())) throw new Error('OIDC clock unavailable');
  context.decisionNow = decisionNow;
  return decisionNow;
}

/**
 * Runs provider work on one checked-out connection and one database clock.  It
 * deliberately owns the ALS rather than borrowing oidc-provider's Koa context.
 */
export async function runOidcTransaction<T>(pool: Pick<import('pg').Pool, 'connect'>, work: (context: OidcRequestContext) => Promise<T>): Promise<T> {
  let client: PoolClient;
  try { client = await pool.connect(); } catch { throw new Error('OIDC storage unavailable'); }
  let poison: Error | undefined;
  let context: OidcRequestContext | undefined;
  try {
    await client.query('BEGIN');
    await acquireRuntimeWriteFence(client);
    const clock = await client.query<{ decision_now: Date }>('SELECT clock_timestamp() AS decision_now');
    const decisionNow = clock.rows[0]?.decision_now;
    if (!(decisionNow instanceof Date) || !Number.isFinite(decisionNow.valueOf())) throw new Error('OIDC clock unavailable');
    context = { client, decisionNow };
    const active = context;
    const value = await oidcRequestContext.run(active, async () => {
      let result: T | undefined;
      let workError: unknown;
      try { result = await work(active); }
      catch (error) { workError = error; }
      try { await drainOidcAdapterQueue(); }
      catch (error) { workError ??= error; }
      if (active.requestCancelled) throw new OidcRequestCancelledError();
      if (workError !== undefined) throw workError;
      return result as T;
    });
    if (context.requestCancelled) throw new OidcRequestCancelledError();
    if (context.providerResponseStatus !== undefined && context.providerResponseStatus >= 400 && context.tokenConsumeSavepoint) {
      await commitConsumptionOnly(client, context);
      context.dispositionComplete = true;
      if (context.providerResponseStatus >= 500) throw new Error('OIDC provider server failure');
      return value;
    }
    if (context.providerResponseStatus !== undefined && context.providerResponseStatus >= 500) throw new Error('OIDC provider server failure');
    await commit(client, context);
    context.dispositionComplete = true;
    return value;
  } catch (error) {
    // A consumed authorization code is intentionally burned even if provider
    // signing/rendering fails afterwards. Slice 5 adds the complete
    // commit-indeterminate matrix; this seam prevents partial token writes now.
    if (context?.dispositionComplete) throw error;
    if (error instanceof OidcIndeterminateCommitError) { poison = error; throw error; }
    // A failed COMMIT was already classified and cleaned up.  Never attempt
    // savepoint recovery after a COMMIT attempt.
    if (context?.commitAttempted) { poison = context.commitCleanupError; throw error; }
    if (context?.tokenConsumeSavepoint && !context.consumptionRecoveryAttempted) {
      try {
        await commitConsumptionOnly(client, context);
        throw error;
      } catch (savepointError) {
        if (savepointError === error) throw error;
        if (savepointError instanceof OidcIndeterminateCommitError) { poison = savepointError; throw savepointError; }
        poison = savepointError instanceof Error ? savepointError : new Error('OIDC savepoint recovery failed');
      }
    }
    try { await client.query('ROLLBACK'); }
    catch (rollback) { poison = rollback instanceof Error ? rollback : new Error('OIDC rollback failed'); }
    throw error;
  } finally { client.release(poison); }
}

async function commit(client: PoolClient, context: OidcRequestContext): Promise<void> {
  context.commitAttempted = true;
  try { await client.query('COMMIT'); }
  catch (error) {
    if (commitIsIndeterminate(error)) throw new OidcIndeterminateCommitError(error);
    try { await client.query('ROLLBACK'); }
    catch (rollback) { context.commitCleanupError = rollback instanceof Error ? rollback : new Error('OIDC rollback after commit failure failed'); }
    throw error;
  }
}
async function commitConsumptionOnly(client: PoolClient, context: OidcRequestContext): Promise<void> {
  if (context.consumptionRecoveryAttempted) throw new Error('OIDC consumption recovery already attempted');
  context.consumptionRecoveryAttempted = true;
  try {
    await client.query(`ROLLBACK TO SAVEPOINT ${context.tokenConsumeSavepoint}`);
    await commit(client, context);
  } catch (error) {
    if (error instanceof OidcIndeterminateCommitError) throw error;
    throw error;
  }
}
