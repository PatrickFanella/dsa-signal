import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Pool } from 'pg';
import type { KeyRing } from '../config.js';
import { clearSessionCookie, readSessionCookie } from '../identity/session-cookie.js';
import {
  loadLiveAuthorizationDecision,
  OidcAuthorizationRejectedError,
  oidcFingerprints,
  oidcFingerprintsForKey,
  saveAuthorizationContext,
} from './authorization-decision.js';
import type { OidcProvider } from './provider.js';
import { OidcIndeterminateCommitError, refreshOidcDecisionNow, requireOidcRequestContext, runOidcTransaction } from './request-context.js';

const responseHeaders = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
};
const errorHtml = '<!doctype html><title>Request rejected</title>';
const page = (csrf: string): string =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Continue</title></head><body><form method="post" action="/oidc/interaction"><input type="hidden" name="csrf" value="${csrf}"><button type="submit">Continue</button></form></body></html>`;

type Details = Readonly<{
  jti?: unknown;
  cid?: unknown;
  params?: Readonly<{ client_id?: unknown; redirect_uri?: unknown }>;
}>;
type ValidDetails = Readonly<{
  jti: string;
  cid: string;
  params: Readonly<{ client_id: string; redirect_uri: string }>;
}>;

function validDetails(details: Details, clientId: string, redirectUri: string): details is ValidDetails {
  return typeof details.jti === 'string' && /^[A-Za-z0-9_-]{43}$/.test(details.jti) &&
    typeof details.cid === 'string' && /^[A-Za-z0-9_-]{43}$/.test(details.cid) &&
    details.params?.client_id === clientId && details.params?.redirect_uri === redirectUri;
}

function clearFingerprints(value: ReturnType<typeof oidcFingerprints>): void {
  value.client.fill(0);
  value.interactionChain.fill(0);
  value.interactionUid.fill(0);
  value.csrf?.fill(0);
}

function reject(response: ServerResponse, clearCookie = false): void {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  for (const name of response.getHeaderNames()) response.removeHeader(name);
  response.writeHead(400, {
    ...responseHeaders,
    connection: 'close',
    ...(clearCookie ? { 'set-cookie': clearSessionCookie() } : {}),
  });
  response.end(errorHtml);
}

function headerCount(request: IncomingMessage, name: string): number {
  return request.rawHeaders.reduce(
    (total, value, index) => total + (index % 2 === 0 && value.toLowerCase() === name ? 1 : 0),
    0,
  );
}

async function readBody(request: IncomingMessage, response: ServerResponse): Promise<string | undefined> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = []; let size = 0; let settled = false;
    const cleanup = (): void => { request.off('data', onData); request.off('end', onEnd); request.off('error', onError); request.off('aborted', onAborted); };
    const fail = (): void => {
      if (settled) return;
      settled = true; chunks.length = 0; cleanup();
      request.resume(); reject(response); resolve(undefined);
    };
    const onData = (part: Buffer): void => {
      if (settled) return;
      const chunk = Buffer.from(part); size += chunk.length;
      if (size > 1024 || chunk.some((byte) => byte > 0x7f)) fail(); else chunks.push(chunk);
    };
    const onEnd = (): void => { if (!settled) { settled = true; cleanup(); resolve(Buffer.concat(chunks).toString('ascii')); } };
    const onError = (): void => fail();
    const onAborted = (): void => fail();
    request.on('data', onData); request.once('end', onEnd); request.once('error', onError); request.once('aborted', onAborted);
  });
}

function parseCsrfForm(body: string | undefined): string | undefined {
  if (!body || !/^csrf=[A-Za-z0-9_-]{43}$/.test(body)) return undefined;
  const value = body.slice('csrf='.length);
  const decoded = Buffer.from(value, 'base64url');
  try {
    return decoded.length === 32 && decoded.toString('base64url') === value ? value : undefined;
  } finally {
    decoded.fill(0);
  }
}

export type InteractionOptions = Readonly<{
  pool: Pool;
  provider: OidcProvider;
  epoch: string;
  clientId: string;
  redirectUri: string;
  origin: string;
  cookieKey: Uint8Array;
  indexKeys: KeyRing;
  bindingKeys: KeyRing;
  minimumIssuedAt?: number;
  onError?: (error: unknown) => void;
}>;

async function renderInteraction(options: InteractionOptions, request: IncomingMessage, response: ServerResponse): Promise<void> {
  const token = randomBytes(32);
  try {
    const encoded = token.toString('base64url');
    await runOidcTransaction(options.pool, async () => {
      const details = await options.provider.interactionDetails(request, response) as Details;
      if (!validDetails(details, options.clientId, options.redirectUri)) throw new Error('invalid interaction');
      const fingerprints = oidcFingerprints(
        options.indexKeys,
        options.epoch,
        options.clientId,
        details.cid,
        details.jti,
        token,
      );
      try {
        const { client, decisionNow } = requireOidcRequestContext();
        let existingId: string | undefined;
        for (const keyId of Object.keys(options.indexKeys.keys)) {
          const candidate = oidcFingerprintsForKey(options.indexKeys, keyId, options.epoch, options.clientId, details.cid, details.jti);
          try {
            const found = await client.query<{ id: string }>('SELECT id FROM oidc.interaction_csrf WHERE epoch=$1 AND interaction_uid_key_id=$2 AND interaction_uid_fingerprint=$3 FOR UPDATE', [options.epoch, keyId, candidate.interactionUid]);
            if (found.rowCount === 1) {
              if (existingId && existingId !== found.rows[0]!.id) throw new Error('ambiguous interaction');
              existingId = found.rows[0]!.id;
            }
          } finally { clearFingerprints(candidate); }
        }
        const replaced = existingId
          ? await client.query(
            `UPDATE oidc.interaction_csrf SET csrf_key_id=$1,csrf_fingerprint=$2,
               client_key_id=$1,client_fingerprint=$3,interaction_chain_key_id=$1,
               interaction_chain_fingerprint=$4,interaction_uid_key_id=$1,
               interaction_uid_fingerprint=$5,created_at=$6,
               expires_at=$6::timestamptz+interval '300 seconds',retained_until=$6::timestamptz+interval '330 seconds'
             WHERE id=$7 AND consumed_at IS NULL`,
            [fingerprints.keyId, fingerprints.csrf, fingerprints.client, fingerprints.interactionChain, fingerprints.interactionUid, decisionNow, existingId],
          )
          : await client.query(
            `INSERT INTO oidc.interaction_csrf(
               id,epoch,csrf_key_id,csrf_fingerprint,client_key_id,client_fingerprint,
               interaction_chain_key_id,interaction_chain_fingerprint,
               interaction_uid_key_id,interaction_uid_fingerprint,created_at,expires_at,retained_until
             ) VALUES($1,$2,$3,$4,$3,$5,$3,$6,$3,$7,$8::timestamptz,
               $8::timestamptz+interval '300 seconds',$8::timestamptz+interval '330 seconds')`,
            [randomUUID(), options.epoch, fingerprints.keyId, fingerprints.csrf, fingerprints.client, fingerprints.interactionChain, fingerprints.interactionUid, decisionNow],
          );
        if (replaced.rowCount !== 1) throw new Error('consumed interaction');
      } finally { clearFingerprints(fingerprints); }
    });
    response.writeHead(200, responseHeaders);
    response.end(page(encoded));
  } finally {
    token.fill(0);
  }
}

async function completeInteraction(options: InteractionOptions, request: IncomingMessage, response: ServerResponse): Promise<void> {
  const controlCookie = readSessionCookie(request.headers.cookie, options.cookieKey);
  if (controlCookie.duplicate || !controlCookie.id) {
    reject(response, true);
    return;
  }
  const controlSessionId = controlCookie.id;
  const rawBody = await readBody(request, response);
  if (response.writableEnded) return;
  const csrf = parseCsrfForm(rawBody);
  if (!csrf) {
    reject(response);
    return;
  }
  // Derive every retained candidate before entering the transaction. The exact
  // stored binding is resolved without a row lock and then revalidated under
  // the common advisory/session lock by loadLiveAuthorizationDecision().
  const bindings = Object.entries(options.bindingKeys.keys).map(([keyId, key]) => ({
    keyId,
    fingerprint: createHmac('sha256', key).update('dsa-signal-session-fingerprint:v1\0').update(controlSessionId, 'utf8').digest(),
  }));

  const location = await runOidcTransaction(options.pool, async () => {
    const details = await options.provider.interactionDetails(request, response) as Details;
    if (!validDetails(details, options.clientId, options.redirectUri)) throw new Error('invalid interaction');
    const token = Buffer.from(csrf, 'base64url');
    const context = requireOidcRequestContext();
    const { client } = context;
    let matched: { id: string; fingerprints: ReturnType<typeof oidcFingerprints> } | undefined;
    try {
      for (const keyId of Object.keys(options.indexKeys.keys)) {
        const candidate = oidcFingerprintsForKey(options.indexKeys, keyId, options.epoch, options.clientId, details.cid, details.jti, token);
        const found = await client.query<{ id: string }>(`SELECT id FROM oidc.interaction_csrf
          WHERE epoch=$1 AND csrf_key_id=$2 AND csrf_fingerprint=$3
            AND client_key_id=$2 AND client_fingerprint=$4
            AND interaction_chain_key_id=$2 AND interaction_chain_fingerprint=$5
            AND interaction_uid_key_id=$2 AND interaction_uid_fingerprint=$6
            AND consumed_at IS NULL AND expires_at>$7`,
        [options.epoch, keyId, candidate.csrf, candidate.client, candidate.interactionChain, candidate.interactionUid, context.decisionNow]);
        if (found.rowCount === 1) {
          if (matched) { clearFingerprints(candidate); throw new Error('ambiguous csrf'); }
          matched = { id: found.rows[0]!.id, fingerprints: candidate };
        } else clearFingerprints(candidate);
      }
    } catch (error) {
      if (matched) clearFingerprints(matched.fingerprints);
      throw error;
    } finally { token.fill(0); }
    if (!matched) throw new Error('csrf rejected');
    const contextFingerprints = oidcFingerprints(options.indexKeys, options.epoch, options.clientId, details.cid, details.jti);
    try {
      const consumeCsrf = async (): Promise<void> => {
        // This is deliberately the final database operation in each terminal
        // branch: expiry must be checked against a clock read after provider
        // artifacts and staged output have been created.
        const decisionNow = await refreshOidcDecisionNow();
        const consumed = await client.query(
          `UPDATE oidc.interaction_csrf SET consumed_at=$1
           WHERE id=$2 AND epoch=$3 AND csrf_key_id=$4 AND csrf_fingerprint=$5
             AND client_key_id=$4 AND client_fingerprint=$6
             AND interaction_chain_key_id=$4 AND interaction_chain_fingerprint=$7
             AND interaction_uid_key_id=$4 AND interaction_uid_fingerprint=$8
             AND consumed_at IS NULL AND expires_at>$1`,
          [decisionNow, matched.id, options.epoch, matched.fingerprints.keyId, matched.fingerprints.csrf, matched.fingerprints.client, matched.fingerprints.interactionChain, matched.fingerprints.interactionUid],
        );
        if (consumed.rowCount !== 1) throw new Error('csrf rejected');
      };
      const resolved = await client.query<{ binding_key_id: string; binding_fingerprint: Buffer }>(`SELECT binding_key_id,binding_fingerprint
        FROM control_plane.identity_sessions
        WHERE (binding_key_id,binding_fingerprint) IN (SELECT * FROM unnest($1::text[],$2::bytea[]))
          AND origin=$3 AND revoked_at IS NULL AND idle_expires_at>$4 AND absolute_expires_at>$4`,
      [bindings.map(value => value.keyId), bindings.map(value => value.fingerprint), options.origin, context.decisionNow]);
      if (resolved.rowCount !== 1) {
        const location = await options.provider.interactionResult(request, response, { error: 'access_denied', error_description: 'Access denied' }, { mergeWithLastSubmission: false });
        await consumeCsrf();
        return location;
      }
      const storedBinding = resolved.rows[0]!;
      let decision;
      try {
        decision = await loadLiveAuthorizationDecision(options.epoch, storedBinding.binding_key_id, storedBinding.binding_fingerprint, options.minimumIssuedAt ?? 0);
      } catch (error) {
        if (!(error instanceof OidcAuthorizationRejectedError)) throw error;
        const location = await options.provider.interactionResult(request, response, { error: 'access_denied', error_description: 'Access denied' }, { mergeWithLastSubmission: false });
        await consumeCsrf();
        return location;
      }
      const grant = new options.provider.Grant({
        accountId: decision.mappingId,
        clientId: options.clientId,
      });
      grant.addOIDCScope('openid dsa_signal_entitlement');
      const grantId = await grant.save(900);
      await saveAuthorizationContext(
        options.epoch,
        contextFingerprints,
        storedBinding.binding_key_id,
        storedBinding.binding_fingerprint,
        grantId,
        options.indexKeys,
        decision,
      );
      const location = await options.provider.interactionResult(
        request,
        response,
        {
          login: {
            accountId: decision.mappingId,
            remember: false,
            ts: Math.floor(context.decisionNow.getTime() / 1000),
          },
          dsa_signal_fresh_entitlement: { verified: true },
          consent: { grantId },
        },
        { mergeWithLastSubmission: false },
      );
      await consumeCsrf();
      return location;
    } finally { clearFingerprints(matched.fingerprints); clearFingerprints(contextFingerprints); }
  }).finally(() => { for (const binding of bindings) binding.fingerprint.fill(0); });

  response.writeHead(303, {
    location,
    'content-length': '0',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
  });
  response.end();
}

function handleInteractionError(options: InteractionOptions, error: unknown, response: ServerResponse): void {
  try {
    options.onError?.(error);
  } finally {
    if (error instanceof OidcIndeterminateCommitError) response.destroy();
    else if (!response.writableEnded) reject(response);
  }
}

/** Application interaction endpoint. Browser input contains only the CSRF token. */
export function createInteractionHandler(options: InteractionOptions): (request: IncomingMessage, response: ServerResponse) => Promise<void> {
  return async (request, response) => {
    if (request.method === 'GET') {
      try {
        await renderInteraction(options, request, response);
      } catch (error) {
        handleInteractionError(options, error, response);
      }
      return;
    }

    const duplicateCookie = headerCount(request, 'cookie') > 1;
    const malformed = request.method !== 'POST' ||
      ['origin', 'content-type', 'content-length'].some((name) => headerCount(request, name) > 1) || duplicateCookie ||
      request.headers.origin !== options.origin ||
      request.headers['content-type'] !== 'application/x-www-form-urlencoded' ||
      request.headers['content-encoding'] !== undefined ||
      (request.url ?? '').includes('?');
    if (malformed) {
      reject(response, duplicateCookie);
      return;
    }

    try {
      await completeInteraction(options, request, response);
    } catch (error) {
      handleInteractionError(options, error, response);
    }
  };
}
