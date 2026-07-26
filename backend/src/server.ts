import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { z } from 'zod';
import type { Config } from './config.js';
import { parseStrictJson } from './http/strict-json.js';
import type { IdentityFoundation, IdentityHandoffResult } from './identity/identity-handoff.js';
import { newSessionId } from './identity/identity-handoff.js';
import { clearSessionCookie, makeSessionCookie, readSessionCookie } from './identity/session-cookie.js';
import type { SessionRepository } from './identity/session-repository.js';
import { IdentityStorageError } from './identity/session-repository.js';
import { FoundationHandoffRejectedError, FoundationUnavailableError } from './foundation/foundation-service.js';
import { ChallengeRejectedError, ChallengeUnavailableError, InvalidChallengeRequest } from './entitlements/challenge-service.js';
import { InvalidVerificationRequest, VerificationRejectedError, VerificationUnavailableError } from './entitlements/verify-entitlement.js';
import type { OidcDispatcher } from './routes/oidc.js';
import type { LogoutService } from './routes/auth.js';
import { LogoutUnavailableError } from './routes/auth.js';
import { OidcIndeterminateCommitError } from './oidc/request-context.js';
export { getConfig } from './config.js';

const identitySchema = z.object({ version: z.literal('v1'), code: z.string().regex(/^[A-Za-z0-9_-]{43}$/), verifier: z.string().regex(/^[A-Za-z0-9~._-]{43,128}$/), audience: z.string() }).strict();
const challengeSchema = z.object({ version: z.literal('v1'), jkt: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict();
type ChallengeService = { issue(sessionId: string, origin: string, jkt: string): Promise<Readonly<{ challenge: string; expiresAt: number }>> };
type VerificationService = { verify(sessionId: string, origin: string, rawBody: Uint8Array): Promise<Readonly<{ status: 200 | 401 | 409; body: Record<string, unknown> }>> };
export type AppDependencies = Readonly<{ config: Pick<Config, 'PWA_ORIGIN' | 'COOKIE_KEY'>; foundation: IdentityFoundation; sessions: SessionRepository; challenges: ChallengeService; verifications: VerificationService; logout: LogoutService; oidcDispatcher?: OidcDispatcher }>;

const securityHeaders = { 'content-type': 'application/json', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' };
const reply = (res: ServerResponse, status: number, body: Record<string, unknown>, headers: Record<string, string | string[]> = {}): void => { res.writeHead(status, { ...securityHeaders, ...headers }); res.end(JSON.stringify(body)); };
const rejected = (res: ServerResponse, status: number, error: 'invalid_request' | 'rejected' | 'unavailable' | 'conflict' = 'invalid_request', headers?: Record<string, string | string[]>): void => reply(res, status, { version: 'v1', result: 'rejected', error }, headers);
const headerCount = (req: IncomingMessage, name: string): number => req.rawHeaders.reduce((n, value, index) => n + (index % 2 === 0 && value.toLowerCase() === name ? 1 : 0), 0);
async function readBody(req: IncomingMessage, cap: number): Promise<Uint8Array> { const chunks: Buffer[] = []; let size = 0; for await (const chunk of req) { const value = Buffer.from(chunk); size += value.length; if (size > cap) throw new RangeError(); chunks.push(value); } return Buffer.concat(chunks); }
function transport(req: IncomingMessage, res: ServerResponse, cap: number, strictSingletons = false): boolean {
  const names = strictSingletons ? ['accept', 'content-type', 'content-encoding', 'content-length', 'origin', 'cookie', 'host', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto'] : ['accept', 'content-type', 'origin', 'content-length'];
  if (names.some(name => headerCount(req, name) > 1)) { rejected(res, 400); return false; }
  if (req.headers.accept !== 'application/json') { rejected(res, 406); return false; }
  if (!/^application\/json$/i.test(req.headers['content-type'] ?? '') || req.headers['content-encoding'] !== undefined) { rejected(res, 415); return false; }
  const length = req.headers['content-length'];
  if (length !== undefined && (!/^(?:0|[1-9][0-9]*)$/.test(length) || !Number.isSafeInteger(Number(length)))) { rejected(res, 400); return false; }
  if (length !== undefined && Number(length) > cap) { rejected(res, 413); return false; }
  return true;
}
const clear = (): Record<string, string> => ({ 'set-cookie': clearSessionCookie() });

export function createApp(deps: AppDependencies) {
  return createServer({ maxHeaderSize: 8_192, headersTimeout: 10_000, requestTimeout: 15_000, keepAliveTimeout: 5_000 }, async (req, res) => {
    if (deps.oidcDispatcher?.(req, res)) return;
    const target = req.url ?? '/'; const queryAt = target.indexOf('?');
    const path = queryAt < 0 ? target : target.slice(0, queryAt);
    const hasQuery = queryAt >= 0;
    if (path === '/health' && !hasQuery) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ status: 'ok' })); return; }
    const routes = new Set(['/v1/identity/sessions', '/v1/identity/logout', '/v1/entitlements/challenges', '/v1/entitlements/verifications']);
    if (!routes.has(path)) { res.writeHead(404, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'not_found' })); return; }
    if (hasQuery) { rejected(res, 400); return; }
    if (req.method !== 'POST') { res.writeHead(405, { ...securityHeaders, allow: 'POST' }); res.end(JSON.stringify({ error: 'method_not_allowed' })); return; }
    const cap = path === '/v1/entitlements/verifications' ? 16_384 : 1024;
    if (path === '/v1/identity/logout' && headerCount(req, 'cookie') > 1) { rejected(res, 400, 'invalid_request', clear()); return; }
    if (!transport(req, res, cap, path === '/v1/identity/logout')) return;
    let raw: Uint8Array;
    try { raw = await readBody(req, cap); } catch (error) { if (!res.writableEnded) rejected(res, error instanceof RangeError ? 413 : 400); return; }
    if (req.headers.origin !== deps.config.PWA_ORIGIN) { rejected(res, 400); return; }
    if (path === '/v1/identity/logout') {
      const cookie = readSessionCookie(req.headers.cookie, deps.config.COOKIE_KEY);
      if (cookie.duplicate || cookie.invalid) { rejected(res, 400, 'invalid_request', clear()); return; }
      try { if (JSON.stringify(parseStrictJson(raw)) !== '{"version":"v1"}') throw new Error(); } catch { rejected(res, 400); return; }
      if (!cookie.id) { reply(res, 200, { version: 'v1', result: 'logged_out' }, clear()); return; }
      try { await deps.logout.logout(cookie.id); reply(res, 200, { version: 'v1', result: 'logged_out' }, clear()); }
      catch (error) { if (error instanceof OidcIndeterminateCommitError) res.destroy(); else if (error instanceof LogoutUnavailableError) rejected(res, 503, 'unavailable'); else rejected(res, 503, 'unavailable'); }
      return;
    }
    if (path === '/v1/identity/sessions') {
      let input: z.infer<typeof identitySchema>;
      try { const parsed = identitySchema.safeParse(parseStrictJson(raw)); if (!parsed.success || parsed.data.audience !== deps.config.PWA_ORIGIN) throw new Error(); input = parsed.data; } catch { rejected(res, 400); return; }
      const old = readSessionCookie(req.headers.cookie, deps.config.COOKIE_KEY);
      if (old.duplicate) { rejected(res, 400, 'invalid_request', clear()); return; }
      try {
        const result = await deps.foundation.exchangeIdentityHandoff(input);
        const id = newSessionId(); await deps.sessions.establishFromHandoff(result as IdentityHandoffResult, id, old.id);
        reply(res, 201, { version: 'v1', result: 'authenticated' }, { 'set-cookie': makeSessionCookie(id, deps.config.COOKIE_KEY) });
      } catch (error) {
        const headers = old.id === undefined && req.headers.cookie !== undefined ? clear() : undefined;
        if (error instanceof FoundationHandoffRejectedError) rejected(res, 401, 'rejected', headers);
        else if (error instanceof FoundationUnavailableError || error instanceof IdentityStorageError) rejected(res, 503, 'unavailable', headers);
        else rejected(res, 503, 'unavailable', headers);
      }
      return;
    }
    const cookie = readSessionCookie(req.headers.cookie, deps.config.COOKIE_KEY);
    if (cookie.duplicate) { rejected(res, 400, 'invalid_request', clear()); return; }
    if (!cookie.id) { rejected(res, 401, 'rejected', clear()); return; }
    try { if (!(await deps.sessions.authenticate(cookie.id, deps.config.PWA_ORIGIN))) { rejected(res, 401, 'rejected', clear()); return; } }
    catch (error) { if (error instanceof IdentityStorageError) rejected(res, 503, 'unavailable'); else rejected(res, 503, 'unavailable'); return; }
    try {
      if (path === '/v1/entitlements/challenges') {
        let parsed: unknown; try { parsed = parseStrictJson(raw); } catch { rejected(res, 400); return; }
        const input = challengeSchema.safeParse(parsed); if (!input.success) { rejected(res, 400); return; }
        const result = await deps.challenges.issue(cookie.id, deps.config.PWA_ORIGIN, input.data.jkt);
        reply(res, 201, { version: 'v1', ...result }); return;
      }
      const result = await deps.verifications.verify(cookie.id, deps.config.PWA_ORIGIN, raw);
      reply(res, result.status, result.body); return;
    } catch (error) {
      if (error instanceof InvalidChallengeRequest || error instanceof InvalidVerificationRequest) rejected(res, 400);
      else if (error instanceof ChallengeRejectedError || error instanceof VerificationRejectedError) rejected(res, 401, 'rejected');
      else if (error instanceof ChallengeUnavailableError || error instanceof VerificationUnavailableError || error instanceof IdentityStorageError) rejected(res, 503, 'unavailable');
      else rejected(res, 503, 'unavailable');
    }
  });
}
