import type { IncomingMessage, ServerResponse } from 'node:http';
import type { OidcProvider } from '../oidc/provider.js';
import { drainOidcAdapterQueue, OidcIndeterminateCommitError, OidcRequestCancelledError, requireOidcRequestContext, runOidcTransaction, type OidcRequestContext } from '../oidc/request-context.js';
import type { Pool } from 'pg';
import { createHmac, randomBytes } from 'node:crypto';
const headers = { 'content-type': 'application/json', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' };
const missing = (res: ServerResponse): void => { res.writeHead(404, headers); res.end('{"error":"not_found"}'); };
const limited = (res: ServerResponse): void => { res.writeHead(429, { ...headers, 'retry-after': '60' }); res.end('{"error":"temporarily_unavailable"}'); };
const invalid = (res: ServerResponse): void => { res.writeHead(400, { ...headers, connection: 'close' }); res.end('{"error":"invalid_request"}'); };
type LimitedRoute = 'authorization' | 'token';
export type OidcRateLimiter = Readonly<{ acquire(route: LimitedRoute, source: string): (() => void) | undefined }>;
/** In-process backstop; the trusted proxy remains the primary distributed limiter. Raw addresses are never retained. */
export function createOidcRateLimiter(clock: () => number = Date.now): OidcRateLimiter {
  const secret = randomBytes(32); const buckets = new Map<string, { started: number; count: number }>(); let concurrent = 0; let lastNow = 0; let requests = 0;
  const now = (): number => { lastNow = Math.max(lastNow, clock()); return lastNow; };
  const expired = (bucket: { started: number }, current: number): boolean => current - bucket.started >= 60_000;
  const prune = (current: number, maximum: number): void => { let examined = 0; for (const [key, bucket] of buckets) { if (expired(bucket, current)) buckets.delete(key); if (++examined >= maximum) break; } };
  return { acquire(route, source) {
    if (source.length < 1 || source.length > 64 || concurrent >= 32) return undefined;
    const key = createHmac('sha256', secret).update(route).update('\0').update(source).digest('base64url');
    const current = now(); if (++requests % 64 === 0) prune(current, 64);
    let bucket = buckets.get(key);
    if (bucket && expired(bucket, current)) { bucket = { started: current, count: 0 }; buckets.set(key, bucket); }
    if (!bucket) { if (buckets.size >= 4_096) prune(current, Number.POSITIVE_INFINITY); if (buckets.size >= 4_096) return undefined; bucket = { started: current, count: 0 }; buckets.set(key, bucket); }
    const limit = route === 'authorization' ? 30 : 60;
    if (bucket.count >= limit) return undefined;
    bucket.count += 1; concurrent += 1; let released = false;
    return () => { if (!released) { released = true; concurrent -= 1; } };
  } };
}
/** Host mount preserving provider-owned endpoints and issuer-relative request paths. */
export type OidcInteractionDispatcher = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
export type OidcDispatcher = (req: IncomingMessage, res: ServerResponse) => boolean;
export type OidcProviderInvocation = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
export type OidcProviderPreflight = (req: IncomingMessage, res: ServerResponse) => Promise<void>;
/** Buffer provider output so a redirect/cookie is never observable before commit. */
export function createTransactionalProviderInvocation(pool: Pool, provider: OidcProvider, preflight?: OidcProviderPreflight): OidcProviderInvocation {
  return async (request, response) => {
    const chunks: Buffer[] = []; const write = response.write.bind(response); const end = response.end.bind(response); const writeHead = response.writeHead.bind(response); let ended = false; let status = 200; let headers: Parameters<ServerResponse['writeHead']> | undefined;
    let cancellationError: OidcRequestCancelledError | undefined; let activeContext: OidcRequestContext | undefined;
    let cancel: ((error: OidcRequestCancelledError) => void) | undefined;
    const cancellation = new Promise<never>((_resolve, reject) => { cancel = reject; });
    void cancellation.catch(() => undefined);
    const cancelled = (): void => { cancellationError ??= new OidcRequestCancelledError(); if (activeContext) activeContext.requestCancelled = true; cancel?.(cancellationError); };
    const throwIfCancelled = (): void => { if (cancellationError) throw cancellationError; };
    const drain = async (): Promise<void> => { try { await drainOidcAdapterQueue(); } catch (error) { throwIfCancelled(); throw error; } throwIfCancelled(); };
    request.once?.('aborted', cancelled); response.once?.('close', cancelled);
    if (request.aborted || response.destroyed) cancelled();
    const buffered = response as ServerResponse & { write: typeof response.write; end: typeof response.end; writeHead: typeof response.writeHead };
    buffered.write = ((chunk: unknown, encoding?: BufferEncoding, callback?: () => void) => { if (chunk !== undefined) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), encoding)); callback?.(); return true; }) as typeof response.write;
    buffered.end = ((chunk?: unknown, encoding?: BufferEncoding, callback?: () => void) => { if (chunk !== undefined) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), encoding)); ended = true; callback?.(); return response; }) as typeof response.end;
    buffered.writeHead = ((...args: Parameters<ServerResponse['writeHead']>) => { status = typeof args[0] === 'number' ? args[0] : 200; headers = args; return response; }) as typeof response.writeHead;
    try {
      await runOidcTransaction(pool, async (context) => {
        activeContext = context;
        throwIfCancelled();
        try { await preflight?.(request, response); } catch (error) { throwIfCancelled(); throw error; }
        throwIfCancelled();
        const providerSettled = new Promise<void>((resolve, reject) => {
          try {
            const result = (provider.callback() as unknown as (r: IncomingMessage, s: ServerResponse) => unknown)(request, response);
            Promise.resolve(result).then(() => { if (ended) resolve(); else reject(new Error('OIDC provider response incomplete')); }, reject);
          } catch (error) { reject(error); }
        });
        try { await Promise.race([providerSettled, cancellation]); }
        catch (error) {
          if (error instanceof OidcRequestCancelledError) {
            await providerSettled.catch(() => undefined);
            try { await drainOidcAdapterQueue(); } catch { /* cancellation remains authoritative */ }
          }
          throw error;
        }
        throwIfCancelled();
        const requestContext = requireOidcRequestContext();
        requestContext.providerResponseStatus = Math.max(status, response.statusCode);
        await drain();
        try { await requestContext.pendingCodeClaim?.finalize(); } catch (error) { throwIfCancelled(); throw error; }
        throwIfCancelled(); await drain();
      });
    } catch (error) {
      if (error instanceof OidcIndeterminateCommitError || error instanceof OidcRequestCancelledError) {
        buffered.write = write; buffered.end = end; buffered.writeHead = writeHead;
        response.destroy();
        return;
      }
      for (const name of response.getHeaderNames()) response.removeHeader(name);
      response.statusCode = 500;
      buffered.write = write; buffered.end = end; buffered.writeHead = writeHead;
      response.writeHead(500, { 'content-type': 'application/json', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
      response.end('{"error":"server_error"}');
      return;
    } finally { request.off?.('aborted', cancelled); response.off?.('close', cancelled); buffered.write = write; buffered.end = end; buffered.writeHead = writeHead; }
    if (headers) writeHead(...headers);
    end(Buffer.concat(chunks));
  };
}
const singleton = (req: IncomingMessage, name: string): string | undefined => {
  const values = req.rawHeaders.filter((_, index) => index % 2 === 1 && req.rawHeaders[index - 1]!.toLowerCase() === name);
  return values.length === 1 && !values[0]!.includes(',') ? values[0] : undefined;
};
const canonicalLength = (req: IncomingMessage): number | undefined => {
  const value = singleton(req, 'content-length');
  if (header(req, 'content-length') && (value === undefined || !/^(?:0|[1-9][0-9]*)$/.test(value))) return undefined;
  if (value === undefined) return 0;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= 4_096 ? parsed : undefined;
};
/** Reads a token form once so oidc-provider 9.9.1 can use its pre-read-body fallback. */
async function readTokenBody(req: IncomingMessage, res: ServerResponse, expectedLength?: number): Promise<Buffer | undefined> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = []; let size = 0; let settled = false;
    const cleanup = (): void => { req.off('data', onData); req.off('end', onEnd); req.off('error', onError); req.off('aborted', onAborted); };
    const fail = (): void => {
      if (settled) return;
      settled = true; chunks.length = 0; cleanup();
      // Flowing mode discards the rest without waiting for an attacker-controlled EOF.
      req.resume(); invalid(res); resolve(undefined);
    };
    const onData = (part: Buffer): void => {
      if (settled) return;
      const chunk = Buffer.from(part); size += chunk.length;
      if (size > 4_096 || (expectedLength !== undefined && size > expectedLength)) fail(); else chunks.push(chunk);
    };
    const onEnd = (): void => {
      if (settled) return;
      if (expectedLength !== undefined && size !== expectedLength) { fail(); return; }
      settled = true; cleanup(); resolve(Buffer.concat(chunks));
    };
    const onError = (): void => fail();
    const onAborted = (): void => fail();
    req.on('data', onData); req.once('end', onEnd); req.once('error', onError); req.once('aborted', onAborted);
  });
}
/** Binds the trusted ingress boundary; production callers cannot dispatch without it. */
export function createOidcDispatcher(options: Readonly<{ issuer: string; trustedProxyAddress: string }>, provider: OidcProvider, interaction?: OidcInteractionDispatcher, invokeProvider: OidcProviderInvocation = (req, res) => provider.callback()(req, res), limiter: OidcRateLimiter = createOidcRateLimiter()): OidcDispatcher {
  const issuer = new URL(options.issuer); const authority = issuer.host;
  return (req, res) => {
    const target = req.url ?? ''; const question = target.indexOf('?'); const path = question === -1 ? target : target.slice(0, question); const query = question === -1 ? undefined : target.slice(question + 1);
    const candidate = path.startsWith('/oidc') || path === '/.well-known/oauth-authorization-server/oidc';
    if (!candidate) return false;
    const unsafeTarget = [...target].some((character) => character === '\\' || character === '#' || character.charCodeAt(0) < 0x20 || character.charCodeAt(0) > 0x7e);
    if (!target.startsWith('/') || target.length > 4_096 || unsafeTarget || path.includes('%') || path.includes('//') || path.split('/').some((part) => part === '.' || part === '..')) { missing(res); return true; }
    const resume = /^\/oidc\/auth\/([A-Za-z0-9_-]{43})$/.test(path);
    const isAuth = path === '/oidc/auth';
    if (query !== undefined && !isAuth) { missing(res); return true; }
    const source = singleton(req, 'x-forwarded-for') ?? req.socket.remoteAddress ?? '';
    if (req.socket.remoteAddress !== options.trustedProxyAddress || singleton(req, 'host') !== authority || singleton(req, 'x-forwarded-host') !== authority || singleton(req, 'x-forwarded-proto') !== 'https' || header(req, 'forwarded') || invalidXff(req) || !source || source.length > 64) { missing(res); return true; }
    const isInteraction = query === undefined && path === '/oidc/interaction' && (req.method === 'GET' || req.method === 'POST');
    const allowed = (req.method === 'GET' && query === undefined && ['/oidc/.well-known/openid-configuration', '/.well-known/oauth-authorization-server/oidc', '/oidc/jwks'].includes(path)) || (req.method === 'GET' && isAuth) || (req.method === 'GET' && query === undefined && resume) || (req.method === 'POST' && query === undefined && path === '/oidc/token') || isInteraction;
    if (!allowed) { missing(res); return true; }
    if (isInteraction) {
      if (interaction) void Promise.resolve().then(() => interaction(req, res)).catch(() => { if (!res.writableEnded) missing(res); });
      else missing(res);
      return true;
    }
    const limitedRoute: LimitedRoute | undefined = isAuth ? 'authorization' : path === '/oidc/token' ? 'token' : undefined;
    const release = limitedRoute ? limiter.acquire(limitedRoute, source) : () => undefined;
    if (!release) { limited(res); return true; }
    if (path === '/oidc/token') {
      if (canonicalLength(req) === undefined || header(req, 'content-encoding')) { release(); invalid(res); return true; }
    }
    const incoming = req as IncomingMessage & { originalUrl?: string };
    if (path === '/.well-known/oauth-authorization-server/oidc') { incoming.originalUrl = '/oidc/.well-known/oauth-authorization-server'; incoming.url = '/.well-known/oauth-authorization-server'; }
    else { incoming.originalUrl = incoming.url; incoming.url = path.slice('/oidc'.length) + (query === undefined ? '' : `?${query}`); }
    if (path === '/oidc/token') {
      const expectedLength = singleton(req, 'content-length');
      void readTokenBody(incoming, res, expectedLength === undefined ? undefined : Number(expectedLength)).then((body) => {
        if (body === undefined) return;
        (incoming as IncomingMessage & { body?: Buffer }).body = body;
        if (!res.destroyed && !res.writableEnded) return invokeProvider(incoming, res);
      }).catch(() => { if (!res.writableEnded) res.destroy(); }).finally(release);
      return true;
    }
    void Promise.resolve().then(() => invokeProvider(incoming, res)).catch(() => { if (!res.writableEnded) res.destroy(); }).finally(release); return true;
  };
}
const header = (req: IncomingMessage, name: string): boolean => req.rawHeaders.some((value, index) => index % 2 === 0 && value.toLowerCase() === name);
const invalidXff = (req: IncomingMessage): boolean => { const value = singleton(req, 'x-forwarded-for'); return header(req, 'x-forwarded-for') && value === undefined; };
