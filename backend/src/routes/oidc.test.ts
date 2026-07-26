import { describe, expect, it } from 'vitest';
import { createServer, request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import { createOidcDispatcher, createOidcRateLimiter, type OidcRateLimiter } from './oidc.js';

describe('OIDC ingress rate limiter', () => {
  it('enforces route limits and releases concurrency exactly once', () => {
    const limiter = createOidcRateLimiter(() => 0);
    const authorization = Array.from({ length: 30 }, () => limiter.acquire('authorization', 'one'));
    expect(authorization.every(Boolean)).toBe(true);
    authorization.forEach((release) => release?.());
    expect(limiter.acquire('authorization', 'one')).toBeUndefined();
    const concurrent = Array.from({ length: 32 }, (_, index) => limiter.acquire('token', `source-${index}`));
    expect(concurrent.every(Boolean)).toBe(true);
    expect(limiter.acquire('token', 'overflow')).toBeUndefined();
    concurrent[0]!(); concurrent[0]!();
    expect(limiter.acquire('token', 'overflow')).toBeTypeOf('function');
  });

  it('uses a monotonic clock and bounds/prunes live source buckets', () => {
    let current = 0; const limiter = createOidcRateLimiter(() => current);
    const first = limiter.acquire('token', 'reuse'); first?.();
    current = 60_000;
    expect(limiter.acquire('token', 'reuse')).toBeTypeOf('function');
    current = 1; // A supplied clock rollback cannot revive an expired window.
    for (let index = 0; index < 4_095; index += 1) limiter.acquire('token', `source-${index}`)?.();
    expect(limiter.acquire('token', 'unseen')).toBeUndefined();
    current = 120_000;
    expect(limiter.acquire('token', 'unseen')).toBeTypeOf('function');
  });
});

const trustedHeaders = { host: 'chat.example.test', 'x-forwarded-host': 'chat.example.test', 'x-forwarded-proto': 'https' };
async function dispatchRequest(dispatcher: ReturnType<typeof createOidcDispatcher>, headers: Record<string, string>, body?: string, path = '/oidc/token'): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  const server = createServer((request, response) => { dispatcher(request, response); });
  try {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('not listening');
    return await new Promise((resolve, reject) => {
      const request = httpRequest({ host: '127.0.0.1', port: address.port, path, method: 'POST', headers: { ...trustedHeaders, ...headers } }, (response) => {
        let received = ''; response.setEncoding('utf8'); response.on('data', (chunk: string) => { received += chunk; });
        response.on('end', () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: received }));
      });
      request.on('error', reject); request.end(body);
    });
  } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
}

describe('OIDC dispatcher token ingress', () => {
  const dispatcher = (invoke: (request: import('node:http').IncomingMessage) => void | Promise<void>, limiter?: OidcRateLimiter) =>
    createOidcDispatcher({ issuer: 'https://chat.example.test/oidc', trustedProxyAddress: '127.0.0.1' }, {} as never, undefined, async (request, response) => {
      await invoke(request); response.writeHead(204); response.end();
    }, limiter);

  it('accepts exactly 4096 bytes and rejects a chunked 4097-byte body before the provider', async () => {
    let calls = 0;
    const handler = dispatcher(() => { calls += 1; });
    expect((await dispatchRequest(handler, { 'content-length': '4096' }, 'a'.repeat(4096))).status).toBe(204);
    expect(calls).toBe(1);
    const rejected = await dispatchRequest(handler, { 'transfer-encoding': 'chunked' }, 'a'.repeat(4097));
    expect(rejected).toMatchObject({ status: 400, body: '{"error":"invalid_request"}', headers: { connection: 'close', 'cache-control': 'no-store', 'content-type': 'application/json', 'referrer-policy': 'no-referrer' } });
    expect(calls).toBe(1);
  });

  it('rejects malformed, duplicate, comma, oversized content lengths and content encoding before the provider', async () => {
    let calls = 0; const handler = dispatcher(() => { calls += 1; });
    const invalidHeaders: Record<string, string>[] = [
      { 'content-length': 'nope' }, { 'content-length': '1, 1' }, { 'content-length': '4097' }, { 'content-encoding': 'gzip' },
    ];
    for (const headers of invalidHeaders) expect((await dispatchRequest(handler, headers, 'x')).status).toBe(400);
    expect(calls).toBe(0);
  });

  it('passes a small chunked form as the exact Buffer before provider invocation', async () => {
    let body: Buffer | undefined;
    const result = await dispatchRequest(dispatcher((request) => { body = (request as typeof request & { body?: Buffer }).body; }), { 'transfer-encoding': 'chunked' }, 'grant_type=authorization_code');
    expect(result.status).toBe(204); expect(body).toEqual(Buffer.from('grant_type=authorization_code'));
  });

  it('releases a limiter slot once for synchronous and asynchronous provider failures', async () => {
    let releases = 0;
    const limiter: OidcRateLimiter = { acquire: () => () => { releases += 1; } };
    await expect(dispatchRequest(dispatcher(() => { throw new Error('sync'); }, limiter), { 'content-length': '1' }, 'x')).rejects.toThrow('socket hang up');
    await expect(dispatchRequest(dispatcher(async () => { throw new Error('async'); }, limiter), { 'content-length': '1' }, 'x')).rejects.toThrow('socket hang up');
    expect(releases).toBe(2);
  });

  it('releases the limiter after a dispatcher-boundary synchronous invokeProvider throw', async () => {
    let active = false; let releases = 0;
    const limiter: OidcRateLimiter = { acquire: () => active ? undefined : (() => { active = false; releases += 1; }) };
    const handler = createOidcDispatcher({ issuer: 'https://chat.example.test/oidc', trustedProxyAddress: '127.0.0.1' }, {} as never, undefined, () => { active = true; throw new Error('boundary'); }, limiter);
    await expect(dispatchRequest(handler, { 'content-length': '1' }, 'x')).rejects.toThrow('socket hang up');
    await expect(dispatchRequest(handler, { 'content-length': '1' }, 'x')).rejects.toThrow('socket hang up');
    expect(releases).toBe(2);
  });

  it('catches a synchronous interaction failure at the dispatcher boundary', async () => {
    const handler = createOidcDispatcher({ issuer: 'https://chat.example.test/oidc', trustedProxyAddress: '127.0.0.1' }, {} as never, () => { throw new Error('sync interaction'); });
    await expect(dispatchRequest(handler, {}, undefined, '/oidc/interaction')).resolves.toMatchObject({ status: 404, body: '{"error":"not_found"}' });
  });
});
