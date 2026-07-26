import { afterEach, describe, expect, it } from 'vitest';
import type { Server } from 'node:http';
import { connect } from 'node:net';
import { createApp, type AppDependencies } from './server.js';
import { makeSessionCookie } from './identity/session-cookie.js';
import { FoundationHandoffRejectedError, FoundationUnavailableError } from './foundation/foundation-service.js';
import { ChallengeRejectedError, ChallengeUnavailableError } from './entitlements/challenge-service.js';
import { InvalidVerificationRequest, VerificationRejectedError, VerificationUnavailableError } from './entitlements/verify-entitlement.js';
import { IdentityStorageError } from './identity/session-repository.js';
import { LogoutUnavailableError } from './routes/auth.js';
import { OidcIndeterminateCommitError } from './oidc/request-context.js';

const key = new Uint8Array(32).fill(7); const secret = 'do-not-leak';
const code = 'A'.repeat(43); const verifier = 'B'.repeat(43); const session = 'A'.repeat(43); const jkt = 'J'.repeat(43);
const apps: Server[] = [];
type Overrides = Partial<AppDependencies>;
const deps = (overrides: Overrides = {}): AppDependencies => ({
  config: { PWA_ORIGIN: 'https://chat.example', COOKIE_KEY: key },
  foundation: { exchangeIdentityHandoff: async () => ({ did: 'did:plc:abcdefghijklmnopqrstuvwx', audience: 'https://chat.example', authenticatedAt: '2026-07-18T12:00:00Z', expiresIn: 60 }) },
  sessions: { establishFromHandoff: async () => ({ mappingId: 'mapping', sessionId: 'session' }), authenticate: async () => ({ mappingId: 'mapping', sessionId: session, bindingFingerprint: key, bindingKeyId: 'v1' }), renew: async () => false, revoke: async () => false },
  challenges: { issue: async () => ({ challenge: 'C'.repeat(43), expiresAt: 1 }) },
  verifications: { verify: async () => ({ status: 409, body: { version: 'v1', result: 'rejected', error: 'conflict' } }) },
  logout: { logout: async () => undefined },
  ...overrides,
});
async function app(overrides: Overrides = {}): Promise<number> {
  const server = createApp(deps(overrides)); apps.push(server); await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('no address'); return address.port;
}
async function request(path: string, init: RequestInit = {}, overrides: Overrides = {}): Promise<Response> {
  return fetch(`http://127.0.0.1:${await app(overrides)}${path}`, init);
}
const headers = (extra: Record<string, string> = {}): Record<string, string> => ({ accept: 'application/json', 'content-type': 'application/json', origin: 'https://chat.example', ...extra });
const identity = (): string => JSON.stringify({ version: 'v1', code, verifier, audience: 'https://chat.example' });
const challenge = (): string => JSON.stringify({ version: 'v1', jkt });
const cookie = (): string => makeSessionCookie(session, key).split(';')[0]!;
async function raw(port: number, wire: string): Promise<{ status: number; headers: string; body: string }> {
  return new Promise((resolve, reject) => { const socket = connect(port, '127.0.0.1'); let data = ''; socket.on('connect', () => socket.end(wire)); socket.on('data', chunk => { data += chunk; }); socket.on('error', reject); socket.on('end', () => { const [head, body = ''] = data.split('\r\n\r\n'); resolve({ status: Number(/^HTTP\/1\.1 (\d+)/.exec(head)?.[1]), headers: head, body }); }); });
}
afterEach(async () => { await Promise.all(apps.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve())))); });

describe('HTTP adapter', () => {
  it('keeps health, unknown, method, and query responses distinct', async () => {
    expect(await (await request('/health')).json()).toEqual({ status: 'ok' });
    expect((await request('/missing')).status).toBe(404);
    expect((await request('/v1/identity/sessions', { method: 'GET' })).headers.get('allow')).toBe('POST');
    expect((await request('/v1/identity/sessions?x=1', { method: 'POST', headers: { accept: 'text/plain' } })).status).toBe(400);
    expect((await request('/v1/identity/logout?x=1', { method: 'GET' })).status).toBe(400);
    const port = await app(); expect((await raw(port, 'POST /v1/identity/logout? HTTP/1.1\r\nHost: x\r\n\r\n')).status).toBe(400);
    expect((await raw(port, 'POST /v1/identity/./logout HTTP/1.1\r\nHost: x\r\n\r\n')).status).toBe(404);
    expect((await raw(port, 'POST /v1/identity/%6logout HTTP/1.1\r\nHost: x\r\n\r\n')).status).toBe(404);
  });

  it('mounts the injected OIDC dispatcher before generic 404 without changing Task 5 routes', async () => {
    const oidcDispatcher = (_req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => { res.writeHead(204); res.end(); return true; };
    expect((await request('/oidc/jwks', {}, { oidcDispatcher })).status).toBe(204);
    expect((await request('/not-oidc')).status).toBe(404);
    expect((await request('/v1/identity/sessions', { method: 'GET' })).status).toBe(405);
  });

  it('enforces one exact transport contract, including streamed boundaries', async () => {
    for (const [extra, status] of [
      [{ accept: 'application/json, text/plain' }, 406], [{ accept: '*/*' }, 406],
      [{ 'content-type': 'application/json; charset=utf-8' }, 415], [{ origin: 'https://wrong.example' }, 400],
      [{ 'content-encoding': 'gzip' }, 415],
    ] as const) expect((await request('/v1/identity/sessions', { method: 'POST', headers: headers(extra), body: identity() })).status).toBe(status);
    expect((await request('/v1/identity/sessions', { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://chat.example' }, body: identity() })).status).toBe(406);
    expect((await request('/v1/identity/sessions', { method: 'POST', headers: { accept: 'application/json', origin: 'https://chat.example' }, body: identity() })).status).toBe(415);
    expect((await request('/v1/identity/sessions', { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' }, body: identity() })).status).toBe(400);
    const port = await app(); const body = identity();
    for (const wire of [
      `POST /v1/identity/sessions HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\nContent-Type: application/json\r\nOrigin: https://chat.example\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
      `POST /v1/identity/sessions HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\nContent-Type: application/json\r\nOrigin: https://chat.example\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n${body.slice(0, 16)}\r\n${(Buffer.byteLength(body) - 16).toString(16)}\r\n${body.slice(16)}\r\n0\r\n\r\n`,
    ]) expect((await raw(port, wire)).status).toBe(201);
    for (const length of ['x', '-1', '01', '9007199254740992', '1025']) expect((await raw(port, `POST /v1/identity/sessions HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\nContent-Type: application/json\r\nOrigin: https://chat.example\r\nContent-Length: ${length}\r\n\r\n`)).status).toBe(length === '1025' ? 413 : 400);
    const over = 'x'.repeat(1025); expect((await raw(port, `POST /v1/identity/sessions HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\nContent-Type: application/json\r\nOrigin: https://chat.example\r\nTransfer-Encoding: chunked\r\n\r\n401\r\n${over}\r\n0\r\n\r\n`)).status).toBe(413);
  });

  it('rejects duplicate security headers without fetch normalization', async () => {
    const port = await app(); const wire = `POST /v1/identity/sessions HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nOrigin: https://chat.example\r\nOrigin: https://chat.example\r\nContent-Length: 0\r\n\r\n`;
    const response = await raw(port, wire); expect(response.status).toBe(400); expect(response.body).toContain('invalid_request');
    expect((await raw(port, `POST /v1/identity/sessions HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\nContent-Type: application/json\r\nOrigin: https://chat.example\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n`)).status).toBe(400);
  });

  it('has origin, session, and schema precedence and clears unusable cookies', async () => {
    const bad = '{"version":"v1"}';
    expect((await request('/v1/entitlements/challenges', { method: 'POST', headers: headers({ origin: 'https://wrong.example' }), body: bad })).status).toBe(400);
    const missing = await request('/v1/entitlements/challenges', { method: 'POST', headers: headers(), body: bad }); expect(missing.status).toBe(401); expect(missing.headers.get('set-cookie')).toContain('Max-Age=0');
    const malformed = await request('/v1/entitlements/challenges', { method: 'POST', headers: headers({ cookie: '__Host-dsa_signal_session=nope' }), body: bad }); expect(malformed.headers.get('set-cookie')).toContain('Max-Age=0');
    const duplicate = await request('/v1/entitlements/challenges', { method: 'POST', headers: headers({ cookie: `${cookie()}; ${cookie()}` }), body: challenge() }); expect(duplicate.status).toBe(400); expect(duplicate.headers.get('set-cookie')).toContain('Max-Age=0');
    expect((await request('/v1/entitlements/challenges', { method: 'POST', headers: headers({ cookie: cookie() }), body: bad })).status).toBe(400);
    expect((await request('/v1/identity/sessions', { method: 'POST', headers: headers(), body: new Uint8Array([0xc3, 0x28]) })).status).toBe(400);
    expect((await request('/v1/identity/sessions', { method: 'POST', headers: headers(), body: `{"version":"v1","code":"${code}","verifier":"${verifier}","audience":"https://chat.example","extra":{"x":1,"\\u0078":2}}` })).status).toBe(400);
  });

  it('maps identity, challenge, and verification outcomes without leaking sentinels', async () => {
    const success = await request('/v1/identity/sessions', { method: 'POST', headers: headers(), body: identity() });
    expect(success.status).toBe(201); expect(await success.json()).toEqual({ version: 'v1', result: 'authenticated' }); expect(success.headers.get('set-cookie')).toMatch(/^__Host-dsa_signal_session=v1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}; Path=\/; Max-Age=900; HttpOnly; Secure; SameSite=Strict$/); expect(success.headers.get('cache-control')).toBe('no-store'); expect(success.headers.get('referrer-policy')).toBe('no-referrer');
    for (const [error, status] of [[new FoundationHandoffRejectedError(), 401], [new FoundationUnavailableError(), 503], [new IdentityStorageError(), 503]] as const) expect((await request('/v1/identity/sessions', { method: 'POST', headers: headers(), body: identity() }, { foundation: { exchangeIdentityHandoff: async () => { throw error; } } })).status).toBe(status);
    let established = false;
    const unavailable = await request('/v1/identity/sessions', { method: 'POST', headers: headers(), body: identity() }, { foundation: { exchangeIdentityHandoff: async () => { throw new FoundationUnavailableError(); } }, sessions: { ...deps().sessions, establishFromHandoff: async () => { established = true; return { mappingId: 'mapping', sessionId: 'session' }; } } });
    expect(unavailable.status).toBe(503); expect(established).toBe(false);
    for (const [error, status] of [[undefined, 201], [new ChallengeRejectedError(), 401], [new ChallengeUnavailableError(), 503]] as const) expect((await request('/v1/entitlements/challenges', { method: 'POST', headers: headers({ cookie: cookie() }), body: challenge() }, { challenges: { issue: async () => { if (error) throw error; return { challenge: 'C'.repeat(43), expiresAt: 1 }; } } })).status).toBe(status);
    for (const [answer, status] of [[{ status: 200, body: { version: 'v1', result: 'authorized' } }, 200], [{ status: 401, body: { version: 'v1', result: 'rejected', error: 'rejected' } }, 401], [{ status: 409, body: { version: 'v1', result: 'rejected', error: 'conflict' } }, 409]] as const) expect((await request('/v1/entitlements/verifications', { method: 'POST', headers: headers({ cookie: cookie() }), body: '{}' }, { verifications: { verify: async () => answer } })).status).toBe(status);
    expect((await request('/v1/entitlements/verifications', { method: 'POST', headers: headers({ cookie: cookie() }), body: '{}' }, { verifications: { verify: async () => { throw new InvalidVerificationRequest(); } } })).status).toBe(400);
    for (const error of [new VerificationRejectedError(), new VerificationUnavailableError(), new Error(secret)]) { const response = await request('/v1/entitlements/verifications', { method: 'POST', headers: headers({ cookie: cookie() }), body: '{}' }, { verifications: { verify: async () => { throw error; } } }); expect(response.status).toBe(error instanceof VerificationRejectedError ? 401 : 503); expect(await response.text()).not.toContain(secret); }
  });
  it('logs out missing and valid cookies, rejecting malformed cookies and retaining retry cookies', async () => {
    const body = JSON.stringify({ version: 'v1' });
    const missing = await request('/v1/identity/logout', { method: 'POST', headers: headers(), body });
    expect(missing.status).toBe(200); expect(missing.headers.get('set-cookie')).toContain('Max-Age=0');
    const malformed = await request('/v1/identity/logout', { method: 'POST', headers: headers({ cookie: '__Host-dsa_signal_session=bad' }), body });
    expect(malformed.status).toBe(400); expect(malformed.headers.get('set-cookie')).toContain('Max-Age=0');
    let called = false;
    const success = await request('/v1/identity/logout', { method: 'POST', headers: headers({ cookie: cookie() }), body }, { logout: { logout: async () => { called = true; } } });
    expect(success.status).toBe(200); expect(called).toBe(true); expect(success.headers.get('set-cookie')).toContain('Max-Age=0');
    const unavailable = await request('/v1/identity/logout', { method: 'POST', headers: headers({ cookie: cookie() }), body }, { logout: { logout: async () => { throw new LogoutUnavailableError(); } } });
    expect(unavailable.status).toBe(503); expect(unavailable.headers.get('set-cookie')).toBeNull();
    expect((await request('/v1/identity/logout', { method: 'POST', headers: headers({ cookie: cookie() }), body: JSON.stringify({ version: 'v1', matrix_token: secret }) })).status).toBe(400);
    await expect(request('/v1/identity/logout', { method: 'POST', headers: headers({ cookie: cookie() }), body }, { logout: { logout: async () => { throw new OidcIndeterminateCommitError(new Error('lost')); } } })).rejects.toThrow();
    const port = await app();
    const duplicate = await raw(port, `POST /v1/identity/logout HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\nContent-Type: application/json\r\nOrigin: https://chat.example\r\nCookie: ${cookie()}\r\nCookie: ${cookie()}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    expect(duplicate.status).toBe(400); expect(duplicate.headers).toContain('Max-Age=0');
    expect((await raw(port, `POST /v1/identity/logout HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\nContent-Type: application/json\r\nOrigin: https://chat.example\r\nForwarded: for=a\r\nForwarded: for=b\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`)).status).toBe(400);
    const over = 'x'.repeat(1025); expect((await raw(port, `POST /v1/identity/logout HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\nContent-Type: application/json\r\nOrigin: https://chat.example\r\nTransfer-Encoding: chunked\r\n\r\n401\r\n${over}\r\n0\r\n\r\n`)).status).toBe(413);
  });
});
