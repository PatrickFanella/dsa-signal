import { generateKeyPair } from 'node:crypto';
import { createServer, request as httpRequest, type Server } from 'node:http';
import { connect } from 'node:net';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { exportJWK } from 'jose';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createOidcProvider } from './provider.js';
import type { OidcSecrets, SigningJwk } from './secrets.js';
import { createOidcDispatcher } from '../routes/oidc.js';

const issuer = 'https://chat.example.test/oidc'; const callback = 'https://mas.example/upstream/callback/01J00000000000000000000000';
const servers: Server[] = []; let active: SigningJwk; let overlap: SigningJwk;
type Reply = { status: number; headers: Record<string, string | string[] | undefined>; body: string };
const pair = async (kid: string): Promise<SigningJwk> => new Promise((resolve, reject) => generateKeyPair('rsa', { modulusLength: 2048 }, async (error, _publicKey, privateKey) => error ? reject(error) : resolve({ ...await exportJWK(privateKey), kid, use: 'sig', alg: 'RS256' } as SigningJwk)));
beforeAll(async () => { active = await pair('active'); overlap = await pair('overlap'); });
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve())))); });

function provider(interactions: string[] = []) {
  class Adapter { constructor(readonly model: string) {} async find() { return undefined; } async upsert(id: string) { if (this.model === 'Interaction') interactions.push(id); } async findByUid() { return undefined; } async consume() {} async destroy() {} async revokeByGrantId() {} }
  const secrets: OidcSecrets = { clientSecret: new Uint8Array(32).fill(9), cookieKeys: [new Uint8Array(32).fill(8)], signingKeys: [active, overlap], publicJwks: { keys: [active, overlap].map(({ kty, n, e, kid, use, alg }) => ({ kty, n, e, kid, use, alg })) } };
  return createOidcProvider({ OIDC_ISSUER: issuer, MAS_CLIENT_ID: 'mas-client', MAS_REDIRECT_URI: callback }, secrets, Adapter, { findAccount: async () => undefined, pairwiseIdentifier: async () => 'subject' });
}
async function request(path: string, method = 'GET', headers: Record<string, string> = {}, body?: string, interactions: string[] = []): Promise<Reply> {
  const instance = provider(interactions); const dispatcher = createOidcDispatcher({ issuer, trustedProxyAddress: '127.0.0.1' }, instance, (_req, res) => { res.writeHead(204); res.end(); }); const server = createServer((req, res) => { if (!dispatcher(req, res)) { res.writeHead(404, { 'content-type': 'application/json', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' }); res.end('{"error":"not_found"}'); } });
  servers.push(server); await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve)); const address = server.address(); if (!address || typeof address === 'string') throw new Error('not bound');
  return new Promise((resolve, reject) => { const req = httpRequest({ host: '127.0.0.1', port: address.port, method, path, headers: { host: 'chat.example.test', 'x-forwarded-host': 'chat.example.test', 'x-forwarded-proto': 'https', ...headers, ...(body === undefined ? {} : { 'content-length': Buffer.byteLength(body) }) } }, (res) => { let text = ''; res.setEncoding('utf8'); res.on('data', (chunk: string) => { text += chunk; }); res.on('end', () => resolve({ status: res.statusCode ?? 500, headers: res.headers, body: text })); }); req.on('error', reject); req.end(body); });
}
async function rawOidc(target: string, headers = ''): Promise<number> {
  const server = createServer((req, res) => { const dispatcher = createOidcDispatcher({ issuer, trustedProxyAddress: '127.0.0.1' }, provider()); if (!dispatcher(req, res)) { res.writeHead(404); res.end(); } }); servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve)); const address = server.address(); if (!address || typeof address === 'string') throw new Error('not bound');
  return new Promise((resolve, reject) => { const socket = connect(address.port, '127.0.0.1'); let response = ''; socket.on('connect', () => socket.end(`GET ${target} HTTP/1.1\r\nHost: chat.example.test\r\nX-Forwarded-Host: chat.example.test\r\nX-Forwarded-Proto: https\r\n${headers}\r\n`)); socket.on('data', (chunk) => { response += chunk; }); socket.on('error', reject); socket.on('end', () => resolve(Number(/^HTTP\/1\.1 (\d+)/.exec(response)?.[1]))); });
}
const auth = (extra: Record<string, string> = {}) => new URLSearchParams({ client_id: 'mas-client', redirect_uri: callback, response_type: 'code', scope: 'openid dsa_signal_entitlement', state: 'state', nonce: 'nonce', code_challenge: 'A'.repeat(43), code_challenge_method: 'S256', ...extra });
const missing = (reply: Reply, method: string) => { expect(reply.status).toBe(404); expect(reply.headers).toMatchObject({ 'content-type': 'application/json', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' }); expect(reply.body).toBe(method === 'HEAD' ? '' : '{"error":"not_found"}'); };

describe('production OIDC provider factory', () => {
  it.each([['/oidc/.well-known/openid-configuration', 'openid-configuration.http'], ['/.well-known/oauth-authorization-server/oidc', 'oauth-authorization-server.http']])('matches complete checked-in metadata fixture bytes for %s', async (path, name) => {
    const actual = await request(path); const ignored = new Set(['connection', 'date', 'keep-alive', 'transfer-encoding']); const headers = Object.entries(actual.headers).filter(([key]) => !ignored.has(key)).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`).join('\n');
    expect(`HTTP/1.1 ${actual.status} OK\n${headers}\n\n${actual.body}\n`).toBe(await readFile(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8'));
  });

  it('allows only the mounted method/path inventory and fixed 404s', async () => {
    const resume = `/oidc/auth/${'A'.repeat(43)}`; const allowed: Array<[string, string]> = [['/oidc/.well-known/openid-configuration', 'GET'], ['/.well-known/oauth-authorization-server/oidc', 'GET'], ['/oidc/jwks', 'GET'], ['/oidc/auth', 'GET'], [resume, 'GET'], ['/oidc/token', 'POST'], ['/oidc/interaction', 'GET'], ['/oidc/interaction', 'POST']];
    for (const [path, method] of allowed) expect((await request(path, method)).status).not.toBe(404);
    for (const path of [...new Set(allowed.map(([value]) => value))]) for (const method of ['GET', 'POST', 'HEAD', 'OPTIONS']) if (!allowed.some(([allowedPath, allowedMethod]) => allowedPath === path && allowedMethod === method)) missing(await request(path, method), method);
    for (const path of [`/oidc/auth/${'A'.repeat(42)}`, `/oidc/auth/${'A'.repeat(44)}`, '/oidc/auth/a.b', '/oidc/auth/a%2Fb', '/oidc/auth/%C3%A9', '/oidc/.well-known/openid-configuration?x=1', '/.well-known/oauth-authorization-server/oidc?x=1', '/oidc/jwks?x=1', '/oidc/token?x=1', '/oidc/interaction?x=1', `${resume}?x=1`]) missing(await request(path), 'GET');
    missing(await request('/oidc/token?x=1', 'POST'), 'POST');
    for (const path of ['/oidc/session/end', '/oidc/callback', '/oidc/token/refresh', '/oidc/credential', '/oidc/credentials', '/v1/matrix/token', '/v1/matrix/callback']) missing(await request(path), 'GET');
  });

  it('rejects raw target aliases and untrusted or ambiguous proxy headers before provider dispatch', async () => {
    for (const path of ['/oidc/%2e%2e/jwks', '/oidc/%2f/jwks', '/oidc\\jwks', '/oidc/%C3%A9', '/oidc/jwks?']) missing(await request(path), 'GET');
    expect((await request('/oidc/auth?')).status).not.toBe(404);
    for (const headers of [{ host: 'wrong.example' }, { 'x-forwarded-host': 'wrong.example' }, { 'x-forwarded-proto': 'http' }, { forwarded: 'host=chat.example.test' }, { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }] as Record<string, string>[]) missing(await request('/oidc/jwks', 'GET', headers), 'GET');
    for (const [target, headers] of [['/oidc/jwks', 'Host: chat.example.test\r\n'], ['/oidc/jwks', 'X-Forwarded-Host: chat.example.test\r\n'], ['/oidc/jwks', 'X-Forwarded-Proto: https\r\n'], ['/oidc/jwks', 'X-Forwarded-Proto: https \r\n'], ['/oidc/jwks', 'X-Forwarded-For: 1.1.1.1\r\nX-Forwarded-For: 2.2.2.2\r\n'], ['/oidc/x/../jwks', ''], ['//oidc/jwks', '']]) expect(await rawOidc(target, headers)).toBe(404);
  });

  it('pins RS256 runtime configuration, key order, and static-client authorization validation', async () => {
    const jwks = await request('/oidc/jwks'); expect(JSON.parse(jwks.body)).toEqual({ keys: [active, overlap].map(({ kty, n, e, kid, use, alg }) => ({ kty, n, e, kid, use, alg })) });
    const discovery = JSON.parse((await request('/oidc/.well-known/openid-configuration')).body) as Record<string, unknown>;
    expect(discovery).toMatchObject({ id_token_signing_alg_values_supported: ['RS256'], scopes_supported: ['openid', 'dsa_signal_entitlement'], response_types_supported: ['code'], grant_types_supported: ['authorization_code'], token_endpoint_auth_methods_supported: ['client_secret_basic'], subject_types_supported: ['pairwise'], code_challenge_methods_supported: ['S256'] });
    for (const parameters of [auth(), auth({ response_mode: 'query' })]) expect((await request(`/oidc/auth?${parameters}`)).status).toBe(303);
    const invalids = [(p: URLSearchParams) => p.set('response_mode', 'form_post'), (p: URLSearchParams) => p.set('response_mode', 'fragment'), (p: URLSearchParams) => p.set('redirect_uri', 'https://wrong.example'), (p: URLSearchParams) => p.set('client_id', 'wrong'), (p: URLSearchParams) => p.set('scope', 'openid'), (p: URLSearchParams) => p.delete('state'), (p: URLSearchParams) => p.delete('nonce'), (p: URLSearchParams) => p.delete('code_challenge'), (p: URLSearchParams) => p.set('code_challenge_method', 'plain')];
    for (const mutate of invalids) { const parameters = auth(); mutate(parameters); const interactions: string[] = []; const reply = await request(`/oidc/auth?${parameters}`, 'GET', {}, undefined, interactions); expect(`${reply.body}${String(reply.headers.location ?? '')}`).toContain('error'); expect(`${reply.body}${String(reply.headers.location ?? '')}`).not.toContain('server_error'); expect(interactions).toEqual([]); }
  });
});
