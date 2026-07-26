import { AsyncLocalStorage } from 'node:async_hooks';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash, generateKeyPair, type KeyObject } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { exportJWK, jwtVerify, type JWK } from 'jose';
import { createOidcProvider, type OidcProvider } from './provider.js';
import { createOidcDispatcher } from '../routes/oidc.js';
import type { OidcSecrets } from './secrets.js';

const ORIGIN = 'https://chat.example.test';
const ISSUER = `${ORIGIN}/oidc`;
const CLIENT_ID = 'mas-client';
const CLIENT_SECRET = Buffer.alloc(32, 9).toString('base64url');
const CALLBACK = 'https://mas.example/upstream/callback/01J00000000000000000000000';
const COOKIE_KEYS = [Buffer.alloc(32, 8).toString('base64url'), Buffer.alloc(32, 7).toString('base64url')];
const PERSISTED_MODELS = ['AuthorizationCode', 'AccessToken', 'Session', 'Grant', 'Interaction'] as const;
type ProbeTransaction = { consumed: boolean; phases: string[]; revoked: boolean };
type HarnessContext = { failAfterConsume?: boolean; transaction?: ProbeTransaction; transactionId: string };
const als = new AsyncLocalStorage<HarnessContext>();
const servers: Server[] = [];
const completedTransactions: ProbeTransaction[] = [];
let signingPrivate: KeyObject;
let signingPublic: KeyObject;
let signingJwk: JWK;

type Operation = { model: string; method: string; keys: string[]; id?: string; payload?: Record<string, unknown>; transactionId?: string };
type Stored = Map<string, Record<string, unknown>>;

beforeAll(async () => {
  // Generated once per suite: no private signing material is committed or used in fixture semantics.
  const pair = await new Promise<{ publicKey: KeyObject; privateKey: KeyObject }>((resolve, reject) =>
    generateKeyPair('rsa', { modulusLength: 2048 }, (error, publicKey, privateKey) => error ? reject(error) : resolve({ publicKey, privateKey })),
  );
  signingPrivate = pair.privateKey;
  signingPublic = pair.publicKey;
  signingJwk = { ...await exportJWK(signingPrivate), kid: 'test-active-rs256', use: 'sig', alg: 'RS256' };
});

function instrumentedAdapter(operations: Operation[], storage: Stored) {
  return class Adapter {
    readonly model: string;
    constructor(modelName: string) {
      this.model = modelName;
      if (modelName !== 'Client' && !PERSISTED_MODELS.includes(modelName as typeof PERSISTED_MODELS[number])) throw new Error(`persistence forbidden for ${modelName}`);
      this.record('constructor', { modelName });
    }
    private record(method: string, payload?: Record<string, unknown>, id?: string) {
      operations.push({ model: this.model, method, keys: payload ? Object.keys(payload).sort() : [], id, payload: payload && structuredClone(payload), transactionId: als.getStore()?.transactionId });
    }
    async upsert(id: string, payload: Record<string, unknown>, expiresIn: number) {
      this.record('upsert', payload, id);
      if (this.model === 'AccessToken') als.getStore()?.transaction?.phases.push('access-token-upsert');
      storage.set(`${this.model}:${id}`, structuredClone({ ...payload, expiresAt: Math.floor(Date.now() / 1000) + expiresIn }));
    }
    async find(id: string) {
      this.record('find', undefined, id);
      if (this.model === 'Client') return undefined;
      const value = storage.get(`${this.model}:${id}`); return value && structuredClone(value);
    }
    async findByUid(uid: string) {
      this.record('findByUid', { uid });
      if (this.model !== 'Session') throw new Error(`findByUid forbidden for ${this.model}`);
      for (const [key, value] of storage) if (key.startsWith('Session:') && value.uid === uid) return structuredClone(value);
      return undefined;
    }
    async consume(id: string) {
      this.record('consume', undefined, id);
      const transaction = als.getStore()?.transaction;
      if (transaction) { transaction.consumed = true; transaction.phases.push('consume', 'savepoint'); }
      const value = storage.get(`${this.model}:${id}`); if (value) value.consumed = Math.floor(Date.now() / 1000);
    }
    async destroy(id: string) { this.record('destroy', undefined, id); storage.delete(`${this.model}:${id}`); }
    async revokeByGrantId(grantId: string) {
      this.record('revokeByGrantId', undefined, grantId);
      const transaction = als.getStore()?.transaction;
      if (transaction) { transaction.revoked = true; transaction.phases.push('revoke-by-grant'); }
    }
  };
}

async function provider(operations: Operation[] = [], storage: Stored = new Map()): Promise<OidcProvider> {
  const secrets: OidcSecrets = { clientSecret: new Uint8Array(Buffer.from(CLIENT_SECRET, 'base64url')), cookieKeys: COOKIE_KEYS.map((key) => new Uint8Array(Buffer.from(key, 'base64url'))), signingKeys: [signingJwk] as OidcSecrets['signingKeys'], publicJwks: { keys: [] } };
  const instance = createOidcProvider({ OIDC_ISSUER: ISSUER, MAS_CLIENT_ID: CLIENT_ID, MAS_REDIRECT_URI: CALLBACK }, secrets, instrumentedAdapter(operations, storage), {
    findAccount: async () => {
      expect(als.getStore()?.transactionId).toBeDefined();
      if (als.getStore()?.failAfterConsume) throw new Error('injected post-consume account failure');
      return { accountId: '00000000-0000-4000-8000-000000000001', claims: () => ({ sub: 'pairwise-subject', dsa_signal_entitlement_policy_version: 'v1' }) };
    },
    pairwiseIdentifier: async () => { expect(als.getStore()?.transactionId).toBeDefined(); return 'pairwise-subject'; },
    loadExistingGrant: async (context: unknown) => {
      const oidc = (context as { oidc: { provider: OidcProvider; result?: { consent?: { grantId?: string } } } }).oidc;
      return oidc.result?.consent?.grantId ? oidc.provider.Grant.find(oidc.result.consent.grantId) : undefined;
    },
    tokenLifetime: () => 300,
  });
  instance.use(async (context, next) => {
    const transactionId = als.getStore()?.transactionId;
    if (!transactionId) throw new Error('provider middleware escaped application ALS');
    await next();
    operations.push({ model: 'Middleware', method: context.oidc?.route ?? 'unmatched', keys: [], transactionId });
  });
  return instance;
}

type HarnessResponse = Readonly<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>;
const notFound = (response: ServerResponse) => { response.writeHead(404, { 'content-type': 'application/json', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' }); response.end('{"error":"not_found"}'); };

async function invokeBufferedProvider(instance: OidcProvider, incoming: IncomingMessage, outgoing: ServerResponse, transaction: ProbeTransaction) {
  const chunks: Buffer[] = [];
  const originalEnd = outgoing.end.bind(outgoing);
  const originalWrite = outgoing.write.bind(outgoing);
  const response = outgoing as ServerResponse & { end: (...args: unknown[]) => ServerResponse; write: (...args: unknown[]) => boolean };
  response.write = ((chunk: unknown, encoding?: BufferEncoding) => {
    if (chunk !== undefined) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), encoding));
    return true;
  }) as typeof response.write;
  response.end = ((chunk?: unknown, encoding?: BufferEncoding) => {
    if (chunk !== undefined) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), encoding));
    return outgoing;
  }) as typeof response.end;
  try {
    await (instance.callback() as unknown as (request: IncomingMessage, response: ServerResponse) => Promise<void>)(incoming, response);
    transaction.phases.push('provider-response-buffered');
    if (incoming.headers['x-harness-commit-fail'] === '1') {
      transaction.phases.push('commit-failed', 'provider-output-discarded');
      for (const name of outgoing.getHeaderNames()) outgoing.removeHeader(name);
      outgoing.statusCode = 503;
      outgoing.setHeader('content-type', 'application/json');
      chunks.splice(0, chunks.length, Buffer.from('{"error":"commit_failed"}'));
    } else if (transaction.revoked) transaction.phases.push('commit-revocation');
    else if (transaction.consumed && outgoing.statusCode >= 400) transaction.phases.push('rollback-to-savepoint', 'commit-consumption-only');
    else if (transaction.consumed) transaction.phases.push('commit');
    else transaction.phases.push('rollback');
    transaction.phases.push('flush');
    completedTransactions.push(transaction);
  } finally {
    response.write = originalWrite as typeof response.write;
    response.end = originalEnd as typeof response.end;
  }
  originalEnd(Buffer.concat(chunks));
}

function dispatch(instance: OidcProvider, incoming: IncomingMessage, outgoing: ServerResponse) {
  const transaction = incoming.url?.startsWith('/oidc/token') ? { consumed: false, phases: ['begin'], revoked: false } : undefined;
  const context: HarnessContext = { failAfterConsume: incoming.headers['x-harness-fail-after-consume'] === '1', transaction, transactionId: crypto.randomUUID() };
  const interaction = async (request: IncomingMessage, response: ServerResponse) => {
    try {
      if (request.method === 'GET') { const details = await instance.interactionDetails(request, response); response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify({ uid: details.uid, prompt: details.prompt })); return; }
      const details = await instance.interactionDetails(request, response);
      if ((details.prompt as { name: string }).name !== 'dsa_signal_fresh_entitlement') throw new Error('unexpected prompt');
      const grant = new instance.Grant({ accountId: '00000000-0000-4000-8000-000000000001', clientId: CLIENT_ID }); grant.addOIDCScope('openid dsa_signal_entitlement'); const grantId = await grant.save(900);
      const result = { login: { accountId: '00000000-0000-4000-8000-000000000001', remember: false, ts: 1_800_000_000 }, dsa_signal_fresh_entitlement: { verified: true }, consent: { grantId } };
      if (request.headers['x-harness-interaction-finished'] === '1') { await instance.interactionFinished(request, response, result, { mergeWithLastSubmission: false }); if (!response.writableEnded) throw new Error('interactionFinished did not end the response'); return; }
      const destination = await instance.interactionResult(request, response, result, { mergeWithLastSubmission: false }); if (response.headersSent || response.writableEnded) throw new Error('interactionResult committed the response'); response.writeHead(303, { location: destination, 'content-length': '0' }); response.end();
    } catch { notFound(response); }
  };
  const dispatcher = createOidcDispatcher({ issuer: ISSUER, trustedProxyAddress: '127.0.0.1' }, instance, interaction, (request, response) => transaction ? invokeBufferedProvider(instance, request, response, transaction) : instance.callback()(request, response));
  als.run(context, () => dispatcher(incoming, outgoing));
}

async function request(instance: OidcProvider, path: string, method = 'GET', headers: Record<string, string> = {}, body?: string): Promise<HarnessResponse> {
  const server = createServer((incoming, outgoing) => dispatch(instance, incoming, outgoing));
  servers.push(server); await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('server did not bind');
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest({ host: '127.0.0.1', port: address.port, path, method, headers: { host: 'chat.example.test', 'x-forwarded-host': 'chat.example.test', 'x-forwarded-proto': 'https', ...(body === undefined ? {} : { 'content-length': String(Buffer.byteLength(body)) }), ...headers } }, (incoming) => {
      let body = ''; incoming.setEncoding('utf8'); incoming.on('data', (chunk: string) => { body += chunk; });
      incoming.on('end', () => resolve({ status: incoming.statusCode ?? 500, headers: incoming.headers, body }));
    }); outgoing.on('error', reject); outgoing.end(body);
  });
}

async function fixture(name: string) { return readFile(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), 'utf8'); }
const cookieHeader = (value: string | string[] | undefined): string => (Array.isArray(value) ? value : [value ?? '']).map((cookie) => cookie.split(';')[0]).filter(Boolean).join('; ');
function mergeCookies(...values: (string | string[] | undefined)[]): string {
  const jar = new Map<string, string>();
  for (const value of values) {
    const pairs = Array.isArray(value)
      ? value.map((cookie) => cookie.split(';')[0]!).filter(Boolean)
      : (value ?? '').split('; ').filter(Boolean);
    for (const pair of pairs) jar.set(pair.slice(0, pair.indexOf('=')), pair);
  }
  return [...jar.values()].join('; ');
}
function selectCookies(cookies: string, names: readonly string[]): string {
  const allowed = new Set(names);
  return cookies.split('; ').filter((pair) => allowed.has(pair.slice(0, pair.indexOf('=')))).join('; ');
}
const headerString = (value: string | string[] | undefined): string => Array.isArray(value) ? value[0] ?? '' : value ?? '';
const s256 = (value: string): string => createHash('sha256').update(value).digest('base64url');
async function beginAuthorization(instance: OidcProvider, state = 'state') {
  const verifier = 'verifier-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.abc';
  const response = await request(instance, `/oidc/auth?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(CALLBACK)}&response_type=code&scope=${encodeURIComponent('openid dsa_signal_entitlement')}&state=${state}&nonce=nonce-${state}&code_challenge=${s256(verifier)}&code_challenge_method=S256`);
  expect(response.status).toBe(303); expect(response.headers.location).toBe('/oidc/interaction');
  return { verifier, interaction: headerString(response.headers.location), cookies: cookieHeader(response.headers['set-cookie']), rawCookies: response.headers['set-cookie'] };
}

async function completeAuthorization(instance: OidcProvider, state: string, existingCookies = '') {
  const started = await beginAuthorizationWithCookies(instance, state, existingCookies);
  const sessionNames = ['__Host-dsa_signal_oidc_session', '__Host-dsa_signal_oidc_session.sig'];
  const interactionNames = [...sessionNames, 'dsa_signal_oidc_interaction', 'dsa_signal_oidc_interaction.sig'];
  const resumeNames = [...sessionNames, 'dsa_signal_oidc_interaction_resume', 'dsa_signal_oidc_interaction_resume.sig'];
  const details = await request(instance, started.interaction, 'GET', { cookie: selectCookies(started.cookies, interactionNames) });
  expect(details.status).toBe(200);
  const interaction = JSON.parse(details.body) as { uid: string; prompt: { name: string } };
  expect(interaction.uid).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(interaction.prompt.name).toBe('dsa_signal_fresh_entitlement');
  const decided = await request(instance, started.interaction, 'POST', { cookie: selectCookies(started.cookies, interactionNames) });
  expect(decided.status).toBe(303);
  const resume = new URL(headerString(decided.headers.location));
  expect(resume.origin).toBe(ORIGIN);
  expect(resume.pathname).toMatch(/^\/oidc\/auth\/[A-Za-z0-9_-]{43}$/);
  const cookies = mergeCookies(started.cookies, details.headers['set-cookie'], decided.headers['set-cookie']);
  const resumed = await request(instance, `${resume.pathname}${resume.search}`, 'GET', { cookie: selectCookies(cookies, resumeNames) });
  expect(resumed.status, resumed.body).toBe(303);
  const callback = new URL(headerString(resumed.headers.location));
  expect(callback.origin + callback.pathname).toBe(CALLBACK);
  expect(callback.searchParams.get('state')).toBe(state);
  const code = callback.searchParams.get('code');
  expect(code).toBeTruthy();
  return {
    code: code!,
    cookies: selectCookies(mergeCookies(cookies, resumed.headers['set-cookie']), sessionNames),
    rawCookies: [started.rawCookies, details.headers['set-cookie'], decided.headers['set-cookie'], resumed.headers['set-cookie']].flatMap((value) => Array.isArray(value) ? value : value ? [value] : []),
    verifier: started.verifier,
  };
}

async function beginAuthorizationWithCookies(instance: OidcProvider, state: string, cookies: string) {
  const verifier = 'verifier-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.abc';
  const response = await request(instance, `/oidc/auth?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(CALLBACK)}&response_type=code&scope=${encodeURIComponent('openid dsa_signal_entitlement')}&state=${state}&nonce=nonce-${state}&code_challenge=${s256(verifier)}&code_challenge_method=S256`, 'GET', cookies ? { cookie: cookies } : {});
  expect(response.status).toBe(303);
  expect(response.headers.location).toBe('/oidc/interaction');
  return { verifier, interaction: '/oidc/interaction', cookies: mergeCookies(cookies, response.headers['set-cookie']), rawCookies: response.headers['set-cookie'] };
}

async function exchangeCode(instance: OidcProvider, code: string, verifier: string, headers: Record<string, string> = {}) {
  const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: CALLBACK, code_verifier: verifier }).toString();
  return request(instance, '/oidc/token', 'POST', {
    authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`,
    'content-type': 'application/x-www-form-urlencoded',
    ...headers,
  }, body);
}
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve())))); });

describe('oidc-provider 9.9.1 compatibility harness', () => {
  it('uses exactly the supported package version and the deny-by-default adapter boundary', async () => {
    const metadata = JSON.parse(await readFile(fileURLToPath(new URL('../../package.json', import.meta.url)), 'utf8')) as { dependencies: Record<string, string> };
    expect(metadata.dependencies['oidc-provider']).toBe('9.9.1');
    const operations: Operation[] = []; const instance = await provider(operations);
    await request(instance, '/oidc/jwks');
    expect(PERSISTED_MODELS).toEqual(['AuthorizationCode', 'AccessToken', 'Session', 'Grant', 'Interaction']);
    expect(operations.every((operation) => operation.transactionId)).toBe(true);
    expect(operations.filter((operation) => operation.method === 'findByUid').every((operation) => operation.model === 'Session')).toBe(true);
  });

  it('has exact external endpoint URLs, issuer, and semantic public JWKS shape', async () => {
    const instance = await provider(); const response = await request(instance, '/oidc/jwks');
    expect(response.status).toBe(200); const body = JSON.parse(response.body) as { keys: Record<string, string>[] };
    expect(body.keys).toHaveLength(1); expect(Object.keys(body.keys[0]!).sort()).toEqual(['alg', 'e', 'kid', 'kty', 'n', 'use']);
    expect(body.keys[0]).toMatchObject({ kty: 'RSA', kid: 'test-active-rs256', use: 'sig', alg: 'RS256' });
    const discovery = await request(instance, '/oidc/.well-known/openid-configuration');
    expect(discovery.body).toContain(`"issuer":"${ISSUER}"`); expect(discovery.body).toContain(`"token_endpoint":"${ISSUER}/token"`);
  });

  it.each([['/oidc/.well-known/openid-configuration', 'openid-configuration.http'], ['/.well-known/oauth-authorization-server/oidc', 'oauth-authorization-server.http']])('matches complete provider-owned %s fixture bytes', async (path, fixtureName) => {
    const instance = await provider(); const actual = await request(instance, path); const expected = await fixture(fixtureName);
    const ignoredTransportHeaders = new Set(['connection', 'date', 'keep-alive', 'transfer-encoding']);
    const deterministicHeaders = Object.entries(actual.headers)
      .filter(([name]) => !ignoredTransportHeaders.has(name))
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, value]) => `${name}: ${Array.isArray(value) ? value.join(', ') : value}`)
      .join('\n');
    const raw = `HTTP/1.1 ${actual.status} ${actual.status === 200 ? 'OK' : ''}\n${deterministicHeaders}\n\n${actual.body}\n`;
    expect(raw).toBe(expected);
  });

  it('rejects disabled and malformed external routes at host dispatch', async () => {
    const instance = await provider();
    const disallowed: [string, string][] = [
      ['/oidc/.well-known/openid-configuration', 'POST'], ['/oidc/.well-known/openid-configuration', 'HEAD'], ['/oidc/.well-known/openid-configuration', 'OPTIONS'],
      ['/.well-known/oauth-authorization-server/oidc', 'POST'], ['/.well-known/oauth-authorization-server/oidc', 'HEAD'], ['/.well-known/oauth-authorization-server/oidc', 'OPTIONS'],
      ['/oidc/jwks', 'POST'], ['/oidc/jwks', 'HEAD'], ['/oidc/jwks', 'OPTIONS'],
      ['/oidc/auth', 'POST'], ['/oidc/auth', 'HEAD'], ['/oidc/auth', 'OPTIONS'],
      [`/oidc/auth/${'A'.repeat(43)}`, 'POST'], [`/oidc/auth/${'A'.repeat(43)}`, 'HEAD'], [`/oidc/auth/${'A'.repeat(43)}`, 'OPTIONS'],
      ['/oidc/token', 'GET'], ['/oidc/token', 'HEAD'], ['/oidc/token', 'OPTIONS'], ['/oidc/token?x=1', 'POST'],
      ['/oidc/interaction', 'PUT'], ['/oidc/interaction', 'HEAD'], ['/oidc/interaction', 'OPTIONS'],
    ];
    for (const [path, method] of disallowed) {
      const response = await request(instance, path, method);
      expect(response.status).toBe(404); expect(response.body).toBe(method === 'HEAD' ? '' : '{"error":"not_found"}');
      expect(response.headers).toMatchObject({ 'cache-control': 'no-store', 'content-type': 'application/json', 'referrer-policy': 'no-referrer' });
    }
    for (const path of [
      `/oidc/auth/${'A'.repeat(42)}`, `/oidc/auth/${'A'.repeat(44)}`, '/oidc/auth/a%2Fb', '/oidc/auth/a.b', '/oidc/session/end/confirm', '/oidc/nope',
      '/oidc/.well-known/openid-configuration?x=1', '/.well-known/oauth-authorization-server/oidc?x=1', '/oidc/jwks?x=1', `/oidc/auth/${'A'.repeat(43)}?x=1`, '/oidc/token?x=1', '/oidc/interaction?x=1',
    ]) {
      const response = await request(instance, path);
      expect(response).toMatchObject({ status: 404, body: '{"error":"not_found"}' });
    }
  });

  it('pins all six signed provider cookies, narrow paths, attributes, and lifetimes', async () => {
    const instance = await provider();
    const completed = await completeAuthorization(instance, 'cookies');
    const cookies = completed.rawCookies;
    expect(new Set(cookies.map((cookie) => cookie.slice(0, cookie.indexOf('=')))).size).toBe(6);
    const byName = new Map<string, string>();
    for (const cookie of cookies) {
      const name = cookie.slice(0, cookie.indexOf('='));
      const value = cookie.slice(cookie.indexOf('=') + 1, cookie.indexOf(';'));
      if (value && !byName.has(name)) byName.set(name, cookie);
    }
    const resumeUid = /^dsa_signal_oidc_interaction_resume=([A-Za-z0-9_-]{43});/.exec(byName.get('dsa_signal_oidc_interaction_resume') ?? '')?.[1];
    expect(resumeUid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const expectedPaths: Record<string, string> = {
      '__Host-dsa_signal_oidc_session': '/',
      '__Host-dsa_signal_oidc_session.sig': '/',
      dsa_signal_oidc_interaction: '/oidc/interaction',
      'dsa_signal_oidc_interaction.sig': '/oidc/interaction',
      dsa_signal_oidc_interaction_resume: `/oidc/auth/${resumeUid}`,
      'dsa_signal_oidc_interaction_resume.sig': `/oidc/auth/${resumeUid}`,
    };
    for (const [name, path] of Object.entries(expectedPaths)) {
      const cookie = byName.get(name) ?? '';
      expect(cookie.toLowerCase()).toContain(`path=${path}`.toLowerCase());
      expect(cookie.toLowerCase()).toContain('httponly');
      expect(cookie.toLowerCase()).toContain('secure');
      expect(cookie.toLowerCase()).toContain('samesite=lax');
      expect(cookie.toLowerCase()).not.toContain('domain=');
      if (name.startsWith('__Host-')) {
        expect(cookie.toLowerCase()).not.toContain('expires=');
        expect(cookie.toLowerCase()).not.toContain('max-age=');
      } else {
        const expires = /expires=([^;]+)/i.exec(cookie)?.[1];
        expect(expires).toBeDefined();
        const remaining = Date.parse(expires!) - Date.now();
        expect(remaining).toBeGreaterThan(295_000);
        expect(remaining).toBeLessThanOrEqual(300_000);
      }
    }
  });

  it('completes code plus S256 through public interactions and emits the exact RS256 claim set', async () => {
    const operations: Operation[] = [];
    const storage: Stored = new Map();
    const instance = await provider(operations, storage);
    const authorization = await completeAuthorization(instance, 'golden');
    const token = await exchangeCode(instance, authorization.code, authorization.verifier);
    expect(token.status).toBe(200);
    const payload = JSON.parse(token.body) as { access_token: string; id_token: string; token_type: string; expires_in: number };
    expect(payload).toMatchObject({ token_type: 'Bearer', expires_in: 300 });
    expect(payload.access_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const verified = await jwtVerify(payload.id_token, signingPublic, { algorithms: ['RS256'], issuer: ISSUER, audience: CLIENT_ID });
    expect(Object.keys(verified.payload).sort()).toEqual(['aud', 'auth_time', 'dsa_signal_entitlement_policy_version', 'exp', 'iat', 'iss', 'nonce', 'sub']);
    expect(verified.payload).toMatchObject({ nonce: 'nonce-golden', sub: 'pairwise-subject', dsa_signal_entitlement_policy_version: 'v1' });
    expect(verified.payload.auth_time).toBe(1_800_000_000);
    expect(Number(verified.payload.exp) - Number(verified.payload.iat)).toBe(300);
    expect(operations.some((operation) => operation.model === 'Middleware' && operation.method === 'token')).toBe(true);
    const uidFinds = operations.filter((operation) => operation.method === 'findByUid');
    expect(uidFinds.length).toBeGreaterThan(0);
    expect(uidFinds.every((operation) => operation.model === 'Session')).toBe(true);
    const persisted = new Set(operations.filter((operation) => operation.method === 'upsert').map((operation) => operation.model));
    expect([...persisted].sort()).toEqual([...PERSISTED_MODELS].sort());
    const payloadShapes = Object.fromEntries(PERSISTED_MODELS.map((model) => [model, [...new Set(operations.filter((operation) => operation.model === model && operation.method === 'upsert').map((operation) => operation.keys.join(',')))].sort()]));
    expect(payloadShapes).toEqual({
      AccessToken: ['accountId,claims,clientId,exp,expiresWithSession,extra,grantId,gty,iat,jti,kind,scope,sessionUid'],
      AuthorizationCode: ['accountId,authTime,claims,clientId,codeChallenge,codeChallengeMethod,exp,expiresWithSession,grantId,iat,jti,kind,nonce,redirectUri,scope,sessionUid'],
      Grant: ['accountId,clientId,exp,iat,jti,kind,openid'],
      Interaction: ['cid,exp,iat,jti,kind,params,prompt,result,returnTo', 'cid,exp,iat,jti,kind,params,prompt,returnTo'],
      Session: ['accountId,authorizations,exp,iat,jti,kind,loginTs,transient,uid'],
    });
    const codePayload = operations.find((operation) => operation.model === 'AuthorizationCode' && operation.method === 'upsert')?.payload;
    const accessPayload = operations.find((operation) => operation.model === 'AccessToken' && operation.method === 'upsert')?.payload;
    expect(codePayload?.grantId).toBeTypeOf('string');
    expect(accessPayload?.grantId).toBe(codePayload?.grantId);
    expect(storage.has(`Grant:${String(codePayload?.grantId)}`)).toBe(true);
    expect(operations.every((operation) => operation.transactionId)).toBe(true);
  });

  it('round-trips unknown provider payload members without persisting unsupported models', async () => {
    const operations: Operation[] = [];
    const storage: Stored = new Map();
    const Adapter = instrumentedAdapter(operations, storage);
    const interaction = new Adapter('Interaction');
    await interaction.upsert('future-id', { futureExtension: { nested: true }, kind: 'Interaction' }, 60);
    expect(await interaction.find('future-id')).toMatchObject({ futureExtension: { nested: true }, kind: 'Interaction' });
    expect(() => new Adapter('RefreshToken')).toThrow('persistence forbidden for RefreshToken');
  });

  it('creates a distinct fresh Grant on a second authorization with the same provider cookie', async () => {
    const operations: Operation[] = [];
    const storage: Stored = new Map();
    const instance = await provider(operations, storage);
    const first = await completeAuthorization(instance, 'one');
    expect((await exchangeCode(instance, first.code, first.verifier)).status).toBe(200);
    const firstCodePayload = operations.filter((operation) => operation.model === 'AuthorizationCode' && operation.method === 'upsert').at(-1)?.payload;
    const firstGrantId = String(firstCodePayload?.grantId);
    const secondStart = operations.length;
    const second = await completeAuthorization(instance, 'two', first.cookies);
    expect((await exchangeCode(instance, second.code, second.verifier)).status).toBe(200);
    expect(second.code).not.toBe(first.code);
    const grantIds = [...storage.keys()].filter((key) => key.startsWith('Grant:')).map((key) => key.slice('Grant:'.length));
    expect(new Set(grantIds).size).toBe(2);
    const secondOperations = operations.slice(secondStart);
    const secondCodePayload = secondOperations.filter((operation) => operation.model === 'AuthorizationCode' && operation.method === 'upsert').at(-1)?.payload;
    expect(secondCodePayload?.grantId).toBeTypeOf('string');
    expect(secondCodePayload?.grantId).not.toBe(firstGrantId);
    expect(secondOperations.filter((operation) => operation.model === 'Grant' && operation.method === 'find').map((operation) => operation.id)).not.toContain(firstGrantId);
  });

  it('proves interactionResult stays buffered while interactionFinished ends the response', async () => {
    const instance = await provider();
    const normal = await beginAuthorization(instance, 'buffered');
    const normalResponse = await request(instance, normal.interaction, 'POST', { cookie: normal.cookies });
    expect(normalResponse.status).toBe(303);
    const ended = await beginAuthorization(instance, 'ended');
    const endedResponse = await request(instance, ended.interaction, 'POST', { cookie: ended.cookies, 'x-harness-interaction-finished': '1' });
    expect(endedResponse.status).toBe(303);
    expect(endedResponse.body).toBe('');
  });

  it('rejects missing state, nonce, exact-scope, PKCE, response-mode, redirect, and unknown clients through provider errors', async () => {
    const operations: Operation[] = [];
    const instance = await provider(operations);
    const base = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: CALLBACK, response_type: 'code', scope: 'openid dsa_signal_entitlement', state: 's', nonce: 'n', code_challenge: 'A'.repeat(43), code_challenge_method: 'S256' });
    const explicitQuery = new URLSearchParams(base); explicitQuery.set('response_mode', 'query');
    expect((await request(instance, `/oidc/auth?${explicitQuery}`)).status).toBe(303);
    const cases: ((parameters: URLSearchParams) => void)[] = [
      (parameters) => parameters.delete('state'),
      (parameters) => parameters.delete('nonce'),
      (parameters) => parameters.set('scope', 'openid'),
      (parameters) => parameters.delete('code_challenge'),
      (parameters) => parameters.set('code_challenge_method', 'plain'),
      (parameters) => parameters.set('response_mode', 'form_post'),
      (parameters) => parameters.set('redirect_uri', 'https://attacker.example/callback'),
      (parameters) => parameters.set('client_id', 'unknown'),
    ];
    for (const mutate of cases) {
      const parameters = new URLSearchParams(base); mutate(parameters);
      const interactionsBefore = operations.filter((operation) => operation.model === 'Interaction' && operation.method === 'upsert').length;
      const response = await request(instance, `/oidc/auth?${parameters}`);
      expect([303, 400]).toContain(response.status);
      expect(`${response.body}${headerString(response.headers.location)}`).toContain('error');
      expect(`${response.body}${headerString(response.headers.location)}`).not.toContain('server_error');
      expect(operations.filter((operation) => operation.model === 'Interaction' && operation.method === 'upsert').length).toBe(interactionsBefore);
    }
    const unknownToken = await request(instance, '/oidc/token', 'POST', { authorization: `Basic ${Buffer.from('unknown:secret').toString('base64')}`, 'content-type': 'application/x-www-form-urlencoded' }, 'grant_type=authorization_code&code=x');
    expect(unknownToken.status).toBe(401);
    expect(unknownToken.body).toContain('invalid_client');
    expect(unknownToken.body).not.toContain('server_error');
    expect(operations.some((operation) => operation.model === 'Client' && operation.method === 'find')).toBe(true);
    expect(operations.some((operation) => operation.model === 'Client' && operation.method === 'upsert')).toBe(false);
  });

  it('keeps concurrent provider requests isolated in application-owned ALS', async () => {
    const operations: Operation[] = [];
    const instance = await provider(operations);
    await Promise.all([beginAuthorization(instance, 'concurrent-a'), beginAuthorization(instance, 'concurrent-b')]);
    const transactionIds = new Set(operations.filter((operation) => operation.model === 'Interaction' && operation.method === 'upsert').map((operation) => operation.transactionId));
    expect(transactionIds.size).toBe(2);
    expect(transactionIds.has(undefined)).toBe(false);
  });

  it('proves provider output buffering and token consume/savepoint disposition seams', async () => {
    completedTransactions.splice(0);
    const instance = await provider();

    const successful = await completeAuthorization(instance, 'transaction-success');
    expect((await exchangeCode(instance, successful.code, successful.verifier)).status).toBe(200);
    expect(completedTransactions.at(-1)?.phases).toEqual(['begin', 'consume', 'savepoint', 'access-token-upsert', 'provider-response-buffered', 'commit', 'flush']);

    expect((await exchangeCode(instance, successful.code, successful.verifier)).status).toBe(400);
    expect(completedTransactions.at(-1)?.phases).toEqual(['begin', 'revoke-by-grant', 'revoke-by-grant', 'provider-response-buffered', 'commit-revocation', 'flush']);

    expect((await exchangeCode(instance, 'missing-code', successful.verifier)).status).toBe(400);
    expect(completedTransactions.at(-1)?.phases).toEqual(['begin', 'provider-response-buffered', 'rollback', 'flush']);

    const failedAfterConsume = await completeAuthorization(instance, 'transaction-failure');
    expect((await exchangeCode(instance, failedAfterConsume.code, failedAfterConsume.verifier, { 'x-harness-fail-after-consume': '1' })).status).toBe(500);
    expect(completedTransactions.at(-1)?.phases).toEqual(['begin', 'consume', 'savepoint', 'provider-response-buffered', 'rollback-to-savepoint', 'commit-consumption-only', 'flush']);

    const commitFailure = await completeAuthorization(instance, 'commit-failure');
    const discarded = await exchangeCode(instance, commitFailure.code, commitFailure.verifier, { 'x-harness-commit-fail': '1' });
    expect(discarded).toMatchObject({ status: 503, body: '{"error":"commit_failed"}' });
    expect(completedTransactions.at(-1)?.phases).toContain('provider-output-discarded');
    expect(completedTransactions.at(-1)?.phases.at(-1)).toBe('flush');
  });
});
