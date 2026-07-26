import { describe, expect, it } from 'vitest';
import { createServer, request as httpRequest } from 'node:http';
import { EventEmitter } from 'node:events';
import { makeSessionCookie } from '../identity/session-cookie.js';
import { createInteractionHandler } from './interaction.js';
import { OidcIndeterminateCommitError } from './request-context.js';

const clientId = 'mas-client';
const redirectUri = 'https://mas.example/upstream/callback/01J00000000000000000000000';
const id = 'A'.repeat(43);
const csrf = 'A'.repeat(43);
const key = Buffer.alloc(32, 1);

function responseFixture(): { headersSent: boolean; writableEnded: boolean; destroyed: boolean; statusCode: number; headers: Record<string, string | string[]>; getHeaderNames(): string[]; setHeader(name: string, value: string | string[]): void; removeHeader(name: string): void; writeHead(status: number, values: Record<string, string | string[]>): unknown; end(body?: string): unknown; destroy(): void } {
  const response = {
    headersSent: false, writableEnded: false, destroyed: false, statusCode: 0, headers: {} as Record<string, string | string[]>,
    getHeaderNames() { return Object.keys(response.headers); },
    setHeader(name: string, value: string | string[]) { response.headers[name] = value; },
    removeHeader(name: string) { delete response.headers[name]; },
    writeHead(status: number, values: Record<string, string | string[]>) { response.statusCode = status; Object.assign(response.headers, values); return response; },
    end() { response.writableEnded = true; return response; },
    destroy() { response.destroyed = true; },
  };
  return response;
}

function postRequest(): unknown {
  const request = Object.assign(new EventEmitter(), {
    method: 'POST', url: '/oidc/interaction', rawHeaders: ['Origin', 'https://app.example', 'Content-Type', 'application/x-www-form-urlencoded', 'Content-Length', '48', 'Cookie', makeSessionCookie(id, key)],
    headers: { origin: 'https://app.example', 'content-type': 'application/x-www-form-urlencoded', 'content-length': '48', cookie: makeSessionCookie(id, key) },
    body: Buffer.from(`csrf=${csrf}`), resume() { return request; },
  });
  queueMicrotask(() => { request.emit('data', request.body); request.emit('end'); });
  return request;
}

function poolFixture(query: (sql: string, values?: unknown[]) => Promise<{ rowCount?: number; rows?: unknown[] }>): unknown {
  return { connect: async () => ({ query, release: () => undefined }) };
}

function options(provider: Record<string, unknown>, pool: unknown) {
  return { pool, provider, epoch: 'C'.repeat(22), clientId, redirectUri, origin: 'https://app.example', cookieKey: key, indexKeys: { active: 'one', keys: { one: key } }, bindingKeys: { active: 'one', keys: { one: key } } };
}

function deferred<T = void>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  return { promise: new Promise<T>((done) => { resolve = done; }), resolve };
}

function liveDecisionRow() {
  return {
    mapping_id: '00000000-0000-4000-8000-000000000001', entitlement_id: '00000000-0000-4000-8000-000000000002', generation: '1',
    jkt: 'jkt', policy_snapshot_id: '00000000-0000-4000-8000-000000000003', policy_version: 'v1', subject: 'subject',
    expires_at: new Date(Date.now() + 60_000), idle_expires_at: new Date(Date.now() + 60_000), absolute_expires_at: new Date(Date.now() + 60_000),
  };
}

function successfulPostProvider(events: string[]) {
  return {
    interactionDetails: async () => ({ jti: id, cid: id, params: { client_id: clientId, redirect_uri: redirectUri } }),
    interactionResult: async (_request: unknown, response: { setHeader(name: string, value: string): void }) => {
      events.push('interaction-result'); response.setHeader('set-cookie', 'provider=value'); response.setHeader('x-provider-staged', 'yes'); return '/oidc/auth/resume';
    },
    Grant: class {
      addOIDCScope() { return undefined; }
      async save() { events.push('grant-save'); return '00000000-0000-4000-8000-000000000004'; }
    },
  };
}

describe('OIDC interaction transport', () => {
  it('rejects a high-bit form alias before provider or database work', async () => {
    let providerCalls = 0; let connections = 0;
    const request = postRequest() as { body: Buffer; };
    request.body = Buffer.concat([Buffer.from(`csrf=${csrf.slice(0, 42)}`), Buffer.from([0x80])]);
    const response = responseFixture();
    const handler = createInteractionHandler(options({ interactionDetails: async () => { providerCalls += 1; return {}; } }, { connect: async () => { connections += 1; throw new Error('must not connect'); } }) as never);

    await handler(request as never, response as never);

    expect(response.statusCode).toBe(400);
    expect(providerCalls).toBe(0);
    expect(connections).toBe(0);
  });

  it('returns observable 400 for a real HTTP high-bit form before provider or database work', async () => {
    let providerCalls = 0; let connections = 0;
    const handler = createInteractionHandler(options({ interactionDetails: async () => { providerCalls += 1; return {}; } }, { connect: async () => { connections += 1; throw new Error('must not connect'); } }) as never);
    const server = createServer((request, response) => { void handler(request, response); });
    try {
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address(); if (!address || typeof address === 'string') throw new Error('server did not bind');
      const response = await new Promise<{ status: number; body: string }>((resolve, fail) => {
        const request = httpRequest({ host: '127.0.0.1', port: address.port, path: '/oidc/interaction', method: 'POST', headers: { origin: 'https://app.example', 'content-type': 'application/x-www-form-urlencoded', cookie: makeSessionCookie(id, key), 'transfer-encoding': 'chunked' } }, (incoming) => {
          let body = ''; incoming.setEncoding('utf8'); incoming.on('data', (chunk: string) => { body += chunk; }); incoming.on('end', () => resolve({ status: incoming.statusCode ?? 0, body }));
        });
        request.on('error', fail); request.end(Buffer.concat([Buffer.from(`csrf=${csrf.slice(0, 42)}`), Buffer.from([0x80])]));
      });
      expect(response).toEqual({ status: 400, body: '<!doctype html><title>Request rejected</title>' });
      expect(providerCalls).toBe(0); expect(connections).toBe(0);
    } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
  });

  it('clears the control cookie when duplicate Cookie headers are rejected', async () => {
    const headers: Record<string, string | string[]> = {};
    const response = {
      headersSent: false, writableEnded: false,
      getHeaderNames: () => Object.keys(headers),
      removeHeader: (name: string) => { delete headers[name]; },
      writeHead: (status: number, values: Record<string, string | string[]>) => { response.statusCode = status; Object.assign(headers, values); return response; },
      end: () => { response.writableEnded = true; return response; },
      statusCode: 0,
    };
    const handler = createInteractionHandler({} as never);
    await handler({ method: 'POST', url: '/oidc/interaction', rawHeaders: ['Cookie', 'a=1', 'Cookie', 'b=2'], headers: {} } as never, response as never);
    expect(response.statusCode).toBe(400);
    expect(headers['set-cookie']).toBe('__Host-dsa_signal_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
  });
});

describe('OIDC interaction fail-closed validation', () => {
  it('does not commit staged provider output when authorization-context insertion fails after Grant.save', async () => {
    const events: string[] = [];
    const provider = successfulPostProvider(events);
    let clockReads = 0;
    const pool = poolFixture(async (sql) => {
      if (sql === 'ROLLBACK') { events.push('rollback'); return { rows: [] }; }
      if (sql.includes('clock_timestamp')) { events.push(['initial-clock', 'authoritative-clock'][clockReads++]!); return { rows: [{ decision_now: new Date() }] }; }
      if (sql.includes('FROM oidc.interaction_csrf') && sql.includes('csrf_key_id')) { events.push('csrf-match'); return { rowCount: 1, rows: [{ id: 'csrf-row' }] }; }
      if (sql.includes('FROM control_plane.identity_sessions') && sql.includes('binding_key_id,binding_fingerprint')) { events.push('control-session'); return { rowCount: 1, rows: [{ binding_key_id: 'one', binding_fingerprint: Buffer.alloc(32, 2) }] }; }
      if (sql.startsWith('SELECT control_plane.membership_access_source_set_fence')) { events.push('source-set'); return { rows: [] }; }
      if (sql.startsWith('SELECT DISTINCT mapping_id')) { events.push(events.includes('authoritative-clock') ? 'candidate-after' : 'candidate-before'); return { rowCount: 1, rows: [{ mapping_id: liveDecisionRow().mapping_id }] }; }
      if (sql.includes("dsa-signal-membership-access:v1:")) { events.push('mapping-advisory'); return { rows: [] }; }
      if (sql.includes('membership_access_states WHERE mapping_id=$1')) { events.push('mapping-state'); return { rowCount: 1, rows: [{ barrier_state: 'active' }] }; }
      if (sql.includes("pg_advisory_xact_lock(('x'")) { events.push('canonical-session-advisory'); return { rows: [] }; }
      if (sql.includes('identity_sessions WHERE binding_key_id') && sql.includes('FOR UPDATE')) { events.push('identity-session-lock'); return { rows: [] }; }
      if (sql.includes('FROM control_plane.entitlements')) { events.push('entitlement-lock'); return { rows: [] }; }
      if (sql.includes('FROM control_plane.active_policy') && sql.includes('FOR UPDATE')) { events.push('policy-lock'); return { rows: [] }; }
      if (sql.startsWith('SELECT 1 FROM control_plane.active_policy')) { events.push('policy-floor'); return { rowCount: 1, rows: [] }; }
      if (sql.includes('SELECT s.mapping_id')) { events.push('live-decision'); return { rowCount: 1, rows: [liveDecisionRow()] }; }
      if (sql.includes('INSERT INTO oidc.authorization_contexts')) throw new Error('context insert failed');
      return { rowCount: 1, rows: [] };
    });
    const response = responseFixture();

    await createInteractionHandler(options(provider, pool) as never)(postRequest() as never, response as never);

    expect(events).toEqual(['initial-clock', 'csrf-match', 'control-session', 'source-set', 'candidate-before', 'mapping-advisory', 'mapping-state', 'canonical-session-advisory', 'identity-session-lock', 'entitlement-lock', 'policy-lock', 'authoritative-clock', 'candidate-after', 'policy-floor', 'live-decision', 'grant-save', 'rollback']);
    expect(response.statusCode).toBe(400);
    expect(response.headers).toEqual(expect.objectContaining({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }));
    expect(response.headers).not.toHaveProperty('set-cookie');
    expect(response.headers).not.toHaveProperty('x-provider-staged');
  });

  it('holds a real HTTP response behind COMMIT after the full successful POST branch', async () => {
    const events: string[] = [];
    const commitStarted = deferred();
    const allowCommit = deferred();
    const responseReceived = deferred<{ status: number; headers: import('node:http').IncomingHttpHeaders }>();
    const provider = successfulPostProvider(events);
    let clockReads = 0;
    const pool = poolFixture(async (sql) => {
      if (sql === 'BEGIN') { events.push('begin'); return { rows: [] }; }
      if (sql.includes('pg_advisory_xact_lock_shared')) { events.push('fence'); return { rows: [] }; }
      if (sql.includes('clock_timestamp')) { events.push(['initial-clock', 'authoritative-clock', 'consume-clock'][clockReads++]!); return { rows: [{ decision_now: new Date() }] }; }
      if (sql.includes('FROM oidc.interaction_csrf') && sql.includes('csrf_key_id')) { events.push('csrf-match'); return { rowCount: 1, rows: [{ id: 'csrf-row' }] }; }
      if (sql.includes('FROM control_plane.identity_sessions') && sql.includes('binding_key_id,binding_fingerprint')) { events.push('control-session'); return { rowCount: 1, rows: [{ binding_key_id: 'one', binding_fingerprint: Buffer.alloc(32, 2) }] }; }
      if (sql.startsWith('SELECT control_plane.membership_access_source_set_fence')) { events.push('source-set'); return { rows: [] }; }
      if (sql.startsWith('SELECT DISTINCT mapping_id')) { events.push(events.includes('authoritative-clock') ? 'candidate-after' : 'candidate-before'); return { rowCount: 1, rows: [{ mapping_id: liveDecisionRow().mapping_id }] }; }
      if (sql.includes("dsa-signal-membership-access:v1:")) { events.push('mapping-advisory'); return { rows: [] }; }
      if (sql.includes('membership_access_states WHERE mapping_id=$1')) { events.push('mapping-state'); return { rowCount: 1, rows: [{ barrier_state: 'active' }] }; }
      if (sql.includes("pg_advisory_xact_lock(('x'")) { events.push('canonical-session-advisory'); return { rows: [] }; }
      if (sql.includes('identity_sessions WHERE binding_key_id') && sql.includes('FOR UPDATE')) { events.push('identity-session-lock'); return { rows: [] }; }
      if (sql.includes('FROM control_plane.entitlements')) { events.push('entitlement-lock'); return { rows: [] }; }
      if (sql.includes('FROM control_plane.active_policy') && sql.includes('FOR UPDATE')) { events.push('policy-lock'); return { rows: [] }; }
      if (sql.includes('SELECT s.mapping_id')) { events.push('live-decision'); return { rowCount: 1, rows: [liveDecisionRow()] }; }
      if (sql.startsWith('SELECT 1 FROM control_plane.active_policy')) { events.push('policy-floor'); return { rowCount: 1, rows: [] }; }
      if (sql.includes('INSERT INTO oidc.authorization_contexts')) { events.push('context-insert'); return { rowCount: 1, rows: [] }; }
      if (sql.includes('UPDATE oidc.interaction_csrf')) { events.push('csrf-consume'); return { rowCount: 1, rows: [] }; }
      if (sql === 'COMMIT') { events.push('commit'); commitStarted.resolve(); await allowCommit.promise; return { rows: [] }; }
      return { rowCount: 1, rows: [] };
    });
    const server = createServer((request, response) => { void createInteractionHandler(options(provider, pool) as never)(request, response); });
    let client: ReturnType<typeof httpRequest> | undefined;
    try {
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address(); if (!address || typeof address === 'string') throw new Error('server did not bind');
      client = httpRequest({ host: '127.0.0.1', port: address.port, path: '/oidc/interaction', method: 'POST', headers: { origin: 'https://app.example', 'content-type': 'application/x-www-form-urlencoded', 'content-length': '48', cookie: makeSessionCookie(id, key) } });
      let received = false;
      client.on('response', (incoming) => { received = true; responseReceived.resolve({ status: incoming.statusCode ?? 0, headers: incoming.headers }); incoming.resume(); });
      client.end(`csrf=${csrf}`);

      await commitStarted.promise;
      expect(received).toBe(false);
      expect(events).toEqual(['begin', 'fence', 'initial-clock', 'csrf-match', 'control-session', 'source-set', 'candidate-before', 'mapping-advisory', 'mapping-state', 'canonical-session-advisory', 'identity-session-lock', 'entitlement-lock', 'policy-lock', 'authoritative-clock', 'candidate-after', 'policy-floor', 'live-decision', 'grant-save', 'context-insert', 'interaction-result', 'consume-clock', 'csrf-consume', 'commit']);
      allowCommit.resolve();
      const actual = await responseReceived.promise;
      // The response event runs only once Node has committed the staged headers.
      expect(events.at(-1)).toBe('commit');
      expect(actual).toMatchObject({ status: 303, headers: { location: '/oidc/auth/resume', 'x-provider-staged': 'yes', 'set-cookie': ['provider=value'] } });
    } finally {
      allowCommit.resolve();
      client?.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('rolls back staged provider artifacts when CSRF expires before the final consume-time clock refresh', async () => {
    const events: string[] = [];
    const initial = new Date('2026-07-20T12:00:00.000Z');
    const expired = new Date('2026-07-20T12:05:01.000Z');
    let clockReads = 0;
    let consumeTimestamp: unknown;
    const provider = successfulPostProvider(events);
    const pool = poolFixture(async (sql, values) => {
      if (sql === 'ROLLBACK') { events.push('rollback'); return { rows: [] }; }
      if (sql.includes('clock_timestamp')) {
        events.push(['initial-clock', 'authoritative-clock', 'consume-clock'][clockReads++]!);
        return { rows: [{ decision_now: clockReads === 3 ? expired : initial }] };
      }
      if (sql.includes('FROM oidc.interaction_csrf') && sql.includes('csrf_key_id')) { events.push('csrf-match'); return { rowCount: 1, rows: [{ id: 'csrf-row' }] }; }
      if (sql.includes('FROM control_plane.identity_sessions') && sql.includes('binding_key_id,binding_fingerprint')) { events.push('control-session'); return { rowCount: 1, rows: [{ binding_key_id: 'one', binding_fingerprint: Buffer.alloc(32, 2) }] }; }
      if (sql.startsWith('SELECT control_plane.membership_access_source_set_fence')) { events.push('source-set'); return { rows: [] }; }
      if (sql.startsWith('SELECT DISTINCT mapping_id')) { events.push(events.includes('authoritative-clock') ? 'candidate-after' : 'candidate-before'); return { rowCount: 1, rows: [{ mapping_id: liveDecisionRow().mapping_id }] }; }
      if (sql.includes("dsa-signal-membership-access:v1:")) { events.push('mapping-advisory'); return { rows: [] }; }
      if (sql.includes('membership_access_states WHERE mapping_id=$1')) { events.push('mapping-state'); return { rowCount: 1, rows: [{ barrier_state: 'active' }] }; }
      if (sql.includes("pg_advisory_xact_lock(('x'")) { events.push('canonical-session-advisory'); return { rows: [] }; }
      if (sql.includes('identity_sessions WHERE binding_key_id') && sql.includes('FOR UPDATE')) { events.push('identity-session-lock'); return { rows: [] }; }
      if (sql.includes('FROM control_plane.entitlements')) { events.push('entitlement-lock'); return { rows: [] }; }
      if (sql.includes('FROM control_plane.active_policy') && sql.includes('FOR UPDATE')) { events.push('policy-lock'); return { rows: [] }; }
      if (sql.startsWith('SELECT 1 FROM control_plane.active_policy')) { events.push('policy-floor'); return { rowCount: 1, rows: [] }; }
      if (sql.includes('SELECT s.mapping_id')) { events.push('live-decision'); return { rowCount: 1, rows: [liveDecisionRow()] }; }
      if (sql.includes('INSERT INTO oidc.authorization_contexts')) { events.push('context-insert'); return { rowCount: 1, rows: [] }; }
      if (sql.includes('UPDATE oidc.interaction_csrf')) { events.push('csrf-consume'); consumeTimestamp = values?.[0]; return { rowCount: 0, rows: [] }; }
      return { rowCount: 1, rows: [] };
    });
    const response = responseFixture();

    await createInteractionHandler(options(provider, pool) as never)(postRequest() as never, response as never);

    expect(events).toEqual(['initial-clock', 'csrf-match', 'control-session', 'source-set', 'candidate-before', 'mapping-advisory', 'mapping-state', 'canonical-session-advisory', 'identity-session-lock', 'entitlement-lock', 'policy-lock', 'authoritative-clock', 'candidate-after', 'policy-floor', 'live-decision', 'grant-save', 'context-insert', 'interaction-result', 'consume-clock', 'csrf-consume', 'rollback']);
    expect(consumeTimestamp).toEqual(expired);
    expect(response.statusCode).toBe(400);
    expect(response.headers).toEqual(expect.objectContaining({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }));
    expect(response.headers).not.toHaveProperty('location');
    expect(response.headers).not.toHaveProperty('set-cookie');
    expect(response.headers).not.toHaveProperty('x-provider-staged');
    expect(events).not.toContain('commit');
  });

  it.each([undefined, 'https://attacker.example/callback'])('rejects a %s redirect before access-denied state is created', async (receivedRedirect) => {
    let interactionResult = 0; let grants = 0; const queries: string[] = [];
    const provider = {
      interactionDetails: async () => ({ jti: id, cid: id, params: { client_id: clientId, ...(receivedRedirect === undefined ? {} : { redirect_uri: receivedRedirect }) } }),
      interactionResult: async () => { interactionResult += 1; return '/unexpected'; },
      Grant: class { constructor() { grants += 1; } },
    };
    const pool = poolFixture(async (sql) => {
      queries.push(sql);
      if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date() }] };
      return { rows: [] };
    });
    const response = responseFixture();

    await createInteractionHandler(options(provider, pool) as never)(postRequest() as never, response as never);

    expect(response.statusCode).toBe(400);
    expect(interactionResult).toBe(0);
    expect(grants).toBe(0);
    expect(queries.some((sql) => sql.includes('interaction_csrf') || sql.includes('identity_sessions'))).toBe(false);
  });

  it('destroys the response without emitting output when the POST commit is indeterminate', async () => {
    let interactionResult = 0; let caught: unknown;
    const observerError = new Error('observer failed');
    const provider = {
      interactionDetails: async () => ({ jti: id, cid: id, params: { client_id: clientId, redirect_uri: redirectUri } }),
      interactionResult: async (_request: unknown, response: { setHeader(name: string, value: string): void }) => { interactionResult += 1; response.setHeader('x-provider-staged', 'yes'); return '/oidc/auth/resume'; },
      Grant: class {},
    };
    const pool = poolFixture(async (sql) => {
      if (sql === 'COMMIT') throw Object.assign(new Error('connection lost'), { code: 'ECONNRESET' });
      if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date() }] };
      if (sql.includes('FROM oidc.interaction_csrf')) return { rowCount: 1, rows: [{ id: 'csrf-row' }] };
      if (sql.includes('UPDATE oidc.interaction_csrf')) return { rowCount: 1, rows: [] };
      if (sql.includes('FROM control_plane.identity_sessions')) return { rowCount: 0, rows: [] };
      return { rowCount: 0, rows: [] };
    });
    const response = responseFixture();

    await expect(createInteractionHandler({
      ...options(provider, pool),
      onError: (error: unknown) => { caught = error; throw observerError; },
    } as never)(postRequest() as never, response as never)).rejects.toThrow(observerError);

    expect(caught).toBeInstanceOf(OidcIndeterminateCommitError);
    expect(interactionResult).toBe(1);
    expect(response.destroyed).toBe(true);
    expect(response.statusCode).toBe(0);
    expect(response.headers).toEqual({ 'x-provider-staged': 'yes' });
    expect(response.writableEnded).toBe(false);
  });

  it('discards staged provider headers on a definite POST commit failure', async () => {
    let interactionResult = 0;
    const provider = {
      interactionDetails: async () => ({ jti: id, cid: id, params: { client_id: clientId, redirect_uri: redirectUri } }),
      interactionResult: async (_request: unknown, response: { setHeader(name: string, value: string): void }) => {
        interactionResult += 1;
        response.setHeader('x-provider-staged', 'yes');
        response.setHeader('set-cookie', 'provider=value');
        return '/oidc/auth/resume';
      },
      Grant: class {},
    };
    const pool = poolFixture(async (sql) => {
      if (sql === 'COMMIT') throw Object.assign(new Error('constraint'), { code: '23505' });
      if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date() }] };
      if (sql.includes('FROM oidc.interaction_csrf')) return { rowCount: 1, rows: [{ id: 'csrf-row' }] };
      if (sql.includes('UPDATE oidc.interaction_csrf')) return { rowCount: 1, rows: [] };
      if (sql.includes('FROM control_plane.identity_sessions')) return { rowCount: 0, rows: [] };
      return { rowCount: 0, rows: [] };
    });
    const response = responseFixture();
    await createInteractionHandler(options(provider, pool) as never)(postRequest() as never, response as never);
    expect(interactionResult).toBe(1);
    expect(response.headersSent).toBe(false);
    expect(response.statusCode).toBe(400);
    expect(response.headers).toEqual(expect.objectContaining({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }));
    expect(response.headers).not.toHaveProperty('x-provider-staged');
    expect(response.headers).not.toHaveProperty('set-cookie');
  });

  it('destroys the response without emitting output when the GET commit is indeterminate', async () => {
    let caught: unknown;
    const provider = {
      interactionDetails: async () => ({ jti: id, cid: id, params: { client_id: clientId, redirect_uri: redirectUri } }),
    };
    const pool = poolFixture(async (sql) => {
      if (sql === 'COMMIT') throw Object.assign(new Error('connection lost'), { code: 'ECONNRESET' });
      if (sql.includes('clock_timestamp')) return { rows: [{ decision_now: new Date() }] };
      if (sql.includes('FROM oidc.interaction_csrf')) return { rowCount: 0, rows: [] };
      if (sql.includes('INSERT INTO oidc.interaction_csrf')) return { rowCount: 1, rows: [] };
      return { rowCount: 0, rows: [] };
    });
    const response = responseFixture();

    await createInteractionHandler({ ...options(provider, pool), onError: (error: unknown) => { caught = error; } } as never)(
      { method: 'GET', url: '/oidc/interaction', rawHeaders: [], headers: {} } as never,
      response as never,
    );

    expect(caught).toBeInstanceOf(OidcIndeterminateCommitError);
    expect(response.destroyed).toBe(true);
    expect(response.statusCode).toBe(0);
    expect(response.headers).toEqual({});
    expect(response.writableEnded).toBe(false);
  });
});
