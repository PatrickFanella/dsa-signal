import { describe, expect, it, vi } from 'vitest';
import { CompactSign, exportJWK, generateKeyPair } from 'jose';
import { createCipheriv, randomBytes, webcrypto } from 'node:crypto';
import { InvalidVerificationRequest, VerificationUnavailableError, createVerificationService, inspectCredential, jwkThumbprint, parsePublicJwk } from './verify-entitlement.js';

const decisionNow = new Date('2026-01-01T00:00:00Z');
const issuerDid = 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
const subjectDid = 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb';
const origin = 'https://chat.example';
const signature64 = Buffer.alloc(64).toString('base64url');
const longDid = (bytes: number) => `did:web:a:${'a'.repeat(bytes - 10)}`;
const baseClaims = (iss = issuerDid, sub = subjectDid) => ({ iss, sub, aud: 'dsa-signal', iat: 1, exp: 2, jti: 'A'.repeat(43), cnf: { jkt: 'A'.repeat(43) }, entitlement: 'chat', policyVersion: 'v1' });
const compact = (header: string, payload: string, signature = signature64) => `${Buffer.from(header).toString('base64url')}.${Buffer.from(payload).toString('base64url')}.${signature}`;
const credentialJson = (claims = baseClaims(), header = { alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: `${claims.iss}#key` }) => compact(JSON.stringify(header), JSON.stringify(claims));
/** Produce an exact decoded JSON size by varying a permitted did:web path value. */
function payloadAt(bytes: number, iss = issuerDid): string {
  const minimum = JSON.stringify(baseClaims(iss, longDid(11)));
  return JSON.stringify(baseClaims(iss, longDid(11 + bytes - Buffer.byteLength(minimum))));
}
function headerAt(bytes: number): { header: string; iss: string } {
  for (let length = 11; length <= 2048; length++) {
    const iss = longDid(length); const header = JSON.stringify({ alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: `${iss}#k` });
    if (Buffer.byteLength(header) === bytes) return { header, iss };
  }
  throw new Error(`no valid header at ${bytes}`);
}

async function validAuthorizationFixture(jtiConflict = false, corruptMapping = false) {
  const [issuer, holder] = await Promise.all([generateKeyPair('ES256'), generateKeyPair('ES256')]);
  const issuerPublic = await exportJWK(issuer.publicKey);
  const holderPublic = await exportJWK(holder.publicKey);
  const publicJwk = parsePublicJwk(holderPublic);
  const jkt = jwkThumbprint(publicJwk);
  const challenge = randomBytes(32).toString('base64url');
  const jti = randomBytes(32).toString('base64url');
  const claims = { iss: issuerDid, sub: subjectDid, aud: 'dsa-signal', iat: 1_767_225_570, exp: 1_767_226_170, jti, cnf: { jkt }, entitlement: 'chat', policyVersion: 'v1' };
  const credential = await new CompactSign(Buffer.from(JSON.stringify(claims))).setProtectedHeader({ alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: `${issuerDid}#key` }).sign(issuer.privateKey);
  const message = `dsa-signal-proof:v1\n${challenge}\n${origin}\ndsa-signal\n${subjectDid}\n${jkt}\n${jti}`;
  const signature = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holder.privateKey, Buffer.from(message))).toString('base64url');
  const envelopeKey = randomBytes(32); const nonce = randomBytes(12); const aad = Buffer.from('dsa-signal-did-mapping:v1\0mapping\0chat-sector');
  const cipher = createCipheriv('aes-256-gcm', envelopeKey, nonce); cipher.setAAD(aad); const ciphertext = Buffer.concat([cipher.update(subjectDid), cipher.final(), cipher.getAuthTag()]); if (corruptMapping) ciphertext[ciphertext.length - 1] ^= 1;
  const ring = { active: 'v1', keys: { v1: randomBytes(32) } };
  const queries: string[] = [];
  const client = { release: vi.fn(), query: vi.fn(async (sql: string) => {
    queries.push(sql);
    if (sql.includes('decision_now')) return { rows: [{ decision_now: decisionNow }] };
    if (sql.includes('SELECT mapping_id,binding_key_id')) return { rows: [{ mapping_id: 'mapping', binding_key_id: 'v1', binding_fingerprint: Buffer.alloc(32) }] };
    if (sql.includes('idempotency_key_aliases a JOIN')) return { rows: [] };
    if (sql.includes('FROM control_plane.did_mappings')) return { rows: [{ id: 'mapping', envelope_key_id: 'envelope', nonce, ciphertext }] };
    if (sql.includes('FROM control_plane.proof_challenges')) return { rows: [{ id: 'challenge' }] };
    if (sql.includes('SELECT digest FROM control_plane.policy_snapshots')) return { rows: [{ digest: Buffer.alloc(32, 7) }] };
    if (jtiConflict && sql.includes('INSERT INTO control_plane.jti_key_aliases')) throw Object.assign(new Error('duplicate JTI'), { code: '23505' });
    if (sql.includes('INSERT INTO control_plane.entitlements')) return { rows: [{ id: 'entitlement' }], rowCount: 1 };
    return { rows: [], rowCount: sql.includes('UPDATE control_plane.identity_sessions') || sql.includes('INSERT INTO control_plane.entitlements') ? 1 : 0 };
  }) };
  const policy = { version: 'v1', policyVersion: 'v1', policyUri: `at://${issuerDid}/us.dsaslate.temp.dsaPolicy/rkey`, rootDid: issuerDid, issuedAt: 1_767_225_000, freshUntil: 1_767_230_000, issuers: [{ did: issuerDid, policies: [{ version: 'v1', state: 'active', transitionedAt: 1 }], keys: [{ kid: `${issuerDid}#key`, state: 'active', transitionedAt: 1, publicJwk: parsePublicJwk(issuerPublic) }] }] } as const;
  const service = createVerificationService({ pool: { connect: async () => client as never }, envelopeKeys: { active: 'envelope', keys: { envelope: envelopeKey } }, challengeKeys: ring, bindingKeys: ring, jtiKeys: ring, idempotencyKeys: ring, requestKeys: ring, revocationEvidenceKeys: ring, oidcEpoch: 'AAAAAAAAAAAAAAAAAAAAAA', pwaOrigin: origin, sector: 'chat-sector', policyRefresh: { loadActive: async () => ({ snapshotId: 'snapshot', policy }) } as never });
  return { service, queries, input: { version: 'v1', idempotencyKey: randomBytes(32).toString('base64url'), challenge, signature, publicJwk, credential } };
}

describe('credential inspection', () => {
  it('computes the contract JKT', () => {
    expect(jwkThumbprint(parsePublicJwk({ kty: 'EC', crv: 'P-256', x: 'axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY', y: 'T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU' }))).toBe('xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M');
  });

  it('rejects noncanonical compact segments before crypto', () => {
    expect(() => inspectCredential('e30=.e30.A'.repeat(1))).toThrow('invalid credential');
  });

  it('enforces compact, decoded header, and decoded payload inclusive boundaries', () => {
    const header1024 = headerAt(1024);
    const largestWithHeader = JSON.stringify(baseClaims(header1024.iss, longDid(2048)));
    expect(() => inspectCredential(compact(header1024.header, largestWithHeader))).not.toThrow();

    const header1025 = headerAt(1025);
    expect(() => inspectCredential(compact(header1025.header, JSON.stringify(baseClaims(header1025.iss))))).toThrow('invalid credential');
    // A 4096-byte payload needs an issuer DID too large to coexist with the
    // 1024-byte header (the header repeats it in kid), so only rejection is realizable.
    const payload4096 = payloadAt(4096);
    expect(Buffer.byteLength(payload4096)).toBe(4096);
    expect(() => inspectCredential(compact(JSON.stringify({ alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: `${issuerDid}#key` }), payload4096))).toThrow('invalid credential');
    expect(() => inspectCredential(credentialJson(baseClaims(), JSON.parse(payloadAt(4097))))).toThrow('invalid credential');

    // The inner decoded caps (and the repeated issuer DID) make an 8192-byte
    // valid compact token unrealizable; this is the largest compatible member.
    expect(Buffer.byteLength(compact(header1024.header, largestWithHeader))).toBeLessThan(8192);
    expect(() => inspectCredential('A'.repeat(8193))).toThrow('invalid credential');
    expect(() => inspectCredential('A'.repeat(8192))).toThrow('invalid credential');
  });

  it('documents the realizable kid boundary under the stricter decoded-header cap', () => {
    // A 2113-byte kid necessarily makes this strict JSON header exceed 1024 bytes.
    // The largest valid member is therefore the kid carried by a 1024-byte header.
    const maximum = headerAt(1024); const kid = JSON.parse(maximum.header).kid as string;
    expect(Buffer.byteLength(kid)).toBeLessThan(2113);
    expect(() => inspectCredential(compact(maximum.header, JSON.stringify(baseClaims(maximum.iss))))).not.toThrow();
    const iss = longDid(2048);
    expect(Buffer.byteLength(`${iss}#${'k'.repeat(64)}`)).toBe(2113);
    expect(() => inspectCredential(credentialJson(baseClaims(iss), { alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: `${iss}#${'k'.repeat(64)}` }))).toThrow('invalid credential');
    expect(() => inspectCredential(credentialJson(baseClaims(iss), { alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: `${iss}#${'k'.repeat(65)}` }))).toThrow('invalid credential');
  });

  it('rejects non-profile JOSE and duplicate protected-header members without diagnostics', () => {
    const claims = JSON.stringify(baseClaims()); const secret = 'credential-secret';
    const headers = [
      `{"alg":"ES256","typ":"dsa-signal-membership+jwt","kid":"${issuerDid}#key","jku":"x"}`,
      `{"alg":"ES384","typ":"dsa-signal-membership+jwt","kid":"${issuerDid}#key"}`,
      `{"alg":"ES256","typ":"JWT","kid":"${issuerDid}#key"}`,
      `{"alg":"ES256","typ":"dsa-signal-membership+jwt","kid":"${issuerDid}#key","crit":[]}`,
      `{"alg":"ES256","typ":"dsa-signal-membership+jwt","kid":"${issuerDid}#key","b64":false}`,
      `{"alg":"ES256","typ":"dsa-signal-membership+jwt","kid":"${issuerDid}#key","alg":"ES256"}`,
      `{"alg":"ES256","typ":"dsa-signal-membership+jwt","kid":"${issuerDid}#key","\\u0061lg":"ES256"}`,
    ];
    for (const header of headers) { try { inspectCredential(compact(header, claims)); throw new Error('accepted'); } catch (error) { expect(String(error)).toBe('Error: invalid credential'); expect(String(error)).not.toContain(secret); } }
  });

  it('rejects strict payload and cnf members, duplicates, and all signature segment violations', () => {
    const header = JSON.stringify({ alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: `${issuerDid}#key` });
    const payloads = [
      JSON.stringify({ ...baseClaims(), extra: true }), JSON.stringify({ ...baseClaims(), cnf: { jkt: 'A'.repeat(43), extra: true } }),
      JSON.stringify(baseClaims()).replace('"aud":"dsa-signal"', '"aud":"dsa-signal","aud":"dsa-signal"'),
      JSON.stringify(baseClaims()).replace('"aud":"dsa-signal"', '"aud":"dsa-signal","\\u0061ud":"dsa-signal"'),
      JSON.stringify(baseClaims()).replace('"jkt":"', '"jkt":"A","\\u006akt":"'),
    ];
    for (const payload of payloads) {
      try { inspectCredential(compact(header, payload)); throw new Error('accepted'); } catch (error) {
        expect(String(error)).toBe('Error: invalid credential');
        expect(String(error)).not.toMatch(/ZodError|path|cnf|JOSE/i);
      }
    }
    for (const length of [63, 65]) expect(() => inspectCredential(compact(header, JSON.stringify(baseClaims()), Buffer.alloc(length).toString('base64url')))).toThrow('invalid credential');
    expect(() => inspectCredential(compact(header, JSON.stringify(baseClaims()), signature64))).not.toThrow();
    for (const malformed of ['a.b', 'a.b.c.d', `e30=.${Buffer.from(JSON.stringify(baseClaims())).toString('base64url')}.${signature64}`]) expect(() => inspectCredential(malformed)).toThrow('invalid credential');
  });

  it('rejects noncanonical JWK coordinates', () => {
    expect(() => parsePublicJwk({ kty: 'EC', crv: 'P-256', x: `${'A'.repeat(42)}C`, y: 'A'.repeat(43) })).toThrow(InvalidVerificationRequest);
  });

  it('exposes malformed requests as typed 400-boundary failures without opening a transaction', async () => {
    const ring = { active: 'v1', keys: { v1: new Uint8Array(32) } };
    const service = createVerificationService({ pool: { connect: async () => { throw new Error('not reached'); } }, envelopeKeys: ring, challengeKeys: ring, bindingKeys: ring, jtiKeys: ring, idempotencyKeys: ring, requestKeys: ring, revocationEvidenceKeys: ring, oidcEpoch: 'AAAAAAAAAAAAAAAAAAAAAA', pwaOrigin: 'https://chat.example', sector: 'chat-sector', policyRefresh: {} as never });
    await expect(service.verify('session', 'https://chat.example', new Uint8Array())).rejects.toBeInstanceOf(InvalidVerificationRequest);
  });

  it('coarsens a malformed credential in a schema-valid request to 401 without leaking it', async () => {
    const { service, input } = await validAuthorizationFixture(); const credential = 'credential-secret.not-a-jws';
    const answer = await service.verify('session', origin, Buffer.from(JSON.stringify({ ...input, credential })));
    expect(answer).toEqual({ status: 401, body: { version: 'v1', result: 'rejected', error: 'rejected' } });
    expect(JSON.stringify(answer)).not.toContain(credential);
  });

  it('checks a cached idempotency result before policy or challenge replay work', async () => {
    const queries: string[] = [];
    const key = new Uint8Array(32);
    const client = { release: vi.fn(), query: vi.fn(async (sql: string) => {
      queries.push(sql);
      if (sql.includes('decision_now')) return { rows: [{ decision_now: new Date('2026-01-01T00:00:00Z') }] };
      if (sql.includes('FROM control_plane.identity_sessions')) return { rows: [{ mapping_id: 'mapping', binding_key_id: 'v1', binding_fingerprint: Buffer.alloc(32) }] };
      if (sql.includes('idempotency_key_aliases a JOIN')) return { rows: [{ response_status: 401, request_key_id: 'v1', request_fingerprint: Buffer.alloc(32), binding_key_id: 'v1', binding_fingerprint: Buffer.alloc(32) }] };
      return { rows: [], rowCount: sql.includes('UPDATE control_plane.identity_sessions') ? 1 : 0 };
    }) };
    const ring = { active: 'v1', keys: { v1: key } };
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'dsa-signal-membership+jwt', kid: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#key' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ iss: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa', sub: 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb', aud: 'dsa-signal', iat: 1, exp: 2, jti: 'A'.repeat(43), cnf: { jkt: 'A'.repeat(43) }, entitlement: 'chat', policyVersion: 'v1' })).toString('base64url');
    const input = { version: 'v1', idempotencyKey: 'A'.repeat(43), challenge: 'A'.repeat(43), signature: 'A'.repeat(86), publicJwk: { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'A'.repeat(43) }, credential: `${header}.${payload}.${'A'.repeat(86)}` };
    const policyRefresh = { loadActive: vi.fn() };
    const service = createVerificationService({ pool: { connect: async () => client as never }, envelopeKeys: ring, challengeKeys: ring, bindingKeys: ring, jtiKeys: ring, idempotencyKeys: ring, requestKeys: ring, revocationEvidenceKeys: ring, oidcEpoch: 'AAAAAAAAAAAAAAAAAAAAAA', pwaOrigin: 'https://chat.example', sector: 'chat-sector', policyRefresh: policyRefresh as never });
    await expect(service.verify('session', 'https://chat.example', Buffer.from(JSON.stringify(input)))).resolves.toMatchObject({ status: 409 });
    expect(queries.findIndex(sql => sql.includes('pg_advisory_xact_lock'))).toBeLessThan(queries.findIndex(sql => sql.includes('decision_now')));
    expect(queries.findIndex(sql => sql.includes('idempotency_key_aliases a JOIN'))).toBeLessThan(queries.length);
    expect(policyRefresh.loadActive).not.toHaveBeenCalled();
    expect(queries.some(sql => sql.includes('proof_challenges'))).toBe(false);
  });
});

describe('authorization mutation', () => {
  it('maps a corrupt encrypted DID mapping to unavailable before audit or renewal', async () => {
    const { service, queries, input } = await validAuthorizationFixture(false, true);
    await expect(service.verify('session', origin, Buffer.from(JSON.stringify(input)))).rejects.toBeInstanceOf(VerificationUnavailableError);
    expect(queries.some(sql => sql.includes('security_audit_events') || sql.includes('UPDATE control_plane.identity_sessions'))).toBe(false);
    expect(queries).toContain('ROLLBACK');
  });
  it('authorizes a real ES256 holder and issuer proof before recording idempotency', async () => {
    const { service, queries, input } = await validAuthorizationFixture();
    await expect(service.verify('session', origin, Buffer.from(JSON.stringify(input)))).resolves.toMatchObject({ status: 200 });
    const entitlement = queries.findIndex(sql => sql.includes('INSERT INTO control_plane.entitlements'));
    const auditIndexes = queries.flatMap((sql, index) => sql.includes('INSERT INTO control_plane.security_audit_events') ? [index] : []);
    const idempotency = queries.findIndex(sql => sql.includes('INSERT INTO control_plane.idempotency_results'));
    expect(entitlement).toBeGreaterThan(-1);
    expect(auditIndexes).toHaveLength(2);
    expect(idempotency).toBeGreaterThan(entitlement);
    expect(auditIndexes.every(index => index < idempotency)).toBe(true);
    expect(queries.filter(sql => sql.includes('WITH t AS (SELECT clock_timestamp() created_at) INSERT INTO control_plane.idempotency_results'))).toHaveLength(1);
    expect(queries[idempotency + 3]).toBe('COMMIT');
  });

  it('rolls back a duplicate JTI challenge consumption and commits rejected idempotency', async () => {
    const { service, queries, input } = await validAuthorizationFixture(true);
    await expect(service.verify('session', origin, Buffer.from(JSON.stringify(input)))).resolves.toMatchObject({ status: 401 });
    expect(queries).toContain('ROLLBACK TO SAVEPOINT authorization_mutation');
    expect(queries.some(sql => sql.includes('INSERT INTO control_plane.entitlements'))).toBe(false);
    expect(queries.filter(sql => sql.includes('challenge_consumed'))).toHaveLength(0);
    expect(queries.some(sql => sql.includes('INSERT INTO control_plane.idempotency_results'))).toBe(true);
    expect(queries.at(-1)).toBe('COMMIT');
  });
});
