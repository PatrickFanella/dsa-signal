import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { selectIssuerKey, verifyIssuerPolicy } from './issuer-policy.js';
import type { PublicJwk } from './verify-entitlement.js';

const rootDid = 'did:plc:abcdefghijklmnopqrstuvwx';
const issuerDid = 'did:plc:bcdefghijklmnopqrstuvwxy';
const keyId = `${issuerDid}#main`;
async function signed(now: number, mutate?: (body: Record<string, unknown>) => void): Promise<{ compact: string; roots: Record<string, PublicJwk> }> {
  const pair = await generateKeyPair('ES256'); const root = await exportJWK(pair.publicKey) as PublicJwk; const holder = await exportJWK((await generateKeyPair('ES256')).publicKey) as PublicJwk;
  const body: Record<string, unknown> = { version: 'v1', policyVersion: '2026.07-1', policyUri: `at://${rootDid}/us.dsaslate.temp.dsaPolicy/record`, rootDid, issuedAt: now - 1, freshUntil: now + 60, issuers: [{ did: issuerDid, policies: [{ version: '2026.07-1', state: 'active', transitionedAt: now - 1 }], keys: [{ kid: keyId, state: 'active', transitionedAt: now - 1, publicJwk: holder }] }] };
  mutate?.(body);
  return { compact: await new SignJWT(body).setProtectedHeader({ alg: 'ES256', typ: 'dsa-signal-issuer-policy+jws', kid: `${rootDid}#root` }).sign(pair.privateKey), roots: { [`${rootDid}#root`]: root } };
}

describe('verifyIssuerPolicy', () => {
  it('requires configured own roots and returns strictly signed policy', async () => {
    const now = 1_700_000_000; const fixture = await signed(now); const policy = await verifyIssuerPolicy(fixture.compact, fixture.roots, '2026.07-1', now);
    expect(selectIssuerKey(policy, issuerDid, keyId, '2026.07-1', now).kty).toBe('EC');
    await expect(verifyIssuerPolicy(fixture.compact, Object.create(fixture.roots), '2026.07-1', now)).rejects.toThrow('invalid policy');
  });
  it('rejects duplicate nested JSON and non-canonical compact segments before JOSE', async () => {
    const now = 1_700_000_000; const fixture = await signed(now);
    const [header, , signature] = fixture.compact.split('.');
    const duplicatePayload = Buffer.from('{"version":"v1","version":"v1"}').toString('base64url');
    await expect(verifyIssuerPolicy(`${header}.${duplicatePayload}.${signature}`, fixture.roots, '2026.07-1', now)).rejects.toThrow('invalid policy');
    await expect(verifyIssuerPolicy(`${header}=.${duplicatePayload}.${signature}`, fixture.roots, '2026.07-1', now)).rejects.toThrow('invalid policy');
  });
  it('rejects unsorted arrays and revoked decisions', async () => {
    const now = 1_700_000_000; const fixture = await signed(now, body => { (body.issuers as Array<Record<string, unknown>>)[0].policies = [{ version: 'z', state: 'active', transitionedAt: now }, { version: 'a', state: 'active', transitionedAt: now }]; });
    await expect(verifyIssuerPolicy(fixture.compact, fixture.roots, '2026.07-1', now)).rejects.toThrow('invalid policy');
  });
  it('uses the caller decision clock and configured staleness', async () => {
    const now = 1_700_000_000;
    const valid = await signed(now, body => { body.issuedAt = now - 300; body.freshUntil = now; });
    await expect(verifyIssuerPolicy(valid.compact, valid.roots, '2026.07-1', now - 1, 300)).resolves.toBeDefined();
    const stale = await signed(now, body => { body.issuedAt = now - 301; body.freshUntil = now; });
    await expect(verifyIssuerPolicy(stale.compact, stale.roots, '2026.07-1', now - 1, 300)).rejects.toThrow('invalid policy');
    await expect(verifyIssuerPolicy(valid.compact, valid.roots, '2026.07-1', now - 1, 0)).rejects.toThrow('invalid policy');
  });
  it('requires policy signing at or before the decision clock', async () => {
    const now = 1_700_000_000;
    const exact = await signed(now, body => { body.issuedAt = now; body.freshUntil = now + 60; });
    await expect(verifyIssuerPolicy(exact.compact, exact.roots, '2026.07-1', now)).resolves.toBeDefined();
    const future = await signed(now, body => { body.issuedAt = now + 1; body.freshUntil = now + 61; });
    await expect(verifyIssuerPolicy(future.compact, future.roots, '2026.07-1', now)).rejects.toThrow('invalid policy');
  });
  it('allows only aligned active or bounded retiring pairs', async () => {
    const now = 1_700_000_000;
    const fixture = await signed(now, body => {
      const issuer = (body.issuers as Array<Record<string, unknown>>)[0];
      (issuer.policies as Array<Record<string, unknown>>)[0].state = 'retiring';
      (issuer.keys as Array<Record<string, unknown>>)[0].state = 'retiring';
      (issuer.policies as Array<Record<string, unknown>>)[0].transitionedAt = now - 899;
      (issuer.keys as Array<Record<string, unknown>>)[0].transitionedAt = now - 899;
    });
    const policy = await verifyIssuerPolicy(fixture.compact, fixture.roots, '2026.07-1', now);
    expect(selectIssuerKey(policy, issuerDid, keyId, '2026.07-1', now)).toBeDefined();
    const mixed = await signed(now, body => { ((body.issuers as Array<Record<string, unknown>>)[0].keys as Array<Record<string, unknown>>)[0].state = 'retiring'; });
    const mixedPolicy = await verifyIssuerPolicy(mixed.compact, mixed.roots, '2026.07-1', now);
    expect(() => selectIssuerKey(mixedPolicy, issuerDid, keyId, '2026.07-1', now)).toThrow('invalid policy');
  });
});
