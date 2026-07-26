import { generateKeyPair } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportJWK } from 'jose';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { loadOidcSecrets, readSecretFile, type SigningJwk } from './secrets.js';

const dirs: string[] = [];
let first: SigningJwk;
let second: SigningJwk;
const secret = Buffer.alloc(32, 9).toString('base64url');
const cookie = Buffer.alloc(32, 8).toString('base64url');
const temp = (): string => { const path = mkdtempSync(join(tmpdir(), 'dsa-oidc-')); dirs.push(path); return path; };
const put = (path: string, value: string | Uint8Array, mode = 0o600): void => { writeFileSync(path, value, { mode }); chmodSync(path, mode); };
const paths = (dir: string) => ({ MAS_CLIENT_SECRET_PATH: join(dir, 'mas'), OIDC_COOKIE_KEYS_PATH: join(dir, 'cookies'), OIDC_SIGNING_JWKS_PATH: join(dir, 'jwks') });
const valid = (dir: string, keys: SigningJwk[] = [first, second]) => { const p = paths(dir); put(p.MAS_CLIENT_SECRET_PATH, secret); put(p.OIDC_COOKIE_KEYS_PATH, JSON.stringify([cookie, Buffer.alloc(32, 7).toString('base64url')])); put(p.OIDC_SIGNING_JWKS_PATH, JSON.stringify({ keys })); return p; };
const invalid = (fn: () => unknown): void => { try { fn(); throw new Error('accepted'); } catch (error) { expect(String(error)).toBe('Error: Invalid OIDC secret file'); } };

beforeAll(async () => {
  const key = async (kid: string): Promise<SigningJwk> => {
    const pair = await new Promise<{ privateKey: import('node:crypto').KeyObject }>((resolve, reject) => generateKeyPair('rsa', { modulusLength: 2048 }, (error, _publicKey, privateKey) => error ? reject(error) : resolve({ privateKey })));
    return { ...await exportJWK(pair.privateKey), kid, use: 'sig', alg: 'RS256' } as SigningJwk;
  };
  first = await key('active'); second = await key('overlap');
});
afterEach(async () => { await Promise.all(dirs.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe('OIDC secret loader', () => {
  it('loads active then overlap signing keys and publishes exactly their public members', () => {
    const loaded = loadOidcSecrets(valid(temp()));
    expect(loaded.signingKeys.map((key) => key.kid)).toEqual(['active', 'overlap']);
    expect(loaded.publicJwks.keys).toEqual([first, second].map(({ kty, n, e, kid, use, alg }) => ({ kty, n, e, kid, use, alg })));
    expect([...loaded.clientSecret].every((value) => value === 9)).toBe(true);
  });

  it('fails closed with a coarse error for unsafe descriptor reads', () => {
    const dir = temp(); const p = valid(dir); const target = join(dir, 'target'); put(target, secret); unlinkSync(p.MAS_CLIENT_SECRET_PATH); symlinkSync(target, p.MAS_CLIENT_SECRET_PATH);
    invalid(() => loadOidcSecrets(p));
    const owner = join(dir, 'owner'); put(owner, secret); expect(readSecretFile(owner, process.getuid?.())).toEqual(new Uint8Array(Buffer.from(secret))); invalid(() => readSecretFile(owner, (process.getuid?.() ?? 0) + 1));
    const modes: number[] = [0o640, 0o604];
    for (const mode of modes) { const file = join(dir, `mode-${mode}`); put(file, secret, mode); invalid(() => readSecretFile(file)); }
    const nested = join(dir, 'directory'); mkdirSync(nested); invalid(() => readSecretFile(nested));
    const large = join(dir, 'large'); put(large, Buffer.alloc(65_537)); invalid(() => readSecretFile(large));
  });

  it('rejects malformed secret encodings and strict JSON', () => {
    const cases: Array<(p: ReturnType<typeof paths>) => void> = [
      (p) => put(p.MAS_CLIENT_SECRET_PATH, Buffer.from([0xc3, 0x28])),
      (p) => put(p.MAS_CLIENT_SECRET_PATH, `${secret}=`),
      (p) => put(p.MAS_CLIENT_SECRET_PATH, Buffer.alloc(31).toString('base64url')),
      (p) => put(p.MAS_CLIENT_SECRET_PATH, Buffer.alloc(257).toString('base64url')),
      (p) => put(p.OIDC_COOKIE_KEYS_PATH, `[{"x":"${cookie}","x":"${cookie}"}]`),
      (p) => put(p.OIDC_COOKIE_KEYS_PATH, JSON.stringify([cookie, cookie])),
      (p) => put(p.OIDC_COOKIE_KEYS_PATH, JSON.stringify([`${cookie}=`])),
      (p) => put(p.OIDC_COOKIE_KEYS_PATH, JSON.stringify([Buffer.alloc(31).toString('base64url')])),
      (p) => put(p.OIDC_SIGNING_JWKS_PATH, `{"keys":[],"keys":[]}`),
    ];
    for (const mutate of cases) { const p = valid(temp()); mutate(p); invalid(() => loadOidcSecrets(p)); }
  });

  it('rejects a canonical 256-byte modulus below 2048 bits before private-key validation', () => {
    const modulus = Buffer.from(first.n, 'base64url'); modulus[0] = 0x7f;
    const p = valid(temp(), [{ ...first, n: modulus.toString('base64url') }]);
    invalid(() => loadOidcSecrets(p));
  });

  it('rejects incomplete, noncanonical, duplicate, weak, and inconsistent JWKs', async () => {
    const weakPair = await new Promise<{ privateKey: import('node:crypto').KeyObject }>((resolve, reject) => generateKeyPair('rsa', { modulusLength: 1024 }, (error, _publicKey, privateKey) => error ? reject(error) : resolve({ privateKey })));
    const weak = { ...await exportJWK(weakPair.privateKey), kid: 'weak', use: 'sig', alg: 'RS256' } as SigningJwk;
    const altered = { ...first, dp: first.dq };
    const cases: unknown[] = [
      { ...first, extra: 'x' }, (() => { const missing: Record<string, unknown> = { ...first }; delete missing.qi; return missing; })(),
      { ...first, n: `A${first.n}` }, { ...first, e: 'AAEAAQ' }, { ...first, kid: 'bad kid' }, weak, altered,
    ];
    for (const [index, candidate] of cases.entries()) { const p = valid(temp(), [candidate as SigningJwk]); try { loadOidcSecrets(p); throw new Error(`accepted ${index}`); } catch (error) { expect(String(error)).toBe('Error: Invalid OIDC secret file'); } }
    const duplicate = valid(temp(), [first, { ...second, kid: first.kid }]); invalid(() => loadOidcSecrets(duplicate));
  });

  it('does not disclose paths or secret content on errors', () => {
    const dir = temp(); const p = valid(dir); put(p.MAS_CLIENT_SECRET_PATH, 'very-secret-value');
    try { loadOidcSecrets(p); } catch (error) { const message = String(error); expect(message).not.toContain(dir); expect(message).not.toContain('very-secret-value'); }
    expect(lstatSync(p.MAS_CLIENT_SECRET_PATH).isFile()).toBe(true);
  });
});
