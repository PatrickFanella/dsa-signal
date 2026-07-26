import { constants, openSync, closeSync, fstatSync, readSync } from 'node:fs';
import { createPrivateKey, createPublicKey, createSign, createVerify, timingSafeEqual } from 'node:crypto';
import { parseStrictJson } from '../http/strict-json.js';
import type { Config } from '../config.js';

export type SigningJwk = Readonly<{ kty: 'RSA'; n: string; e: string; d: string; p: string; q: string; dp: string; dq: string; qi: string; kid: string; use: 'sig'; alg: 'RS256' }>;
export type OidcSecrets = Readonly<{ clientSecret: Uint8Array; cookieKeys: readonly Uint8Array[]; signingKeys: readonly SigningJwk[]; publicJwks: Readonly<{ keys: readonly Readonly<{ kty: 'RSA'; n: string; e: string; kid: string; use: 'sig'; alg: 'RS256' }>[] }> }>;
const fail = (): never => { throw new Error('Invalid OIDC secret file'); };
const b64 = (value: unknown, size?: number): Uint8Array => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return fail();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length === 0 || (size !== undefined && bytes.length !== size) || bytes.toString('base64url') !== value) return fail();
  return new Uint8Array(bytes);
};
const unsigned = (value: unknown): Uint8Array => {
  const valueBytes = b64(value);
  if (valueBytes[0] === 0) return fail();
  return valueBytes;
};
const integer = (value: unknown): bigint => BigInt(`0x${Buffer.from(unsigned(value)).toString('hex')}`);
const gcd = (left: bigint, right: bigint): bigint => right === 0n ? left : gcd(right, left % right);
/** Descriptor based, fail-closed secret read. Call before accepting traffic. */
export function readSecretFile(path: string, owner = process.getuid?.()): Uint8Array {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 65_536 || (stat.mode & 0o077) !== 0 || (owner !== undefined && stat.uid !== owner)) return fail();
    const output = Buffer.alloc(stat.size); let offset = 0;
    while (offset < output.length) { const count = readSync(fd, output, offset, output.length - offset, offset); if (count <= 0) return fail(); offset += count; }
    return new Uint8Array(output);
  } catch { return fail(); } finally { if (fd !== undefined) closeSync(fd); }
}

/** Rejects reuse between environment key rings and descriptor-loaded OIDC secrets. */
export function assertOidcSecretSeparation(config: Config, secrets: OidcSecrets): void {
  const rings = [config.SUBJECT_KEY_RING, config.ENVELOPE_KEY_RING, config.CHALLENGE_KEY_RING, config.SESSION_BINDING_KEY_RING, config.JTI_KEY_RING, config.IDEMPOTENCY_KEY_RING, config.REQUEST_FINGERPRINT_KEY_RING, config.OIDC_ADAPTER_KEY_RING, config.OIDC_INDEX_KEY_RING];
  const values = [config.COOKIE_KEY, ...rings.flatMap((ring) => Object.values(ring.keys)), secrets.clientSecret, ...secrets.cookieKeys].map((value) => Buffer.from(value).toString('base64url'));
  if (new Set(values).size !== values.length) fail();
}
const json = (path: string): unknown => {
  const bytes = readSecretFile(path);
  try { return parseStrictJson(bytes); } catch { return fail(); } finally { bytes.fill(0); }
};
export function loadOidcSecrets(paths: Readonly<{ MAS_CLIENT_SECRET_PATH: string; OIDC_COOKIE_KEYS_PATH: string; OIDC_SIGNING_JWKS_PATH: string }>): OidcSecrets {
  let clientText: string;
  const clientBytes = readSecretFile(paths.MAS_CLIENT_SECRET_PATH);
  try { clientText = new TextDecoder('utf-8', { fatal: true }).decode(clientBytes); } catch { return fail(); } finally { clientBytes.fill(0); }
  const clientSecret = b64(clientText);
  if (clientSecret.length < 32 || clientSecret.length > 256) return fail();
  const cookieRaw = json(paths.OIDC_COOKIE_KEYS_PATH);
  if (!Array.isArray(cookieRaw) || cookieRaw.length === 0) return fail();
  const cookieKeys = cookieRaw.map((value) => b64(value, 32));
  if (new Set(cookieKeys.map((value) => Buffer.from(value).toString('base64url'))).size !== cookieKeys.length) return fail();
  if (cookieKeys.some((key) => key.length === clientSecret.length && timingSafeEqual(key, clientSecret))) return fail();
  const raw = json(paths.OIDC_SIGNING_JWKS_PATH);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).length !== 1 || !Array.isArray((raw as { keys?: unknown }).keys) || (raw as { keys: unknown[] }).keys.length === 0) return fail();
  const signingKeys = (raw as { keys: unknown[] }).keys.map((candidate): SigningJwk => {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return fail();
    const key = candidate as Record<string, unknown>; const names = ['alg', 'd', 'dp', 'dq', 'e', 'kid', 'kty', 'n', 'p', 'q', 'qi', 'use'];
    if (Object.keys(key).sort().join(',') !== names.join(',')) return fail();
    if (key.kty !== 'RSA' || key.use !== 'sig' || key.alg !== 'RS256' || typeof key.kid !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(key.kid)) return fail();
    const modulus = unsigned(key.n);
    if ((modulus.length - 1) * 8 + (32 - Math.clz32(modulus[0])) < 2048) return fail();
    for (const member of ['e', 'd', 'p', 'q', 'dp', 'dq', 'qi']) unsigned(key[member]);
    try {
      const [n, e, d, p, q, dp, dq, qi] = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'].map((member) => integer(key[member]));
      const lambda = ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n);
      if (n !== p * q || (d * e) % lambda !== 1n || dp !== d % (p - 1n) || dq !== d % (q - 1n) || (qi * q) % p !== 1n) return fail();
      const privateKey = createPrivateKey({ key: key as unknown as import('node:crypto').JsonWebKey, format: 'jwk' });
      const publicKey = createPublicKey({ key: { kty: 'RSA', n: key.n, e: key.e } as import('node:crypto').JsonWebKey, format: 'jwk' });
      const signer = createSign('sha256'); signer.update('OIDC key consistency'); signer.end(); const signature = signer.sign(privateKey);
      const verifier = createVerify('sha256'); verifier.update('OIDC key consistency'); verifier.end(); if (!verifier.verify(publicKey, signature)) return fail();
    } catch { return fail(); }
    return key as SigningJwk;
  });
  if (new Set(signingKeys.map((key) => key.kid)).size !== signingKeys.length) return fail();
  if (new Set(signingKeys.map((key) => `${key.n}.${key.e}`)).size !== signingKeys.length) return fail();
  return { clientSecret, cookieKeys, signingKeys, publicJwks: { keys: signingKeys.map(({ kty, n, e, kid, use, alg }) => ({ kty, n, e, kid, use, alg })) } };
}
