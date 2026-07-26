import { compactVerify, importJWK } from 'jose';
import { parseStrictJson } from '../http/strict-json.js';
import { validateDid } from './claims.js';
import type { PublicJwk } from './verify-entitlement.js';

const utf8 = new TextEncoder();
const B64URL = /^[A-Za-z0-9_-]+$/;
const B64URL32 = /^[A-Za-z0-9_-]{43}$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const FRAGMENT = /^[A-Za-z0-9._-]{1,64}$/;
const RKEY = /^[A-Za-z0-9._~:-]{1,512}$/;
const MAX_STALENESS = 86_400;

export type PolicyState = 'active' | 'retiring' | 'revoked';
export type IssuerPolicy = Readonly<{ version: 'v1'; policyVersion: string; policyUri: string; rootDid: string; issuedAt: number; freshUntil: number; issuers: readonly Issuer[] }>;
export type Issuer = Readonly<{ did: string; policies: readonly VersionPolicy[]; keys: readonly IssuerKey[] }>;
export type VersionPolicy = Readonly<{ version: string; state: PolicyState; transitionedAt: number }>;
export type IssuerKey = Readonly<{ kid: string; state: PolicyState; transitionedAt: number; publicJwk: PublicJwk }>;

function invalid(): never { throw new Error('invalid policy'); }
function object(value: unknown): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) invalid(); return value as Record<string, unknown>; }
function exact(value: Record<string, unknown>, keys: readonly string[]): void { const actual = Object.keys(value).sort(); if (actual.length !== keys.length || actual.some((key, index) => key !== [...keys].sort()[index])) invalid(); }
function string(value: unknown, max?: number): string { if (typeof value !== 'string' || (max !== undefined && utf8.encode(value).length > max)) invalid(); return value; }
function integer(value: unknown): number { if (typeof value !== 'number' || !Number.isSafeInteger(value)) invalid(); return value; }
function canonicalB64(segment: string): Uint8Array { if (!B64URL.test(segment)) invalid(); const bytes = Buffer.from(segment, 'base64url'); if (bytes.length === 0 || bytes.toString('base64url') !== segment) invalid(); return bytes; }
function did(value: unknown): string { const result = string(value); if (!validateDid(result)) invalid(); return result; }
function version(value: unknown): string { const result = string(value); if (!VERSION.test(result)) invalid(); return result; }
function state(value: unknown): PolicyState { if (value !== 'active' && value !== 'retiring' && value !== 'revoked') invalid(); return value; }

/** Strictly parses the contract's public P-256 JWK; no JOSE extensions are allowed. */
export function parsePolicyPublicJwk(value: unknown): PublicJwk {
  const jwk = object(value); exact(jwk, ['kty', 'crv', 'x', 'y']);
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string' || !B64URL32.test(jwk.x) || !B64URL32.test(jwk.y)) invalid();
  for (const coordinate of [jwk.x, jwk.y]) { const bytes = canonicalB64(coordinate); if (bytes.length !== 32) invalid(); }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

function kid(value: unknown, issuerDid: string): string {
  const result = string(value, 2113); const prefix = `${issuerDid}#`; if (!result.startsWith(prefix) || !FRAGMENT.test(result.slice(prefix.length))) invalid(); return result;
}
function policyUri(value: unknown, rootDid: string): string {
  const result = string(value, 2048); const prefix = `at://${rootDid}/us.dsaslate.temp.dsaPolicy/`;
  if (!result.startsWith(prefix) || !RKEY.test(result.slice(prefix.length))) invalid(); return result;
}
function sortedUnique<T>(items: readonly T[], id: (item: T) => string, max: number): void {
  if (items.length < 1 || items.length > max) invalid(); let previous: string | undefined;
  for (const item of items) { const current = id(item); if (previous !== undefined && previous >= current) invalid(); previous = current; }
}

function parsePayload(raw: unknown, configuredRootDid: string, expectedVersion: string, now: number, maxStaleness: number): IssuerPolicy {
  const body = object(raw); exact(body, ['version', 'policyVersion', 'policyUri', 'rootDid', 'issuedAt', 'freshUntil', 'issuers']);
  if (body.version !== 'v1' || did(body.rootDid) !== configuredRootDid || version(body.policyVersion) !== expectedVersion) invalid();
  const issuedAt = integer(body.issuedAt); const freshUntil = integer(body.freshUntil);
  if (freshUntil <= issuedAt || freshUntil > issuedAt + maxStaleness || issuedAt > now || freshUntil <= now) invalid();
  const issuersRaw = body.issuers; if (!Array.isArray(issuersRaw)) invalid();
  const issuers = issuersRaw.map((entry): Issuer => {
    const issuer = object(entry); exact(issuer, ['did', 'policies', 'keys']); const issuerDid = did(issuer.did);
    if (!Array.isArray(issuer.policies) || !Array.isArray(issuer.keys)) invalid();
    const policies = issuer.policies.map((entry): VersionPolicy => { const item = object(entry); exact(item, ['version', 'state', 'transitionedAt']); return { version: version(item.version), state: state(item.state), transitionedAt: integer(item.transitionedAt) }; });
    const keys = issuer.keys.map((entry): IssuerKey => { const item = object(entry); exact(item, ['kid', 'state', 'transitionedAt', 'publicJwk']); return { kid: kid(item.kid, issuerDid), state: state(item.state), transitionedAt: integer(item.transitionedAt), publicJwk: parsePolicyPublicJwk(item.publicJwk) }; });
    sortedUnique(policies, item => item.version, 64); sortedUnique(keys, item => item.kid, 64);
    return { did: issuerDid, policies, keys };
  });
  sortedUnique(issuers, item => item.did, 256);
  return { version: 'v1', policyVersion: expectedVersion, policyUri: policyUri(body.policyUri, configuredRootDid), rootDid: configuredRootDid, issuedAt, freshUntil, issuers };
}

/** Validates compact bytes before ES256 verification and selects only an own configured root key. */
export async function verifyIssuerPolicy(compact: string, roots: Readonly<Record<string, PublicJwk>>, expectedVersion: string, now: number, maxStaleness: number = MAX_STALENESS): Promise<IssuerPolicy> {
  if (typeof compact !== 'string' || utf8.encode(compact).length > 16_384 || !Number.isSafeInteger(now) || !Number.isSafeInteger(maxStaleness) || maxStaleness < 1 || maxStaleness > MAX_STALENESS || !VERSION.test(expectedVersion)) invalid();
  const parts = compact.split('.'); if (parts.length !== 3) invalid();
  const [headerBytes, payloadBytes] = [canonicalB64(parts[0]), canonicalB64(parts[1])]; canonicalB64(parts[2]);
  const header = object(parseStrictJson(headerBytes)); exact(header, ['alg', 'typ', 'kid']);
  if (header.alg !== 'ES256' || header.typ !== 'dsa-signal-issuer-policy+jws' || typeof header.kid !== 'string') invalid();
  const hash = header.kid.indexOf('#'); if (hash < 1 || !FRAGMENT.test(header.kid.slice(hash + 1))) invalid();
  const rootDid = header.kid.slice(0, hash);
  if (!validateDid(rootDid) || !Object.hasOwn(roots, header.kid)) invalid();
  const root = parsePolicyPublicJwk(roots[header.kid]);
  // Scan payload before crypto so duplicate/escaped-equivalent JSON names are never tolerated.
  let parsed: IssuerPolicy;
  try { parsed = parsePayload(parseStrictJson(payloadBytes), rootDid, expectedVersion, now, maxStaleness); } catch { invalid(); }
  try { await compactVerify(compact, await importJWK(root, 'ES256'), { algorithms: ['ES256'] }); } catch { invalid(); }
  return parsed;
}

/** Returns the exact key only when both version and key are usable at the decision clock. */
export function selectIssuerKey(policy: IssuerPolicy, issuerDid: string, keyId: string, policyVersion: string, now: number): PublicJwk {
  if (!Number.isSafeInteger(now) || now >= policy.freshUntil || policyVersion !== policy.policyVersion) invalid();
  const issuer = policy.issuers.find(item => item.did === issuerDid); if (!issuer) invalid();
  const p = issuer.policies.find(item => item.version === policyVersion); const key = issuer.keys.find(item => item.kid === keyId);
  if (!p || !key || p.state === 'revoked' || key.state === 'revoked' || p.state !== key.state) invalid();
  if (p.state === 'retiring' && (now >= p.transitionedAt + 900 || now >= key.transitionedAt + 900)) invalid();
  return key.publicJwk;
}
