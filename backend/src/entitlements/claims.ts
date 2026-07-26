import { Buffer } from 'node:buffer';
import { isIP } from 'node:net';
import { z } from 'zod';

export type MembershipEntitlement = {
  iss: string;
  sub: string;
  aud: 'dsa-signal';
  iat: number;
  exp: number;
  jti: string;
  cnf: { jkt: string };
  entitlement: 'chat';
  policyVersion: string;
};

const encoder = new TextEncoder();
const genericDid = /^did:[a-z0-9]+:(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$/;
const plcDid = /^did:plc:[a-z2-7]{24}$/;
const dnsLabel = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const dnsHostname = `(?:${dnsLabel}\\.)*${dnsLabel}`;
const canonicalDnsHostname = new RegExp(`^(?:${dnsLabel}\\.)*(?=[a-z0-9-]*[a-z])${dnsLabel}$`);
const webDid = new RegExp(
  `^did:web:(${dnsHostname})(?:(?:%3A|%3a)([1-9][0-9]{0,4}))?(?::(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+)*$`,
);
const base64url32 = /^[A-Za-z0-9_-]{43}$/;
const policyVersion = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function matchesEntire(value: string, pattern: RegExp): RegExpExecArray | null {
  const match = pattern.exec(value);
  return match !== null && match[0] === value ? match : null;
}

/** Validates DNS host bytes without accepting WHATWG URL hostname normalization. */
export function isCanonicalDnsHostname(host: string): boolean {
  if (matchesEntire(host, canonicalDnsHostname) === null || isIP(host) !== 0) {
    return false;
  }
  try {
    return new URL(`https://${host}`).hostname === host;
  } catch {
    return false;
  }
}

export function isBareDid(value: string): boolean {
  const byteLength = encoder.encode(value).byteLength;
  return byteLength >= 7 && byteLength <= 2048 && matchesEntire(value, genericDid) !== null;
}

export const bareDidSchema = z.string().refine(isBareDid, 'Invalid bare DID');

function isConfiguredDid(value: string): boolean {
  if (!isBareDid(value)) {
    return false;
  }
  if (matchesEntire(value, plcDid) !== null) {
    return true;
  }
  const match = matchesEntire(value, webDid);
  if (
    match === null ||
    encoder.encode(match[1]).byteLength > 253 ||
    !isCanonicalDnsHostname(match[1])
  ) {
    return false;
  }
  return match[2] === undefined || Number(match[2]) <= 65535;
}

export const didSchema = z.string().refine(isConfiguredDid, 'Invalid configured DID');

export function validateDid(value: string): boolean {
  return didSchema.safeParse(value).success;
}

const base64url32Schema = z
  .string()
  .refine((value) => matchesEntire(value, base64url32) !== null, 'Must be 43 base64url characters')
  .refine((value) => {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.byteLength === 32 && decoded.toString('base64url') === value;
  }, 'Must be a canonical encoding of 32 bytes');

const numericDateSchema = z.number().refine(Number.isFinite).refine(Number.isSafeInteger);

export const membershipEntitlementSchema = z
  .object({
    iss: didSchema,
    sub: didSchema,
    aud: z.literal('dsa-signal'),
    iat: numericDateSchema,
    exp: numericDateSchema,
    jti: base64url32Schema,
    cnf: z.object({ jkt: base64url32Schema }).strict(),
    entitlement: z.literal('chat'),
    policyVersion: z
      .string()
      .refine((value) => matchesEntire(value, policyVersion) !== null, 'Invalid policy version'),
  })
  .strict()
  .superRefine((claims, context) => {
    if (claims.exp <= claims.iat) {
      context.addIssue({ code: 'custom', message: 'exp must be after iat', path: ['exp'] });
    }
    if (claims.exp - claims.iat > 900) {
      context.addIssue({ code: 'custom', message: 'Claim lifetime exceeds 900 seconds', path: ['exp'] });
    }
  });

export function parseMembershipEntitlement(value: unknown): MembershipEntitlement {
  return membershipEntitlementSchema.parse(value);
}

/** `now` must be captured from an authoritative server clock, never request-derived. */
export function parseMembershipEntitlementAt(value: unknown, now: number): MembershipEntitlement {
  const authoritativeNow = now;
  if (!Number.isSafeInteger(authoritativeNow)) {
    throw new Error('Authoritative time must be a safe integer Unix second');
  }
  const claims = parseMembershipEntitlement(value);
  if (
    claims.iat > authoritativeNow + 30 ||
    claims.exp <= authoritativeNow ||
    claims.exp > authoritativeNow + 900
  ) {
    throw new Error('Claim is outside the authoritative time window');
  }
  return claims;
}
