import { createHmac } from 'node:crypto';
import { z } from 'zod';
import { didSchema, isCanonicalDnsHostname } from '../entitlements/claims.js';

const encoder = new TextEncoder();
const dnsLabel = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const dnsHostname = `(?:${dnsLabel}\\.)*${dnsLabel}`;
const canonicalSector = new RegExp(`^https://(${dnsHostname})(?::([1-9][0-9]{0,4}))?$`);
const printableAscii = /^[\x21-\x7e]+$/;

function matchesEntire(value: string, pattern: RegExp): RegExpExecArray | null {
  const match = pattern.exec(value);
  return match !== null && match[0] === value ? match : null;
}

function isCanonicalSector(value: string): boolean {
  if (encoder.encode(value).byteLength > 255 || matchesEntire(value, printableAscii) === null) {
    return false;
  }
  const match = matchesEntire(value, canonicalSector);
  if (match === null) {
    return false;
  }
  return (
    isCanonicalDnsHostname(match[1]) &&
    (match[2] === undefined || (Number(match[2]) <= 65535 && match[2] !== '443'))
  );
}

export const sectorSchema = z.string().refine(isCanonicalSector, 'Invalid canonical HTTPS sector origin');

/**
 * `sector` must be immutable configured v1 DNS-origin data; never derive it from a request.
 */
export function derivePairwiseSubject(key: Uint8Array, sector: string, did: string): string {
  if (key.byteLength !== 32) {
    throw new Error('Pairwise subject key must be exactly 32 bytes');
  }
  const canonicalSectorValue = sectorSchema.parse(sector);
  const canonicalDid = didSchema.parse(did);
  const keyCopy = Buffer.from(key);
  const input = encoder.encode(`dsa-signal-subject:v1\0${canonicalSectorValue}\0${canonicalDid}`);
  try {
    return createHmac('sha256', keyCopy).update(input).digest('base64url');
  } finally {
    keyCopy.fill(0);
  }
}
