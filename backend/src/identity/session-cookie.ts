import { createHmac, timingSafeEqual } from 'node:crypto';

export const SESSION_COOKIE = '__Host-dsa_signal_session';
const attrs = 'Path=/; Max-Age=900; HttpOnly; Secure; SameSite=Strict';
const b64 = /^[A-Za-z0-9_-]{43}$/;
export function sessionTag(id: string, key: Uint8Array): string {
  return createHmac('sha256', key).update('dsa-signal-cookie:v1\0').update(id, 'ascii').digest('base64url');
}
export function makeSessionCookie(id: string, key: Uint8Array): string {
  return `${SESSION_COOKIE}=v1.${id}.${sessionTag(id, key)}; ${attrs}`;
}
export function clearSessionCookie(): string { return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`; }
export function readSessionCookie(header: string | undefined, key: Uint8Array): { id?: string; duplicate: boolean; invalid: boolean } {
  if (!header) return { duplicate: false, invalid: false };
  const hits = header.split(';').map((part) => part.trim()).filter((part) => part === SESSION_COOKIE || part.startsWith(`${SESSION_COOKIE}=`));
  if (hits.length !== 1) return { duplicate: hits.length > 1, invalid: hits.length === 1 };
  const parts = hits[0].slice(SESSION_COOKIE.length + 1).split('.');
  if (parts.length !== 3 || parts[0] !== 'v1' || !b64.test(parts[1]) || !b64.test(parts[2])) return { duplicate: false, invalid: true };
  // Canonical decode/re-encode rejects alternate encodings before constant-time comparison.
  if (Buffer.from(parts[1], 'base64url').toString('base64url') !== parts[1] || Buffer.from(parts[2], 'base64url').toString('base64url') !== parts[2]) return { duplicate: false, invalid: true };
  const expected = Buffer.from(sessionTag(parts[1], key), 'ascii'); const actual = Buffer.from(parts[2], 'ascii');
  return expected.length === actual.length && timingSafeEqual(expected, actual) ? { id: parts[1], duplicate: false, invalid: false } : { duplicate: false, invalid: true };
}
