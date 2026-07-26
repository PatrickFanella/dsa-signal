import { describe, expect, it } from 'vitest';
import { SESSION_COOKIE, clearSessionCookie, makeSessionCookie, readSessionCookie } from './session-cookie.js';

const key = Buffer.alloc(32, 7); const id = Buffer.alloc(32, 9).toString('base64url');
describe('session cookies', () => {
  it('uses canonical signed values and rejects duplicate target names', () => {
    const cookie = makeSessionCookie(id, key); const value = cookie.split(';')[0];
    expect(readSessionCookie(value, key)).toEqual({ id, duplicate: false, invalid: false });
    expect(readSessionCookie(`${value}; ${SESSION_COOKIE}=bad`, key)).toEqual({ duplicate: true, invalid: false });
    expect(clearSessionCookie()).toBe(`${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`);
  });
  it('rejects a bad tag without exposing it', () => {
    expect(readSessionCookie(`${SESSION_COOKIE}=v1.${id}.${'A'.repeat(43)}`, key)).toEqual({ duplicate: false, invalid: true });
  });
});
