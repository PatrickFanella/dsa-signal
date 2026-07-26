/** Synchronous, dependency-light callback preflight.  It deliberately stores no browser-global state. */
import { MATRIX_ISSUER, MATRIX_REDIRECT_URI } from './matrix-topology';

const B64URL43 = /^[A-Za-z0-9_-]{43}$/;
const CALLBACK_KEYS = new Set(['code', 'state', 'iss', 'error', 'error_description']);
export interface OAuthBrowser { location: { pathname: string; search: string; hash: string }; history: { replaceState(data: unknown, title: string, url?: string | URL | null): void }; hardNavigate(url: string): void; }
export type OAuthCallback = { kind: 'success'; code: string; state: string; issuer?: string } | { kind: 'error'; state: string; issuer?: string } | { kind: 'none' } | { kind: 'invalid' };
export class OAuthAbortError extends Error { public constructor() { super('OAuth callback cleanup failed'); this.name = 'OAuthAbortError'; } }
let captured: OAuthCallback | undefined;

export function captureAndScrubOAuthCallback(browser: OAuthBrowser): OAuthCallback {
  const { pathname, search, hash } = browser.location; const callbackShaped = pathname !== '/' || search.length > 0 || hash.length > 0;
  if (!callbackShaped) return pathname === '/' ? { kind: 'none' } : { kind: 'invalid' };
  try { browser.history.replaceState(null, '', MATRIX_REDIRECT_URI); } catch { try { browser.hardNavigate(MATRIX_REDIRECT_URI); } catch { /* best effort */ } throw new OAuthAbortError(); }
  if (pathname !== '/' || search !== '' || hash.length < 2) return { kind: 'invalid' };
  const params = new URLSearchParams(hash.slice(1)); const keys = [...params.keys()];
  if (keys.some(key => !CALLBACK_KEYS.has(key)) || new Set(keys).size !== keys.length) return { kind: 'invalid' };
  const get = (name: string): string | undefined => params.get(name) ?? undefined; const state = get('state'); const issuer = get('iss'); const code = get('code'); const error = get('error');
  if (!state || !B64URL43.test(state) || (issuer !== undefined && issuer !== MATRIX_ISSUER) || (code !== undefined && error !== undefined)) return { kind: 'invalid' };
  if (code !== undefined && code.length > 0 && get('error_description') === undefined) return { kind: 'success', code, state, ...(issuer === undefined ? {} : { issuer }) };
  if (error !== undefined && error.length > 0 && code === undefined) return { kind: 'error', state, ...(issuer === undefined ? {} : { issuer }) };
  return { kind: 'invalid' };
}
/** Called only by main before importing application code. */
export function captureInstalledOAuthCallback(browser: OAuthBrowser): void { if (captured !== undefined) throw new OAuthAbortError(); captured = captureAndScrubOAuthCallback(browser); }
/** Transfers the preflight result exactly once to later integration. */
export function takeCapturedOAuthCallback(): OAuthCallback { if (captured === undefined) throw new OAuthAbortError(); const value = captured; captured = undefined; return value; }
