import { randomBytes } from 'node:crypto';
import { validateDid } from '../entitlements/claims.js';
export type IdentityHandoffResult = Readonly<{ did: string; audience: string; authenticatedAt: string; expiresIn: number }>;
export type IdentityFoundation = Readonly<{ exchangeIdentityHandoff(input: { code: string; verifier: string; audience: string }): Promise<IdentityHandoffResult> }>;
export class HandoffRejectedError extends Error {
  constructor() { super('rejected'); this.name = 'HandoffRejectedError'; }
}
/** Validation is deliberately clock-injected: callers must pass the DB decision clock. */
export function validateHandoff(result: IdentityHandoffResult, audience: string, decisionNow: Date | number): string {
  if (!result || typeof result !== 'object' || Array.isArray(result) || Object.keys(result).sort().join(',') !== 'audience,authenticatedAt,did,expiresIn' || typeof result.did !== 'string' || typeof result.audience !== 'string' || typeof result.authenticatedAt !== 'string' || typeof result.expiresIn !== 'number' || !validateDid(result.did) || result.audience !== audience || result.expiresIn !== 60) throw new HandoffRejectedError();
  const authenticatedAt = strictRfc3339(result.authenticatedAt);
  const now = typeof decisionNow === 'number' ? decisionNow * 1_000 : decisionNow.valueOf();
  if (!Number.isFinite(authenticatedAt) || !Number.isFinite(now) || authenticatedAt > now + 30_000 || now >= authenticatedAt + 60_000) throw new HandoffRejectedError();
  return result.did;
}
function strictRfc3339(value: string): number {
  const match = value.match(/^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|([+-])(\d\d):(\d\d))$/);
  if (!match) throw new HandoffRejectedError();
  const time = Date.parse(value); const offset = match[7] === 'Z' ? 0 : (Number(match[9]) * 60 + Number(match[10])) * (match[8] === '+' ? 1 : -1);
  if (!Number.isFinite(time) || Number(match[4]) > 23 || Number(match[5]) > 59 || Number(match[6]) > 59 || Math.abs(offset) > 23 * 60 + 59) throw new HandoffRejectedError();
  const local = new Date(time + offset * 60_000);
  if (local.getUTCFullYear() !== Number(match[1]) || local.getUTCMonth() + 1 !== Number(match[2]) || local.getUTCDate() !== Number(match[3]) || local.getUTCHours() !== Number(match[4]) || local.getUTCMinutes() !== Number(match[5]) || local.getUTCSeconds() !== Number(match[6])) throw new HandoffRejectedError();
  return time;
}
export const newSessionId = (): string => randomBytes(32).toString('base64url');
