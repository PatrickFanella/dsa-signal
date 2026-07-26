import { describe, expect, it } from 'vitest';
import { HandoffRejectedError, validateHandoff } from './identity-handoff.js';

const handoff = { did: 'did:plc:abcdefghijklmnopqrstuvwx', audience: 'https://chat.example', authenticatedAt: '2026-07-17T00:00:00Z', expiresIn: 60 };
describe('validateHandoff', () => {
  it('uses the caller supplied decision clock at exact boundaries', () => {
    expect(validateHandoff(handoff, handoff.audience, new Date('2026-07-17T00:00:30Z'))).toBe(handoff.did);
    expect(() => validateHandoff({ ...handoff, authenticatedAt: '2026-07-17T00:00:30.001Z' }, handoff.audience, new Date('2026-07-17T00:00:00Z'))).toThrow(HandoffRejectedError);
    expect(() => validateHandoff({ ...handoff, authenticatedAt: '2026-07-16T23:59:00Z' }, handoff.audience, new Date('2026-07-17T00:00:00Z'))).toThrow(HandoffRejectedError);
    expect(validateHandoff({ ...handoff, authenticatedAt: '2026-07-16T23:59:00.001Z' }, handoff.audience, Date.parse('2026-07-17T00:00:00Z') / 1_000)).toBe(handoff.did);
  });
  it('does not serialize sensitive handoff values in errors', () => {
    const error = (() => { try { validateHandoff({ ...handoff, did: 'did:plc:secret' }, handoff.audience, new Date()); } catch (value) { return value; } })();
    expect(JSON.stringify(error)).not.toContain('secret');
  });
  it('accepts exactly the four contract keys', () => {
    expect(() => validateHandoff({ ...handoff, extra: true } as never, handoff.audience, new Date('2026-07-17T00:00:00Z'))).toThrow(HandoffRejectedError);
    expect(() => validateHandoff({ did: handoff.did, audience: handoff.audience, expiresIn: 60 } as never, handoff.audience, new Date('2026-07-17T00:00:00Z'))).toThrow(HandoffRejectedError);
  });
  it('rejects invalid RFC3339 calendar dates and offsets', () => {
    for (const authenticatedAt of ['2026-02-30T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00+24:00', '2026-01-01T00:00:00+00:60']) expect(() => validateHandoff({ ...handoff, authenticatedAt }, handoff.audience, new Date('2026-07-17T00:00:00Z'))).toThrow(HandoffRejectedError);
  });
});
