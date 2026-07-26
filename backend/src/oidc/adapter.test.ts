import { describe, expect, it } from 'vitest';
import { createOidcAdapter } from './adapter.js';
import { oidcRequestContext } from './request-context.js';

describe('OIDC adapter clock boundary', () => {
  it('uses the transaction decision clock for artifact liveness', async () => {
    const decisionNow = new Date('2026-07-19T12:00:00.000Z');
    const calls: Array<{ text: string; values: unknown[] }> = [];
    const client = {
      query: async (text: string, values: unknown[]) => {
        calls.push({ text, values });
        return { rowCount: 0, rows: [] };
      },
    };
    const key = Buffer.alloc(32, 7);
    const Adapter = createOidcAdapter({
      epoch: 'AAAAAAAAAAAAAAAAAAAAAA',
      adapter: { active: 'current', keys: { current: key } },
      index: { active: 'current', keys: { current: key } },
    });

    await oidcRequestContext.run({ client: client as never, decisionNow }, async () => {
      await new Adapter('Interaction').find('artifact-id');
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.text).toContain('expires_at>$5');
    expect(calls[0]!.values[4]).toBe(decisionNow);
    expect(calls[0]!.text).not.toContain('clock_timestamp');
  });
});
