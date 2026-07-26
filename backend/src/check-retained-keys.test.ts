import { describe, expect, it } from 'vitest';
import { getConfig } from './config.js';
import { runRetainedKeyPreflight } from './check-retained-keys.js';
import type { PoolClient } from 'pg';

const config = getConfig({ APP_ENV: 'test' });

describe('retained-key preflight', () => {
  it('checks the complete key material, releases the client, then ends the pool', async () => {
    const events: string[] = []; const output: string[] = [];
    const client = { release: (error?: Error) => events.push(`release:${error ? 'poisoned' : 'clean'}`) } as unknown as PoolClient;
    const status = await runRetainedKeyPreflight({
      getConfig: () => config,
      createRuntimePool: () => ({ connect: async () => client, end: async () => { events.push('end'); } }) as never,
      assertRetainedKeys: async (_client, keys) => { events.push('check'); expect(keys).toEqual({ subject: config.SUBJECT_KEY_RING.keys, envelope: config.ENVELOPE_KEY_RING.keys, challenge: ['v1'], binding: ['v1'], jti: { active: 'v1', retained: ['v1'] }, idempotency: { active: 'v1', retained: ['v1'] }, request: ['v1'], evidence: ['v1'], oidc: { epoch: config.OIDC_EPOCH, adapter: config.OIDC_ADAPTER_KEY_RING.keys, index: ['v1'] } }); },
    }, value => output.push(value), () => undefined);
    expect(status).toBe(0); expect(events).toEqual(['check', 'release:clean', 'end']); expect(output).toEqual(['retained-key preflight ok\n']);
  });

  it('poisons and releases a checked-out client and emits only the coarse failure output', async () => {
    const events: string[] = []; const stderr: string[] = []; const stdout: string[] = [];
    const client = { release: (error?: Error) => events.push(`release:${error?.message}`) } as unknown as PoolClient;
    const status = await runRetainedKeyPreflight({
      getConfig: () => config,
      createRuntimePool: () => ({ connect: async () => client, end: async () => { events.push('end'); } }) as never,
      assertRetainedKeys: async () => { throw new Error('database row id and secret key'); },
    }, value => stdout.push(value), value => stderr.push(value));
    expect(status).toBe(1); expect(events).toEqual(['release:retained-key preflight failed', 'end']); expect(stdout).toEqual([]); expect(stderr).toEqual(['retained-key preflight failed\n']);
  });

  it('keeps configuration failures coarse and does not create a pool', async () => {
    const stderr: string[] = []; let created = false;
    const status = await runRetainedKeyPreflight({
      getConfig: () => { throw new Error('key material'); },
      createRuntimePool: () => { created = true; throw new Error('unreachable'); },
      assertRetainedKeys: async () => undefined,
    }, () => undefined, value => stderr.push(value));
    expect(status).toBe(1); expect(created).toBe(false); expect(stderr).toEqual(['retained-key preflight failed\n']);
  });
});
