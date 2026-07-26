import { EventEmitter } from 'node:events';
import { describe, expect, it } from 'vitest';
import { drainOidcAdapterQueue, OidcIndeterminateCommitError, OidcRequestCancelledError, runOidcTransaction, serializeOidcAdapterCall, type OidcRequestContext } from './request-context.js';
import { createTransactionalProviderInvocation } from '../routes/oidc.js';
import { requireOidcRequestContext } from './request-context.js';

function database(options: Readonly<{ fail?: (sql: string) => Error | undefined }> = {}) {
  const sql: string[] = []; let released: Error | undefined;
  const client = {
    query: async (statement: string) => {
      sql.push(statement);
      const failure = options.fail?.(statement);
      if (failure) throw failure;
      return statement.startsWith('SELECT clock_timestamp') ? { rows: [{ decision_now: new Date(0) }], rowCount: 1 } : { rows: [], rowCount: 1 };
    },
    release: (error?: Error) => { released = error; },
  };
  return { pool: { connect: async () => client } as never, sql, released: () => released };
}

describe('OIDC request transaction disposition', () => {
  it('settles later queued calls before rollback and preserves the first failure', async () => {
    const db = database(); const finished: string[] = []; const first = new Error('first');
    await expect(runOidcTransaction(db.pool, async () => {
      const one = serializeOidcAdapterCall(async () => { finished.push('one'); throw first; });
      const two = serializeOidcAdapterCall(async () => { finished.push('two'); });
      await expect(one).rejects.toBe(first); await two;
      await drainOidcAdapterQueue();
    })).rejects.toBe(first);
    expect(finished).toEqual(['one', 'two']);
    expect(db.sql.at(-1)).toBe('ROLLBACK');
  });

  it('drains queued work even when request work throws first', async () => {
    const db = database(); const finished: string[] = [];
    await expect(runOidcTransaction(db.pool, async () => {
      void serializeOidcAdapterCall(async () => { await Promise.resolve(); finished.push('queued'); });
      throw new Error('request failed');
    })).rejects.toThrow('request failed');
    expect(finished).toEqual(['queued']);
    expect(db.sql.at(-1)).toBe('ROLLBACK');
  });

  it('prioritizes cancellation latched during queue drain over an earlier work failure', async () => {
    const db = database(); let context: OidcRequestContext | undefined;
    let started!: () => void; const didStart = new Promise<void>(resolve => { started = resolve; });
    let finish!: () => void; const canFinish = new Promise<void>(resolve => { finish = resolve; });
    const pending = runOidcTransaction(db.pool, async active => {
      context = active;
      void serializeOidcAdapterCall(async () => { started(); await canFinish; });
      throw new Error('finalization failed');
    });
    await didStart; context!.requestCancelled = true; finish();
    await expect(pending).rejects.toBeInstanceOf(OidcRequestCancelledError);
    expect(db.sql.at(-1)).toBe('ROLLBACK');
  });

  it('commits successful work and fully rolls back pre-consume errors', async () => {
    const success = database(); await runOidcTransaction(success.pool, async () => undefined);
    expect(success.sql).toContain('COMMIT');
    const failed = database(); await expect(runOidcTransaction(failed.pool, async () => { throw new Error('no code'); })).rejects.toThrow('no code');
    expect(failed.sql).toContain('ROLLBACK');
  });

  it('rolls back post-consume work to its savepoint and commits only consumption', async () => {
    const db = database(); await expect(runOidcTransaction(db.pool, async (context) => { context.tokenConsumeSavepoint = 'oidc_after_code_consume'; throw new Error('render'); })).rejects.toThrow('render');
    expect(db.sql).toContain('ROLLBACK TO SAVEPOINT oidc_after_code_consume');
    expect(db.sql).toContain('COMMIT');
  });

  it('does not retry failed savepoint recovery before a full rollback', async () => {
    const db = database({ fail: (sql) => sql.startsWith('ROLLBACK TO SAVEPOINT') ? Object.assign(new Error('savepoint failed'), { code: '3B001' }) : undefined });
    await expect(runOidcTransaction(db.pool, async (context) => { context.tokenConsumeSavepoint = 'oidc_after_code_consume'; throw new Error('render'); })).rejects.toThrow('render');
    expect(db.sql.filter(sql => sql.startsWith('ROLLBACK TO SAVEPOINT'))).toHaveLength(1);
    expect(db.sql.at(-1)).toBe('ROLLBACK');
  });

  it('commits replay revocation 4xx without a savepoint and uses consumption-only commit for a consumed 4xx', async () => {
    const replay = database(); await runOidcTransaction(replay.pool, async (context) => { context.providerResponseStatus = 400; });
    expect(replay.sql).toContain('COMMIT'); expect(replay.sql).not.toContainEqual(expect.stringMatching(/^ROLLBACK TO/));
    const consumed = database(); await runOidcTransaction(consumed.pool, async (context) => { context.tokenConsumeSavepoint = 'oidc_after_code_consume'; context.providerResponseStatus = 400; });
    expect(consumed.sql).toContain('ROLLBACK TO SAVEPOINT oidc_after_code_consume'); expect(consumed.sql).toContain('COMMIT');
  });

  it('distinguishes definite from indeterminate COMMIT failures and poisons only the latter', async () => {
    const definite = database({ fail: (sql) => sql === 'COMMIT' ? Object.assign(new Error('constraint'), { code: '23505' }) : undefined });
    await expect(runOidcTransaction(definite.pool, async () => undefined)).rejects.toThrow('constraint');
    expect(definite.sql).toContain('ROLLBACK'); expect(definite.released()).toBeUndefined();
    const unknown = database({ fail: (sql) => sql === 'COMMIT' ? new Error('disconnect') : undefined });
    await expect(runOidcTransaction(unknown.pool, async () => undefined)).rejects.toBeInstanceOf(OidcIndeterminateCommitError);
    expect(unknown.released()).toBeInstanceOf(OidcIndeterminateCommitError);
    expect(unknown.sql).not.toContain('ROLLBACK');

    for (const code of ['ECONNRESET', 'EPIPE', '40003', '08006', '57P01']) {
      const uncertain = database({ fail: (sql) => sql === 'COMMIT' ? Object.assign(new Error(code), { code }) : undefined });
      await expect(runOidcTransaction(uncertain.pool, async () => undefined)).rejects.toBeInstanceOf(OidcIndeterminateCommitError);
      expect(uncertain.sql).not.toContain('ROLLBACK');
    }
  });

  it('propagates an indeterminate consumption-only commit without further SQL', async () => {
    const db = database({ fail: (sql) => sql === 'COMMIT' ? Object.assign(new Error('reset'), { code: 'ECONNRESET' }) : undefined });
    await expect(runOidcTransaction(db.pool, async (context) => { context.tokenConsumeSavepoint = 'oidc_after_code_consume'; throw new Error('post-consume'); })).rejects.toBeInstanceOf(OidcIndeterminateCommitError);
    expect(db.sql.filter(sql => sql === 'ROLLBACK')).toHaveLength(0);
    expect(db.released()).toBeInstanceOf(OidcIndeterminateCommitError);
  });

  it('flushes a handled consumed 4xx only after commit, and destroys on an indeterminate commit', async () => {
    const response = () => {
      const output: string[] = []; let destroyed = false;
      const value = {
        statusCode: 200, write: (chunk: unknown) => { output.push(String(chunk)); return true; }, end: (chunk?: unknown) => { if (chunk !== undefined) output.push(String(chunk)); return value; }, writeHead: (status: number) => { value.statusCode = status; return value; }, getHeaderNames: () => [], removeHeader: () => undefined, destroy: () => { destroyed = true; },
      };
      return { value, output, destroyed: () => destroyed };
    };
    const handled = database(); const handledResponse = response();
    const invoke = createTransactionalProviderInvocation(handled.pool as never, { callback: () => (_req: unknown, res: typeof handledResponse.value) => { requireOidcRequestContext().tokenConsumeSavepoint = 'oidc_after_code_consume'; res.writeHead(400); res.end('oauth-error'); } } as never);
    await invoke({} as never, handledResponse.value as never);
    expect(handled.sql).toContain('COMMIT');
    expect(handledResponse.output).toContain('oauth-error');
    const unknown = database({ fail: (sql) => sql === 'COMMIT' ? new Error('lost') : undefined }); const unknownResponse = response();
    const bad = createTransactionalProviderInvocation(unknown.pool as never, { callback: () => (_req: unknown, res: typeof unknownResponse.value) => { requireOidcRequestContext().tokenConsumeSavepoint = 'oidc_after_code_consume'; res.writeHead(500); res.end('failure'); } } as never);
    await bad({} as never, unknownResponse.value as never);
    expect(unknown.sql).toContain('ROLLBACK TO SAVEPOINT oidc_after_code_consume');
    expect(unknownResponse.destroyed()).toBe(true); expect(unknownResponse.output).toEqual([]);
  });

  it('waits for provider settlement after cancellation, commits consumption only, and emits nothing', async () => {
    const db = database(); const request = new EventEmitter(); const response = new EventEmitter() as EventEmitter & Record<string, unknown>;
    const output: string[] = []; let destroyed = false;
    Object.assign(response, {
      statusCode: 200,
      write: (chunk: unknown) => { output.push(String(chunk)); return true; },
      end: (chunk?: unknown) => { if (chunk !== undefined) output.push(String(chunk)); return response; },
      writeHead: (status: number) => { response.statusCode = status; return response; },
      getHeaderNames: () => [], removeHeader: () => undefined, destroy: () => { destroyed = true; },
    });
    let started!: () => void; const didStart = new Promise<void>(resolve => { started = resolve; });
    let finish!: () => void; const canFinish = new Promise<void>(resolve => { finish = resolve; });
    const provider = { callback: () => async () => { requireOidcRequestContext().tokenConsumeSavepoint = 'oidc_after_code_consume'; started(); await canFinish; } };
    const invocation = createTransactionalProviderInvocation(db.pool as never, provider as never);
    const pending = invocation(request as never, response as never);
    await didStart; request.emit('aborted'); finish(); await pending;
    expect(db.sql).toContain('ROLLBACK TO SAVEPOINT oidc_after_code_consume');
    expect(db.sql).toContain('COMMIT');
    expect(destroyed).toBe(true); expect(output).toEqual([]);
  });
});
