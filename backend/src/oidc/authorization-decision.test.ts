import { createHmac } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { describe, expect, it } from 'vitest';
import { createAuthorizationCodeClaim, createAuthorizationHooks, createResumePreflight, createTokenPreflight, loadLiveAuthorizationDecision, OidcAuthorizationRejectedError } from './authorization-decision.js';
import { oidcRequestContext, type OidcRequestContext } from './request-context.js';

const uid = 'A'.repeat(43);
const cid = 'B'.repeat(43);
const index = { active: 'key', keys: { key: Buffer.alloc(32) } };
const denial = { error: 'access_denied', error_description: 'Access denied' };

function preflight(details: Record<string, unknown> | undefined) {
  class Adapter { async find(): Promise<Record<string, unknown> | undefined> { return details; } }
  return createResumePreflight('C'.repeat(22), index, Adapter as never);
}

describe('OIDC terminal denial resume preflight', () => {
  it('resolves an exact terminal denial without an ALS context', async () => {
    await expect(preflight({ jti: uid, cid, result: denial })({ url: `/auth/${uid}` } as never, {} as never)).resolves.toBeUndefined();
  });

  it.each([
    ['wrong jti', { jti: cid, cid, result: denial }],
    ['malformed cid', { jti: uid, cid: 'bad', result: denial }],
    ['other error', { jti: uid, cid, result: { ...denial, error: 'server_error' } }],
    ['missing description', { jti: uid, cid, result: { error: 'access_denied' } }],
    ['wrong description', { jti: uid, cid, result: { ...denial, error_description: 'Denied' } }],
    ['extra result field', { jti: uid, cid, result: { ...denial, extra: true } }],
    ['consent presence', { jti: uid, cid, result: { ...denial, consent: {} } }],
    ['own grantId', { jti: uid, cid, result: denial, grantId: undefined }],
  ])('rejects %s before ALS work', async (_name, details) => {
    await expect(preflight(details)({ url: `/auth/${uid}` } as never, {} as never)).rejects.toThrow('resume binding unavailable');
  });
});

const epoch = 'E'.repeat(22);
const clientId = 'token-client';
const code = 'C'.repeat(43);
const grantId = 'G'.repeat(43);
const alternateGrantId = 'H'.repeat(43);
const sessionUid = 'S'.repeat(43);
const alternateSessionUid = 'T'.repeat(43);
const decisionNow = new Date('2026-07-20T12:00:00.000Z');
const indexRing = { active: 'current', keys: { current: Buffer.alloc(32, 1), retained: Buffer.alloc(32, 2) } };
const controlFingerprint = Buffer.alloc(32, 3);
const artifactFingerprint = Buffer.alloc(32, 4);
const contextId = 'context-id';
const liveDecision = {
  mapping_id: 'mapping-id', entitlement_id: 'entitlement-id', generation: '7', jkt: 'jkt', policy_snapshot_id: 'snapshot-id', policy_version: 'v7', subject: 'subject-id',
  expires_at: new Date('2026-07-20T12:10:00.000Z'), idle_expires_at: new Date('2026-07-20T12:09:00.000Z'), absolute_expires_at: new Date('2026-07-20T12:08:00.000Z'),
};

describe('live authorization decision clock boundary', () => {
  it('refreshes the clock only after every common row lock and revalidates afterward', async () => {
    const initial = new Date('2026-07-20T11:59:00.000Z');
    const refreshed = new Date('2026-07-20T12:00:00.000Z');
    const order: string[] = [];
    const query = async (text: string, values: unknown[] = []) => {
      if (text === 'SELECT clock_timestamp() AS decision_now') { order.push('clock'); return { rowCount: 1, rows: [{ decision_now: refreshed }] }; }
      if (text.includes('membership_access_source_set_fence')) { order.push('source'); return { rowCount: 1, rows: [] }; }
      if (text.startsWith('SELECT DISTINCT mapping_id')) { order.push('candidate'); return { rowCount: 1, rows: [{ mapping_id: 'mapping-id' }] }; }
      if (text.includes('dsa-signal-membership-access')) { order.push('mapping'); return { rowCount: 1, rows: [] }; }
      if (text.includes('membership_access_states')) { order.push('state'); return { rowCount: 1, rows: [{ barrier_state: 'active' }] }; }
      if (text.startsWith('SELECT pg_advisory_xact_lock')) { order.push('advisory'); return { rowCount: 1, rows: [] }; }
      if (text.includes('identity_sessions WHERE binding_key_id')) { order.push('session'); expect(values).toEqual(['control-key', controlFingerprint]); return { rowCount: 1, rows: [] }; }
      if (text.includes('entitlements WHERE session_binding_key_id')) { order.push('entitlement'); return { rowCount: 1, rows: [] }; }
      if (text.includes('active_policy WHERE singleton=true FOR UPDATE')) { order.push('policy'); return { rowCount: 1, rows: [] }; }
      if (text.includes('p.signed_at>=to_timestamp')) { order.push('floor'); return { rowCount: 1, rows: [] }; }
      if (text.includes('SELECT s.mapping_id,e.id AS entitlement_id')) { order.push('live'); expect(values[3]).toBe(refreshed); return { rowCount: 0, rows: [] }; }
      throw new HarnessViolation(`unexpected SQL: ${text}`);
    };
    const context: OidcRequestContext = { client: { query } as never, decisionNow: initial };
    await oidcRequestContext.run(context, async () => {
      await expect(loadLiveAuthorizationDecision(epoch, 'control-key', controlFingerprint)).rejects.toBeInstanceOf(OidcAuthorizationRejectedError);
    });
    expect(context.decisionNow).toBe(refreshed);
    expect(order).toEqual(['source', 'candidate', 'mapping', 'state', 'advisory', 'session', 'entitlement', 'policy', 'clock', 'candidate', 'floor', 'live']);
  });
});

const fingerprint = (key: Uint8Array, prefix: string, value: string): Buffer => createHmac('sha256', key).update(prefix).update('\0').update(value).digest();
const clientFingerprint = () => fingerprint(indexRing.keys.current, `dsa-signal-oidc-client:v1\0${epoch}`, clientId);
const grantFingerprint = (keyId: keyof typeof indexRing.keys, id = grantId) => fingerprint(indexRing.keys[keyId], `dsa-signal-oidc-grant-id:v1\0${epoch}`, id);
const sessionFingerprint = (keyId: keyof typeof indexRing.keys, uid = sessionUid) => fingerprint(indexRing.keys[keyId], `dsa-signal-oidc-session-uid:v1\0${epoch}`, uid);

type Scenario = Readonly<{
  storedClientMismatch?: boolean;
  storedGrantMismatch?: boolean;
  storedSessionMismatch?: boolean;
  missingContext?: boolean;
  exactContextLost?: boolean;
  liveMismatch?: keyof Pick<typeof liveDecision, 'mapping_id' | 'entitlement_id' | 'generation' | 'jkt' | 'policy_snapshot_id' | 'policy_version'>;
  contextLiveness?: 'revoked' | 'expired';
  codeLiveness?: 'revoked' | 'expired';
  grantState?: 'missing' | 'revoked';
  sessions?: 'zero' | 'multiple';
  finalNow?: Date;
  finalGrantExpired?: boolean;
  finalSessionExpired?: boolean;
  finalContextExpired?: boolean;
  sessionState?: 'revoked';
}>;
type QueryCall = Readonly<{ text: string; values: unknown[] }>;
type TerminalPath = Readonly<{ name: string; matches: (call: QueryCall) => boolean }>;

class HarnessViolation extends Error {}

function expectQueryValues(actual: unknown[], expected: unknown[]): void {
  if (!isDeepStrictEqual(actual, expected)) throw new HarnessViolation('unexpected SQL parameters');
}

const initialContextLookup: TerminalPath = { name: 'initial authorization-context lookup', matches: (call) => call.text.includes('authorization_code_key_id=$2 AND authorization_code_fingerprint=$3') && !call.text.includes('FOR UPDATE') };
const lockedCodeLookup: TerminalPath = { name: 'locked authorization-code lookup', matches: (call) => call.text.includes("model='AuthorizationCode' AND artifact_key_id=$2") && call.text.includes('SELECT consumed_at') };
const liveDecisionLookup: TerminalPath = { name: 'live authorization-decision lookup', matches: (call) => call.text.includes('SELECT s.mapping_id,e.id AS entitlement_id') };
const exactContextLookup: TerminalPath = { name: 'exact live authorization-context lookup', matches: (call) => call.text.includes('client_key_id=$3 AND client_fingerprint=$4') };
const grantLookup: TerminalPath = { name: 'live Grant lookup', matches: (call) => call.text.includes("model='Grant' AND grant_key_id=$2") };
const sessionLookup: TerminalPath = { name: 'live Session lookup', matches: (call) => call.text.includes("model='Session' AND session_uid_key_id=$2") };

function tokenHarness(scenario: Scenario = {}) {
  const calls: QueryCall[] = [];
  const stored = {
    id: contextId, client_key_id: 'current', client_fingerprint: scenario.storedClientMismatch ? Buffer.alloc(32, 9) : clientFingerprint(),
    grant_key_id: 'current', grant_fingerprint: scenario.storedGrantMismatch ? Buffer.alloc(32, 8) : grantFingerprint('current'),
    provider_session_uid_key_id: 'current', provider_session_uid_fingerprint: scenario.storedSessionMismatch ? Buffer.alloc(32, 7) : sessionFingerprint('current'),
    control_session_key_id: 'control-key', control_session_fingerprint: controlFingerprint,
    mapping_id: liveDecision.mapping_id, entitlement_id: liveDecision.entitlement_id, generation: liveDecision.generation, jkt: liveDecision.jkt, policy_snapshot_id: liveDecision.policy_snapshot_id, policy_version: liveDecision.policy_version,
  };
  const live = { ...liveDecision };
  if (scenario.liveMismatch) live[scenario.liveMismatch] = scenario.liveMismatch === 'generation' ? '8' : `${live[scenario.liveMismatch]}-changed`;
  let clocks = 0;
  const clockValues: Date[] = [];
  let currentNow = decisionNow;
  const query = async (text: string, values: unknown[] = []) => {
    calls.push({ text, values });
    if (text.includes('authorization_code_key_id=$2 AND authorization_code_fingerprint=$3') && !text.includes('FOR UPDATE')) {
      expectQueryValues(values, [epoch, 'current', artifactFingerprint]);
      return scenario.missingContext ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [stored] };
    }
    if (text.startsWith("SELECT pg_advisory_xact_lock")) {
      expectQueryValues(values, text.includes('dsa-signal-membership-access') ? [liveDecision.mapping_id] : [Buffer.from(controlFingerprint.subarray(0, 8))]); return { rowCount: 1, rows: [{}] };
    }
    if (text === 'SELECT clock_timestamp() AS decision_now') { currentNow = clocks++ === 0 ? decisionNow : (scenario.finalNow ?? decisionNow); clockValues.push(currentNow); return { rowCount: 1, rows: [{ decision_now: currentNow }] }; }
    if (text.includes('membership_access_source_set_fence')) return { rowCount: 1, rows: [] };
    if (text.startsWith('SELECT DISTINCT mapping_id')) {
      expectQueryValues(values, ['control-key', controlFingerprint]);
      return { rowCount: 1, rows: [{ mapping_id: liveDecision.mapping_id }] };
    }
    if (text.includes('membership_access_states WHERE mapping_id=$1')) {
      expectQueryValues(values, [liveDecision.mapping_id]); return { rowCount: 1, rows: [{ barrier_state: 'active' }] };
    }
    if (text.includes('FROM control_plane.identity_sessions WHERE binding_key_id=$1')) {
      expectQueryValues(values, ['control-key', controlFingerprint]); return { rowCount: 1, rows: [{}] };
    }
    if (text.includes('FROM control_plane.entitlements WHERE session_binding_key_id=$1')) {
      expectQueryValues(values, ['control-key', controlFingerprint]); return { rowCount: 1, rows: [{}] };
    }
    if (text.includes('FROM control_plane.active_policy WHERE singleton=true FOR UPDATE')) {
      expectQueryValues(values, []); return { rowCount: 1, rows: [{}] };
    }
    if (text.includes('p.signed_at>=to_timestamp($1)')) {
      expectQueryValues(values, [0]); return { rowCount: 1, rows: [{}] };
    }
    if (text.includes('SELECT s.mapping_id,e.id AS entitlement_id')) {
      expectQueryValues(values, ['control-key', controlFingerprint, epoch, currentNow]); return { rowCount: 1, rows: [live] };
    }
    if (text.includes('SELECT id,revoked_at,expires_at FROM oidc.authorization_contexts')) {
      expectQueryValues(values, [contextId, epoch, 'current', artifactFingerprint]); return { rowCount: 1, rows: [{ id: contextId }] };
    }
    if (text.includes("model='AuthorizationCode' AND artifact_key_id=$2") && text.includes('SELECT consumed_at')) {
      expectQueryValues(values, [epoch, 'current', artifactFingerprint]);
      return { rowCount: 1, rows: [{ consumed_at: null, revoked_at: scenario.codeLiveness === 'revoked' ? decisionNow : null, expires_at: scenario.codeLiveness === 'expired' ? decisionNow : liveDecision.expires_at }] };
    }
    if (text.includes('client_key_id=$3 AND client_fingerprint=$4')) {
      expectQueryValues(values, [contextId, epoch, 'current', clientFingerprint(), 'current', artifactFingerprint, 'current', grantFingerprint('current'), 'current', sessionFingerprint('current'), live.mapping_id, live.entitlement_id, live.generation, live.jkt, live.policy_snapshot_id, live.policy_version, currentNow]);
      return scenario.exactContextLost || scenario.contextLiveness || (scenario.finalContextExpired && currentNow === scenario.finalNow) ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [{ id: contextId }] };
    }
    if (text.includes("model='Grant' AND grant_key_id=$2")) {
      expectQueryValues(values, [epoch, 'current', grantFingerprint('current')]);
      return scenario.grantState === 'missing' ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [{ id: 'grant-id', revoked_at: scenario.grantState === 'revoked' ? decisionNow : null, expires_at: scenario.finalGrantExpired ? scenario.finalNow : liveDecision.expires_at }] };
    }
    if (text.includes("model='Session' AND session_uid_key_id=$2")) {
      const keyId = values[1];
      if (keyId !== 'current' && keyId !== 'retained') throw new HarnessViolation('unexpected Session key ID');
      expectQueryValues(values, [epoch, keyId, sessionFingerprint(keyId)]);
      if (scenario.sessions === 'zero') return { rowCount: 0, rows: [] };
      if (scenario.sessions === 'multiple') return { rowCount: 1, rows: [{ id: `session-${keyId}` }] };
      return keyId === 'current' ? { rowCount: 1, rows: [{ id: 'session-current', revoked_at: scenario.sessionState === 'revoked' ? decisionNow : null, expires_at: scenario.finalSessionExpired ? scenario.finalNow : liveDecision.expires_at }] } : { rowCount: 0, rows: [] };
    }
    throw new HarnessViolation(`unexpected SQL: ${text}`);
  };
  return { calls, clockValues, client: { query }, stored };
}

async function redeem(scenario: Scenario = {}, payload: Record<string, unknown> = { clientId, grantId, sessionUid }) {
  const harness = tokenHarness(scenario);
  const context: OidcRequestContext = { client: harness.client as never, decisionNow: new Date('2026-07-20T11:59:00.000Z') };
  const preflight = createTokenPreflight(epoch, clientId, indexRing);
  const result = await oidcRequestContext.run(context, async () => {
    let error: unknown;
    try { await preflight(code, payload, { keyId: 'current', fingerprint: artifactFingerprint, consumedAt: null }); } catch (caught) { if (caught instanceof HarnessViolation) throw caught; error = caught; }
    return { error, context };
  });
  return { ...harness, ...result };
}

function expectNoTokenState(context: Record<string, unknown>): void {
  expect(context).not.toHaveProperty('authorizedAccount');
  expect(context).not.toHaveProperty('pendingResume');
  expect(context).not.toHaveProperty('pendingTokenRedemption');
}

describe('OIDC token preflight direct mismatch boundary', () => {
  it('sets only the deterministic pending token redemption on the successful baseline', async () => {
    const result = await redeem();
    expect(result.error).toBeUndefined();
    expect(result.context.pendingTokenRedemption).toEqual({ mappingId: 'mapping-id', subject: 'subject-id', policyVersion: 'v7', ttl: 300 });
    expect(result.context).not.toHaveProperty('authorizedAccount');
    expect(result.context).not.toHaveProperty('pendingResume');
  });

  it.each([
    ['Grant', { finalNow: new Date('2026-07-20T12:01:00.000Z'), finalGrantExpired: true }],
    ['Session', { finalNow: new Date('2026-07-20T12:01:00.000Z'), finalSessionExpired: true }],
  ] as const)('does not stage redemption when a locked %s expires during the final lock wait', async (_artifact, scenario) => {
    const result = await redeem(scenario);
    expect(result.error).toMatchObject({ message: 'token artifacts unavailable' });
    expectNoTokenState(result.context);
    expect(result.clockValues).toEqual([decisionNow, scenario.finalNow]);
  });

  const rejectionCases: ReadonlyArray<readonly [string, Scenario, Record<string, unknown> | undefined, string, TerminalPath | undefined]> = [
    ['wrong configured payload.clientId', {}, { clientId: 'other-token-client', grantId, sessionUid }, 'token binding unavailable', undefined],
    ['stored client fingerprint', { storedClientMismatch: true }, undefined, 'token artifact binding changed', initialContextLookup],
    ['supplied Grant ID', {}, { clientId, grantId: alternateGrantId, sessionUid }, 'token artifact binding changed', initialContextLookup],
    ['stored Grant fingerprint', { storedGrantMismatch: true }, undefined, 'token artifact binding changed', initialContextLookup],
    ['supplied provider Session UID', {}, { clientId, grantId, sessionUid: alternateSessionUid }, 'token artifact binding changed', initialContextLookup],
    ['stored provider Session fingerprint', { storedSessionMismatch: true }, undefined, 'token artifact binding changed', initialContextLookup],
    ['missing initial code context', { missingContext: true }, undefined, 'token context unavailable', initialContextLookup],
    ['binding lost at exact-context recheck', { exactContextLost: true }, undefined, 'token artifacts unavailable', exactContextLookup],
    ['live mapping ID', { liveMismatch: 'mapping_id' }, undefined, 'token decision changed', liveDecisionLookup],
    ['live entitlement ID', { liveMismatch: 'entitlement_id' }, undefined, 'token decision changed', liveDecisionLookup],
    ['live generation', { liveMismatch: 'generation' }, undefined, 'token decision changed', liveDecisionLookup],
    ['live JKT', { liveMismatch: 'jkt' }, undefined, 'token decision changed', liveDecisionLookup],
    ['live policy snapshot ID', { liveMismatch: 'policy_snapshot_id' }, undefined, 'token decision changed', liveDecisionLookup],
    ['live policy version', { liveMismatch: 'policy_version' }, undefined, 'token decision changed', liveDecisionLookup],
    ['revoked context excluded by exact-context liveness SQL', { contextLiveness: 'revoked' }, undefined, 'token artifacts unavailable', exactContextLookup],
    ['expired context excluded by exact-context liveness SQL', { contextLiveness: 'expired' }, undefined, 'token artifacts unavailable', exactContextLookup],
    ['revoked code', { codeLiveness: 'revoked' }, undefined, 'token code unavailable', lockedCodeLookup],
    ['expired code', { codeLiveness: 'expired' }, undefined, 'token code unavailable', lockedCodeLookup],
    ['missing Grant (then Session liveness completion)', { grantState: 'missing' }, undefined, 'token artifacts unavailable', sessionLookup],
    ['revoked Grant row', { grantState: 'revoked' }, undefined, 'token artifacts unavailable', liveDecisionLookup],
    ['revoked Session row', { sessionState: 'revoked' }, undefined, 'token artifacts unavailable', liveDecisionLookup],
    ['zero live Sessions', { sessions: 'zero' }, undefined, 'token artifacts unavailable', sessionLookup],
    ['multiple live Sessions under retained keys', { sessions: 'multiple' }, undefined, 'token artifacts unavailable', sessionLookup],
  ];
  it.each(rejectionCases)('fails closed for %s', async (_name, scenario, payload, expectedMessage, terminalPath) => {
    const result = await redeem(scenario, payload);
    expect(result.error).toBeInstanceOf(Error);
    expect((result.error as Error).message).toBe(expectedMessage);
    expectNoTokenState(result.context);
    if (terminalPath) expect(result.calls.at(-1), `last query should be ${terminalPath.name}`).toSatisfy(terminalPath.matches);
    else expect(result.calls).toHaveLength(0);
    if (scenario.contextLiveness) {
      const exact = result.calls.at(-1);
      expect(exact?.text).toContain('expires_at>$17');
      expect(exact?.text).toContain('revoked_at IS NULL');
    }
    if (scenario.grantState) {
      const grant = result.calls.find(grantLookup.matches);
      expect(grant).toBeDefined();
      expect(grant?.text).not.toContain('expires_at>');
      expect(grant?.text).not.toContain('revoked_at IS NULL');
    }
    if (scenario.sessionState) expect(result.calls.find(sessionLookup.matches)).toBeDefined();
    if (scenario.sessions) {
      const sessions = result.calls.filter((call) => call.text.includes("model='Session' AND session_uid_key_id=$2"));
      expect(sessions).not.toHaveLength(0);
      expect(sessions.every((call) => !call.text.includes('expires_at>') && !call.text.includes('revoked_at IS NULL'))).toBe(true);
    }
  });

  it('rejects a context that expires only after exact artifacts lock and the final clock advances', async () => {
    const finalNow = new Date('2026-07-20T12:01:00.000Z');
    const result = await redeem({ finalNow, finalContextExpired: true });
    expect(result.error).toMatchObject({ message: 'token artifacts unavailable' });
    expectNoTokenState(result.context);
    expect(result.clockValues).toEqual([decisionNow, finalNow]);
    expect(result.calls.at(-1)).toSatisfy(exactContextLookup.matches);
  });
});

describe('OIDC authorization-code claim final clock boundary', () => {
  it('does not update its context when policy authorization expires after exact code and Session locks', async () => {
    let clocks = 0;
    let updated = false;
    const calls: string[] = [];
    const finalNow = new Date('2026-07-20T12:01:00.000Z');
    const query = async (text: string, values: unknown[] = []) => {
      calls.push(text);
      if (text.includes("model='AuthorizationCode'")) { expectQueryValues(values, [epoch, 'current', fingerprint(indexRing.keys.current, `dsa-signal-oidc-artifact-id:v1\0${epoch}\0AuthorizationCode`, code)]); return { rowCount: 1, rows: [{ expires_at: new Date('2026-07-20T12:02:00.000Z'), revoked_at: null }] }; }
      if (text.includes("model='Session'")) { expectQueryValues(values, [epoch, 'current', sessionFingerprint('current')]); return { rowCount: 1, rows: [{ expires_at: new Date('2026-07-20T12:02:00.000Z'), revoked_at: null }] }; }
      if (text === 'SELECT clock_timestamp() AS decision_now') return { rowCount: 1, rows: [{ decision_now: clocks++ === 0 ? finalNow : decisionNow }] };
      if (text.includes('p.signed_at>=to_timestamp')) return { rowCount: 1, rows: [{}] };
      if (text.includes('SELECT s.mapping_id,e.id AS entitlement_id')) return { rowCount: 0, rows: [] };
      if (text.startsWith('UPDATE oidc.authorization_contexts')) { updated = true; return { rowCount: 1, rows: [] }; }
      throw new HarnessViolation(`unexpected SQL: ${text}`);
    };
    const context: OidcRequestContext = { client: { query } as never, decisionNow, pendingResume: { contextId, grantId, interactionChain: cid, interactionUid: uid, indexKeyId: 'current', mappingId: 'mapping-id', entitlementId: 'entitlement-id', generation: 7n, jkt: 'jkt', policySnapshotId: 'snapshot-id', policyVersion: 'v7', minimumIssuedAt: 0, controlSessionKeyId: 'control-key', controlSessionFingerprint: controlFingerprint } };
    await oidcRequestContext.run(context, async () => {
      const claim = createAuthorizationCodeClaim(epoch, indexRing);
      await claim(code, { grantId, sessionUid });
      await expect(context.pendingCodeClaim!.finalize()).rejects.toThrow('authorization rejected');
    });
    expect(updated).toBe(false);
    expect(clocks).toBe(1);
    expect(calls.findIndex(text => text.includes("model='AuthorizationCode'"))).toBeLessThan(calls.findIndex(text => text.includes("model='Session'")));
    expect(calls.findIndex(text => text.includes("model='Session'"))).toBeLessThan(calls.indexOf('SELECT clock_timestamp() AS decision_now'));
    expect(calls.at(-1)).toContain('SELECT s.mapping_id,e.id AS entitlement_id');
  });
});

describe('OIDC resume late-lock boundaries', () => {
  it('does not authorize a resume when its exact context expires after the common locks', async () => {
    const initial = new Date('2026-07-20T11:59:00.000Z');
    const finalNow = new Date('2026-07-20T12:01:00.000Z');
    const clocks: Date[] = []; const calls: string[] = [];
    const query = async (text: string, values: unknown[] = []) => {
      calls.push(text);
      if (text.includes('grant_key_id=$2') && text.includes('expires_at>$6')) return values[1] === 'current' ? { rowCount: 1, rows: [{ id: contextId, control_session_key_id: 'control-key', control_session_fingerprint: controlFingerprint, mapping_id: 'mapping-id', entitlement_id: 'entitlement-id', generation: '7', jkt: 'jkt', policy_snapshot_id: 'snapshot-id', policy_version: 'v7' }] } : { rowCount: 0, rows: [] };
      if (text === 'SELECT clock_timestamp() AS decision_now') { const now = clocks.length === 0 ? decisionNow : finalNow; clocks.push(now); return { rowCount: 1, rows: [{ decision_now: now }] }; }
      if (text.includes('membership_access_source_set_fence') || text.includes('dsa-signal-membership-access') || text.startsWith('SELECT pg_advisory_xact_lock') || text.includes('identity_sessions WHERE binding_key_id') || text.includes('entitlements WHERE session_binding_key_id') || text.includes('active_policy WHERE singleton=true FOR UPDATE') || text.includes('p.signed_at>=to_timestamp')) return { rowCount: 1, rows: [{}] };
      if (text.startsWith('SELECT DISTINCT mapping_id')) return { rowCount: 1, rows: [{ mapping_id: 'mapping-id' }] };
      if (text.includes('membership_access_states')) return { rowCount: 1, rows: [{ barrier_state: 'active' }] };
      if (text.includes('SELECT s.mapping_id,e.id AS entitlement_id')) return { rowCount: clocks.length === 1 ? 1 : 0, rows: clocks.length === 1 ? [liveDecision] : [] };
      if (text.includes('FROM oidc.authorization_contexts') && text.includes('FOR UPDATE')) return { rowCount: 1, rows: [{ revoked_at: null, expires_at: new Date('2026-07-20T12:00:30.000Z'), mapping_id: 'mapping-id', entitlement_id: 'entitlement-id', generation: '7', jkt: 'jkt', policy_snapshot_id: 'snapshot-id', policy_version: 'v7' }] };
      throw new HarnessViolation(`unexpected SQL: ${text}`);
    };
    class Adapter { async find() { return { jti: uid, cid, result: { consent: { grantId } } }; } }
    const context: OidcRequestContext = { client: { query } as never, decisionNow: initial };
    await oidcRequestContext.run(context, async () => await expect(createResumePreflight(epoch, indexRing, Adapter)({ url: `/auth/${uid}` } as never, {} as never)).rejects.toThrow('authorization rejected'));
    expect(clocks).toEqual([decisionNow, finalNow]);
    expect(calls.findIndex(text => text.includes('FROM oidc.authorization_contexts') && text.includes('FOR UPDATE'))).toBeLessThan(calls.lastIndexOf('SELECT clock_timestamp() AS decision_now'));
    expect(calls.at(-1)).toContain('SELECT s.mapping_id,e.id AS entitlement_id');
    expect(context).not.toHaveProperty('authorizedAccount');
    expect(context).not.toHaveProperty('pendingResume');
  });

  it('rejects findAccount when the refreshed clock makes its exact resume context no longer live', async () => {
    const finalNow = new Date('2026-07-20T12:01:00.000Z');
    const calls: string[] = [];
    const query = async (text: string) => {
      calls.push(text);
      if (text.includes('FROM oidc.authorization_contexts')) return { rowCount: 1, rows: [{ mapping_id: 'mapping-id', entitlement_id: 'entitlement-id', generation: '7', jkt: 'jkt', policy_snapshot_id: 'snapshot-id', policy_version: 'v7', expires_at: new Date('2026-07-20T12:00:30.000Z'), revoked_at: null, control_session_key_id: 'control-key', control_session_fingerprint: controlFingerprint }] };
      if (text === 'SELECT clock_timestamp() AS decision_now') return { rowCount: 1, rows: [{ decision_now: finalNow }] };
      if (text.includes('p.signed_at>=to_timestamp')) return { rowCount: 1, rows: [{}] };
      if (text.includes('SELECT s.mapping_id,e.id AS entitlement_id')) return { rowCount: 0, rows: [] };
      throw new HarnessViolation(`unexpected SQL: ${text}`);
    };
    const context: OidcRequestContext = { client: { query } as never, decisionNow, authorizedAccount: { mappingId: 'mapping-id', subject: 'subject-id', policyVersion: 'v7' }, pendingResume: { contextId, grantId, interactionChain: cid, interactionUid: uid, indexKeyId: 'current', mappingId: 'mapping-id', entitlementId: 'entitlement-id', generation: 7n, jkt: 'jkt', policySnapshotId: 'snapshot-id', policyVersion: 'v7', minimumIssuedAt: 0, controlSessionKeyId: 'control-key', controlSessionFingerprint: controlFingerprint } };
    await oidcRequestContext.run(context, async () => await expect(createAuthorizationHooks(epoch, indexRing).findAccount({ oidc: { result: { consent: { grantId } } } }, 'mapping-id')).rejects.toThrow('authorization rejected'));
    expect(finalNow.getTime()).toBeGreaterThan(decisionNow.getTime());
    expect(calls.at(-1)).toContain('SELECT s.mapping_id,e.id AS entitlement_id');
  });
});
