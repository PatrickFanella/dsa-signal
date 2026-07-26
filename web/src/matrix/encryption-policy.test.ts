import { describe, expect, it } from 'vitest';
import { EncryptionPolicyEpoch, MEGOLM_V1_AES_SHA2, assessPostAdmission, assessPreJoinAdmission, buildEncryptedRoomCreateRequest, type AdmissionResult } from './encryption-policy';

const state = [
  { type: 'm.room.join_rules', stateKey: '', content: { join_rule: 'invite' } },
  { type: 'm.room.encryption', stateKey: '', content: { algorithm: MEGOLM_V1_AES_SHA2 } },
  { type: 'm.room.history_visibility', stateKey: '', content: { history_visibility: 'joined' } },
] as const;
const reasonOf = (result: AdmissionResult): string => result.allowed ? '' : result.reason;

describe('encryption policy', () => {
  it('creates a private invite-only megolm request without override options', () => {
    expect(buildEncryptedRoomCreateRequest(['@a:test'])).toEqual({ visibility: 'private', preset: 'private_chat', invite: ['@a:test'], initial_state: [
      { type: 'm.room.join_rules', state_key: '', content: { join_rule: 'invite' } },
      { type: 'm.room.encryption', state_key: '', content: { algorithm: MEGOLM_V1_AES_SHA2 } },
      { type: 'm.room.history_visibility', state_key: '', content: { history_visibility: 'joined' } },
    ] });
  });

  it('requires an invite and exactly one correct stripped event of each kind', () => {
    expect(assessPreJoinAdmission({ membership: { userId: '@a:test', membership: 'invite' }, strippedState: state })).toEqual({ allowed: true });
    for (const strippedState of [[], [...state, state[0]], [{ ...state[0], content: { join_rule: 'public' } }, state[1]]]) {
      expect(assessPreJoinAdmission({ membership: { userId: '@a:test', membership: 'invite' }, strippedState }).allowed).toBe(false);
    }
    expect(reasonOf(assessPreJoinAdmission({ membership: { userId: '@a:test', membership: 'join' }, strippedState: state }))).toBe('not-invited');
  });

  it('blocks absent state, nonpersistent crypto, incomplete and untrusted devices', () => {
    const base = { currentState: state, rustCryptoPersistent: true, encryptionTargetMembers: [{ userId: '@a:test', membership: 'join' }] as const };
    expect(reasonOf(assessPostAdmission({ ...base, currentState: [], devicesByUser: new Map() }))).toBe('invalid-room-state');
    expect(reasonOf(assessPostAdmission({ ...base, currentState: [...state, state[1]], devicesByUser: new Map() }))).toBe('invalid-room-state');
    expect(reasonOf(assessPostAdmission({ ...base, currentState: [state[0], { ...state[1], content: { algorithm: 'm.megolm.v0.aes-sha2' } }], devicesByUser: new Map() }))).toBe('invalid-room-state');
    expect(reasonOf(assessPostAdmission({ ...base, rustCryptoPersistent: false, devicesByUser: new Map() }))).toBe('rust-crypto-unavailable');
    expect(reasonOf(assessPostAdmission({ ...base, devicesByUser: new Map() }))).toBe('incomplete-device-enumeration');
    for (const device of [{ known: false, signed: true, verified: true }, { known: true, signed: false, verified: true }, { known: true, signed: true, verified: false }]) {
      expect(reasonOf(assessPostAdmission({ ...base, devicesByUser: new Map([['@a:test', { complete: true, devices: [{ deviceId: 'd', ...device }] }]]) }))).toBe('unverified-device');
    }
    expect(assessPostAdmission({ ...base, devicesByUser: new Map([['@a:test', { complete: true, devices: [{ deviceId: 'd', known: true, signed: true, verified: true }] }]]) })).toEqual({ allowed: true });
    expect(reasonOf(assessPostAdmission({ ...base, devicesByUser: new Map([['@a:test', { complete: true, devices: [{ deviceId: '', known: true, signed: true, verified: true }] }]]) }))).toBe('unverified-device');
    expect(reasonOf(assessPostAdmission({ ...base, devicesByUser: new Map([['@a:test', { complete: true, devices: [{ deviceId: 'd', known: true, signed: true, verified: true }, { deviceId: 'd', known: true, signed: true, verified: true }] }]]) }))).toBe('unverified-device');
  });

  it('does not invoke a capability when an async admission sees epoch drift', async () => {
    const epoch = new EncryptionPolicyEpoch();
    let called = false;
    const result = await epoch.runGuarded(async () => { epoch.devicesChanged(); return { allowed: true }; }, async () => { called = true; return 'joined'; });
    expect(result).toEqual({ admitted: false, result: { allowed: false, reason: 'policy-epoch-drift', unverified: false } });
    expect(called).toBe(false);
  });

  it('runs a stable guarded capability', async () => {
    const epoch = new EncryptionPolicyEpoch();
    epoch.roomStateChanged(); epoch.membershipChanged(); epoch.devicesChanged(); epoch.userTrustOrKeysChanged();
    expect(epoch.value).toBe(4);
    await expect(epoch.runGuarded(() => ({ allowed: true }), async () => 'created')).resolves.toEqual({ admitted: true, value: 'created' });
  });

});
