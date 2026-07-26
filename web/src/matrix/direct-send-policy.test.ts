import { describe, expect, it } from 'vitest';
import { MEGOLM_V1_AES_SHA2, assessDirectSendReadiness, type AdmissionResult } from './encryption-policy';

const reasonOf = (result: AdmissionResult): string => result.allowed ? '' : result.reason;
describe('direct send policy', () => {
  it('requires fresh exact keys and identity trust before direct sending', () => {
    const state = [{ type: 'm.room.join_rules', stateKey: '', content: { join_rule: 'invite' } }, { type: 'm.room.encryption', stateKey: '', content: { algorithm: MEGOLM_V1_AES_SHA2 } }, { type: 'm.room.history_visibility', stateKey: '', content: { history_visibility: 'joined' } }] as const;
    const devices: readonly { readonly deviceId: string; readonly ed25519Fingerprint: string; readonly curve25519Fingerprint: string }[] = [{ deviceId: 'd', ed25519Fingerprint: 'ed', curve25519Fingerprint: 'curve' }];
    const snapshot = { currentState: state, rustCryptoPersistent: true, encryptionTargetMembers: [{ userId: '@me:test', membership: 'join' }, { userId: '@peer:test', membership: 'join' }] as const, devicesByUser: new Map([['@me:test', { complete: true, devices: [{ deviceId: 'd', known: true, signed: true, verified: true }] }], ['@peer:test', { complete: true, devices: [{ deviceId: 'd', known: true, signed: true, verified: true }] }]]), selfUserId: '@me:test', peerUserId: '@peer:test', activeMembers: [{ userId: '@me:test', membership: 'join' }, { userId: '@peer:test', membership: 'join' }] as const, ownCurrentDeviceReady: true, identities: new Map([['@me:test', { known: true, crossSigningVerified: true, awaitingApproval: false }], ['@peer:test', { known: true, crossSigningVerified: true, awaitingApproval: false }]]), keysQueryFailures: [], authoritativeDevicesByUser: new Map([['@me:test', devices], ['@peer:test', devices]]), rustDevicesByUser: new Map([['@me:test', devices], ['@peer:test', devices]]) };
    expect(assessDirectSendReadiness(snapshot)).toEqual({ allowed: true });
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, keysQueryFailures: ['@peer:test'] }))).toBe('keys-query-failed');
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, rustDevicesByUser: new Map([['@me:test', devices], ['@peer:test', [{ ...devices[0], ed25519Fingerprint: 'wrong' }]]]) }))).toBe('authoritative-key-mismatch');
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, authoritativeDevicesByUser: new Map([['@me:test', [...devices, { ...devices[0], ed25519Fingerprint: 'other' }]], ['@peer:test', devices]]) }))).toBe('authoritative-key-mismatch');
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, rustDevicesByUser: new Map([['@me:test', devices], ['@peer:test', [...devices, { deviceId: 'extra', ed25519Fingerprint: 'ed2', curve25519Fingerprint: 'curve2' }]]]) }))).toBe('authoritative-key-mismatch');
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, devicesByUser: new Map([['@me:test', { complete: true, devices: [{ deviceId: 'other', known: true, signed: true, verified: true }] }], ['@peer:test', { complete: true, devices: [{ deviceId: 'd', known: true, signed: true, verified: true }] }]]) }))).toBe('authoritative-key-mismatch');
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, activeMembers: [...snapshot.activeMembers, { userId: '@third:test', membership: 'invite' }] }))).toBe('invalid-room-state');
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, activeMembers: [...snapshot.activeMembers, { userId: '@third:test', membership: 'knock' }] }))).toBe('invalid-room-state');
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, activeMembers: [{ userId: '@me:test', membership: 'join' }, { userId: '@peer:test', membership: 'invite' }] }))).toBe('invalid-room-state');
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, ownCurrentDeviceReady: false }))).toBe('identity-not-ready');
    for (const identity of [{ known: false, crossSigningVerified: true, awaitingApproval: false }, { known: true, crossSigningVerified: false, awaitingApproval: false }, { known: true, crossSigningVerified: true, awaitingApproval: true }]) expect(reasonOf(assessDirectSendReadiness({ ...snapshot, identities: new Map([['@me:test', { known: true, crossSigningVerified: true, awaitingApproval: false }], ['@peer:test', identity]]) }))).toBe('identity-not-ready');
    expect(reasonOf(assessDirectSendReadiness({ ...snapshot, authoritativeDevicesByUser: new Map([['@me:test', []], ['@peer:test', devices]]) }))).toBe('authoritative-key-mismatch');
  });
});
