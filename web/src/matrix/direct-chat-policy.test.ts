import { describe, expect, it } from 'vitest';
import { assessDirectRoomAdmission, buildDirectRoomCreateRequest, canInitiateSas, type DirectMember } from './direct-chat-policy';

const room = (members: readonly DirectMember[] = [{ userId: '@me:test', membership: 'join' }, { userId: '@peer:test', membership: 'invite' }]) => ({ selfUserId: '@me:test', peerUserId: '@peer:test', members, joinRule: 'invite', historyVisibility: 'joined', encryptionAlgorithm: 'm.megolm.v1.aes-sha2', rustCryptoPersistent: true });
describe('direct room policy', () => {
  it('admits exactly self and peer for verification but requires both joined for SAS', () => {
    expect(assessDirectRoomAdmission(room())).toEqual({ admitted: true, verificationOnly: true });
    expect(canInitiateSas(room())).toBe(false);
    expect(canInitiateSas(room([{ userId: '@me:test', membership: 'join' }, { userId: '@peer:test', membership: 'join' }]))).toBe(true);
    expect(assessDirectRoomAdmission(room([{ userId: '@me:test', membership: 'join' }, { userId: '@peer:test', membership: 'join' }, { userId: '@third:test', membership: 'knock' }]))).toEqual({ admitted: false, reason: 'invalid-members' });
  });
  it('builds a fixed one-peer private encrypted request', () => {
    expect(buildDirectRoomCreateRequest('@peer:test').invite).toEqual(['@peer:test']);
    expect(() => buildDirectRoomCreateRequest('')).toThrow('invalid-peer');
  });
});
