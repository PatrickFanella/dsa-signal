import { INVITE_JOIN_RULE, JOINED_HISTORY_VISIBILITY, MEGOLM_V1_AES_SHA2, type EncryptedRoomCreateRequest } from './encryption-policy';

export type DirectMembership = 'invite' | 'join' | 'leave' | 'ban' | 'knock';
export interface DirectMember { readonly userId: string; readonly membership: DirectMembership; }
export interface DirectRoomPolicySnapshot {
  readonly selfUserId: string;
  readonly peerUserId: string;
  readonly members: readonly DirectMember[];
  readonly joinRule: string;
  readonly historyVisibility: string;
  readonly encryptionAlgorithm: string;
  readonly rustCryptoPersistent: boolean;
}
export type DirectRoomAdmission = { readonly admitted: true; readonly verificationOnly: boolean } | { readonly admitted: false; readonly reason: 'invalid-peer' | 'invalid-state' | 'invalid-members' | 'rust-crypto-unavailable' | 'not-both-joined' };
const active = (membership: DirectMembership): boolean => membership === 'invite' || membership === 'join' || membership === 'knock';

/** Verification admission is deliberately weaker than sending: invite/knock is safe but cannot send. */
export const assessDirectRoomAdmission = (snapshot: DirectRoomPolicySnapshot): DirectRoomAdmission => {
  if (!snapshot.selfUserId || !snapshot.peerUserId || snapshot.selfUserId === snapshot.peerUserId) return { admitted: false, reason: 'invalid-peer' };
  if (snapshot.joinRule !== INVITE_JOIN_RULE || snapshot.historyVisibility !== JOINED_HISTORY_VISIBILITY || snapshot.encryptionAlgorithm !== MEGOLM_V1_AES_SHA2) return { admitted: false, reason: 'invalid-state' };
  if (!snapshot.rustCryptoPersistent) return { admitted: false, reason: 'rust-crypto-unavailable' };
  const members = snapshot.members.filter(member => active(member.membership));
  if (members.length !== 2 || new Set(members.map(member => member.userId)).size !== 2 || !members.some(member => member.userId === snapshot.selfUserId) || !members.some(member => member.userId === snapshot.peerUserId)) return { admitted: false, reason: 'invalid-members' };
  return { admitted: true, verificationOnly: !members.every(member => member.membership === 'join') };
};
export const canInitiateSas = (snapshot: DirectRoomPolicySnapshot): boolean => {
  const admission = assessDirectRoomAdmission(snapshot);
  return admission.admitted && !admission.verificationOnly;
};
/** No caller-controlled options or multiple invitees can weaken a direct-room create request. */
export const buildDirectRoomCreateRequest = (peerUserId: string): EncryptedRoomCreateRequest => {
  if (!peerUserId) throw new Error('invalid-peer');
  return { visibility: 'private', preset: 'private_chat', invite: [peerUserId], initial_state: [
    { type: 'm.room.join_rules', state_key: '', content: { join_rule: INVITE_JOIN_RULE } },
    { type: 'm.room.encryption', state_key: '', content: { algorithm: MEGOLM_V1_AES_SHA2 } },
    { type: 'm.room.history_visibility', state_key: '', content: { history_visibility: JOINED_HISTORY_VISIBILITY } },
  ] };
};
