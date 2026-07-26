/**
 * Matrix protocol policy expressed as application-owned data.  The SDK adapter
 * translates these DTOs at its boundary; it must not make policy decisions.
 */
export const ROOM_JOIN_RULES_EVENT_TYPE = 'm.room.join_rules' as const;
export const ROOM_ENCRYPTION_EVENT_TYPE = 'm.room.encryption' as const;
export const ROOM_HISTORY_VISIBILITY_EVENT_TYPE = 'm.room.history_visibility' as const;
export const INVITE_JOIN_RULE = 'invite' as const;
export const JOINED_HISTORY_VISIBILITY = 'joined' as const;
export const MEGOLM_V1_AES_SHA2 = 'm.megolm.v1.aes-sha2' as const;

export interface RoomStateEvent {
  readonly type: string;
  readonly stateKey: string;
  readonly content: Readonly<Record<string, unknown>>;
}

export interface Membership {
  readonly userId: string;
  readonly membership: 'invite' | 'join' | 'leave' | 'ban' | 'knock';
}

export interface EncryptionTargetMember {
  readonly userId: string;
  readonly membership: Membership['membership'];
}

export interface DeviceTrust {
  readonly deviceId: string;
  readonly known: boolean;
  readonly signed: boolean;
  readonly verified: boolean;
}

export interface DeviceEnumeration {
  /** False until the Rust crypto machine has completely enumerated this user. */
  readonly complete: boolean;
  readonly devices: readonly DeviceTrust[];
}

export interface PreJoinSnapshot {
  readonly membership: Membership | undefined;
  readonly strippedState: readonly RoomStateEvent[];
}

export interface PostAdmissionSnapshot {
  readonly currentState: readonly RoomStateEvent[];
  /** Persistent Rust crypto, not a transient or legacy crypto implementation. */
  readonly rustCryptoPersistent: boolean;
  /** The actual recipients selected by the encryption layer. */
  readonly encryptionTargetMembers: readonly EncryptionTargetMember[];
  readonly devicesByUser: ReadonlyMap<string, DeviceEnumeration>;
}

export type AdmissionFailure =
  | 'not-invited'
  | 'invalid-room-state'
  | 'rust-crypto-unavailable'
  | 'incomplete-device-enumeration'
  | 'unverified-device'
  | 'identity-not-ready'
  | 'keys-query-failed'
  | 'authoritative-key-mismatch'
  | 'policy-epoch-drift';

export type AdmissionResult =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly reason: AdmissionFailure; readonly unverified: boolean };

const allowed: AdmissionResult = { allowed: true };
const blocked = (reason: AdmissionFailure, unverified = false): AdmissionResult => ({ allowed: false, reason, unverified });

const hasExactlyExpectedState = (events: readonly RoomStateEvent[]): boolean => {
  const joinRules = events.filter((event) => event.type === ROOM_JOIN_RULES_EVENT_TYPE && event.stateKey === '');
  const encryption = events.filter((event) => event.type === ROOM_ENCRYPTION_EVENT_TYPE && event.stateKey === '');
  const historyVisibility = events.filter((event) => event.type === ROOM_HISTORY_VISIBILITY_EVENT_TYPE && event.stateKey === '');
  return events.length === 3
    && joinRules.length === 1
    && encryption.length === 1
    && historyVisibility.length === 1
    && joinRules[0].content.join_rule === INVITE_JOIN_RULE
    && encryption[0].content.algorithm === MEGOLM_V1_AES_SHA2
    && historyVisibility[0].content.history_visibility === JOINED_HISTORY_VISIBILITY;
};

/** Reject before the raw join request: an invite alone is insufficient. */
export const assessPreJoinAdmission = (snapshot: PreJoinSnapshot): AdmissionResult => {
  if (snapshot.membership?.membership !== 'invite') return blocked('not-invited');
  return hasExactlyExpectedState(snapshot.strippedState) ? allowed : blocked('invalid-room-state');
};

/** Reject send/create completion until current state and all recipient devices are trusted. */
export const assessPostAdmission = (snapshot: PostAdmissionSnapshot): AdmissionResult => {
  if (!hasExactlyExpectedState(snapshot.currentState)) return blocked('invalid-room-state');
  if (!snapshot.rustCryptoPersistent) return blocked('rust-crypto-unavailable');
  if (snapshot.encryptionTargetMembers.length === 0) return blocked('invalid-room-state');
  const users = new Set<string>();
  for (const member of snapshot.encryptionTargetMembers) {
    if (member.userId.length === 0 || users.has(member.userId)) return blocked('invalid-room-state');
    users.add(member.userId);
    if (member.membership !== 'join') return blocked('invalid-room-state');
    const enumeration = snapshot.devicesByUser.get(member.userId);
    if (!enumeration?.complete) return blocked('incomplete-device-enumeration', true);
    if (enumeration.devices.length === 0) return blocked('unverified-device', true);
    const deviceIds = new Set<string>();
    if (enumeration.devices.some((device) => device.deviceId.length === 0 || deviceIds.has(device.deviceId) || (deviceIds.add(device.deviceId), !device.known || !device.signed || !device.verified))) {
      return blocked('unverified-device', true);
    }
  }
  return allowed;
};

export interface EncryptedRoomCreateRequest {
  readonly visibility: 'private';
  readonly preset: 'private_chat';
  readonly invite: readonly string[];
  readonly initial_state: readonly [
    { readonly type: typeof ROOM_JOIN_RULES_EVENT_TYPE; readonly state_key: ''; readonly content: { readonly join_rule: typeof INVITE_JOIN_RULE } },
    { readonly type: typeof ROOM_ENCRYPTION_EVENT_TYPE; readonly state_key: ''; readonly content: { readonly algorithm: typeof MEGOLM_V1_AES_SHA2 } },
    { readonly type: typeof ROOM_HISTORY_VISIBILITY_EVENT_TYPE; readonly state_key: ''; readonly content: { readonly history_visibility: typeof JOINED_HISTORY_VISIBILITY } },
  ];
}

/** There is deliberately no options parameter: callers cannot weaken this request. */
export const buildEncryptedRoomCreateRequest = (invitees: readonly string[]): EncryptedRoomCreateRequest => {
  if (invitees.length === 0 || invitees.some(userId => userId.length === 0) || new Set(invitees).size !== invitees.length) throw new Error('invalid-invitees');
  return { visibility: 'private', preset: 'private_chat', invite: [...invitees], initial_state: [
    { type: ROOM_JOIN_RULES_EVENT_TYPE, state_key: '', content: { join_rule: INVITE_JOIN_RULE } },
    { type: ROOM_ENCRYPTION_EVENT_TYPE, state_key: '', content: { algorithm: MEGOLM_V1_AES_SHA2 } },
    { type: ROOM_HISTORY_VISIBILITY_EVENT_TYPE, state_key: '', content: { history_visibility: JOINED_HISTORY_VISIBILITY } },
  ] };
};

/** Event ports call these methods synchronously when their respective inputs change. */
export class EncryptionPolicyEpoch {
  #epoch = 0;

  get value(): number { return this.#epoch; }
  roomStateChanged(): void { this.#epoch += 1; }
  membershipChanged(): void { this.#epoch += 1; }
  devicesChanged(): void { this.#epoch += 1; }
  userTrustOrKeysChanged(): void { this.#epoch += 1; }
  verificationChanged(): void { this.#epoch += 1; }

  /** `capability` is invoked immediately beside the final epoch check; it must synchronously call the injected private operation and return its promise. */
  async runGuarded<T>(
    admission: () => AdmissionResult | Promise<AdmissionResult>,
    capability: () => Promise<T>,
  ): Promise<{ readonly admitted: true; readonly value: T } | { readonly admitted: false; readonly result: AdmissionResult }> {
    const epoch = this.#epoch;
    const result = await admission();
    if (this.#epoch !== epoch) return { admitted: false, result: blocked('policy-epoch-drift') };
    if (!result.allowed) return { admitted: false, result };
    // The private SDK facade, not this pure precheck, owns raw synchronous invocation enforcement.
    if (this.#epoch !== epoch) return { admitted: false, result: blocked('policy-epoch-drift') };
    return { admitted: true, value: await capability() };
  }
}

/** Fresh `/keys/query` data projected into owned values; its device set must exactly equal Rust's belief. */
export interface AuthoritativeDeviceKey {
  readonly deviceId: string;
  readonly ed25519Fingerprint: string;
  readonly curve25519Fingerprint: string;
}
export interface UserIdentityReadiness {
  readonly known: boolean;
  readonly crossSigningVerified: boolean;
  readonly awaitingApproval: boolean;
}
export interface DirectSendSnapshot extends PostAdmissionSnapshot {
  readonly selfUserId: string;
  readonly peerUserId: string;
  readonly activeMembers: readonly Membership[];
  readonly ownCurrentDeviceReady: boolean;
  readonly identities: ReadonlyMap<string, UserIdentityReadiness>;
  /** A direct authenticated keys query has completed; a nonempty failure set is fail-closed. */
  readonly keysQueryFailures: readonly string[];
  readonly authoritativeDevicesByUser: ReadonlyMap<string, readonly AuthoritativeDeviceKey[]>;
  /** Rust trust projection, including fingerprints, after its own refresh. */
  readonly rustDevicesByUser: ReadonlyMap<string, readonly AuthoritativeDeviceKey[]>;
}

const exactDevices = (left: readonly AuthoritativeDeviceKey[] | undefined, right: readonly AuthoritativeDeviceKey[] | undefined, trust: readonly DeviceTrust[] | undefined): boolean => {
  if (!left || !right || left.length === 0 || right.length === 0 || left.length !== right.length) return false;
  if (!trust || trust.length !== left.length) return false;
  const fingerprints = new Map<string, string>();
  for (const device of left) {
    if (!device.deviceId || !device.ed25519Fingerprint || !device.curve25519Fingerprint) return false;
    const fingerprint = `${device.deviceId}\u0000${device.ed25519Fingerprint}\u0000${device.curve25519Fingerprint}`;
    if (fingerprints.has(device.deviceId)) return false;
    fingerprints.set(device.deviceId, fingerprint);
  }
  const rustIds = new Set<string>();
  if (!right.every(device => !!device.deviceId && !!device.ed25519Fingerprint && !!device.curve25519Fingerprint && !rustIds.has(device.deviceId) && (rustIds.add(device.deviceId), fingerprints.get(device.deviceId) === `${device.deviceId}\u0000${device.ed25519Fingerprint}\u0000${device.curve25519Fingerprint}`))) return false;
  const trustIds = new Set<string>();
  return trust.every(device => !!device.deviceId && !trustIds.has(device.deviceId) && (trustIds.add(device.deviceId), fingerprints.has(device.deviceId)));
};

/** Stronger than structural admission: only this result may precede the private send operation. */
export const assessDirectSendReadiness = (snapshot: DirectSendSnapshot): AdmissionResult => {
  const users = [snapshot.selfUserId, snapshot.peerUserId];
  if (!users[0] || !users[1] || users[0] === users[1]) return blocked('invalid-room-state');
  const active = snapshot.activeMembers.filter(member => member.membership === 'join' || member.membership === 'invite' || member.membership === 'knock');
  if (active.length !== 2 || new Set(active.map(member => member.userId)).size !== 2 || !users.every(user => active.some(member => member.userId === user && member.membership === 'join'))) return blocked('invalid-room-state');
  if (snapshot.encryptionTargetMembers.length !== 2 || new Set(snapshot.encryptionTargetMembers.map(member => member.userId)).size !== 2 || !users.every(user => snapshot.encryptionTargetMembers.some(member => member.userId === user && member.membership === 'join'))) return blocked('invalid-room-state');
  if (!snapshot.ownCurrentDeviceReady) return blocked('identity-not-ready', true);
  for (const userId of users) {
    const identity = snapshot.identities.get(userId);
    if (!identity?.known || !identity.crossSigningVerified || identity.awaitingApproval) return blocked('identity-not-ready', true);
  }
  if (snapshot.keysQueryFailures.length !== 0) return blocked('keys-query-failed', true);
  for (const userId of users) if (!exactDevices(snapshot.authoritativeDevicesByUser.get(userId), snapshot.rustDevicesByUser.get(userId), snapshot.devicesByUser.get(userId)?.devices)) return blocked('authoritative-key-mismatch', true);
  return assessPostAdmission(snapshot);
};
