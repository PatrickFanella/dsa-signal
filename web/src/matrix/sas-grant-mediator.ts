/** Dormant, SDK-free grant-effect containment boundary. */
import { canonicalProfileId } from '../auth/canonical-profile';
import { MATRIX_HOMESERVER } from '../auth/matrix-topology';
import type { ActiveProfileLocator, SasAuthorization, SasProfileBinding, SasStableGrantBinding } from '../auth/session-store';
import { parseMatrixDeviceId, parseMatrixUserId, parseSupportedDomainRoomId } from './identifiers';

export type SasGrantEffectResult = 'authorized' | 'denied' | 'blocked' | 'indeterminate';
export interface SasGrantProfileSession { readonly profileId: string; readonly sessionGeneration: number; readonly homeserver: string; readonly localUserId: string; readonly localDeviceId: string; }
export interface SasGrantStorePort { getSasAuthorization(expected: ActiveProfileLocator): Promise<SasAuthorization | undefined>; requireSasReverification(binding: SasProfileBinding, expectedGeneration: number): Promise<SasAuthorization | undefined>; }
export interface SasGrantMediatorInput {
  readonly locator: ActiveProfileLocator;
  readonly profile: SasGrantProfileSession;
  readonly roomId: string;
  readonly peerUserId: string;
  /**
   * Nonnegative EncryptionPolicyEpoch. A future caller must use one epoch that
   * covers room, device, trust, verification, and runtime changes.
   */
  readonly roomEpoch: number;
  readonly readRoomEpoch: () => number;
  readonly store: SasGrantStorePort;
  readonly proveFreshBinding: () => Promise<SasStableGrantBinding | undefined>;
  /**
   * Trusted asynchronous capability. This type/source boundary prevents an
   * accidental voided async call; it neither sandboxes same-origin code nor
   * revokes an effect that has already started.
   */
  readonly effect: () => Promise<undefined>;
}

const own = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype;
const dataSnapshot = (value: unknown, keys: readonly string[], primitiveOnly = false): Readonly<Record<string, unknown>> | undefined => {
  if (!own(value)) return undefined;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length || !keys.every(key => Object.hasOwn(descriptors, key))) return undefined;
  const entries: [string, unknown][] = [];
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable || (primitiveOnly && (typeof descriptor.value === 'object' || typeof descriptor.value === 'function'))) return undefined;
    entries.push([key, descriptor.value]);
  }
  return Object.freeze(Object.fromEntries(entries));
};
const exact = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => dataSnapshot(value, keys) !== undefined;
const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
const epoch = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const profileId = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const ref = (value: unknown): value is string => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}$/.test(value)) return false;
  try { const bytes = atob(value); return bytes.length === 32 && btoa(bytes).replace(/=+$/, '') === value; } catch { return false; }
};
const profileKeys = ['schemaVersion', 'profileId', 'sessionGeneration', 'homeserver', 'localUserId', 'localDeviceId'] as const;
const stableKeys = [...profileKeys, 'roomId', 'peerUserId', 'localEd25519', 'localCurve25519', 'peerDeviceId', 'peerEd25519', 'peerCurve25519', 'localMasterRef', 'peerMasterRef'] as const;
const validProfile = (value: unknown): value is SasProfileBinding => exact(value, profileKeys) && value.schemaVersion === 1 && profileId(value.profileId) && positive(value.sessionGeneration) && value.homeserver === MATRIX_HOMESERVER && parseMatrixUserId(value.localUserId) !== undefined && parseMatrixDeviceId(value.localDeviceId) !== undefined;
const validStable = (value: unknown): value is SasStableGrantBinding => exact(value, stableKeys) && validProfile({ schemaVersion: value.schemaVersion, profileId: value.profileId, sessionGeneration: value.sessionGeneration, homeserver: value.homeserver, localUserId: value.localUserId, localDeviceId: value.localDeviceId }) && parseSupportedDomainRoomId(value.roomId) !== undefined && parseMatrixUserId(value.peerUserId) !== undefined && value.peerUserId !== value.localUserId && parseMatrixDeviceId(value.peerDeviceId) !== undefined && [value.localEd25519, value.localCurve25519, value.peerEd25519, value.peerCurve25519, value.localMasterRef, value.peerMasterRef].every(ref);
const sameProfile = (left: SasProfileBinding, right: SasProfileBinding): boolean => profileKeys.every(key => left[key] === right[key]);
const sameStable = (left: SasStableGrantBinding, right: SasStableGrantBinding): boolean => stableKeys.every(key => left[key] === right[key]);
const validGranted = (value: unknown): value is SasStableGrantBinding & { readonly state: 'granted'; readonly generation: number } => own(value) && exact(value, [...stableKeys, 'state', 'generation']) && value.state === 'granted' && positive(value.generation) && validStable(Object.fromEntries(stableKeys.map(key => [key, value[key]])));
const grantedSnapshot = (value: unknown): (SasStableGrantBinding & { readonly state: 'granted'; readonly generation: number }) | undefined => {
  const snapshot = dataSnapshot(value, [...stableKeys, 'state', 'generation'], true);
  return snapshot && validGranted(snapshot) ? snapshot as SasStableGrantBinding & { readonly state: 'granted'; readonly generation: number } : undefined;
};
const stableSnapshot = (value: unknown): SasStableGrantBinding | undefined => {
  const snapshot = dataSnapshot(value, stableKeys, true);
  return snapshot && validStable(snapshot) ? snapshot as SasStableGrantBinding : undefined;
};
const validNonGrantedAuthorization = (value: unknown): boolean => {
  if (!own(value) || !positive(value.generation)) return false;
  if (value.state === 'reverification-required') return exact(value, [...profileKeys, 'state', 'generation']) && validProfile(Object.fromEntries(profileKeys.map(key => [key, value[key]])));
  if (value.state !== 'active' || !validStable(Object.fromEntries(stableKeys.map(key => [key, value[key]]))) || (value.direction !== 'incoming' && value.direction !== 'outgoing') || !['intent', 'bound', 'consented', 'sas-shown', 'confirmation-intent'].includes(value.stage as string) || (value.direction === 'incoming' && value.stage === 'intent') || typeof value.expiresAt !== 'number' || !Number.isFinite(value.expiresAt)) return false;
  const noFlow = value.direction === 'outgoing' && value.stage === 'intent';
  return exact(value, noFlow ? [...stableKeys, 'state', 'direction', 'stage', 'expiresAt', 'generation'] : [...stableKeys, 'state', 'direction', 'stage', 'expiresAt', 'generation', 'flowId']) && (noFlow || typeof value.flowId === 'string' && value.flowId.startsWith('$') && value.flowId.length <= 1024 && !/\s|\0/.test(value.flowId));
};
const exactBarrier = (value: unknown, profile: SasProfileBinding, priorGeneration: number): boolean => own(value) && exact(value, [...profileKeys, 'state', 'generation']) && value.state === 'reverification-required' && positive(value.generation) && priorGeneration < Number.MAX_SAFE_INTEGER && value.generation === priorGeneration + 1 && validProfile(Object.fromEntries(profileKeys.map(key => [key, value[key]]))) && sameProfile(value as unknown as SasProfileBinding, profile);
const thenable = (value: unknown): value is PromiseLike<unknown> => (typeof value === 'object' && value !== null || typeof value === 'function') && typeof (value as { then?: unknown }).then === 'function';

/** Authorizes a trusted asynchronous effect only while an unchanged, freshly proved grant remains current. */
export async function mediateSasGrantedEffect(input: SasGrantMediatorInput): Promise<SasGrantEffectResult> {
  let effectStarted = false;
  try {
    const supplied = dataSnapshot(input, ['locator', 'profile', 'roomId', 'peerUserId', 'roomEpoch', 'readRoomEpoch', 'store', 'proveFreshBinding', 'effect']);
    const locator = supplied && dataSnapshot(supplied.locator, ['profileId', 'generation'], true);
    const profile = supplied && dataSnapshot(supplied.profile, ['profileId', 'sessionGeneration', 'homeserver', 'localUserId', 'localDeviceId'], true);
    if (!supplied || !locator || !profile || !profileId(locator.profileId) || !positive(locator.generation) || !profileId(profile.profileId) || !positive(profile.sessionGeneration) || locator.profileId !== profile.profileId || locator.generation !== profile.sessionGeneration || profile.homeserver !== MATRIX_HOMESERVER || parseMatrixUserId(profile.localUserId) === undefined || parseMatrixDeviceId(profile.localDeviceId) === undefined || parseSupportedDomainRoomId(supplied.roomId) === undefined || parseMatrixUserId(supplied.peerUserId) === undefined || supplied.peerUserId === profile.localUserId || !epoch(supplied.roomEpoch) || typeof supplied.readRoomEpoch !== 'function' || (typeof supplied.store !== 'object' && typeof supplied.store !== 'function') || supplied.store === null || typeof supplied.proveFreshBinding !== 'function' || typeof supplied.effect !== 'function') return 'blocked';
    const store = supplied.store as SasGrantStorePort;
    const getSasAuthorization = store.getSasAuthorization;
    const requireSasReverification = store.requireSasReverification;
    if (typeof getSasAuthorization !== 'function' || typeof requireSasReverification !== 'function') return 'blocked';
    const readRoomEpoch = supplied.readRoomEpoch;
    const proveFreshBinding = supplied.proveFreshBinding;
    const effect = supplied.effect;
    const readAuthorization = getSasAuthorization.bind(store);
    const requireReverification = requireSasReverification.bind(store);
    if (await canonicalProfileId({ homeserver: profile.homeserver as string, userId: profile.localUserId as string, deviceId: profile.localDeviceId as string }) !== profile.profileId) return 'blocked';
    const firstEpoch = readRoomEpoch();
    if (!epoch(firstEpoch)) return 'blocked';
    if (firstEpoch !== supplied.roomEpoch) return 'denied';
    const firstRead = await readAuthorization(locator as unknown as ActiveProfileLocator);
    if (firstRead === undefined || validNonGrantedAuthorization(firstRead)) return 'denied';
    const first = grantedSnapshot(firstRead);
    if (!first) return 'blocked';
    if (first.profileId !== profile.profileId || first.sessionGeneration !== profile.sessionGeneration || first.homeserver !== profile.homeserver || first.localUserId !== profile.localUserId || first.localDeviceId !== profile.localDeviceId || first.roomId !== supplied.roomId || first.peerUserId !== supplied.peerUserId) return 'denied';
    const proofRead = await proveFreshBinding();
    if (proofRead === undefined) return 'denied';
    const proof = stableSnapshot(proofRead);
    if (!proof) return 'blocked';
    if (await canonicalProfileId({ homeserver: proof.homeserver, userId: proof.localUserId, deviceId: proof.localDeviceId }) !== proof.profileId) return 'blocked';
    if (!sameStable(first, proof)) {
      const barrier = await requireReverification({ schemaVersion: first.schemaVersion, profileId: first.profileId, sessionGeneration: first.sessionGeneration, homeserver: first.homeserver, localUserId: first.localUserId, localDeviceId: first.localDeviceId }, first.generation);
      return exactBarrier(barrier, first, first.generation) ? 'denied' : 'blocked';
    }
    const secondRead = await readAuthorization(locator as unknown as ActiveProfileLocator);
    if (secondRead === undefined || validNonGrantedAuthorization(secondRead)) return 'denied';
    const second = grantedSnapshot(secondRead);
    if (!second) return 'blocked';
    if (second.generation !== first.generation || !sameStable(second, first)) return 'denied';
    const finalEpoch = readRoomEpoch();
    if (!epoch(finalEpoch)) return 'blocked';
    if (finalEpoch !== supplied.roomEpoch) return 'denied';
    effectStarted = true;
    const result = effect();
    if (!thenable(result)) return 'indeterminate';
    return await result === undefined ? 'authorized' : 'indeterminate';
  } catch { return effectStarted ? 'indeterminate' : 'blocked'; }
}
