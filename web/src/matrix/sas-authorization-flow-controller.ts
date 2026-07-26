/** Dormant, SDK-free outgoing SAS intent-before-effect boundary. `recorded` only means the exact bind CAS committed at some instant, not that it remains authorized on return. */
import { canonicalProfileId } from '../auth/canonical-profile';
import { MATRIX_HOMESERVER } from '../auth/matrix-topology';
import type { ActiveProfileLocator, SasAuthorization, SasProfileBinding, SasStableGrantBinding } from '../auth/session-store';
import { parseMatrixDeviceId, parseMatrixUserId, parseSupportedDomainRoomId } from './identifiers';

type Result = 'recorded' | 'denied' | 'blocked' | 'indeterminate';
interface StorePort {
  getSasAuthorization(expected: ActiveProfileLocator): Promise<SasAuthorization | undefined>;
  createOutgoingSasIntent(binding: SasStableGrantBinding, expectedGeneration: number, expiresAt: number): Promise<SasAuthorization | undefined>;
  bindOutgoingSasFlow(binding: SasStableGrantBinding, expectedGeneration: number, flowId: string): Promise<SasAuthorization | undefined>;
  requireSasReverification(binding: SasProfileBinding, expectedGeneration: number): Promise<SasAuthorization | undefined>;
}
interface Input {
  readonly locator: ActiveProfileLocator;
  readonly binding: SasStableGrantBinding;
  readonly expectedGeneration: number;
  readonly roomEpoch: number;
  readonly readRoomEpoch: () => number;
  readonly now: number;
  readonly readNow: () => number;
  readonly expiresAt: number;
  readonly store: StorePort;
  readonly requestFlow: () => Promise<string>;
}

const own = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype;
const snapshot = (value: unknown, keys: readonly string[], primitiveOnly = false): Readonly<Record<string, unknown>> | undefined => {
  if (!own(value)) return undefined;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length || !keys.every(key => Object.hasOwn(descriptors, key))) return undefined;
  const entries: [string, unknown][] = [];
  for (const key of keys) { const descriptor = descriptors[key]; if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable || (primitiveOnly && (typeof descriptor.value === 'object' || typeof descriptor.value === 'function'))) return undefined; entries.push([key, descriptor.value]); }
  return Object.freeze(Object.fromEntries(entries));
};
const integer = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const positive = (value: unknown): value is number => integer(value) && value > 0;
const profileId = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const ref = (value: unknown): value is string => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}$/.test(value)) return false;
  try { const bytes = atob(value); return bytes.length === 32 && btoa(bytes).replace(/=+$/, '') === value; } catch { return false; }
};
const profileKeys = ['schemaVersion', 'profileId', 'sessionGeneration', 'homeserver', 'localUserId', 'localDeviceId'] as const;
const stableKeys = [...profileKeys, 'roomId', 'peerUserId', 'localEd25519', 'localCurve25519', 'peerDeviceId', 'peerEd25519', 'peerCurve25519', 'localMasterRef', 'peerMasterRef'] as const;
const stable = (value: unknown): SasStableGrantBinding | undefined => {
  const item = snapshot(value, stableKeys, true);
  if (!item || item.schemaVersion !== 1 || !profileId(item.profileId) || !positive(item.sessionGeneration) || item.homeserver !== MATRIX_HOMESERVER || parseMatrixUserId(item.localUserId) === undefined || parseMatrixDeviceId(item.localDeviceId) === undefined || parseSupportedDomainRoomId(item.roomId) === undefined || parseMatrixUserId(item.peerUserId) === undefined || item.peerUserId === item.localUserId || parseMatrixDeviceId(item.peerDeviceId) === undefined || ![item.localEd25519, item.localCurve25519, item.peerEd25519, item.peerCurve25519, item.localMasterRef, item.peerMasterRef].every(ref)) return undefined;
  return item as unknown as SasStableGrantBinding;
};
const sameStable = (left: SasStableGrantBinding, right: SasStableGrantBinding): boolean => stableKeys.every(key => left[key] === right[key]);
const flowId = (value: unknown): value is string => typeof value === 'string' && value.startsWith('$') && value.length <= 1024 && !/\s|\0/.test(value);
const thenable = (value: unknown): value is PromiseLike<unknown> => (typeof value === 'object' && value !== null || typeof value === 'function') && typeof (value as { then?: unknown }).then === 'function';
const exactActive = (value: unknown, binding: SasStableGrantBinding, generation: number, stage: 'intent' | 'bound', expiresAt: number, expectedFlow?: string): boolean => {
  if (!own(value) || value.state !== 'active' || value.direction !== 'outgoing' || value.stage !== stage || value.generation !== generation || value.expiresAt !== expiresAt || !sameStable(value as unknown as SasStableGrantBinding, binding)) return false;
  const keys = [...stableKeys, 'state', 'direction', 'stage', 'expiresAt', 'generation', ...(stage === 'bound' ? ['flowId'] : [])];
  return snapshot(value, keys, true) !== undefined && (stage === 'intent' ? value.flowId === undefined : value.flowId === expectedFlow);
};
const exactBarrier = (value: unknown, binding: SasStableGrantBinding, generation: number): boolean => own(value) && value.state === 'reverification-required' && value.generation === generation + 1 && snapshot(value, [...profileKeys, 'state', 'generation'], true) !== undefined && profileKeys.every(key => value[key] === binding[key]);
const knownAuthorization = (value: unknown, binding: SasStableGrantBinding): boolean => {
  if (!own(value) || !integer(value.generation)) return false;
  if (value.state === 'reverification-required') return snapshot(value, [...profileKeys, 'state', 'generation'], true) !== undefined && profileKeys.every(key => value[key] === binding[key]);
  if (value.state === 'granted') return snapshot(value, [...stableKeys, 'state', 'generation'], true) !== undefined && sameStable(value as unknown as SasStableGrantBinding, binding);
  if (value.state !== 'active' || (value.direction !== 'outgoing' && value.direction !== 'incoming') || !['intent', 'bound', 'consented', 'sas-shown', 'confirmation-intent'].includes(value.stage as string) || !integer(value.expiresAt)) return false;
  const hasFlow = value.flowId !== undefined;
  return snapshot(value, [...stableKeys, 'state', 'direction', 'stage', 'expiresAt', 'generation', ...(hasFlow ? ['flowId'] : [])], true) !== undefined && sameStable(value as unknown as SasStableGrantBinding, binding) && (!hasFlow || flowId(value.flowId));
};

/** Records an outgoing SAS flow only; it never grants or starts runtime authority. */
export async function beginDormantOutgoingSasFlow(input: Input): Promise<Result> {
  let effectStarted = false;
  let store: StorePort | undefined; let binding: SasStableGrantBinding | undefined; let intentGeneration = 0;
  const contain = async (): Promise<void> => {
    if (!store || !binding || !positive(intentGeneration)) return;
    const profile: SasProfileBinding = Object.freeze(Object.fromEntries(profileKeys.map(key => [key, binding![key]]))) as unknown as SasProfileBinding;
    for (const generation of [intentGeneration, ...(intentGeneration < Number.MAX_SAFE_INTEGER ? [intentGeneration + 1] : [])]) {
      try { await store.requireSasReverification(profile, generation); } catch { /* uncertainty remains indeterminate */ }
    }
  };
  try {
    const supplied = snapshot(input, ['locator', 'binding', 'expectedGeneration', 'roomEpoch', 'readRoomEpoch', 'now', 'readNow', 'expiresAt', 'store', 'requestFlow']);
    const locator = supplied && snapshot(supplied.locator, ['profileId', 'generation'], true); binding = supplied && stable(supplied.binding);
    if (!supplied || !locator || !binding || !profileId(locator.profileId) || !positive(locator.generation) || locator.profileId !== binding.profileId || locator.generation !== binding.sessionGeneration || !integer(supplied.expectedGeneration) || supplied.expectedGeneration > Number.MAX_SAFE_INTEGER - 3 || !integer(supplied.roomEpoch) || !integer(supplied.now) || !integer(supplied.expiresAt) || supplied.expiresAt <= supplied.now || typeof supplied.readRoomEpoch !== 'function' || typeof supplied.readNow !== 'function' || (typeof supplied.store !== 'object' && typeof supplied.store !== 'function') || supplied.store === null || typeof supplied.requestFlow !== 'function') return 'blocked';
    store = supplied.store as StorePort;
    const get = store.getSasAuthorization; const create = store.createOutgoingSasIntent; const bind = store.bindOutgoingSasFlow; const barrier = store.requireSasReverification; const readEpoch = supplied.readRoomEpoch; const readNow = supplied.readNow; const requestFlow = supplied.requestFlow;
    if (typeof get !== 'function' || typeof create !== 'function' || typeof bind !== 'function' || typeof barrier !== 'function') return 'blocked';
    store = { getSasAuthorization: get.bind(supplied.store), createOutgoingSasIntent: create.bind(supplied.store), bindOutgoingSasFlow: bind.bind(supplied.store), requireSasReverification: barrier.bind(supplied.store) };
    if (await canonicalProfileId({ homeserver: binding.homeserver, userId: binding.localUserId, deviceId: binding.localDeviceId }) !== binding.profileId) return 'blocked';
    const initialEpoch = readEpoch(); const initialNow = readNow();
    if (!integer(initialEpoch) || !integer(initialNow)) return 'blocked';
    if (initialEpoch !== supplied.roomEpoch || initialNow >= supplied.expiresAt) return 'denied';
    intentGeneration = supplied.expectedGeneration + 1;
    let created: SasAuthorization | undefined;
    try { created = await store.createOutgoingSasIntent(binding, supplied.expectedGeneration, supplied.expiresAt); } catch { await contain(); return 'blocked'; }
    if (created === undefined) return 'denied';
    if (!exactActive(created, binding, intentGeneration, 'intent', supplied.expiresAt)) { await contain(); return 'blocked'; }
    let authoritative: SasAuthorization | undefined;
    try { authoritative = await store.getSasAuthorization(locator as unknown as ActiveProfileLocator); } catch { await contain(); return 'blocked'; }
    if (authoritative === undefined || exactBarrier(authoritative, binding, intentGeneration)) return 'denied';
    if (!exactActive(authoritative, binding, intentGeneration, 'intent', supplied.expiresAt)) {
      if (knownAuthorization(authoritative, binding)) return 'denied';
      await contain(); return 'blocked';
    }
    /* The exact reread is an async linearization barrier: do not insert an await before these checks and the effect. */
    let preEffectEpoch: number; let preEffectNow: number;
    try { preEffectEpoch = readEpoch(); preEffectNow = readNow(); } catch { await contain(); return 'blocked'; }
    if (!integer(preEffectEpoch) || !integer(preEffectNow)) { await contain(); return 'blocked'; }
    if (preEffectEpoch !== supplied.roomEpoch || preEffectNow >= supplied.expiresAt) {
      try {
        const fenced = await store.requireSasReverification(Object.freeze(Object.fromEntries(profileKeys.map(key => [key, binding![key]]))) as unknown as SasProfileBinding, intentGeneration);
        if (exactBarrier(fenced, binding, intentGeneration)) return 'denied';
      } catch { /* contain below */ }
      await contain(); return 'blocked';
    }
    effectStarted = true;
    const requested = requestFlow();
    if (!thenable(requested)) { await contain(); return 'indeterminate'; }
    const id = await requested;
    if (!flowId(id)) { await contain(); return 'indeterminate'; }
    const bound = await store.bindOutgoingSasFlow(binding, intentGeneration, id);
    if (!exactActive(bound, binding, intentGeneration + 1, 'bound', supplied.expiresAt, id)) { await contain(); return 'indeterminate'; }
    const finalEpoch = readEpoch(); const finalNow = readNow();
    if (!integer(finalEpoch) || !integer(finalNow) || finalEpoch !== supplied.roomEpoch || finalNow >= supplied.expiresAt) { await contain(); return 'indeterminate'; }
    return 'recorded';
  } catch {
    if (effectStarted) { await contain(); return 'indeterminate'; }
    if (intentGeneration) { await contain(); return 'blocked'; }
    return 'blocked';
  }
}
