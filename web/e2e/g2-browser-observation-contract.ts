import { parseMatrixDeviceId, parseMatrixUserId, parseSupportedDomainRoomId } from '../src/matrix/identifiers';

export const G2_BROWSER_OBSERVATION_KIND = 'non_authoritative_g2_browser_observations_v1' as const;
export type G2BrowserObservationResult = Readonly<{ kind: typeof G2_BROWSER_OBSERVATION_KIND; accepted: true }>;

type Snapshot = { readonly accountId: string; readonly deviceId: string; readonly profileRef: string; readonly crossSigningMasterRef: string; readonly roomId: string };
type G2BrowserContractErrorMessage = 'G2_BROWSER_INPUT_INVALID' | 'G2_BROWSER_ACCOUNT_BINDING_INVALID' | 'G2_BROWSER_CONTINUITY_INVALID' | 'G2_BROWSER_ROOM_INVALID' | 'G2_BROWSER_OBSERVATION_INCOMPLETE';
const keys = (value: object, expected: readonly string[]): boolean => {
  const actual = Object.keys(value);
  return actual.length === expected.length && actual.every(key => expected.includes(key));
};
/** Observable plain-record check; proxy traps are deliberately treated as invalid. */
const record = (value: unknown, expected: readonly string[]): value is Record<string, unknown> => {
  try {
    if (typeof value !== 'object' || value === null || Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length !== 0 || !keys(value, expected)) return false;
    return Object.getOwnPropertyNames(value).every(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined && descriptor.enumerable && Object.hasOwn(descriptor, 'value') && !Object.hasOwn(descriptor, 'get') && !Object.hasOwn(descriptor, 'set');
    });
  } catch { return false; }
};
const snapshotKeys = ['accountId', 'deviceId', 'profileRef', 'crossSigningMasterRef', 'roomId'] as const;
const freshKeys = ['bothReadyUi', 'joinedLineUiBoth', 'sasComparisonUiBoth', 'humanConfirmedBoth', 'sendReadyUiBoth', 'firstToSecondReceiptUi'] as const;
const restartKeys = ['bothReadyUi', 'joinedLineUiBoth', 'priorFirstMessageDecryptedUiOnSecond', 'sendReadyUiBoth', 'comparisonUiObserved', 'secondToFirstReceiptUi'] as const;
const validMaster = (value: string): boolean => /^[A-Za-z0-9+/]{43}$/.test(value) && (() => { try { return btoa(atob(value)).replace(/=+$/, '') === value && atob(value).length === 32; } catch { return false; } })();
const validSnapshot = (value: unknown): value is Snapshot => record(value, snapshotKeys) && snapshotKeys.every(key => typeof value[key] === 'string');
const validFacts = (value: unknown, expected: readonly string[]): value is Record<string, boolean> => record(value, expected) && expected.every(key => typeof value[key] === 'boolean');

/** Validates untrusted UI observations without making lifecycle or evidence claims. */
export const validateG2BrowserObservationsV1 = (value: unknown): G2BrowserObservationResult => {
  const issued = new WeakSet<object>();
  const issue = (message: G2BrowserContractErrorMessage): never => {
    const error = new Error(message);
    issued.add(error);
    throw error;
  };
  const inputError = (): never => issue('G2_BROWSER_INPUT_INVALID');
  const fail = (message: Exclude<G2BrowserContractErrorMessage, 'G2_BROWSER_INPUT_INVALID'>): never => issue(message);
  try {
    if (!record(value, ['declared', 'snapshots', 'facts']) || !record(value.declared, ['firstAccountId', 'secondAccountId']) || !record(value.snapshots, ['freshFirst', 'freshSecond', 'restartFirst', 'restartSecond']) || !record(value.facts, ['fresh', 'restart'])) inputError();
    const input = value as Record<string, Record<string, unknown>>;
    const declared = input.declared; const snapshots = input.snapshots; const facts = input.facts;
    if (typeof declared.firstAccountId !== 'string' || typeof declared.secondAccountId !== 'string' || !validSnapshot(snapshots.freshFirst) || !validSnapshot(snapshots.freshSecond) || !validSnapshot(snapshots.restartFirst) || !validSnapshot(snapshots.restartSecond) || !validFacts(facts.fresh, freshKeys) || !validFacts(facts.restart, restartKeys)) inputError();
    const [freshFirst, freshSecond, restartFirst, restartSecond] = [snapshots.freshFirst, snapshots.freshSecond, snapshots.restartFirst, snapshots.restartSecond] as [Snapshot, Snapshot, Snapshot, Snapshot];
    const [fresh, restart] = [facts.fresh, facts.restart] as [Record<string, boolean>, Record<string, boolean>];
    const all = [freshFirst, freshSecond, restartFirst, restartSecond];
    if (parseMatrixUserId(declared.firstAccountId) === undefined || parseMatrixUserId(declared.secondAccountId) === undefined || all.some(snapshot => parseMatrixUserId(snapshot.accountId) === undefined || parseMatrixDeviceId(snapshot.deviceId) === undefined || !/^[a-f0-9]{64}$/.test(snapshot.profileRef) || !validMaster(snapshot.crossSigningMasterRef))) inputError();
    if (all.some(snapshot => parseSupportedDomainRoomId(snapshot.roomId) === undefined)) fail('G2_BROWSER_ROOM_INVALID');
    if (declared.firstAccountId === declared.secondAccountId || freshFirst.accountId !== declared.firstAccountId || restartFirst.accountId !== declared.firstAccountId || freshSecond.accountId !== declared.secondAccountId || restartSecond.accountId !== declared.secondAccountId) fail('G2_BROWSER_ACCOUNT_BINDING_INVALID');
    if (all.some(snapshot => snapshot.roomId !== freshFirst.roomId)) fail('G2_BROWSER_ROOM_INVALID');
    const same = (field: keyof Snapshot, left: Snapshot, right: Snapshot): boolean => left[field] === right[field];
    if (!same('deviceId', freshFirst, restartFirst) || !same('profileRef', freshFirst, restartFirst) || !same('crossSigningMasterRef', freshFirst, restartFirst) || !same('deviceId', freshSecond, restartSecond) || !same('profileRef', freshSecond, restartSecond) || !same('crossSigningMasterRef', freshSecond, restartSecond) || freshFirst.profileRef === freshSecond.profileRef || freshFirst.crossSigningMasterRef === freshSecond.crossSigningMasterRef) fail('G2_BROWSER_CONTINUITY_INVALID');
    if (!fresh.bothReadyUi || !fresh.joinedLineUiBoth || !fresh.sasComparisonUiBoth || !fresh.humanConfirmedBoth || !fresh.sendReadyUiBoth || !fresh.firstToSecondReceiptUi || !restart.bothReadyUi || !restart.joinedLineUiBoth || !restart.priorFirstMessageDecryptedUiOnSecond || !restart.sendReadyUiBoth || restart.comparisonUiObserved || !restart.secondToFirstReceiptUi) fail('G2_BROWSER_OBSERVATION_INCOMPLETE');
    return Object.freeze({ kind: G2_BROWSER_OBSERVATION_KIND, accepted: true });
  } catch (error) {
    if (typeof error === 'object' && error !== null && issued.has(error)) throw error;
    return inputError();
  }
};
