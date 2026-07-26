import { describe, expect, it, vi } from 'vitest';
import { canonicalProfileId } from '../auth/canonical-profile';
import { MATRIX_HOMESERVER } from '../auth/matrix-topology';
import type { SasAuthorization, SasStableGrantBinding } from '../auth/session-store';
import { mediateSasGrantedEffect, type SasGrantMediatorInput } from './sas-grant-mediator';

const b64 = (byte: number) => btoa(String.fromCharCode(...new Uint8Array(32).fill(byte))).replace(/=+$/, '');
const binding = async (changes: Partial<SasStableGrantBinding> = {}): Promise<SasStableGrantBinding> => ({ schemaVersion: 1, profileId: await canonicalProfileId({ homeserver: MATRIX_HOMESERVER, userId: '@me:example.test', deviceId: 'device' }), sessionGeneration: 1, homeserver: MATRIX_HOMESERVER, localUserId: '@me:example.test', localDeviceId: 'device', roomId: '!room:example.test', peerUserId: '@peer:example.test', localEd25519: b64(1), localCurve25519: b64(2), peerDeviceId: 'peer-device', peerEd25519: b64(3), peerCurve25519: b64(4), localMasterRef: b64(5), peerMasterRef: b64(6), ...changes });
const granted = (value: SasStableGrantBinding, generation = 4): SasAuthorization => ({ ...value, state: 'granted', generation });
const barrier = (value: SasStableGrantBinding, generation = 5): SasAuthorization => ({ schemaVersion: 1, profileId: value.profileId, sessionGeneration: value.sessionGeneration, homeserver: value.homeserver, localUserId: value.localUserId, localDeviceId: value.localDeviceId, state: 'reverification-required', generation });
const input = async (first?: SasAuthorization, proof?: SasStableGrantBinding): Promise<SasGrantMediatorInput> => {
  const value = await binding();
  return { locator: { profileId: value.profileId, generation: 1 }, profile: { profileId: value.profileId, sessionGeneration: 1, homeserver: MATRIX_HOMESERVER, localUserId: value.localUserId, localDeviceId: value.localDeviceId }, roomId: value.roomId, peerUserId: value.peerUserId, roomEpoch: 1, readRoomEpoch: () => 1, store: { getSasAuthorization: vi.fn().mockResolvedValue(first ?? granted(value)), requireSasReverification: vi.fn() }, proveFreshBinding: vi.fn().mockResolvedValue(proof ?? value), effect: vi.fn(async () => undefined) };
};

describe('dormant SAS grant mediator', () => {
  it('accepts epoch zero and a class-instance port, with no operation between final epoch and effect start', async () => {
    const value = await binding(); const calls: string[] = [];
    class Port { public getSasAuthorization = vi.fn(async () => { calls.push('read'); return granted(value); }); public requireSasReverification = vi.fn(); }
    const candidate = await input();
    Object.assign(candidate, { roomEpoch: 0, readRoomEpoch: () => { calls.push('epoch'); return 0; }, store: new Port(), proveFreshBinding: vi.fn(async () => { calls.push('proof'); return value; }), effect: vi.fn(async () => { calls.push('effect'); }) });
    expect(await mediateSasGrantedEffect(candidate)).toBe('authorized');
    expect(calls).toEqual(['epoch', 'read', 'proof', 'read', 'epoch', 'effect']);
  });

  it('blocks all malformed epoch values and epoch-read exceptions, but denies a valid mismatch', async () => {
    for (const value of [undefined, null, false, '0', {}, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
      const candidate = await input(); Object.assign(candidate, { roomEpoch: value });
      expect(await mediateSasGrantedEffect(candidate)).toBe('blocked');
    }
    for (const value of [undefined, null, false, '0', {}, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
      const candidate = await input(); Object.assign(candidate, { readRoomEpoch: () => value });
      expect(await mediateSasGrantedEffect(candidate)).toBe('blocked');
    }
    const throwing = await input(); Object.assign(throwing, { readRoomEpoch: () => { throw new Error('secret'); } }); expect(await mediateSasGrantedEffect(throwing)).toBe('blocked');
    const mismatch = await input(); Object.assign(mismatch, { readRoomEpoch: () => 2 }); expect(await mediateSasGrantedEffect(mismatch)).toBe('denied');
  });

  it('denies valid non-grants and blocks malformed active combinations', async () => {
    const value = await binding();
    for (const authorization of [barrier(value), { ...value, state: 'active', direction: 'outgoing', stage: 'intent', expiresAt: 1, generation: 4 }]) {
      const candidate = await input(authorization as SasAuthorization); expect(await mediateSasGrantedEffect(candidate)).toBe('denied');
    }
    for (const authorization of [
      { ...value, state: 'active', direction: 'incoming', stage: 'intent', expiresAt: 1, generation: 4, flowId: '$x' },
      { ...value, state: 'active', direction: 'outgoing', stage: 'bound', expiresAt: 1, generation: 4 },
      { ...value, state: 'active', direction: 'outgoing', stage: 'intent', expiresAt: 1, generation: 4, flowId: '$x' },
    ]) { const candidate = await input(authorization as SasAuthorization); expect(await mediateSasGrantedEffect(candidate)).toBe('blocked'); }
  });

  it('contains every stable binding drift with only the exact next sticky barrier', async () => {
    const value = await binding();
    for (const key of ['roomId', 'peerUserId', 'localEd25519', 'localCurve25519', 'peerDeviceId', 'peerEd25519', 'peerCurve25519', 'localMasterRef', 'peerMasterRef'] as const) {
      const drift = { ...value, [key]: key === 'peerUserId' ? '@other:example.test' : key === 'roomId' ? '!other:example.test' : key.endsWith('Id') ? 'other-device' : b64(9) } as SasStableGrantBinding;
      const candidate = await input(granted(value), drift); Object.assign(candidate, { store: { ...candidate.store, requireSasReverification: vi.fn().mockResolvedValue(barrier(value)) } });
      expect(await mediateSasGrantedEffect(candidate)).toBe('denied'); expect(candidate.effect).not.toHaveBeenCalled();
    }
    for (const drift of [
      { ...value, sessionGeneration: 2 },
      { ...value, localDeviceId: 'other-device', profileId: await canonicalProfileId({ homeserver: MATRIX_HOMESERVER, userId: value.localUserId, deviceId: 'other-device' }) },
      { ...value, localUserId: '@other:example.test', profileId: await canonicalProfileId({ homeserver: MATRIX_HOMESERVER, userId: '@other:example.test', deviceId: value.localDeviceId }) },
    ]) {
      const candidate = await input(granted(value), drift); Object.assign(candidate, { store: { ...candidate.store, requireSasReverification: vi.fn().mockResolvedValue(barrier(value)) } });
      expect(await mediateSasGrantedEffect(candidate)).toBe('denied');
    }
    for (const result of [undefined, barrier(value, 4), barrier(value, 6), { ...barrier(value), profileId: '0'.repeat(64) }, { state: 'reverification-required', generation: 5 }]) {
      const candidate = await input(granted(value), { ...value, roomId: '!other:example.test' }); Object.assign(candidate, { store: { ...candidate.store, requireSasReverification: vi.fn().mockResolvedValue(result) } });
      expect(await mediateSasGrantedEffect(candidate)).toBe('blocked');
    }
    const overflow = await input(granted(value, Number.MAX_SAFE_INTEGER), { ...value, roomId: '!other:example.test' }); Object.assign(overflow, { store: { ...overflow.store, requireSasReverification: vi.fn() } }); expect(await mediateSasGrantedEffect(overflow)).toBe('blocked');
  });

  it('blocks proof/read/CAS failures and denies unavailable proof or second-read changes', async () => {
    const readFailure = await input(); Object.assign(readFailure, { store: { ...readFailure.store, getSasAuthorization: vi.fn(() => { throw new Error('secret'); }) } }); expect(await mediateSasGrantedEffect(readFailure)).toBe('blocked');
    const casValue = await binding(); const casFailure = await input(granted(casValue), { ...casValue, roomId: '!other:example.test' }); Object.assign(casFailure, { store: { ...casFailure.store, requireSasReverification: vi.fn(() => { throw new Error('secret'); }) } }); expect(await mediateSasGrantedEffect(casFailure)).toBe('blocked');
    const unavailable = await input(); Object.assign(unavailable, { proveFreshBinding: vi.fn().mockResolvedValue(undefined) }); expect(await mediateSasGrantedEffect(unavailable)).toBe('denied');
    const proofFailure = await input(); Object.assign(proofFailure, { proveFreshBinding: vi.fn(() => { throw new Error('secret'); }) }); expect(await mediateSasGrantedEffect(proofFailure)).toBe('blocked');
    const value = await binding();
    for (const second of [undefined, barrier(value), { ...value, state: 'active', direction: 'outgoing', stage: 'intent', expiresAt: 1, generation: 4 }, granted(value, 5), granted({ ...value, peerDeviceId: 'other-device' })]) {
      const candidate = await input(granted(value)); Object.assign(candidate, { store: { ...candidate.store, getSasAuthorization: vi.fn().mockResolvedValueOnce(granted(value)).mockResolvedValueOnce(second) } }); expect(await mediateSasGrantedEffect(candidate)).toBe('denied');
    }
    const finalEpoch = await input(); Object.assign(finalEpoch, { readRoomEpoch: vi.fn().mockReturnValueOnce(1).mockReturnValueOnce(2) }); expect(await mediateSasGrantedEffect(finalEpoch)).toBe('denied'); expect(finalEpoch.effect).not.toHaveBeenCalled();
  });

  it('makes post-effect failures indeterminate; callers must never automatically retry', async () => {
    for (const effect of [vi.fn(() => { throw new Error('secret'); }), vi.fn(async () => { throw new Error('secret'); }), vi.fn(() => undefined), vi.fn(async () => 'wrong')]) {
      const candidate = await input(); Object.assign(candidate, { effect: effect as unknown as SasGrantMediatorInput['effect'] }); expect(await mediateSasGrantedEffect(candidate)).toBe('indeterminate'); expect(effect).toHaveBeenCalledOnce();
    }
  });

  it('uses immutable authorization snapshots across proof and reread', async () => {
    const value = await binding(); const shared = granted(value) as unknown as Record<string, unknown>;
    const candidate = await input();
    Object.assign(candidate, {
      store: { getSasAuthorization: vi.fn(() => shared as unknown as SasAuthorization), requireSasReverification: vi.fn() },
      proveFreshBinding: vi.fn(async () => { shared.peerUserId = '@other:example.test'; return value; }),
    });
    expect(await mediateSasGrantedEffect(candidate)).toBe('denied');
    expect(candidate.effect).not.toHaveBeenCalled();
    expect(candidate.store.requireSasReverification).not.toHaveBeenCalled();
  });

  it('uses the first snapshot, not a proof-time mutation, for downgrade arguments', async () => {
    const value = await binding(); const shared = granted(value) as unknown as Record<string, unknown>;
    const requireSasReverification = vi.fn().mockResolvedValue(barrier(value));
    const candidate = await input();
    Object.assign(candidate, {
      store: { getSasAuthorization: vi.fn(() => shared as unknown as SasAuthorization), requireSasReverification },
      proveFreshBinding: vi.fn(async () => { shared.localDeviceId = 'mutated-device'; return { ...value, roomId: '!other:example.test' }; }),
    });
    expect(await mediateSasGrantedEffect(candidate)).toBe('denied');
    expect(requireSasReverification).toHaveBeenCalledWith(expect.objectContaining({ localDeviceId: value.localDeviceId }), 4);
    expect(candidate.effect).not.toHaveBeenCalled();
  });

  it('blocks accessor descriptors and authorization records with throwing descriptor traps', async () => {
    const value = await binding();
    const accessor = granted(value) as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, 'peerUserId', { enumerable: true, get: () => value.peerUserId });
    const proxy = new Proxy(granted(value), { getOwnPropertyDescriptor: () => { throw new Error('secret'); } });
    for (const authorization of [accessor, proxy]) {
      const candidate = await input(authorization as SasAuthorization);
      expect(await mediateSasGrantedEffect(candidate)).toBe('blocked'); expect(candidate.effect).not.toHaveBeenCalled();
    }
  });

  it('uses the pre-await input snapshot through profile hashing, reads, proof, and reread', async () => {
    const value = await binding();
    for (const stage of ['hash', 'first-read', 'proof', 'reread'] as const) {
      const candidate = await input();
      const originalRead = vi.fn(async () => granted(value));
      const originalBarrier = vi.fn();
      const originalEpoch = vi.fn(() => 1);
      const originalProof = vi.fn(async () => value);
      const originalEffect = vi.fn(async () => undefined);
      const originalStore = { getSasAuthorization: originalRead, requireSasReverification: originalBarrier };
      Object.assign(candidate, { store: originalStore, readRoomEpoch: originalEpoch, proveFreshBinding: originalProof, effect: originalEffect });
      const mutate = () => {
        Object.assign(candidate, { locator: { profileId: '0'.repeat(64), generation: 9 }, profile: { profileId: '0'.repeat(64), sessionGeneration: 9, homeserver: 'https://attacker.test', localUserId: '@attacker:example.test', localDeviceId: 'attacker' }, roomId: '!attacker:example.test', peerUserId: '@attacker:example.test', roomEpoch: 9, readRoomEpoch: () => 9, store: originalStore, proveFreshBinding: vi.fn(), effect: vi.fn() });
        originalStore.getSasAuthorization = vi.fn(); originalStore.requireSasReverification = vi.fn();
      };
      if (stage === 'hash') queueMicrotask(mutate);
      else if (stage === 'first-read') originalRead.mockImplementationOnce(async () => { mutate(); return granted(value); });
      else if (stage === 'proof') originalProof.mockImplementationOnce(async () => { mutate(); return value; });
      else originalRead.mockImplementationOnce(async () => granted(value)).mockImplementationOnce(async () => { mutate(); return granted(value); });
      expect(await mediateSasGrantedEffect(candidate)).toBe('authorized');
      expect(originalRead).toHaveBeenCalledTimes(2); expect(originalProof).toHaveBeenCalledOnce(); expect(originalEffect).toHaveBeenCalledOnce();
    }
  });
});
