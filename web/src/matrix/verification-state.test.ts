import { describe, expect, it } from 'vitest';
import { reduceSasState } from './verification-state';

describe('SAS state reducer', () => {
  it('implements the one-shot happy path and disposes SAS at terminal states', () => {
    let state = reduceSasState({ phase: 'idle' }, 'incoming-request');
    state = reduceSasState(state, 'accept');
    state = reduceSasState(state, 'remote-ready');
    state = reduceSasState(state, 'start');
    state = reduceSasState(state, 'show-sas', { emojis: [{ emoji: '🐱', label: 'cat' }], decimals: [1, 2, 3] });
    expect(state.phase).toBe('sas-shown');
    state = reduceSasState(state, 'confirm');
    expect('sas' in state ? state.sas : undefined).toBeUndefined();
    state = reduceSasState(state, 'resolved');
    expect(state).toEqual({ phase: 'done', direction: 'incoming' });
    expect(reduceSasState(state, 'cancel')).toEqual(state);
  });
  it('fails invalid transitions and accepts cancellation from nonterminal states', () => {
    expect(reduceSasState({ phase: 'idle' }, 'start')).toEqual({ phase: 'idle' });
    expect(reduceSasState({ phase: 'ready', direction: 'outgoing' }, 'cancel')).toEqual({ phase: 'cancelled', direction: 'outgoing' });
  });
  it('keeps local acceptance waiting for the authoritative SDK ready event', () => {
    const accepted = reduceSasState(reduceSasState({ phase: 'idle' }, 'incoming-request'), 'accept');
    expect(accepted).toMatchObject({ phase: 'accepted', direction: 'incoming', peerDeviceBound: true });
    expect(reduceSasState(accepted, 'remote-ready')).toEqual({ phase: 'ready', direction: 'incoming' });
    const outgoing = reduceSasState({ phase: 'idle' }, 'initiate');
    expect(reduceSasState(outgoing, 'remote-ready')).toEqual({ phase: 'failed', direction: 'outgoing' });
    expect(reduceSasState(outgoing, 'peer-device-bound')).toMatchObject({ peerDeviceBound: true });
  });
  it('accepts a remote start racing Ready only for a bound outgoing request', () => {
    const outgoing = reduceSasState(reduceSasState({ phase: 'idle' }, 'initiate'), 'peer-device-bound');
    expect(reduceSasState(outgoing, 'remote-started')).toEqual({ phase: 'started', direction: 'outgoing' });
    const incoming = reduceSasState({ phase: 'idle' }, 'incoming-request');
    expect(reduceSasState(incoming, 'remote-started')).toEqual({ phase: 'failed', direction: 'incoming' });
  });
});
