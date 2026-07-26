import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConversationView, TrustWarnings, type PendingTextAttempt, subscribeRoomFeeds } from './ConversationView';
import type { DirectConversation, DirectTrustState, MatrixGateway, TimelineTextMessage, VerificationState } from '../../matrix';

const room = '!direct:test' as never;
const peer = '@peer:test' as never;
const line = (overrides: Partial<DirectConversation> = {}): DirectConversation => ({ roomId: room, peerUserId: peer, membership: 'joined', roomEpoch: 1, ...overrides });
const readyTrust = (conversation = line()): DirectTrustState => ({ roomId: conversation.roomId, peerUserId: conversation.peerUserId, roomEpoch: conversation.roomEpoch, sendReady: true, self: { userId: '@self:test' as never, identityKnown: true, crossSigningVerified: true, awaitingApproval: false, devices: [] }, peer: { userId: conversation.peerUserId, identityKnown: true, crossSigningVerified: true, awaitingApproval: false, devices: [] } });

afterEach(cleanup);

function RetryHarness({ gateway }: { readonly gateway: MatrixGateway }) {
  const [attempt, setAttempt] = useState<PendingTextAttempt>();
  return <ConversationView conversation={line()} gateway={gateway} pendingAttempt={attempt} onPendingAttempt={(expected, next) => { if (expected === undefined ? attempt !== undefined : attempt?.transactionId !== expected.transactionId) return false; setAttempt(next); return true; }} />;
}

describe('ConversationView mounted behavior', () => {
  it.each([
    ['unknown identity', { identityKnown: false }, /identity is unknown/],
    ['approval required', { awaitingApproval: true }, /Identity approval is required/],
    ['unverified cross-signing', { crossSigningVerified: false }, /cross-signing identity is not verified/],
    ['unknown device', { devices: [{ deviceId: 'd', known: false, ownerSigned: false, verified: false, ed25519Fingerprint: 'e', curve25519Fingerprint: 'c' }] }, /unknown device/],
    ['unverified device', { devices: [{ deviceId: 'd', known: true, ownerSigned: true, verified: false, ed25519Fingerprint: 'e', curve25519Fingerprint: 'c' }] }, /unverified device/],
    ['unsigned device', { devices: [{ deviceId: 'd', known: true, ownerSigned: false, verified: true, ed25519Fingerprint: 'e', curve25519Fingerprint: 'c' }] }, /missing identity approval/],
    ['not send-ready', { sendReady: false }, /not ready to send/],
  ] as const)('reports the %s trust gate', (_name, changes, expected) => {
    const current = { ...readyTrust(), ...changes, peer: { ...readyTrust().peer, ...changes } } as DirectTrustState;
    render(<TrustWarnings trust={current} />);
    expect(screen.getByText(expected)).not.toBeNull();
  });
  it('installs all feeds, isolates throwing cleanup, and unwinds a partial installation', () => {
    const timelineStop = vi.fn(() => { throw new Error('already stopped'); });
    const trustStop = vi.fn();
    const verificationStop = vi.fn();
    const gateway = { subscribeTimeline: vi.fn(() => timelineStop), subscribeDirectTrust: vi.fn(() => trustStop), subscribeVerification: vi.fn(() => verificationStop) } as unknown as MatrixGateway;
    const feeds = subscribeRoomFeeds(gateway, line(), { timeline: () => undefined, trust: () => undefined, verification: () => undefined });
    feeds.stop();
    expect(timelineStop).toHaveBeenCalledOnce();
    expect(trustStop).toHaveBeenCalledOnce();
    expect(verificationStop).toHaveBeenCalledOnce();

    const partialStop = vi.fn(() => { throw new Error('cleanup failure'); });
    const partialGateway = { subscribeTimeline: vi.fn(() => partialStop), subscribeDirectTrust: vi.fn(() => { throw new Error('trust unavailable'); }), subscribeVerification: vi.fn() } as unknown as MatrixGateway;
    expect(() => subscribeRoomFeeds(partialGateway, line(), { timeline: () => undefined, trust: () => undefined, verification: () => undefined })).toThrow('trust unavailable');
    expect(partialStop).toHaveBeenCalledOnce();
  });

  it('locks editing until fresh trust is ready, retains an exact failed body and opaque transaction for UI retry', async () => {
    let trustListener!: (trust: DirectTrustState) => void;
    const transaction = 'opaque-transaction-id';
    const sendDirectText = vi.fn().mockRejectedValueOnce(new Error('indeterminate')).mockResolvedValueOnce(undefined);
    const gateway = {
      subscribeTimeline: vi.fn(() => () => undefined),
      subscribeDirectTrust: vi.fn((_room: unknown, listener: typeof trustListener) => { trustListener = listener; return () => undefined; }),
      subscribeVerification: vi.fn(() => () => undefined),
      sendDirectText,
    } as unknown as MatrixGateway;
    render(<RetryHarness gateway={gateway} />);
    const composer = screen.getByLabelText('Encrypted text') as HTMLTextAreaElement;
    expect(composer.disabled).toBe(true);
    trustListener({ ...readyTrust(), peerUserId: '@wrong:test' as never });
    expect(composer.disabled).toBe(true);
    trustListener(readyTrust());
    await waitFor(() => expect(composer.disabled).toBe(false));
    fireEvent.change(composer, { target: { value: ' keep this exact\n' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send encrypted text' }));
    await screen.findByText(/Keep this exact submission and retry only when ready/);
    expect(composer.disabled).toBe(true);
    expect(screen.queryByText(transaction)).toBeNull();
    trustListener({ ...readyTrust(), sendReady: false });
    await waitFor(() => expect((screen.getByRole('button', { name: 'Retry exact submission' }) as HTMLButtonElement).disabled).toBe(true));
    fireEvent.click(screen.getByRole('button', { name: 'Retry exact submission' }));
    expect(sendDirectText).toHaveBeenCalledOnce();
    expect(composer.disabled).toBe(true);
    trustListener(readyTrust());
    await waitFor(() => expect((screen.getByRole('button', { name: 'Retry exact submission' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Retry exact submission' }));
    await waitFor(() => expect(sendDirectText).toHaveBeenCalledTimes(2));
    expect(sendDirectText.mock.calls[0][0]).toEqual(sendDirectText.mock.calls[1][0]);
    expect(sendDirectText.mock.calls[0][0]).toMatchObject({ roomId: room, peerUserId: peer, body: ' keep this exact\n' });
  });

  it('submits each SAS action only once while it is in flight', async () => {
    let verificationListener!: (state: VerificationState) => void;
    let release!: () => void;
    const confirmSas = vi.fn(() => new Promise<void>(resolve => { release = resolve; }));
    const gateway = {
      subscribeTimeline: () => () => undefined,
      subscribeDirectTrust: () => () => undefined,
      subscribeVerification: (_room: unknown, listener: typeof verificationListener) => { verificationListener = listener; return () => undefined; },
      confirmSas,
      mismatchSas: vi.fn(), cancelSas: vi.fn(), initiateSas: vi.fn(), acceptSas: vi.fn(),
    } as unknown as MatrixGateway;
    render(<ConversationView conversation={line()} gateway={gateway} onPendingAttempt={() => true} />);
    verificationListener({ roomId: room, peerUserId: peer, roomEpoch: 2, direction: 'incoming', phase: 'sas-shown', sas: { emojis: [{ emoji: '❌', label: 'stale' }], decimals: [1, 2, 3] } });
    expect(screen.queryByText('❌')).toBeNull();
    verificationListener({ roomId: room, peerUserId: peer, roomEpoch: 1, direction: 'incoming', phase: 'sas-shown', sas: { emojis: [{ emoji: '🐙', label: 'octopus' }], decimals: [123, 456, 789] } });
    const confirm = await screen.findByRole('button', { name: 'They match — confirm' });
    fireEvent.click(confirm); fireEvent.click(confirm);
    expect(confirmSas).toHaveBeenCalledOnce();
    release();
    await waitFor(() => expect((confirm as HTMLButtonElement).disabled).toBe(true));
    expect(screen.getByText('🐙')).not.toBeNull();
  });

  it('does not render opaque timeline transaction identifiers', async () => {
    let timelineListener!: (messages: readonly TimelineTextMessage[]) => void;
    const gateway = { subscribeTimeline: (_room: unknown, listener: typeof timelineListener) => { timelineListener = listener; return () => undefined; }, subscribeDirectTrust: () => () => undefined, subscribeVerification: () => () => undefined } as unknown as MatrixGateway;
    render(<ConversationView conversation={line()} gateway={gateway} onPendingAttempt={() => true} />);
    timelineListener([{ identity: { roomId: room, peerUserId: peer, roomEpoch: 2 }, localId: 'stale', peerUserId: peer, timestamp: 0, direction: 'incoming', eventId: '$stale' as never, delivery: 'synced', plaintext: 'stale plaintext' }]);
    expect(screen.queryByText('stale plaintext')).toBeNull();
    timelineListener([{ identity: { roomId: room, peerUserId: peer, roomEpoch: 1 }, localId: 'wrong-peer', peerUserId: '@wrong:test' as never, timestamp: 0, direction: 'incoming', eventId: '$wrong-peer' as never, delivery: 'synced', plaintext: 'wrong peer plaintext' }]);
    expect(screen.queryByText('wrong peer plaintext')).toBeNull();
    timelineListener([{ identity: { roomId: room, peerUserId: peer, roomEpoch: 1 }, localId: 'pending', peerUserId: peer, timestamp: 1, direction: 'outgoing', transactionId: 'opaque-tx' as never, delivery: 'local-pending', plaintext: 'visible text', indeterminate: true }]);
    expect(await screen.findByText('visible text')).not.toBeNull();
    expect(screen.queryByText('opaque-tx')).toBeNull();
  });

  it('bidi-isolates the selectable Matrix peer identifier in the conversation header', () => {
    render(<ConversationView conversation={line()} gateway={{} as MatrixGateway} onPendingAttempt={() => true} />);
    const peerHeader = screen.getByText('@peer:test');
    expect(peerHeader.tagName).toBe('BDI');
    expect(peerHeader.getAttribute('dir')).toBe('ltr');
    expect(peerHeader.className).toContain('select-text');
  });
});
