import { StrictMode } from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App, { applyPendingAttemptCas, ConversationList, RehearsalReferences, RoomControls } from './App';
import type { PendingTextAttempt } from './features/conversations/ConversationView';
import type { DirectConversation, DirectTrustState, MatrixGateway, MatrixRuntime, VerificationState } from './matrix';

const line = (peerUserId = '@first:test', roomEpoch = 1): DirectConversation => ({ roomId: '!shared:test' as never, peerUserId: peerUserId as never, roomEpoch, membership: 'joined' });
const trust = (conversation: DirectConversation): DirectTrustState => ({ roomId: conversation.roomId, peerUserId: conversation.peerUserId, roomEpoch: conversation.roomEpoch, sendReady: true, self: { userId: '@self:test' as never, identityKnown: true, crossSigningVerified: true, awaitingApproval: false, devices: [] }, peer: { userId: conversation.peerUserId, identityKnown: true, crossSigningVerified: true, awaitingApproval: false, devices: [] } });

afterEach(cleanup);

describe('App mounted conversation identity boundaries', () => {
  it('never evicts an unresolved attempt when the bounded reservation set is full', () => {
    let attempts: ReadonlyMap<string, PendingTextAttempt> = new Map();
    for (let index = 0; index < 8; index += 1) {
      const attempt: PendingTextAttempt = { roomId: `!room-${index}:test` as never, peerUserId: `@peer-${index}:test` as never, roomEpoch: 1, body: `text-${index}`, transactionId: `txn-${index}` as never };
      attempts = applyPendingAttemptCas(attempts, undefined, attempt)!;
    }
    const ninth: PendingTextAttempt = { roomId: '!room-9:test' as never, peerUserId: '@peer-9:test' as never, roomEpoch: 1, body: 'ninth', transactionId: 'txn-9' as never };
    expect(applyPendingAttemptCas(attempts, undefined, ninth)).toBeUndefined();
    expect([...attempts.values()].map(value => value.transactionId)).toEqual(Array.from({ length: 8 }, (_, index) => `txn-${index}`));
    const first = attempts.values().next().value!;
    const released = applyPendingAttemptCas(attempts, first, undefined)!;
    expect(applyPendingAttemptCas(released, undefined, ninth)?.get('!room-9:test\u0000@peer-9:test\u00001')).toEqual(ninth);
  });
  it('cleans subscriptions and remounts all conversation UI state when peer or epoch changes', async () => {
    let conversationsListener!: (next: readonly DirectConversation[]) => void;
    let trustListener!: (next: DirectTrustState) => void;
    let verificationListener!: (next: VerificationState) => void;
    const stops = [vi.fn(), vi.fn(), vi.fn(), vi.fn()];
    const gateway = {
      subscribeSecurityState: vi.fn(() => stops[0]),
      subscribeDirectConversations: vi.fn(listener => { conversationsListener = listener; return stops[1]; }),
      subscribeTimeline: vi.fn(() => stops[2]),
      subscribeDirectTrust: vi.fn((_room: unknown, listener: typeof trustListener) => { trustListener = listener; return stops[3]; }),
      subscribeVerification: vi.fn((_room: unknown, listener: typeof verificationListener) => { verificationListener = listener; return vi.fn(); }),
    } as unknown as MatrixGateway;
    const runtime = { startup: Promise.resolve('ready'), gateway, startSignIn: vi.fn(), logout: vi.fn(), close: vi.fn() } as MatrixRuntime;
    const view = render(<App runtime={runtime} />);
    await waitFor(() => expect(gateway.subscribeDirectConversations).toHaveBeenCalledOnce());
    const first = line();
    conversationsListener([first]);
    await screen.findByRole('heading', { name: '@first:test' });
    await waitFor(() => expect(gateway.subscribeDirectTrust).toHaveBeenCalledOnce());
    await waitFor(() => expect(gateway.subscribeVerification).toHaveBeenCalledOnce());
    trustListener(trust(first));
    const composer = screen.getByLabelText('Encrypted text');
    await waitFor(() => expect((composer as HTMLTextAreaElement).disabled).toBe(false));
    fireEvent.change(composer, { target: { value: 'old draft' } });
    verificationListener({ roomId: first.roomId, peerUserId: first.peerUserId, roomEpoch: first.roomEpoch, direction: 'incoming', phase: 'sas-shown', sas: { emojis: [{ emoji: '🐙', label: 'octopus' }], decimals: [123, 456, 789] } });
    await screen.findByText('🐙');
    const changed = line('@second:test', 2);
    conversationsListener([changed]);
    await screen.findByRole('heading', { name: '@second:test' });
    expect(screen.queryByText('🐙')).toBeNull();
    expect((screen.getByLabelText('Encrypted text') as HTMLTextAreaElement).value).toBe('');
    expect((screen.getByLabelText('Encrypted text') as HTMLTextAreaElement).disabled).toBe(true);
    expect(screen.queryByDisplayValue('old draft')).toBeNull();
    view.unmount();
    expect(stops[0]).toHaveBeenCalledOnce();
    expect(stops[1]).toHaveBeenCalledOnce();
    expect(stops[2]).toHaveBeenCalled();
    expect(stops[3]).toHaveBeenCalled();
  });

  it.each([
    ['resolves', (settle: { resolve: () => void; reject: () => void }) => settle.resolve()],
    ['rejects', (settle: { resolve: () => void; reject: () => void }) => settle.reject()],
  ])('keeps a replacement attempt exact when an earlier same-identity send later %s', async (_outcome, settleOld) => {
    let conversationsListener!: (next: readonly DirectConversation[]) => void;
    let trustListener!: (next: DirectTrustState) => void;
    let resolveOld!: () => void;
    let rejectOld!: () => void;
    const oldSend = new Promise<void>((resolve, reject) => { resolveOld = resolve; rejectOld = reject; });
    const sendDirectText = vi.fn()
      .mockImplementationOnce(() => oldSend)
      .mockRejectedValueOnce(new Error('epoch two indeterminate'))
      .mockResolvedValueOnce(undefined);
    const gateway = {
      subscribeSecurityState: vi.fn(() => () => undefined),
      subscribeDirectConversations: vi.fn(listener => { conversationsListener = listener; return () => undefined; }),
      subscribeTimeline: vi.fn(() => () => undefined),
      subscribeDirectTrust: vi.fn((_room: unknown, listener: typeof trustListener) => { trustListener = listener; return () => undefined; }),
      subscribeVerification: vi.fn(() => () => undefined),
      sendDirectText,
    } as unknown as MatrixGateway;
    const runtime = { startup: Promise.resolve('ready'), gateway, startSignIn: vi.fn(), logout: vi.fn(), close: vi.fn() } as MatrixRuntime;
    render(<App runtime={runtime} />);
    await waitFor(() => expect(gateway.subscribeDirectConversations).toHaveBeenCalledOnce());

    const epochOne = line('@same-peer:test', 1);
    conversationsListener([epochOne]);
    await screen.findByRole('heading', { name: '@same-peer:test' });
    await waitFor(() => expect(gateway.subscribeDirectTrust).toHaveBeenCalledOnce());
    trustListener(trust(epochOne));
    const epochOneComposer = screen.getByLabelText('Encrypted text');
    await waitFor(() => expect((epochOneComposer as HTMLTextAreaElement).disabled).toBe(false));
    fireEvent.change(epochOneComposer, { target: { value: 'epoch one text' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send encrypted text' }));
    await waitFor(() => expect(sendDirectText).toHaveBeenCalledOnce());

    // Remove and remount the exact same identity while its first transport is
    // unresolved. The parent deliberately prunes the obsolete reservation.
    conversationsListener([]);
    await waitFor(() => expect(screen.queryByRole('heading', { name: '@same-peer:test' })).toBeNull());
    const epochTwo = line('@same-peer:test', 1);
    conversationsListener([epochTwo]);
    await waitFor(() => expect(gateway.subscribeDirectTrust).toHaveBeenCalledTimes(2));
    trustListener(trust(epochTwo));
    await waitFor(() => expect((screen.getByLabelText('Encrypted text') as HTMLTextAreaElement).disabled).toBe(false));
    const epochTwoComposer = screen.getByLabelText('Encrypted text');
    fireEvent.change(epochTwoComposer, { target: { value: 'epoch two text' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send encrypted text' }));
    await screen.findByRole('button', { name: 'Retry exact submission' });
    expect((epochTwoComposer as HTMLTextAreaElement).disabled).toBe(true);

    settleOld({ resolve: resolveOld, reject: rejectOld });
    await waitFor(() => expect((screen.getByRole('button', { name: 'Retry exact submission' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Retry exact submission' }));
    await waitFor(() => expect(sendDirectText).toHaveBeenCalledTimes(3));
    expect(sendDirectText.mock.calls[1][0]).toMatchObject({ roomId: epochTwo.roomId, peerUserId: epochTwo.peerUserId, roomEpoch: 1, body: 'epoch two text' });
    expect(sendDirectText.mock.calls[2][0]).toEqual(sendDirectText.mock.calls[1][0]);
    expect(screen.queryByText('epoch-1-transaction')).toBeNull();
    expect(screen.queryByText('epoch-2-transaction')).toBeNull();
  });
});

describe('G2 rehearsal references', () => {
  const observation = { userId: '@self:test' as never, deviceId: 'DEVICE' as never, profileRef: 'a'.repeat(64), crossSigningMasterRef: 'A'.repeat(43) };

  const mountedRuntime = (overrides: Partial<MatrixGateway> = {}) => {
    let conversationsListener!: (next: readonly DirectConversation[]) => void;
    let securityListener!: (next: 'ready' | 'blocked') => void;
    const gateway = {
      subscribeSecurityState: vi.fn(listener => { securityListener = listener; return () => undefined; }),
      subscribeDirectConversations: vi.fn(listener => { conversationsListener = listener; return () => undefined; }),
      subscribeTimeline: vi.fn(() => () => undefined),
      subscribeDirectTrust: vi.fn(() => () => undefined),
      subscribeVerification: vi.fn(() => () => undefined),
      observeLocalIdentity: vi.fn().mockResolvedValue(observation),
      ...overrides,
    } as unknown as MatrixGateway;
    return { runtime: { startup: Promise.resolve('ready'), gateway, startSignIn: vi.fn(), logout: vi.fn(), close: vi.fn() } as MatrixRuntime, gateway, publishConversations: (next: readonly DirectConversation[]) => conversationsListener(next), loseSecurity: () => securityListener('blocked') };
  };

  it('deliberately reveals exactly the four local references before a room is selected, then conceals them', async () => {
    const fixture = mountedRuntime();
    const view = render(<App runtime={fixture.runtime} />);
    await waitFor(() => expect(fixture.gateway.subscribeDirectConversations).toHaveBeenCalledOnce());
    const show = screen.getByRole('button', { name: 'Show rehearsal references' });
    const privacy = screen.getByText(/sensitive, linkable metadata/i);
    expect(show.getAttribute('aria-describedby')).toBe(privacy.id);
    expect(privacy.compareDocumentPosition(show) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect((show as HTMLButtonElement).disabled).toBe(false);
    expect(view.container.textContent).not.toContain(observation.profileRef);
    fireEvent.click(show);
    await screen.findByText(observation.profileRef);
    expect([...view.container.querySelectorAll('dt')].map(reference => reference.textContent)).toEqual(['Account', 'Device', 'Browser profile', 'Cross-signing identity']);
    expect(screen.queryByText('Room reference')).toBeNull();
    expect(fixture.gateway.observeLocalIdentity).toHaveBeenCalledOnce();
    fixture.publishConversations([line()]);
    await screen.findByRole('heading', { name: '@first:test' });
    expect(view.container.textContent).not.toContain(observation.profileRef);
    fireEvent.click(screen.getByRole('button', { name: 'Show rehearsal references' }));
    await screen.findByText('Room reference');
    expect(fixture.gateway.observeLocalIdentity).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: 'Hide rehearsal references' }));
    expect(view.container.textContent).not.toContain(observation.profileRef);
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Show rehearsal references' }));
  });

  it('moves focus to the newly rendered hide control after revealing references', async () => {
    const runtime = { gateway: { observeLocalIdentity: vi.fn().mockResolvedValue(observation) } } as unknown as MatrixRuntime;
    render(<RehearsalReferences state="ready" runtime={runtime} />);
    const show = screen.getByRole('button', { name: 'Show rehearsal references' });
    show.focus();
    fireEvent.click(show);
    const hide = await screen.findByRole('button', { name: 'Hide rehearsal references' });
    expect(document.activeElement).toBe(hide);
  });

  it('bidi-isolates selectable Matrix identifiers in conversation navigation', () => {
    render(<ConversationList conversations={[line('@peer:test')]} selectedRoomId="!shared:test" onSelect={() => undefined} />);
    const peer = screen.getByText('@peer:test');
    expect(peer.tagName).toBe('BDI');
    expect(peer.getAttribute('dir')).toBe('ltr');
    expect(peer.className).toContain('select-text');
  });

  it('suppresses stale observations and automatically conceals on security loss or generic failure', async () => {
    let resolve!: (value: typeof observation) => void;
    const delayed = new Promise<typeof observation>(next => { resolve = next; });
    const fixture = mountedRuntime({ observeLocalIdentity: vi.fn().mockReturnValueOnce(delayed).mockRejectedValueOnce(new Error('private cause')) });
    const view = render(<App runtime={fixture.runtime} />);
    await waitFor(() => expect(fixture.gateway.subscribeDirectConversations).toHaveBeenCalledOnce());
    fireEvent.click(screen.getByRole('button', { name: 'Show rehearsal references' }));
    fixture.publishConversations([line('@second:test', 2)]);
    await screen.findByRole('heading', { name: '@second:test' });
    resolve(observation);
    await waitFor(() => expect(view.container.textContent).not.toContain(observation.profileRef));
    fireEvent.click(screen.getByRole('button', { name: 'Show rehearsal references' }));
    const failure = await screen.findByText(/Rehearsal references could not be shown/);
    expect(failure.textContent).toContain('Rehearsal references could not be shown.');
    expect(screen.queryByText('private cause')).toBeNull();
  });

  it('synchronously conceals revealed references when ready authority or runtime changes', async () => {
    const gateway = { observeLocalIdentity: vi.fn().mockResolvedValue(observation) } as unknown as MatrixGateway;
    const runtime = { gateway } as MatrixRuntime;
    const view = render(<RehearsalReferences state="ready" runtime={runtime} conversation={line()} />);
    fireEvent.click(view.getByRole('button', { name: 'Show rehearsal references' }));
    await view.findByText(observation.profileRef);
    view.rerender(<RehearsalReferences state="blocked" runtime={runtime} conversation={line()} />);
    expect(view.container.textContent).not.toContain(observation.profileRef);
    view.rerender(<RehearsalReferences state="ready" runtime={runtime} conversation={line()} />);
    fireEvent.click(view.getByRole('button', { name: 'Show rehearsal references' }));
    await view.findByText(observation.profileRef);
    view.rerender(<RehearsalReferences state="ready" runtime={{ gateway } as MatrixRuntime} conversation={line()} />);
    expect(view.container.textContent).not.toContain(observation.profileRef);
  });

  it('uses Matrix room ID-only copy and the canonical roomId join request', async () => {
    const joinDirectConversation = vi.fn().mockResolvedValue(line());
    const runtime = { gateway: { joinDirectConversation } } as unknown as MatrixRuntime;
    render(<RoomControls state="ready" runtime={runtime} />);
    const roomId = screen.getByLabelText('Matrix room ID');
    fireEvent.change(roomId, { target: { value: '!rehearsal:test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Join direct conversation' }));
    await waitFor(() => expect(joinDirectConversation).toHaveBeenCalledWith({ roomId: '!rehearsal:test' }));
    expect(screen.getByText(/Use the Matrix room ID/i)).not.toBeNull();
    expect(screen.queryByText(/alias/i)).toBeNull();
  });

  it('rejects malformed admissions and a mismatched join response without retaining fields or notices after authority replacement', async () => {
    const joinDirectConversation = vi.fn().mockResolvedValue({ ...line(), roomId: '!other:test' as never });
    const runtime = { gateway: { joinDirectConversation, createDirectConversation: vi.fn() } } as unknown as MatrixRuntime;
    const view = render(<RoomControls state="ready" runtime={runtime} />);
    fireEvent.change(screen.getByLabelText('One peer'), { target: { value: '@UPPER:test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create direct conversation' }));
    expect(screen.getByText(/Add one peer/)).not.toBeNull();
    fireEvent.change(screen.getByLabelText('Matrix room ID'), { target: { value: '!requested:test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Join direct conversation' }));
    await screen.findByText(/could not be joined/);
    view.rerender(<RoomControls state="ready" runtime={{ ...runtime, gateway: runtime.gateway } as MatrixRuntime} />);
    expect((screen.getByLabelText('Matrix room ID') as HTMLInputElement).value).toBe('');
    expect(screen.queryByText(/could not be joined/)).toBeNull();
  });

  it('StrictMode remounts filled and in-flight controls across runtime and security authority replacement', async () => {
    let resolveCreate!: () => void;
    const createDirectConversation = vi.fn(() => new Promise<void>(resolve => { resolveCreate = resolve; }));
    const first = { gateway: { createDirectConversation, joinDirectConversation: vi.fn() } } as unknown as MatrixRuntime;
    const second = { gateway: { createDirectConversation: vi.fn(), joinDirectConversation: vi.fn() } } as unknown as MatrixRuntime;
    const view = render(<StrictMode><RoomControls state="ready" runtime={first} /></StrictMode>);
    fireEvent.change(screen.getByLabelText('One peer'), { target: { value: '@peer:test' } });
    fireEvent.change(screen.getByLabelText('Matrix room ID'), { target: { value: '!room:test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create direct conversation' }));
    await waitFor(() => expect(createDirectConversation).toHaveBeenCalledOnce());
    expect((screen.getByLabelText('Matrix room ID') as HTMLInputElement).value).toBe('!room:test');

    view.rerender(<StrictMode><RoomControls state="ready" runtime={second} /></StrictMode>);
    expect((screen.getByLabelText('One peer') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Matrix room ID') as HTMLInputElement).value).toBe('');
    expect(screen.getByRole('button', { name: 'Create direct conversation' })).not.toHaveProperty('disabled', true);
    resolveCreate();
    await Promise.resolve();
    expect(screen.queryByText('Direct conversation created.')).toBeNull();

    fireEvent.change(screen.getByLabelText('One peer'), { target: { value: '@new:test' } });
    view.rerender(<StrictMode><RoomControls state="blocked" runtime={second} /></StrictMode>);
    view.rerender(<StrictMode><RoomControls state="ready" runtime={second} /></StrictMode>);
    expect((screen.getByLabelText('One peer') as HTMLInputElement).value).toBe('');
  });
});
