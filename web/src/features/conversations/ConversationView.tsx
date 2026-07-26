import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { DirectConversation, DirectTrustState, MatrixGateway, MatrixRoomId, MatrixTransactionId, TimelineTextMessage, VerificationState } from '../../matrix';

export const deliveryCopy: Record<TimelineTextMessage['delivery'], string> = {
  decrypting: 'Decrypting message…',
  'decryption-failed': 'Message could not be decrypted.',
  'local-pending': 'Homeserver acceptance is unknown. Do not assume this message was sent or delivered.',
  'homeserver-accepted': 'Accepted by homeserver — not a delivery or read confirmation.',
  synced: 'Synced',
  failed: 'Message was not sent. Try again when the secure line is ready.',
};

export interface PendingTextAttempt {
  readonly roomId: MatrixRoomId;
  readonly peerUserId: DirectConversation['peerUserId'];
  readonly roomEpoch: DirectConversation['roomEpoch'];
  readonly body: string;
  readonly transactionId: MatrixTransactionId;
}

export const orderedTimeline = (messages: readonly TimelineTextMessage[]): readonly TimelineTextMessage[] =>
  [...messages].sort((left, right) => left.timestamp - right.timestamp || left.localId.localeCompare(right.localId));

export const createTransactionId = (): MatrixTransactionId => {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID() as MatrixTransactionId;
  if (!globalThis.crypto?.getRandomValues) throw new Error('secure transaction identity unavailable');
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40; bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}` as MatrixTransactionId;
};

export function TrustWarnings({ trust }: { readonly trust?: DirectTrustState }) {
  if (!trust) return <p className="text-sm text-zinc-300">Checking the secure line before text sending is available.</p>;
  const peer = trust.peer; const warnings: string[] = [];
  if (!peer.identityKnown) warnings.push('This person’s identity is unknown. Approve their identity before sending.');
  if (peer.awaitingApproval) warnings.push('Identity approval is required before sending.');
  if (!peer.crossSigningVerified) warnings.push('This person’s cross-signing identity is not verified. Complete verification before sending.');
  if (peer.devices.some(device => !device.known)) warnings.push('A new or unknown device needs verification before sending.');
  if (peer.devices.some(device => device.known && !device.verified)) warnings.push('An unverified device needs verification before sending.');
  if (peer.devices.some(device => device.known && !device.ownerSigned)) warnings.push('A device is missing identity approval before sending.');
  if (!warnings.length && !trust.sendReady) warnings.push('The secure line is not ready to send. Keep verification active and wait for a fresh trust check.');
  if (!warnings.length) return <p className="text-sm font-bold text-lime-200">All visible trust checks are ready for encrypted text sending.</p>;
  return <ul aria-label="Security requirements" className="space-y-2 text-sm leading-5 text-amber-100">{warnings.map(warning => <li key={warning} className="border-l-4 border-amber-300 pl-3">{warning}</li>)}</ul>;
}

export function VerificationFlow({ conversation, verification, gateway, announce }: { readonly conversation: DirectConversation; readonly verification?: VerificationState; readonly gateway: MatrixGateway; readonly announce: (copy: string) => void }) {
  const [action, setAction] = useState<string>();
  const usedActions = useRef(new Set<string>());
  const phase = verification?.phase ?? 'idle'; const sas = phase === 'sas-shown' ? verification?.sas : undefined;
  useEffect(() => { usedActions.current.clear(); setAction(undefined); }, [conversation.roomId, conversation.peerUserId, conversation.roomEpoch, phase]);
  const request = { roomId: conversation.roomId, peerUserId: conversation.peerUserId, roomEpoch: conversation.roomEpoch };
  const invoke = (next: string, command: () => Promise<void>) => {
    if (action || usedActions.current.has(next)) return;
    usedActions.current.add(next); setAction(next); announce('Verification operation in progress.');
    void command().then(() => announce('Verification operation submitted. Wait for the secure-line update.')).catch(() => announce('Verification operation could not continue. Wait for a secure-line update before trying again.')).finally(() => setAction(undefined));
  };
  const button = (label: string, actionName: string, command: () => Promise<void>, tone = 'bg-fuchsia-300') => <button type="button" disabled={Boolean(action) || usedActions.current.has(actionName)} onClick={() => invoke(actionName, command)} className={`border-2 border-zinc-950 px-3 py-2 text-sm font-black uppercase text-zinc-950 ${tone} disabled:cursor-not-allowed disabled:opacity-60`}>{action === actionName ? 'Working…' : label}</button>;
  if (phase === 'done' || phase === 'cancelled' || phase === 'failed') return <p className="text-sm font-bold">Verification {phase}. Comparison values have been cleared.</p>;
  return <section aria-labelledby="verification-heading" className="border-2 border-zinc-950 bg-white p-4 text-zinc-950"><h3 id="verification-heading" className="font-mono text-sm font-black uppercase">Identity comparison</h3>
    {phase === 'idle' && <><p className="mt-2 text-sm">Start a person-to-person comparison for this secure line.</p><div className="mt-3">{button('Request verification', 'initiate', () => gateway.initiateSas(request), 'bg-lime-300')}</div></>}
    {phase === 'requested' && verification?.direction === 'incoming' && <><p className="mt-2 text-sm font-bold">This person requested identity verification. Accept only if you intend to compare with them.</p><div className="mt-3 flex gap-2">{button('Accept request', 'accept', () => gateway.acceptSas(request), 'bg-lime-300')}{button('Cancel', 'cancel', () => gateway.cancelSas(request), 'bg-zinc-300')}</div></>}
    {phase === 'requested' && verification?.direction === 'outgoing' && <><p className="mt-2 text-sm">Verification requested. Wait for the other person to make their line ready.</p><div className="mt-3">{button('Cancel request', 'cancel', () => gateway.cancelSas(request), 'bg-zinc-300')}</div></>}
    {phase === 'accepted' && <p className="mt-2 text-sm">Request accepted. Wait until the secure line is ready to start comparison.</p>}
    {phase === 'ready' && <><p className="mt-2 text-sm">Both sides are ready. The secure line is starting the comparison; wait for the temporary values before confirming anything.</p><div className="mt-3">{button('Cancel', 'cancel', () => gateway.cancelSas(request), 'bg-zinc-300')}</div></>}
    {phase === 'started' && <p className="mt-2 text-sm">Preparing a temporary comparison. Do not approve anything yet.</p>}
    {phase === 'sas-shown' && sas && <div className="mt-3"><p className="text-sm font-bold">Compare every symbol and number with the other person using a separate trusted channel. Confirm only when every value matches exactly.</p><ol aria-label="Emoji comparison" className="mt-3 grid grid-cols-3 gap-2">{sas.emojis.map(item => <li key={`${item.emoji}-${item.label}`} className="border-2 border-zinc-950 p-2 text-center"><span aria-hidden="true" className="block text-2xl">{item.emoji}</span><span className="text-xs font-bold">{item.label}</span></li>)}</ol><p className="mt-3 font-mono text-lg font-black" aria-label={`Decimal comparison: ${sas.decimals.join(', ')}`}>{sas.decimals.join(' · ')}</p><div className="mt-4 flex flex-wrap gap-2">{button('They match — confirm', 'confirm', () => gateway.confirmSas(request), 'bg-lime-300')}{button('They do not match', 'mismatch', () => gateway.mismatchSas(request), 'bg-amber-300')}{button('Cancel comparison', 'cancel', () => gateway.cancelSas(request), 'bg-zinc-300')}</div></div>}
    {phase === 'confirming' && <p className="mt-2 text-sm font-bold">Confirmation sent. Temporary comparison values are cleared; wait for the result.</p>}
  </section>;
}

export interface RoomSubscriptions { readonly stop: () => void; }
export function stopAll(unsubscribes: readonly (() => void)[]): void {
  for (const unsubscribe of unsubscribes) {
    try { unsubscribe(); } catch { /* cleanup is best-effort; remaining feeds must still stop */ }
  }
}
/** Starts all room feeds atomically; a partial start is immediately unwound. */
export function subscribeRoomFeeds(gateway: MatrixGateway, identity: DirectConversation, listeners: { timeline: (messages: readonly TimelineTextMessage[]) => void; trust: (trust: DirectTrustState) => void; verification: (verification: VerificationState) => void }): RoomSubscriptions {
  const stops: (() => void)[] = [];
  try {
    stops.push(gateway.subscribeTimeline(identity, listeners.timeline));
    stops.push(gateway.subscribeDirectTrust(identity, listeners.trust));
    stops.push(gateway.subscribeVerification(identity, listeners.verification));
  } catch (error) { stopAll(stops); throw error; }
  return { stop: () => stopAll(stops) };
}

/** Deliberately forwards the retained, opaque transaction identity without displaying it. */
export const submitExactAttempt = (gateway: MatrixGateway, attempt: PendingTextAttempt): Promise<void> => gateway.sendDirectText(attempt);

export function ConversationView({ conversation, gateway, pendingAttempt, onPendingAttempt }: { readonly conversation: DirectConversation; readonly gateway: MatrixGateway; readonly pendingAttempt?: PendingTextAttempt; readonly onPendingAttempt: (expected: PendingTextAttempt | undefined, next: PendingTextAttempt | undefined) => boolean }) {
  const [messages, setMessages] = useState<readonly TimelineTextMessage[]>([]); const [trust, setTrust] = useState<DirectTrustState>(); const [verification, setVerification] = useState<VerificationState>();
  const [body, setBody] = useState(''); const [sending, setSending] = useState(false); const [notice, setNotice] = useState('');
  const activeAttempt = useRef<PendingTextAttempt | undefined>(undefined);
  const roomId = conversation.roomId;
  const identity = `${conversation.roomId}\u0000${conversation.peerUserId}\u0000${conversation.roomEpoch}`;
  useEffect(() => {
    let active = true;
    setMessages([]); setTrust(undefined); setVerification(undefined); setBody(''); setSending(false); setNotice('');
    try {
      const feeds = subscribeRoomFeeds(gateway, conversation, {
        timeline: next => { if (active) setMessages(next.filter(message => message.identity.roomId === roomId && message.identity.peerUserId === conversation.peerUserId && message.peerUserId === conversation.peerUserId && message.identity.roomEpoch === conversation.roomEpoch)); },
        trust: next => { if (active && next.roomId === roomId && next.peerUserId === conversation.peerUserId && next.roomEpoch === conversation.roomEpoch && next.peer.userId === conversation.peerUserId) setTrust(next); },
        verification: next => { if (active && next.roomId === roomId && next.peerUserId === conversation.peerUserId && next.roomEpoch === conversation.roomEpoch) setVerification(next); },
      });
      return () => { active = false; feeds.stop(); };
    } catch { if (active) setNotice('The secure line could not be updated. Try refreshing before taking another action.'); return () => { active = false; }; }
  }, [gateway, identity]);
  const currentAttempt = pendingAttempt && pendingAttempt.roomId === roomId && pendingAttempt.peerUserId === conversation.peerUserId && pendingAttempt.roomEpoch === conversation.roomEpoch ? pendingAttempt : undefined;
  const sendReady = conversation.membership === 'joined' && trust?.sendReady === true && !sending;
  const canSend = sendReady && !currentAttempt;
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (activeAttempt.current || !sendReady) return;
    let attempt: PendingTextAttempt | undefined = currentAttempt;
    if (!attempt) {
      if (!canSend || !body.trim()) return;
      try { attempt = { roomId, peerUserId: conversation.peerUserId, roomEpoch: conversation.roomEpoch, body, transactionId: createTransactionId() }; } catch { setNotice('A secure send identity could not be created. Text was not submitted.'); return; }
      // Reserve the exact transaction in shared state before transport starts.
      // A remount can therefore never launch a successor behind an untracked send.
      if (!onPendingAttempt(undefined, attempt)) return;
    }
    if (!attempt) return;
    activeAttempt.current = attempt;
    setSending(true); setNotice(currentAttempt ? 'Retrying the same encrypted submission.' : 'Submitting encrypted text.');
    void submitExactAttempt(gateway, attempt).then(() => { onPendingAttempt(attempt, undefined); setBody(''); setNotice('Text accepted by the homeserver — not a delivery or read confirmation.'); }).catch(() => { onPendingAttempt(attempt, attempt); setNotice('Homeserver acceptance is unknown. Keep this exact submission and retry only when ready.'); }).finally(() => { activeAttempt.current = undefined; setSending(false); });
  };
  return <section aria-labelledby="conversation-heading" className="border-2 border-white bg-zinc-900 p-5 shadow-[6px_6px_0_0_#d9f99d] sm:p-6"><p className="font-mono text-xs font-bold tracking-[0.15em] text-lime-200">ONE-PEER DIRECT LINE</p><h2 id="conversation-heading" className="mt-2 break-all text-2xl font-black text-white"><bdi dir="ltr" className="select-text">{conversation.peerUserId}</bdi></h2><p role="status" aria-live="polite" aria-atomic="true" className="sr-only">{notice}</p>
    <div className="mt-5 grid gap-5 lg:grid-cols-[1.2fr_0.8fr]"><div><section aria-labelledby="timeline-heading" className="border-2 border-zinc-700 bg-zinc-950 p-4"><h3 id="timeline-heading" className="font-mono text-sm font-bold uppercase">Text timeline</h3><ol className="mt-4 space-y-3">{orderedTimeline(messages).map(message => <li key={message.localId} className={`border-l-4 p-3 ${message.direction === 'outgoing' ? 'border-fuchsia-300 bg-zinc-900' : 'border-lime-300 bg-zinc-900'}`}><p className="text-xs font-black uppercase text-zinc-400">{message.direction === 'outgoing' ? 'You' : 'Peer'} · {deliveryCopy[message.delivery]}</p>{'plaintext' in message && <p className="mt-2 whitespace-pre-wrap text-sm text-white">{message.plaintext}</p>}</li>)}</ol>{!messages.length && <p className="mt-3 text-sm text-zinc-400">No text on this line yet.</p>}</section>
      <form onSubmit={submit} className="mt-5 border-2 border-zinc-700 p-4"><label htmlFor="direct-text" className="block text-sm font-bold">Encrypted text<textarea id="direct-text" value={body} onChange={event => setBody(event.target.value)} disabled={!canSend} rows={3} className="mt-2 block w-full border-2 border-white bg-zinc-950 p-3 text-white disabled:cursor-not-allowed disabled:opacity-60" /></label>{currentAttempt ? <p className="mt-2 border-l-4 border-amber-300 pl-3 text-xs font-bold text-amber-100">Homeserver acceptance is unknown. The composer is locked so this exact submission is not replaced.</p> : <p className="mt-2 text-xs text-zinc-400">{canSend ? 'Ready to send on this verified, joined line.' : 'Text sending is locked until the joined line and all trust checks are ready.'}</p>}<button type="submit" disabled={!sendReady || (!currentAttempt && !body.trim())} className="mt-3 border-2 border-lime-300 bg-lime-300 px-4 py-2 font-black uppercase text-zinc-950 disabled:cursor-not-allowed disabled:opacity-60">{sending ? 'Submitting…' : currentAttempt ? 'Retry exact submission' : 'Send encrypted text'}</button></form></div>
      <aside className="space-y-5"><section aria-labelledby="trust-heading" className="border-2 border-amber-300 bg-zinc-950 p-4"><h3 id="trust-heading" className="font-mono text-sm font-bold uppercase text-amber-100">Trust check</h3><div className="mt-3"><TrustWarnings trust={trust} /></div></section><VerificationFlow conversation={conversation} verification={verification} gateway={gateway} announce={setNotice} /></aside></div>
  </section>;
}
