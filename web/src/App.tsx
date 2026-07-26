import { useEffect, useLayoutEffect, useRef, useState, type FormEvent, type MutableRefObject } from 'react';
import { ConversationView, type PendingTextAttempt } from './features/conversations/ConversationView';
import type { DirectConversation, LocalIdentityObservation, MatrixRuntime, MatrixSecurityState } from './matrix';
import { parseMatrixUserId, parseSupportedDomainRoomId } from './matrix/identifiers';

type RoomOperation = 'create' | 'join' | undefined;

const runtimeKeys = new WeakMap<object, number>();
let nextRuntimeKey = 0;
const roomControlsAuthorityKey = (runtime: MatrixRuntime | undefined, state: MatrixSecurityState): string => {
  if (!runtime) return `none:${state}`;
  let runtimeKey = runtimeKeys.get(runtime);
  if (!runtimeKey) { runtimeKey = ++nextRuntimeKey; runtimeKeys.set(runtime, runtimeKey); }
  return `${runtimeKey}:${state}`;
};

type ConversationIdentity = Pick<DirectConversation, 'roomId' | 'peerUserId' | 'roomEpoch'>;

export const conversationIdentity = ({ roomId, peerUserId, roomEpoch }: ConversationIdentity): string => `${roomId}\u0000${peerUserId}\u0000${roomEpoch}`;
export const attemptIdentity = ({ roomId, peerUserId, roomEpoch }: Pick<PendingTextAttempt, 'roomId' | 'peerUserId' | 'roomEpoch'>): string => `${roomId}\u0000${peerUserId}\u0000${roomEpoch}`;
const maximumRetainedAttempts = 8;

/** Transaction CAS for unresolved in-memory attempts. Capacity never evicts live work. */
export function applyPendingAttemptCas(
  current: ReadonlyMap<string, PendingTextAttempt>,
  expected: PendingTextAttempt | undefined,
  next: PendingTextAttempt | undefined,
): ReadonlyMap<string, PendingTextAttempt> | undefined {
  const identity = attemptIdentity(next ?? expected!);
  const existing = current.get(identity);
  if (expected === undefined ? existing !== undefined || current.size >= maximumRetainedAttempts : existing?.transactionId !== expected.transactionId) return undefined;
  if (next && (attemptIdentity(next) !== identity || (expected && next.transactionId !== expected.transactionId))) return undefined;
  const updated = new Map(current);
  if (next) updated.set(identity, next); else updated.delete(identity);
  return updated;
}

const stateCopy: Record<MatrixSecurityState, { label: string; title: string; detail: string }> = {
  starting: { label: 'STARTING', title: 'Securing this tab', detail: 'Checking this tab’s secure storage and encryption workspace before room actions are available.' },
  blocked: { label: 'SIGNED OUT / BLOCKED', title: 'Sign in to continue', detail: 'Sign in is needed, or this device’s secure storage needs attention. Room actions stay blocked until the secure setup is complete.' },
  follower: { label: 'FOLLOWER', title: 'Encryption is active in another tab', detail: 'Another tab securely owns encryption for this profile. This tab stays read-only and cannot make room changes.' },
  unverified: { label: 'UNVERIFIED', title: 'Verify this device first', detail: 'Your device or its secure storage has not cleared the safety check. Verify it before creating or joining rooms.' },
  ready: { label: 'READY', title: 'Secure room setup available', detail: 'This tab owns persistent encryption and is ready to create or join an encrypted private room.' },
  stopped: { label: 'STOPPED', title: 'Secure session stopped', detail: 'The secure session is no longer running. Refresh or sign in again before taking room actions.' },
  failed: { label: 'FAILED', title: 'Secure setup could not continue', detail: 'The secure session could not be completed. Try signing in again before taking room actions.' },
};

const stateTone: Record<MatrixSecurityState, { panel: string; badge: string }> = {
  starting: { panel: 'border-amber-300 shadow-[6px_6px_0_0_#fcd34d]', badge: 'border-amber-100 bg-amber-300 text-zinc-950' },
  blocked: { panel: 'border-fuchsia-300 shadow-[6px_6px_0_0_#f0abfc]', badge: 'border-fuchsia-200 bg-fuchsia-300 text-zinc-950' },
  follower: { panel: 'border-cyan-300 shadow-[6px_6px_0_0_#67e8f9]', badge: 'border-cyan-100 bg-cyan-300 text-zinc-950' },
  unverified: { panel: 'border-amber-300 shadow-[6px_6px_0_0_#fcd34d]', badge: 'border-amber-100 bg-amber-300 text-zinc-950' },
  ready: { panel: 'border-lime-300 shadow-[6px_6px_0_0_#d9f99d]', badge: 'border-lime-200 bg-lime-300 text-zinc-950' },
  stopped: { panel: 'border-fuchsia-300 shadow-[6px_6px_0_0_#f0abfc]', badge: 'border-fuchsia-200 bg-fuchsia-300 text-zinc-950' },
  failed: { panel: 'border-fuchsia-300 shadow-[6px_6px_0_0_#f0abfc]', badge: 'border-fuchsia-200 bg-fuchsia-300 text-zinc-950' },
};

/** Keeps a redirecting sign-in action single-flight without surfacing its failure details. */
export function beginSingleFlight(
  flightRef: MutableRefObject<Promise<void> | undefined>,
  action: () => Promise<void>,
  onFailure: () => void,
): Promise<void> {
  if (flightRef.current) return flightRef.current;
  const flight = Promise.resolve().then(action).catch(() => {
    flightRef.current = undefined;
    onFailure();
  });
  flightRef.current = flight;
  return flight;
}

export function SecurityState({ state }: { readonly state: MatrixSecurityState }) {
  const copy = stateCopy[state];
  const tone = stateTone[state];

  return (
    <section aria-labelledby="security-heading" className={`border-2 bg-zinc-950 p-5 ${tone.panel} sm:p-6`}>
      <p role="status" aria-atomic="true" className="sr-only">{copy.label}: {copy.title}. {copy.detail}</p>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs font-bold tracking-[0.16em] text-lime-200">SECURITY STATE</p>
          <h2 id="security-heading" className="mt-2 text-2xl font-black uppercase tracking-tight text-white">{copy.title}</h2>
        </div>
        <span className={`border px-2 py-1 font-mono text-xs font-black tracking-[0.12em] ${tone.badge}`}>{copy.label}</span>
      </div>
      <p className="mt-4 max-w-2xl text-sm leading-6 text-zinc-200">{copy.detail}</p>
    </section>
  );
}

export function RoomControls({ state, runtime }: { readonly state: MatrixSecurityState; readonly runtime?: MatrixRuntime }) {
  return <RoomControlsAuthority key={roomControlsAuthorityKey(runtime, state)} state={state} runtime={runtime} />;
}

/** A changed runtime or security authority remounts this local, mutable form state. */
function RoomControlsAuthority({ state, runtime }: { readonly state: MatrixSecurityState; readonly runtime?: MatrixRuntime }) {
  const [peer, setPeer] = useState('');
  const [roomId, setRoomId] = useState('');
  const [operation, setOperation] = useState<RoomOperation>();
  const [notice, setNotice] = useState('');
  const ready = state === 'ready' && Boolean(runtime?.gateway);
  const busy = Boolean(operation);

  const createRoom = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!ready || operation) return;
    const peerUserId = parseMatrixUserId(peer.trim());
    if (!peerUserId) {
      setNotice('Add one peer before creating a direct conversation.');
      return;
    }
    setOperation('create');
    setNotice('');
    try {
      await runtime!.gateway!.createDirectConversation({ peerUserId });
      setNotice('Direct conversation created.');
      setPeer('');
    } catch {
      setNotice('The direct conversation could not be created. Check the peer and try again.');
    } finally {
      setOperation(undefined);
    }
  };

  const joinRoom = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!ready || operation) return;
    const requestedRoomId = parseSupportedDomainRoomId(roomId.trim());
    if (!requestedRoomId) {
      setNotice('Add a Matrix room ID before joining a room.');
      return;
    }
    setOperation('join');
    setNotice('');
    try {
      const joined = await runtime!.gateway!.joinDirectConversation({ roomId: requestedRoomId });
      if (joined.roomId !== requestedRoomId) throw new Error('room mismatch');
      setNotice('Direct conversation joined.');
      setRoomId('');
    } catch {
      setNotice('The direct conversation could not be joined. Check the Matrix room ID and try again.');
    } finally {
      setOperation(undefined);
    }
  };

  if (!ready) {
    return (
      <section aria-labelledby="room-actions-heading" className="border border-zinc-700 bg-zinc-900 p-5">
        <h2 id="room-actions-heading" className="font-mono text-sm font-bold uppercase tracking-[0.12em] text-zinc-100">Direct conversation actions locked</h2>
        <p className="mt-2 text-sm leading-6 text-zinc-300">Create and join controls appear only after this tab has a verified, persistent encryption workspace.</p>
      </section>
    );
  }

  return (
    <section aria-labelledby="room-actions-heading" className="border-2 border-white bg-white p-5 text-zinc-950 shadow-[6px_6px_0_0_#f472b6] sm:p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-4">
        <h2 id="room-actions-heading" className="text-xl font-black uppercase">One-peer direct setup</h2>
        <span className="font-mono text-xs font-bold">TASK 9</span>
      </div>
      <p className="mt-2 text-sm leading-6 text-zinc-700">Create or join one encrypted, exact-two-person line. Groups are not supported here.</p>
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <form onSubmit={createRoom} className="space-y-3 border-2 border-zinc-950 p-4">
          <h3 className="font-bold uppercase">Create direct conversation</h3>
          <label className="block text-sm font-bold" htmlFor="direct-peer">One peer
            <input id="direct-peer" value={peer} onChange={event => setPeer(event.target.value)} disabled={busy} autoCapitalize="off" autoComplete="off" spellCheck={false} className="mt-1 block w-full border-2 border-zinc-950 bg-white px-3 py-2 text-base disabled:cursor-not-allowed disabled:opacity-60" />
          </label>
          <button type="submit" disabled={busy} className="w-full border-2 border-zinc-950 bg-lime-300 px-3 py-2 font-black uppercase hover:bg-lime-200 focus-visible:outline-4 focus-visible:outline-offset-2 focus-visible:outline-fuchsia-600 disabled:cursor-not-allowed disabled:opacity-60">{operation === 'create' ? 'Creating…' : 'Create direct conversation'}</button>
        </form>
        <form onSubmit={joinRoom} className="space-y-3 border-2 border-zinc-950 p-4">
          <h3 className="font-bold uppercase">Join direct conversation</h3>
          <label className="block text-sm font-bold" htmlFor="room-id">Matrix room ID
            <input id="room-id" value={roomId} onChange={event => setRoomId(event.target.value)} disabled={busy} autoCapitalize="off" autoComplete="off" spellCheck={false} aria-describedby="room-id-help" className="mt-1 block w-full border-2 border-zinc-950 bg-white px-3 py-2 text-base disabled:cursor-not-allowed disabled:opacity-60" />
          </label>
          <p id="room-id-help" className="text-sm leading-5 text-zinc-700">Use the Matrix room ID for a one-peer direct room only.</p>
          <button type="submit" disabled={busy} className="w-full border-2 border-zinc-950 bg-fuchsia-300 px-3 py-2 font-black uppercase hover:bg-fuchsia-200 focus-visible:outline-4 focus-visible:outline-offset-2 focus-visible:outline-fuchsia-600 disabled:cursor-not-allowed disabled:opacity-60">{operation === 'join' ? 'Joining…' : 'Join direct conversation'}</button>
        </form>
      </div>
      {notice && <p role="status" aria-live="polite" aria-atomic="true" className="mt-4 border-l-4 border-zinc-950 pl-3 text-sm font-bold">{notice}</p>}
    </section>
  );
}

type RehearsalReferenceState = 'hidden' | 'loading' | 'shown';

/** Sensitive local continuity metadata is intentionally ephemeral and opt-in. */
export function RehearsalReferences({ state, runtime, conversation }: { readonly state: MatrixSecurityState; readonly runtime?: MatrixRuntime; readonly conversation?: DirectConversation }) {
  const [visibility, setVisibility] = useState<RehearsalReferenceState>('hidden');
  const [observation, setObservation] = useState<LocalIdentityObservation>();
  const [notice, setNotice] = useState('');
  const generation = useRef(0);
  const publishedScope = useRef('');
  const publishedRuntime = useRef<MatrixRuntime | undefined>(undefined);
  const showButton = useRef<HTMLButtonElement>(null);
  const hideButton = useRef<HTMLButtonElement>(null);
  const focusHideButton = useRef(false);
  const restoreShowButtonFocus = useRef(false);
  const scope = conversation ? conversationIdentity(conversation) : '';

  const conceal = () => {
    generation.current += 1;
    publishedScope.current = '';
    publishedRuntime.current = undefined;
    setObservation(undefined);
    setVisibility('hidden');
  };

  useEffect(() => {
    conceal();
    // Scope, runtime, and security changes revoke a request before it can publish.
    return () => { generation.current += 1; };
  }, [runtime, state, scope]);

  const reveal = () => {
    if (state !== 'ready' || !runtime?.gateway || visibility !== 'hidden') return;
    const requestGeneration = generation.current + 1;
    generation.current = requestGeneration;
    setNotice('');
    setVisibility('loading');
    void runtime.gateway.observeLocalIdentity().then(next => {
      if (generation.current !== requestGeneration) return;
      publishedScope.current = scope;
      publishedRuntime.current = runtime;
      setObservation(next);
      focusHideButton.current = true;
      setVisibility('shown');
    }).catch(() => {
      if (generation.current !== requestGeneration) return;
      setObservation(undefined);
      setVisibility('hidden');
      setNotice('Rehearsal references could not be shown. Try again only when you intend to view this metadata.');
    });
  };

  const reference = (label: string, value: string) => <div className="border-l-4 border-lime-300 pl-3" key={label}><dt className="font-mono text-[11px] font-bold uppercase tracking-[0.12em] text-zinc-400">{label}</dt><dd className="mt-1 select-text break-all font-mono text-sm text-white"><bdi dir="ltr">{value}</bdi></dd></div>;
  const canReveal = state === 'ready' && Boolean(runtime?.gateway);
  // Rendering is also scope/runtime gated, so a prop replacement cannot flash old metadata before effects run.
  const shown = state === 'ready' && Boolean(runtime?.gateway) && visibility === 'shown' && publishedScope.current === scope && publishedRuntime.current === runtime;
  useLayoutEffect(() => {
    if (focusHideButton.current && shown) {
      focusHideButton.current = false;
      hideButton.current?.focus();
      return;
    }
    if (!restoreShowButtonFocus.current || visibility !== 'hidden') return;
    restoreShowButtonFocus.current = false;
    showButton.current?.focus();
  }, [shown, visibility]);
  return <section aria-labelledby="rehearsal-references-heading" className="border-2 border-cyan-300 bg-zinc-900 p-5 shadow-[6px_6px_0_0_#67e8f9]">
    <p className="font-mono text-xs font-bold tracking-[0.15em] text-cyan-200">G2 REHEARSAL</p>
    <h2 id="rehearsal-references-heading" className="mt-2 text-xl font-black uppercase text-white">Local continuity references</h2>
    <p id="rehearsal-reference-privacy" className="mt-3 border-l-4 border-amber-300 pl-3 text-sm leading-6 text-amber-100">These are sensitive, linkable metadata—not credentials. Reveal them only for a local rehearsal, and hide them when finished.</p>
    {shown ? <><dl className="mt-5 space-y-4">{reference('Account', observation!.userId)}{reference('Device', observation!.deviceId)}{reference('Browser profile', observation!.profileRef)}{reference('Cross-signing identity', observation!.crossSigningMasterRef)}{conversation && reference('Room reference', conversation.roomId)}</dl><button ref={hideButton} type="button" onClick={() => { restoreShowButtonFocus.current = true; conceal(); }} className="mt-5 w-full border-2 border-cyan-300 px-3 py-2 font-black uppercase text-cyan-100 focus-visible:outline-4 focus-visible:outline-offset-2 focus-visible:outline-fuchsia-300">Hide rehearsal references</button></> : <button ref={showButton} type="button" onClick={reveal} disabled={!canReveal || visibility !== 'hidden'} aria-describedby="rehearsal-reference-privacy" className="mt-5 w-full border-2 border-cyan-300 bg-cyan-300 px-3 py-2 font-black uppercase text-zinc-950 focus-visible:outline-4 focus-visible:outline-offset-2 focus-visible:outline-fuchsia-300 disabled:cursor-not-allowed disabled:opacity-60">{visibility === 'loading' ? 'Loading rehearsal references…' : 'Show rehearsal references'}</button>}
    {notice && <p role="status" aria-live="polite" aria-atomic="true" className="mt-3 text-sm font-bold text-amber-100">{notice}</p>}
  </section>;
}

export function ConversationList({ conversations, selectedRoomId, onSelect }: { readonly conversations: readonly DirectConversation[]; readonly selectedRoomId?: string; readonly onSelect: (conversation: DirectConversation) => void }) {
  return <nav aria-labelledby="direct-lines-heading" className="border-2 border-zinc-700 bg-zinc-900 p-5">
    <div className="flex items-baseline justify-between gap-3"><h2 id="direct-lines-heading" className="font-mono text-sm font-bold uppercase tracking-[0.12em]">Direct lines</h2><span className="font-mono text-xs text-lime-200">ONE PEER EACH</span></div>
    {conversations.length === 0 ? <p className="mt-3 text-sm leading-6 text-zinc-300">No direct conversations are available in this tab.</p> : <ul className="mt-3 space-y-2">{conversations.map(conversation => <li key={conversation.roomId}><button type="button" onClick={() => onSelect(conversation)} aria-current={selectedRoomId === conversation.roomId ? 'page' : undefined} className={`w-full border-2 p-3 text-left ${selectedRoomId === conversation.roomId ? 'border-lime-300 bg-lime-300 text-zinc-950' : 'border-zinc-600 bg-zinc-950 text-white'} focus-visible:outline-4 focus-visible:outline-offset-2 focus-visible:outline-fuchsia-300`}><bdi dir="ltr" className="block select-text break-all font-bold">{conversation.peerUserId}</bdi><span className="mt-1 block font-mono text-xs uppercase">{conversation.membership === 'joined' ? 'Joined direct line' : 'Verification-only line'}</span></button></li>)}</ul>}
  </nav>;
}

export default function App({ runtime }: { readonly runtime?: MatrixRuntime }) {
  const [security, setSecurity] = useState<MatrixSecurityState>('starting');
  const [signingIn, setSigningIn] = useState(false);
  const [signInNotice, setSignInNotice] = useState('');
  const [loggingOut, setLoggingOut] = useState(false);
  const [conversations, setConversations] = useState<readonly DirectConversation[]>([]);
  const [selected, setSelected] = useState<DirectConversation>();
  // Attempts stay in memory only and their full room/peer/epoch identity is the key.
  // A bounded retained attempt can never be read by a later incarnation of the line.
  const [pendingAttempts, setRawPendingAttempts] = useState<ReadonlyMap<string, PendingTextAttempt>>(new Map());
  const pendingAttemptsRef = useRef<ReadonlyMap<string, PendingTextAttempt>>(new Map());
  const replacePendingAttempts = (next: ReadonlyMap<string, PendingTextAttempt>) => {
    const retained = new Map(next);
    pendingAttemptsRef.current = retained;
    setRawPendingAttempts(retained);
  };
  const settlePendingAttempt = (expected: PendingTextAttempt | undefined, next: PendingTextAttempt | undefined): boolean => {
    const updated = applyPendingAttemptCas(pendingAttemptsRef.current, expected, next);
    if (!updated) return false;
    replacePendingAttempts(updated);
    return true;
  };
  const signInFlight = useRef<Promise<void> | undefined>(undefined);

  useEffect(() => {
    let subscribed = true;
    let unsubscribe: (() => void) | undefined;
    if (!runtime) {
      setSecurity('blocked');
      return;
    }
    void runtime.startup.then(state => {
      if (!subscribed) return;
      setSecurity(state);
      const gateway = runtime.gateway;
      if (gateway) unsubscribe = gateway.subscribeSecurityState(next => { if (subscribed) setSecurity(next); });
    }).catch(() => { if (subscribed) setSecurity('failed'); });
    return () => { subscribed = false; unsubscribe?.(); };
  }, [runtime]);

  useEffect(() => {
    if (security !== 'ready' || !runtime?.gateway) { setConversations([]); setSelected(undefined); replacePendingAttempts(new Map()); return; }
    try {
      return runtime.gateway.subscribeDirectConversations(next => {
        setConversations(next);
        setSelected(current => next.find(conversation => current && conversationIdentity(conversation) === conversationIdentity(current)) ?? next[0]);
        const live = new Set(next.map(conversationIdentity));
        replacePendingAttempts(new Map([...pendingAttemptsRef.current].filter(([identity]) => live.has(identity))));
      });
    } catch { setConversations([]); setSelected(undefined); replacePendingAttempts(new Map()); return; }
  }, [runtime, security]);

  const signIn = () => {
    if (!runtime || signingIn || security === 'starting') return;
    setSigningIn(true);
    setSignInNotice('');
    void beginSingleFlight(signInFlight, () => runtime.startSignIn(), () => {
      setSigningIn(false);
      setSignInNotice('Sign-in could not be started. Please try again.');
    });
  };
  const showSignIn = security === 'blocked' || security === 'failed' || security === 'stopped';
  const canLogout = Boolean(runtime) && (security === 'ready' || security === 'unverified');
  const logout = () => {
    if (!runtime || !canLogout || loggingOut) return;
    setLoggingOut(true);
    void runtime.logout().then(() => setSecurity('blocked')).catch(() => setSignInNotice('Sign-out could not be completed.')).finally(() => setLoggingOut(false));
  };

  return (
    <main className="min-h-screen bg-zinc-950 px-4 py-5 text-zinc-100 selection:bg-fuchsia-300 selection:text-zinc-950 sm:px-8 sm:py-10">
      <div className="mx-auto max-w-6xl">
        <header className="border-b-2 border-zinc-700 pb-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <p className="font-mono text-xs font-bold tracking-[0.2em] text-lime-200">SUBCULT // DSA SIGNAL</p>
            <span className="border border-fuchsia-300 px-2 py-1 font-mono text-[10px] font-bold tracking-[0.14em] text-fuchsia-200">PRIVATE CHANNEL</span>
          </div>
          <div className="mt-8 grid gap-6 md:grid-cols-[1.4fr_0.6fr]">
            <div>
              <h1 className="max-w-3xl text-4xl font-black uppercase leading-[0.9] tracking-[-0.055em] text-white sm:text-6xl">A secure line,<br /><span className="text-lime-300">owned by this tab.</span></h1>
              <p className="mt-5 max-w-xl text-base leading-7 text-zinc-300">DSA Signal connects directly to Matrix Authentication Service and Synapse. Your encryption stays in this browser tab using persistent Rust end-to-end encryption.</p>
            </div>
            <aside className="border-l-4 border-fuchsia-300 pl-4 text-sm leading-6 text-zinc-300">If a device, its storage, or its verification cannot be trusted yet, room actions remain blocked. That pause protects the people you are about to talk with.</aside>
          </div>
        </header>
        <div className="mt-7 grid gap-6 xl:grid-cols-[0.85fr_1.15fr]">
          <div className="space-y-6">
            <SecurityState state={security} />
            {showSignIn && <section className="border border-zinc-700 bg-zinc-900 p-5">
              <h2 className="font-mono text-sm font-bold uppercase tracking-[0.12em]">Account access</h2>
              <p className="mt-2 text-sm leading-6 text-zinc-300">Sign in directly with the secure service to restore this tab’s encrypted workspace.</p>
              <button type="button" onClick={signIn} disabled={signingIn} className="mt-4 w-full border-2 border-lime-300 bg-lime-300 px-4 py-3 font-black uppercase text-zinc-950 hover:bg-lime-200 focus-visible:outline-4 focus-visible:outline-offset-2 focus-visible:outline-fuchsia-300 disabled:cursor-not-allowed disabled:opacity-60">{signingIn ? 'Opening sign-in…' : 'Sign in'}</button>
              {signInNotice && <p role="status" aria-live="polite" aria-atomic="true" className="mt-3 text-sm font-bold text-fuchsia-200">{signInNotice}</p>}
            </section>}
            {canLogout && <button type="button" onClick={logout} disabled={loggingOut} className="w-full border-2 border-fuchsia-300 px-4 py-3 font-black uppercase text-fuchsia-200 disabled:opacity-60">{loggingOut ? 'Signing out…' : 'Sign out'}</button>}
          </div>
          <div className="space-y-6">
            <RoomControls key={roomControlsAuthorityKey(runtime, security)} state={security} runtime={runtime} />
            {security === 'ready' && <ConversationList conversations={conversations} selectedRoomId={selected?.roomId} onSelect={setSelected} />}
            {security === 'ready' && !loggingOut && <RehearsalReferences key={`references:${selected ? conversationIdentity(selected) : 'no-selection'}`} state={security} runtime={runtime} conversation={selected} />}
            {security === 'ready' && selected && runtime?.gateway && <ConversationView key={`conversation:${conversationIdentity(selected)}`} conversation={selected} gateway={runtime.gateway} pendingAttempt={pendingAttempts.get(attemptIdentity(selected))} onPendingAttempt={settlePendingAttempt} />}
          </div>
        </div>
      </div>
    </main>
  );
}
