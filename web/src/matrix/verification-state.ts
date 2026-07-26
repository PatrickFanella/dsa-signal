export type VerificationPhase = 'idle' | 'requested' | 'accepted' | 'ready' | 'started' | 'sas-shown' | 'confirming' | 'done' | 'cancelled' | 'failed';
export interface SasValues { readonly emojis: readonly { readonly emoji: string; readonly label: string }[]; readonly decimals: readonly number[]; }
export type SasState =
  | { readonly phase: 'idle' }
  | { readonly phase: 'requested'; readonly direction: 'incoming' | 'outgoing'; readonly peerDeviceBound: boolean }
  | { readonly phase: 'accepted'; readonly direction: 'incoming'; readonly peerDeviceBound: true }
  | { readonly phase: 'sas-shown'; readonly direction: 'incoming' | 'outgoing'; readonly sas: SasValues }
  | { readonly phase: Exclude<VerificationPhase, 'idle' | 'requested' | 'accepted' | 'sas-shown'>; readonly direction: 'incoming' | 'outgoing'; readonly sas?: never };
export type SasInput = 'initiate' | 'incoming-request' | 'peer-device-bound' | 'accept' | 'remote-ready' | 'start' | 'remote-started' | 'show-sas' | 'confirm' | 'mismatch' | 'cancel' | 'resolved' | 'timeout' | 'drift' | 'duplicate' | 'unsupported' | 'rejected';
const terminal = (phase: VerificationPhase): boolean => phase === 'done' || phase === 'cancelled' || phase === 'failed';
const failureInputs: readonly SasInput[] = ['timeout', 'drift', 'duplicate', 'unsupported', 'rejected'];
/** Pure reducer: effects are performed by the seam only after this transition is accepted. */
export const reduceSasState = (state: SasState, input: SasInput, sas?: SasValues): SasState => {
  if (terminal(state.phase)) return state;
  if (input === 'cancel' && state.phase !== 'idle') return { phase: 'cancelled', direction: state.direction };
  if (failureInputs.includes(input) && state.phase !== 'idle') return { phase: input === 'timeout' ? 'cancelled' : 'failed', direction: state.direction };
  if (state.phase === 'idle' && input === 'initiate') return { phase: 'requested', direction: 'outgoing', peerDeviceBound: false };
  if (state.phase === 'idle' && input === 'incoming-request') return { phase: 'requested', direction: 'incoming', peerDeviceBound: true };
  if (state.phase === 'requested' && input === 'peer-device-bound' && state.direction === 'outgoing') return { ...state, peerDeviceBound: true };
  // Local acceptance is merely consent; the SDK's authoritative Ready event gates progress.
  if (state.phase === 'requested' && state.direction === 'incoming' && input === 'accept') return { phase: 'accepted', direction: 'incoming', peerDeviceBound: true };
  if (state.phase === 'requested' && state.direction === 'outgoing' && state.peerDeviceBound && input === 'remote-ready') return { phase: 'ready', direction: state.direction };
  if (state.phase === 'accepted' && input === 'remote-ready') return { phase: 'ready', direction: state.direction };
  if (state.phase === 'ready' && input === 'start') return { phase: 'started', direction: state.direction };
  // A remote start may race Ready for an outgoing request, but only after its
  // authenticated peer device has been bound. Incoming requests must first
  // pass local acceptance and the authoritative Ready event.
  if (state.phase === 'requested' && state.direction === 'outgoing' && state.peerDeviceBound && input === 'remote-started') return { phase: 'started', direction: state.direction };
  if (state.phase === 'ready' && input === 'remote-started') return { phase: 'started', direction: state.direction };
  if (state.phase === 'started' && input === 'show-sas' && sas) return { phase: 'sas-shown', direction: state.direction, sas };
  if (state.phase === 'sas-shown' && input === 'confirm') return { phase: 'confirming', direction: state.direction };
  if (state.phase === 'sas-shown' && input === 'mismatch') return { phase: 'cancelled', direction: state.direction };
  if (state.phase === 'confirming' && input === 'resolved') return { phase: 'done', direction: state.direction };
  return state.phase === 'idle' ? { phase: 'idle' } : { phase: 'failed', direction: state.direction };
};
