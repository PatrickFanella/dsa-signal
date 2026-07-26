import { isAuthorizedOutboxRetry, type AuthorizedOutboxRetry } from '../auth/session-store';

export type OutgoingDelivery = 'local-pending' | 'homeserver-accepted' | 'synced' | 'failed';
interface OutgoingBase { readonly localId: string; readonly profileId: string; readonly transactionId: string; readonly bodyHash: string; readonly retryConsumed: boolean; readonly generation: number; readonly requiredGeneration: number; }
export type OutgoingMessage =
  | (OutgoingBase & { readonly delivery: 'local-pending'; readonly eventId?: never; readonly indeterminate: boolean })
  | (OutgoingBase & { readonly delivery: 'homeserver-accepted' | 'synced'; readonly eventId: string; readonly indeterminate?: never })
  /** Pre-raw-invocation failure is presentation-only and is never a store record. */
  | (OutgoingBase & { readonly delivery: 'failed'; readonly eventId?: never; readonly indeterminate?: never; readonly retryable: true });

export type OutgoingInput = { readonly type: 'accepted'; readonly eventId: string } | { readonly type: 'indeterminate-failure' } | { readonly type: 'remote-echo'; readonly eventId: string } | { readonly type: 'retry'; readonly authorized: AuthorizedOutboxRetry };
export type OutgoingReduction = { readonly kind: 'updated' | 'unchanged'; readonly message: OutgoingMessage } | { readonly kind: 'conflict'; readonly message: OutgoingMessage };
const canonicalDelivered = (message: OutgoingMessage, delivery: 'homeserver-accepted' | 'synced', eventId: string): OutgoingMessage => {
  const { delivery: ignoredDelivery, eventId: ignoredEventId, indeterminate: ignoredIndeterminate, retryable: ignoredRetryable, ...base } = message as OutgoingBase & { delivery: OutgoingDelivery; eventId?: string; indeterminate?: boolean; retryable?: true };
  void ignoredDelivery; void ignoredEventId; void ignoredIndeterminate; void ignoredRetryable;
  return { ...base, delivery, eventId };
};
const retryProjection = (message: OutgoingMessage, authorized: AuthorizedOutboxRetry): OutgoingMessage | undefined => {
  if (!isAuthorizedOutboxRetry(authorized)) return undefined;
  const record = authorized.record;
  if (message.delivery !== 'local-pending' || !message.indeterminate || message.eventId !== undefined
    || record.state !== 'local-pending' || record.eventId !== undefined || record.indeterminate || !record.retryConsumed
    || record.profileId !== message.profileId || record.transactionId !== message.transactionId
    || record.bodyHash !== message.bodyHash || record.requiredGeneration !== message.requiredGeneration
    || message.generation >= Number.MAX_SAFE_INTEGER || record.generation !== message.generation + 1) return undefined;
  return { localId: message.localId, profileId: record.profileId, transactionId: record.transactionId, bodyHash: record.bodyHash, retryConsumed: record.retryConsumed, generation: record.generation, requiredGeneration: record.requiredGeneration, delivery: 'local-pending', indeterminate: false };
};
/** Transaction ID is retained across every retry; a remote echo is terminal even if transport settles later. */
export const reduceOutgoing = (message: OutgoingMessage, input: OutgoingInput): OutgoingReduction => {
  const unchanged = (): OutgoingReduction => ({ kind: 'unchanged', message });
  if ((input.type === 'accepted' || input.type === 'remote-echo') && message.eventId !== undefined && message.eventId !== input.eventId) return { kind: 'conflict', message };
  if (message.delivery === 'synced') return unchanged();
  if (input.type === 'remote-echo') return { kind: 'updated', message: canonicalDelivered(message, 'synced', input.eventId) };
  if (message.delivery === 'local-pending' && input.type === 'accepted') return { kind: 'updated', message: canonicalDelivered(message, 'homeserver-accepted', input.eventId) };
  if (message.delivery === 'local-pending' && input.type === 'indeterminate-failure') return { kind: 'updated', message: { ...message, indeterminate: true } };
  if (input.type === 'retry') { const projection = retryProjection(message, input.authorized); return projection === undefined ? unchanged() : { kind: 'updated', message: projection }; }
  return unchanged();
};
/** Presentation-only pre-invocation failure; it is not derived from a durable outbox record. */
export const provisionalFailedOutgoing = (localId: string, profileId: string, transactionId: string, bodyHash: string, requiredGeneration: number, generation: number): OutgoingMessage =>
  ({ localId, profileId, transactionId, bodyHash, requiredGeneration, generation, retryConsumed: false, delivery: 'failed', retryable: true });
export type IncomingMessage =
  | { readonly eventId: string; readonly delivery: 'decrypting' | 'decryption-failed'; readonly plaintext?: never }
  | { readonly eventId: string; readonly delivery: 'synced'; readonly plaintext: string };
export type IncomingInput = { readonly eventId: string; readonly plaintext: string | undefined };
/** Terminal incoming states and event identities are immutable. */
export const reduceIncoming = (message: IncomingMessage, input: IncomingInput): IncomingMessage => {
  if (message.delivery !== 'decrypting' || message.eventId !== input.eventId) return message;
  return input.plaintext === undefined ? { eventId: message.eventId, delivery: 'decryption-failed' } : { eventId: message.eventId, delivery: 'synced', plaintext: input.plaintext };
};
export const decryptIncoming = (message: IncomingMessage, plaintext: string | undefined): IncomingMessage => reduceIncoming(message, { eventId: message.eventId, plaintext });
