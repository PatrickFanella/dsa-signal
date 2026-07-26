import type * as MatrixPublic from './index';
import type { DirectConversationIdentity, LocalIdentityObservation, MatrixDeviceId, MatrixGateway, MatrixSecurityState, MatrixUserId, TimelineTextMessage, VerificationState } from './contract';

type Expect<Condition extends true> = Condition;
type IsAny<Value> = 0 extends 1 & Value ? true : false;
type ExactKeys<Value, Keys extends PropertyKey> = Exclude<keyof Value, Keys> extends never
  ? Exclude<Keys, keyof Value> extends never ? true : false
  : false;

type GatewayKeysAreExact = Expect<ExactKeys<MatrixGateway,
  'start' | 'stop' | 'subscribeSecurityState' | 'observeLocalIdentity' | 'createEncryptedRoom' | 'joinEncryptedRoom' |
  'subscribeDirectConversations' | 'createDirectConversation' | 'joinDirectConversation' |
  'subscribeTimeline' | 'sendDirectText' | 'subscribeDirectTrust' | 'subscribeVerification' |
  'initiateSas' | 'acceptSas' | 'confirmSas' | 'mismatchSas' | 'cancelSas'>>;
type GatewayIsNotAny = Expect<IsAny<MatrixGateway> extends false ? true : false>;
type GatewayHasNoRawSdkEscapeHatches = Expect<Extract<keyof MatrixGateway,
  'getClient' | 'unwrap' | 'sendEvent' | 'sendMessage' | 'client' | 'room' | 'event'> extends never ? true : false>;
type SecurityStatesAreExplicit = Expect<ExactKeys<Record<MatrixSecurityState, true>,
  'starting' | 'follower' | 'unverified' | 'blocked' | 'ready' | 'failed' | 'stopped'>>;
type SasPhasesAreExplicit = Expect<ExactKeys<Record<import('./contract').SasVerificationPhase, true>,
  'idle' | 'requested' | 'accepted' | 'ready' | 'started' | 'sas-shown' | 'confirming' | 'done' | 'cancelled' | 'failed'>>;
type PublicValueExportsAreApproved = Expect<ExactKeys<typeof MatrixPublic, 'createMatrixRuntime'>>;
type DecryptingTimelineCannotContainPlaintext = Expect<Extract<TimelineTextMessage, { delivery: 'decrypting' }> extends { plaintext?: never } ? true : false>;
type PendingTimelineCannotContainEventId = Expect<Extract<TimelineTextMessage, { delivery: 'local-pending' }> extends { eventId?: never } ? true : false>;
type AcceptedTimelineRequiresEventId = Expect<Extract<TimelineTextMessage, { delivery: 'homeserver-accepted' | 'synced' }> extends { eventId: import('./contract').MatrixEventId } ? true : false>;
type TerminalVerificationCannotContainSas = Expect<Extract<VerificationState, { phase: 'done' | 'cancelled' | 'failed' }> extends { sas?: never } ? true : false>;
type DirectRoomFeedsUseCompleteIdentity = Expect<
  Parameters<MatrixGateway['subscribeTimeline']>[0] extends DirectConversationIdentity
    ? Parameters<MatrixGateway['subscribeDirectTrust']>[0] extends DirectConversationIdentity
      ? Parameters<MatrixGateway['subscribeVerification']>[0] extends DirectConversationIdentity ? true : false
      : false
    : false>;
type LocalIdentityObservationIsExact = Expect<ExactKeys<LocalIdentityObservation, 'userId' | 'deviceId' | 'profileRef' | 'crossSigningMasterRef'>>;
type LocalIdentityObservationFieldsAreExact = Expect<
  LocalIdentityObservation['userId'] extends MatrixUserId
    ? LocalIdentityObservation['deviceId'] extends MatrixDeviceId
      ? LocalIdentityObservation['profileRef'] extends string
        ? LocalIdentityObservation['crossSigningMasterRef'] extends string ? true : false : false : false : false>;
type PublicOwnedTypesAreExported = Expect<
  MatrixPublic.TimelineTextMessage extends TimelineTextMessage
    ? MatrixPublic.VerificationState extends VerificationState
      ? MatrixPublic.DirectTrustState extends import('./contract').DirectTrustState ? true : false
      : false
    : false>;

export type MatrixContractAssertions =
  | GatewayKeysAreExact
  | GatewayIsNotAny
  | GatewayHasNoRawSdkEscapeHatches
  | SecurityStatesAreExplicit
  | SasPhasesAreExplicit
  | PublicValueExportsAreApproved
  | DecryptingTimelineCannotContainPlaintext
  | PendingTimelineCannotContainEventId
  | AcceptedTimelineRequiresEventId
  | TerminalVerificationCannotContainSas
  | DirectRoomFeedsUseCompleteIdentity
  | LocalIdentityObservationIsExact
  | LocalIdentityObservationFieldsAreExact
  | PublicOwnedTypesAreExported;
