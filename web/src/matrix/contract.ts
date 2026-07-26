/** Application-owned identifiers; Matrix SDK values never cross this boundary. */
export type MatrixRoomId = string & { readonly __matrixRoomId: unique symbol };
export type MatrixUserId = string & { readonly __matrixUserId: unique symbol };
export type MatrixEventId = string & { readonly __matrixEventId: unique symbol };
export type MatrixDeviceId = string & { readonly __matrixDeviceId: unique symbol };
export type MatrixTransactionId = string & { readonly __matrixTransactionId: unique symbol };

/** `ready` is emitted only after the local device clears the encryption policy. */
export type MatrixSecurityState = 'starting' | 'follower' | 'unverified' | 'blocked' | 'ready' | 'failed' | 'stopped';

export interface CreateEncryptedRoomRequest {
  readonly name: string;
  readonly invitees: readonly MatrixUserId[];
}

export interface JoinEncryptedRoomRequest {
  readonly roomId: MatrixRoomId;
}

/** A user-requested, current-local continuity observation; not remote proof. */
export interface LocalIdentityObservation {
  readonly userId: MatrixUserId;
  readonly deviceId: MatrixDeviceId;
  readonly profileRef: string;
  readonly crossSigningMasterRef: string;
}

export type MatrixSecurityStateListener = (state: MatrixSecurityState) => void;
export type MatrixUnsubscribe = () => void;

/** An owned, exact-two-person room.  No SDK room or event is exposed. */
export interface DirectConversation {
  readonly roomId: MatrixRoomId;
  readonly peerUserId: MatrixUserId;
  readonly membership: 'joined' | 'verification-only' | 'blocked';
  readonly roomEpoch: number;
}
/** Exact authority binding for a direct-line operation or delivered update. */
export interface DirectConversationIdentity {
  readonly roomId: MatrixRoomId;
  readonly peerUserId: MatrixUserId;
  readonly roomEpoch: number;
}
export interface DirectConversationRequest { readonly peerUserId: MatrixUserId; }
export type TextDirection = 'incoming' | 'outgoing';
export type TextDeliveryState = 'decrypting' | 'local-pending' | 'homeserver-accepted' | 'synced' | 'failed' | 'decryption-failed';
interface TimelineTextMessageBase {
  readonly identity: DirectConversationIdentity;
  readonly localId: string;
  readonly peerUserId: MatrixUserId;
  readonly timestamp: number;
}
/** Decrypting and failed inbound events are deliberately incapable of carrying text. */
export type TimelineTextMessage =
  | (TimelineTextMessageBase & { readonly direction: 'incoming'; readonly delivery: 'decrypting' | 'decryption-failed'; readonly eventId: MatrixEventId; readonly transactionId?: never; readonly plaintext?: never; readonly indeterminate?: never })
  | (TimelineTextMessageBase & { readonly direction: 'incoming'; readonly delivery: 'synced'; readonly eventId: MatrixEventId; readonly transactionId?: never; readonly plaintext: string; readonly indeterminate?: never })
  | (TimelineTextMessageBase & { readonly direction: 'outgoing'; readonly transactionId: MatrixTransactionId; readonly delivery: 'local-pending'; readonly eventId?: never; readonly plaintext: string; readonly indeterminate: boolean })
  | (TimelineTextMessageBase & { readonly direction: 'outgoing'; readonly transactionId: MatrixTransactionId; readonly delivery: 'homeserver-accepted' | 'synced'; readonly eventId: MatrixEventId; readonly plaintext: string; readonly indeterminate?: never })
  | (TimelineTextMessageBase & { readonly direction: 'outgoing'; readonly transactionId: MatrixTransactionId; readonly delivery: 'failed'; readonly eventId?: never; readonly plaintext: string; readonly indeterminate?: never; readonly retryable: true });
export interface SendDirectTextRequest extends DirectConversationIdentity { readonly body: string; readonly transactionId: MatrixTransactionId; }
export interface DeviceTrustState { readonly deviceId: MatrixDeviceId; readonly known: boolean; readonly ownerSigned: boolean; readonly verified: boolean; readonly ed25519Fingerprint: string; readonly curve25519Fingerprint: string; }
export interface UserTrustState { readonly userId: MatrixUserId; readonly identityKnown: boolean; readonly crossSigningVerified: boolean; readonly awaitingApproval: boolean; readonly devices: readonly DeviceTrustState[]; }
export interface DirectTrustState extends DirectConversationIdentity { readonly peer: UserTrustState; readonly self: UserTrustState; readonly sendReady: boolean; }
export type SasVerificationPhase = 'idle' | 'requested' | 'accepted' | 'ready' | 'started' | 'sas-shown' | 'confirming' | 'done' | 'cancelled' | 'failed';
export interface SasEmoji { readonly emoji: string; readonly label: string; }
export interface SasDisplay { readonly emojis: readonly SasEmoji[]; readonly decimals: readonly number[]; }
interface VerificationStateBase extends DirectConversationIdentity { readonly direction: 'incoming' | 'outgoing'; }
/** Only the display phase can expose SAS material; terminal DTOs expose neither display nor actions. */
export type VerificationState =
  | (VerificationStateBase & { readonly phase: 'sas-shown'; readonly sas: SasDisplay })
  | (VerificationStateBase & { readonly phase: Exclude<SasVerificationPhase, 'sas-shown'>; readonly sas?: never });
export type VerificationRequest = DirectConversationIdentity;
export type DirectConversationListener = (conversations: readonly DirectConversation[]) => void;
export type TimelineListener = (messages: readonly TimelineTextMessage[]) => void;
export type DirectTrustListener = (trust: DirectTrustState) => void;
export type VerificationListener = (verification: VerificationState) => void;

/**
 * The Task 8 Matrix facade. Room creation and joining are always encrypted;
 * message transport is deliberately outside Phase 1.
 */
export interface MatrixGateway {
  start(): Promise<void>;
  stop(): Promise<void>;
  subscribeSecurityState(listener: MatrixSecurityStateListener): MatrixUnsubscribe;
  observeLocalIdentity(): Promise<LocalIdentityObservation>;
  createEncryptedRoom(request: CreateEncryptedRoomRequest): Promise<MatrixRoomId>;
  joinEncryptedRoom(request: JoinEncryptedRoomRequest): Promise<MatrixRoomId>;
  subscribeDirectConversations(listener: DirectConversationListener): MatrixUnsubscribe;
  createDirectConversation(request: DirectConversationRequest): Promise<DirectConversation>;
  joinDirectConversation(request: JoinEncryptedRoomRequest): Promise<DirectConversation>;
  subscribeTimeline(identity: DirectConversationIdentity, listener: TimelineListener): MatrixUnsubscribe;
  sendDirectText(request: SendDirectTextRequest): Promise<void>;
  subscribeDirectTrust(identity: DirectConversationIdentity, listener: DirectTrustListener): MatrixUnsubscribe;
  subscribeVerification(identity: DirectConversationIdentity, listener: VerificationListener): MatrixUnsubscribe;
  initiateSas(request: VerificationRequest): Promise<void>;
  acceptSas(request: VerificationRequest): Promise<void>;
  confirmSas(request: VerificationRequest): Promise<void>;
  mismatchSas(request: VerificationRequest): Promise<void>;
  cancelSas(request: VerificationRequest): Promise<void>;
}
