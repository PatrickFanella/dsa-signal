/** Exact, SDK-free boundary for the small verification wire surface we admit. */
export interface VerificationEnvelope {
  readonly type: unknown; readonly content: unknown; readonly sender: unknown; readonly eventId: unknown;
  readonly originServerTs: unknown; readonly roomId?: unknown; readonly unsigned?: unknown;
}
export interface VerificationWireContext {
  readonly roomId: string; readonly expectedSender: string; readonly expectedSenderDeviceId?: string;
  readonly expectedRecipient?: string; readonly requestEventId?: string; readonly direction: 'incoming' | 'outgoing';
  readonly now: number;
}
export type ValidatedVerificationEvent =
  | { readonly kind: 'request'; readonly eventId: string; readonly requestEventId: string; readonly roomId: string; readonly sender: string; readonly peerDeviceId: string }
  | { readonly kind: 'ready' | 'start'; readonly eventId: string; readonly requestEventId: string; readonly roomId: string; readonly sender: string; readonly peerDeviceId: string };

type ObjectValue = Record<string, unknown>;
const object = (value: unknown): value is ObjectValue => typeof value === 'object' && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const exactKeys = (value: ObjectValue, keys: readonly string[]): boolean => Object.keys(value).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
const user = (value: unknown): value is string => typeof value === 'string' && /^@[^:]+:.+$/.test(value);
const device = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 255;
const event = (value: unknown): value is string => typeof value === 'string' && /^\$[^\s]+$/.test(value);
const room = (value: unknown): value is string => typeof value === 'string' && /^![^:]+:.+$/.test(value);
const timestamp = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const exact = (value: unknown, expected: readonly string[]): boolean => Array.isArray(value) && value.length === expected.length && value.every((item, index) => item === expected[index]);
const subset = (value: unknown, allowed: readonly string[]): boolean => Array.isArray(value) && value.length > 0 && value.every(item => typeof item === 'string' && allowed.includes(item)) && new Set(value).size === value.length;
const fallback = (sender: string): string => `${sender} is requesting to verify your key, but your client does not support in-chat key verification. You will need to use legacy key verification to verify keys.`;
const relation = (value: unknown, requestEventId: string): boolean => object(value) && exactKeys(value, ['rel_type', 'event_id']) && value.rel_type === 'm.reference' && value.event_id === requestEventId;
const unsigned = (value: unknown): boolean => value === undefined || (object(value) && Object.keys(value).every(key => key === 'age' || key === 'transaction_id') && (value.age === undefined || timestamp(value.age)) && (value.transaction_id === undefined || (typeof value.transaction_id === 'string' && /^[A-Za-z0-9._~-]{1,128}$/.test(value.transaction_id))));

/** Returns only copied, validated primitives; it never exposes an attacker object. */
export const validateVerificationEnvelope = (input: VerificationEnvelope, context: VerificationWireContext): ValidatedVerificationEvent | undefined => {
  if (!room(context.roomId) || !user(context.expectedSender) || !timestamp(context.now) || !object(input) || !exactKeys(input, input.unsigned === undefined && input.roomId === undefined ? ['type', 'content', 'sender', 'eventId', 'originServerTs'] : input.unsigned === undefined ? ['type', 'content', 'sender', 'eventId', 'originServerTs', 'roomId'] : input.roomId === undefined ? ['type', 'content', 'sender', 'eventId', 'originServerTs', 'unsigned'] : ['type', 'content', 'sender', 'eventId', 'originServerTs', 'roomId', 'unsigned'])) return undefined;
  if (!user(input.sender) || input.sender !== context.expectedSender || !event(input.eventId) || !timestamp(input.originServerTs) || (input.roomId !== undefined && (!room(input.roomId) || input.roomId !== context.roomId)) || !unsigned(input.unsigned) || !object(input.content)) return undefined;
  const roomId = context.roomId; const sender = input.sender; const eventId = input.eventId; const content = input.content;
  if (input.type === 'm.room.message') {
    if (context.expectedRecipient === undefined || !user(context.expectedRecipient) || (context.requestEventId !== undefined && input.eventId !== context.requestEventId) || !exactKeys(content, ['msgtype', 'to', 'from_device', 'methods', 'body']) || content.msgtype !== 'm.key.verification.request' || content.to !== context.expectedRecipient || !device(content.from_device) || !exact(content.methods, ['m.sas.v1']) || content.body !== fallback(context.expectedSender) || context.now - input.originServerTs > 600_000 || input.originServerTs - context.now > 300_000) return undefined;
    if (context.expectedSenderDeviceId !== undefined && content.from_device !== context.expectedSenderDeviceId) return undefined;
    return Object.freeze({ kind: 'request', eventId, requestEventId: eventId, roomId, sender, peerDeviceId: content.from_device });
  }
  if (context.requestEventId === undefined || !event(context.requestEventId) || eventId === context.requestEventId || !device(content.from_device) || (context.expectedSenderDeviceId !== undefined && content.from_device !== context.expectedSenderDeviceId)) return undefined;
  if (input.type === 'm.key.verification.ready' && exactKeys(content, ['from_device', 'methods', 'm.relates_to']) && exact(content.methods, ['m.sas.v1']) && relation(content['m.relates_to'], context.requestEventId)) return Object.freeze({ kind: 'ready', eventId, requestEventId: context.requestEventId, roomId, sender, peerDeviceId: content.from_device });
  if (input.type === 'm.key.verification.start' && exactKeys(content, ['from_device', 'method', 'key_agreement_protocols', 'hashes', 'message_authentication_codes', 'short_authentication_string', 'm.relates_to']) && content.method === 'm.sas.v1' && exact(content.key_agreement_protocols, ['curve25519-hkdf-sha256']) && exact(content.hashes, ['sha256']) && subset(content.message_authentication_codes, ['hkdf-hmac-sha256.v2', 'org.matrix.msc3783.hkdf-hmac-sha256']) && subset(content.short_authentication_string, ['decimal', 'emoji']) && relation(content['m.relates_to'], context.requestEventId)) return Object.freeze({ kind: 'start', eventId, requestEventId: context.requestEventId, roomId, sender, peerDeviceId: content.from_device });
  return undefined;
};

export interface MatrixVerificationEvent {
  getType(): unknown; getContent(): unknown; getSender(): unknown; getId(): unknown; getTs(): unknown; getRoomId(): unknown; getUnsigned(): unknown;
}
/** The only SDK translation: absence or a throwing getter produces no envelope. */
export const ownedVerificationEnvelope = (value: MatrixVerificationEvent): VerificationEnvelope | undefined => {
  try {
    const roomId = value.getRoomId(); const unsignedValue = value.getUnsigned();
    const envelope: Record<string, unknown> = { type: value.getType(), content: value.getContent(), sender: value.getSender(), eventId: value.getId(), originServerTs: value.getTs() };
    if (roomId !== undefined) envelope.roomId = roomId;
    if (unsignedValue !== undefined) envelope.unsigned = unsignedValue;
    return Object.freeze(envelope) as unknown as VerificationEnvelope;
  } catch { return undefined; }
};

/** Complete, SDK-free classifier for the locked SAS wire vocabulary.  This is
 * intentionally separate from the adapter above: its result is an owned copy,
 * and it does not widen the request/ready/start adapter contract. */
export type LockedVerificationKind = 'request' | 'ready' | 'start' | 'accept' | 'key' | 'mac' | 'done' | 'cancel';
export type LockedVerificationTarget = 'browser-send-body' | 'server-envelope';
export interface LockedVerificationClassification { readonly target: LockedVerificationTarget; readonly kind: LockedVerificationKind; readonly value: Readonly<Record<string, unknown>>; }
/** Context is deliberately operation-owned: a request body must never select its sender. */
export interface LockedVerificationContext {
  readonly expectedSender: string;
  readonly expectedRecipient: string;
  readonly requestEventId?: string;
  readonly roomId?: string;
  readonly freshness?: { readonly now: number; readonly maxPastMs: number; readonly maxFutureMs: number };
}
/** Only canonical, unpadded RFC4648 standard Base64 is admitted on this wire. */
const b64 = (v: unknown, bytes?: number): v is string => {
  if (typeof v !== 'string' || !/^[A-Za-z0-9+/]+$/.test(v) || v.length % 4 === 1) return false;
  try {
    const decoded = atob(v + '='.repeat((4 - v.length % 4) % 4));
    return (bytes === undefined || decoded.length === bytes) && btoa(decoded).replace(/=+$/, '') === v;
  } catch { return false; }
};
const keyId = (v: string): boolean => new RegExp('^(?:ed25519|curve25519):[A-Za-z0-9._=+/-]{1,255}$').test(v) && controlFree(v);
const mac = (v: unknown): v is string => b64(v, 32);
const controlFree = (v: string): boolean => [...v].every(char => { const code = char.codePointAt(0) ?? 0; return code > 31 && (code < 127 || code > 159); });
const copied = (v: ObjectValue): Readonly<Record<string, unknown>> => Object.freeze(JSON.parse(JSON.stringify(v)) as Record<string, unknown>);
const lockedContent = (content: unknown, context: LockedVerificationContext): LockedVerificationKind | undefined => {
  if (!object(content)) return undefined;
  const rel = (v: unknown) => context.requestEventId !== undefined && relation(v, context.requestEventId);
  if (exactKeys(content, ['msgtype', 'to', 'from_device', 'methods', 'body']) && content.msgtype === 'm.key.verification.request' && content.to === context.expectedRecipient && device(content.from_device) && exact(content.methods, ['m.sas.v1']) && content.body === fallback(context.expectedSender)) return 'request';
  if (exactKeys(content, ['from_device', 'methods', 'm.relates_to']) && device(content.from_device) && exact(content.methods, ['m.sas.v1']) && rel(content['m.relates_to'])) return 'ready';
  if (exactKeys(content, ['from_device', 'method', 'key_agreement_protocols', 'hashes', 'message_authentication_codes', 'short_authentication_string', 'm.relates_to']) && device(content.from_device) && content.method === 'm.sas.v1' && exact(content.key_agreement_protocols, ['curve25519-hkdf-sha256']) && exact(content.hashes, ['sha256']) && subset(content.message_authentication_codes, ['hkdf-hmac-sha256.v2', 'org.matrix.msc3783.hkdf-hmac-sha256']) && subset(content.short_authentication_string, ['decimal', 'emoji']) && rel(content['m.relates_to'])) return 'start';
  if (exactKeys(content, ['commitment', 'key_agreement_protocol', 'hash', 'message_authentication_code', 'short_authentication_string', 'm.relates_to']) && b64(content.commitment, 32) && content.key_agreement_protocol === 'curve25519-hkdf-sha256' && content.hash === 'sha256' && ['hkdf-hmac-sha256.v2', 'org.matrix.msc3783.hkdf-hmac-sha256'].includes(content.message_authentication_code as string) && subset(content.short_authentication_string, ['decimal', 'emoji']) && rel(content['m.relates_to'])) return 'accept';
  if (exactKeys(content, ['key', 'm.relates_to']) && b64(content.key, 32) && rel(content['m.relates_to'])) return 'key';
  if (exactKeys(content, ['mac', 'keys', 'm.relates_to']) && object(content.mac) && Object.keys(content.mac).length > 0 && Object.keys(content.mac).every(keyId) && Object.values(content.mac).every(mac) && mac(content.keys) && rel(content['m.relates_to'])) return 'mac';
  if (exactKeys(content, ['m.relates_to']) && rel(content['m.relates_to'])) return 'done';
  if (exactKeys(content, ['code', 'reason', 'm.relates_to']) && typeof content.code === 'string' && ['m.user', 'm.timeout', 'm.unknown_transaction', 'm.unknown_method', 'm.unexpected_message', 'm.key_mismatch', 'm.user_mismatch', 'm.invalid_message', 'm.accepted', 'm.mismatched_commitment', 'm.mismatched_sas'].includes(content.code) && typeof content.reason === 'string' && content.reason.length >= 1 && content.reason.length <= 256 && controlFree(content.reason) && rel(content['m.relates_to'])) return 'cancel';
  return undefined;
};
export const classifyLockedVerification = (target: LockedVerificationTarget, value: unknown, context: LockedVerificationContext): LockedVerificationClassification | undefined => {
  if (!object(context) || !user(context.expectedSender) || !user(context.expectedRecipient) || (context.requestEventId !== undefined && !event(context.requestEventId)) || (context.roomId !== undefined && !room(context.roomId))) return undefined;
  const content = target === 'browser-send-body' ? value : object(value) ? value.content : undefined;
  if (target === 'server-envelope') {
    const allowed = value && object(value) && Object.keys(value).every(key => ['type', 'content', 'sender', 'event_id', 'origin_server_ts', 'room_id', 'unsigned'].includes(key));
    const f = context.freshness;
    if (!allowed || !exactKeys(value, Object.keys(value)) || typeof value.type !== 'string' || value.sender !== context.expectedSender || !event(value.event_id) || !timestamp(value.origin_server_ts) || (value.room_id !== undefined && (!room(value.room_id) || (context.roomId !== undefined && value.room_id !== context.roomId))) || !unsigned(value.unsigned) || !f || !timestamp(f.now) || !timestamp(f.maxPastMs) || !timestamp(f.maxFutureMs) || f.now - value.origin_server_ts > f.maxPastMs || value.origin_server_ts - f.now > f.maxFutureMs) return undefined;
  }
  const kind = lockedContent(content, context); if (!kind) return undefined;
  if (target === 'server-envelope' && ((value as ObjectValue).type !== (kind === 'request' ? 'm.room.message' : `m.key.verification.${kind}`) || (kind === 'request' ? context.requestEventId === undefined || (value as ObjectValue).event_id !== context.requestEventId : context.requestEventId !== undefined && (value as ObjectValue).event_id === context.requestEventId))) return undefined;
  return Object.freeze({ target, kind, value: copied(target === 'browser-send-body' ? content as ObjectValue : value as ObjectValue) });
};
