/** SDK-free Matrix identifier parsing at every untrusted application boundary. */
import type { MatrixRoomId, MatrixUserId } from './contract';

const maximumUtf8Bytes = 255;
const unpairedSurrogate = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const dnsName = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/;
const ipv4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

const unsafeUiCodePoint = (code: number): boolean => code <= 0x1f || (code >= 0x7f && code <= 0x9f) || code === 0x200e || code === 0x200f || (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069);
const safeText = (value: string): boolean => !unpairedSurrogate.test(value) && !Array.from(value).some(character => unsafeUiCodePoint(character.codePointAt(0)!)) && new TextEncoder().encode(value).length <= maximumUtf8Bytes;
const safeRoomLocalpart = (value: string): boolean => safeText(value) && !/[\s\p{Cf}]/u.test(value);
const serverName = (value: string): boolean => {
  const match = /^(\[[^\]]+\]|[^:]+)(?::(\d{1,5}))?$/.exec(value);
  if (!match || !safeText(value)) return false;
  const [, host, port] = match;
  if (port && (Number(port) < 1 || Number(port) > 65535)) return false;
  if (host.startsWith('[')) {
    try { return new URL(`http://${host}/`).hostname.startsWith('['); } catch { return false; }
  }
  return ipv4.test(host) || (!/^[0-9.]+$/.test(host) && dnsName.test(host));
};

/** Canonical Matrix user IDs supported by this application. */
export const parseMatrixUserId = (value: unknown): MatrixUserId | undefined => {
  if (typeof value !== 'string' || !safeText(value)) return undefined;
  const match = /^@([a-z0-9._=/+-]+):(.+)$/.exec(value);
  return match && serverName(match[2]) ? value as MatrixUserId : undefined;
};

/** Opaque Matrix device IDs use the SDK's UTF-16-unit admission rule. */
export const parseMatrixDeviceId = (value: unknown): import('./contract').MatrixDeviceId | undefined => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) return undefined;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return undefined;
  }
  return value as import('./contract').MatrixDeviceId;
};

/** Domain-bearing room IDs only; this intentionally does not claim domainless-ID support. */
export const parseSupportedDomainRoomId = (value: unknown): MatrixRoomId | undefined => {
  if (typeof value !== 'string' || !safeText(value)) return undefined;
  const match = /^!([^:]+):(.+)$/.exec(value);
  return match && safeRoomLocalpart(match[1]) && serverName(match[2]) ? value as MatrixRoomId : undefined;
};
