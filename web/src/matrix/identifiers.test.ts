import { describe, expect, it } from 'vitest';
import { parseMatrixDeviceId, parseMatrixUserId, parseSupportedDomainRoomId } from './identifiers';

describe('SDK-free Matrix identifiers', () => {
  it.each([
    '@alice:example.org', '@a:localhost:8448', '@a:192.0.2.1', '@a:[2001:db8::1]', '@a:[2001:db8::1]:65535',
  ])('accepts canonical user IDs with supported server names: %s', value => expect(parseMatrixUserId(value)).toBe(value));
  it.each([
    '@Upper:example.org', '@a', '@a:', '@a:bad host', '@a:example.org:0', '@a:example.org:65536', '@a:example.org:123456', '@a:999.1.1.1', '@a:[not-ip]',
    '@a\u0000:example.org', '@a\u202e:example.org', '@a\ud800:example.org', `@${'a'.repeat(253)}:x`,
  ])('rejects malformed user IDs: %s', value => expect(parseMatrixUserId(value)).toBeUndefined());
  it.each([
    '!room:example.org', '!opaque:localhost:8448', '!opaque:192.0.2.1', '!opaque:[2001:db8::1]:8448', '!utf8-☕:example.org', '!room:example.org:65535',
  ])('accepts the explicitly supported domain-bearing room-ID subset: %s', value => expect(parseSupportedDomainRoomId(value)).toBe(value));
  it.each([
    '!room', '!:example.org', '!room:bad:server', '!room:example.org:0', '!room:example.org:65536', '!room:\u0000example.org', '!room\u202e:example.org', '!room\udc00:example.org', '!room name:example.org', '!room\u00a0name:example.org', '!room\u200bname:example.org',
    `!${'r'.repeat(253)}:x`,
  ])('rejects unsupported or unsafe room IDs: %s', value => expect(parseSupportedDomainRoomId(value)).toBeUndefined());
  it.each([
    ['', undefined],
    ['a'.repeat(255), 'a'.repeat(255)],
    ['a'.repeat(256), undefined],
    ['device\u0000', undefined],
    ['device\u001f', undefined],
    ['device\u007f', undefined],
    ['\ud800', '\ud800'],
    ['opaque same-device', 'opaque same-device'],
  ])('applies the SDK UTF-16 device-ID admission rule: %j', (value, expected) => expect(parseMatrixDeviceId(value)).toBe(expected));
});
