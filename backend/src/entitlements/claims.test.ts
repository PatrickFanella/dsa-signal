import { describe, expect, it } from 'vitest';
import { Buffer } from 'node:buffer';
import {
  bareDidSchema,
  didSchema,
  parseMembershipEntitlement,
  parseMembershipEntitlementAt,
} from './claims.js';

const now = 1_700_000_000;
const validClaims = {
  iss: 'did:plc:abcdefghijklmnopqrstuvwx',
  sub: 'did:plc:bcdefghijklmnopqrstuvwxy',
  aud: 'dsa-signal',
  iat: now,
  exp: now + 900,
  jti: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
  cnf: { jkt: 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M' },
  entitlement: 'chat',
  policyVersion: '2026.07-1',
};

describe('didSchema', () => {
  it('parses generic DID Core syntax before applying the configured subset', () => {
    expect(bareDidSchema.parse('did:example:alice%3Akey')).toBe('did:example:alice%3Akey');
    expect(bareDidSchema.parse('did:example::alice')).toBe('did:example::alice');
    expect(() => didSchema.parse('did:example:alice%3Akey')).toThrow();
    expect(() => didSchema.parse('did:example::alice')).toThrow();
  });

  it.each([
    'did:plc:abcdefghijklmnopqrstuvwx',
    'did:web:chat.example',
    'did:web:chat.example%3A8443:users:alice%2Fteam',
    'did:web:chat.example:users:%7Ealice',
    'did:web:chat.example%3A1',
    'did:web:chat.example%3A65535',
    'did:web:chat.example%3a8443',
    'did:web:xn--bcher-kva.example',
  ])('accepts configured DID %s', (did) => {
    expect(didSchema.parse(did)).toBe(did);
  });

  it.each([
    'did:example:alice%3Akey',
    'did:example:alice%',
    'did:example:alice%2',
    'did:example:alice:',
    'did:example:alice/path',
    'did:example:Alice#key',
    'did:plc:abcdefghijklmnopqrstuvwx%20',
    'did:web:Chat.example',
    'did:web:chat.example%3A080',
    'did:web:chat.example%3A0',
    'did:web:chat.example%3A65536',
    'did:web:127.1',
    'did:web:2130706433',
    'did:web:0177.0.0.1',
    'did:web:0x7f.1',
    'did:web:0x7f000001',
    'did:web:127.0x1',
    'did:web:127.0.0.1',
    'did:web:chat.example::path',
    'did:web:chat.example:users:~alice',
    'did:plc:abcdefghijklmnopqrstuvwx\0',
    'did:plc:abcdefghijklmnopqrstuvwx\r',
    'did:plc:abcdefghijklmnopqrstuvwx\n',
  ])('rejects malformed or unsupported DID %s', (did) => {
    expect(() => didSchema.parse(did)).toThrow();
  });

  it('enforces UTF-8 byte bounds without normalizing input', () => {
    expect(() => didSchema.parse(`did:web:${'a'.repeat(2041)}`)).toThrow();
    expect(() => didSchema.parse('did:web:é.example')).toThrow();
  });

  it.each(['\n', '\r', '\r\n', '\u2028', '\u2029'])('rejects a final line terminator %j', (suffix) => {
    expect(() => didSchema.parse(`did:web:chat.example${suffix}`)).toThrow();
  });

  it.each(['\0', '\r', '\n'])('rejects literal DID control character %j', (suffix) => {
    expect(() => bareDidSchema.parse(`did:example:alice${suffix}`)).toThrow();
    expect(() => didSchema.parse(`did:plc:abcdefghijklmnopqrstuvwx${suffix}`)).toThrow();
  });
});

describe('membership entitlement claims', () => {
  it('structurally parses the exact valid contract vector without mutation', () => {
    const input = structuredClone(validClaims);
    expect(parseMembershipEntitlement(input)).toEqual(validClaims);
    expect(input).toEqual(validClaims);
  });

  it('rejects JTI and JKT aliases that differ only in unused base64url pad bits', () => {
    const noncanonicalJti = `${validClaims.jti.slice(0, -1)}9`;
    const noncanonicalJkt = `${validClaims.cnf.jkt.slice(0, -1)}N`;

    expect(Buffer.from(noncanonicalJti, 'base64url')).toEqual(Buffer.from(validClaims.jti, 'base64url'));
    expect(Buffer.from(noncanonicalJkt, 'base64url')).toEqual(Buffer.from(validClaims.cnf.jkt, 'base64url'));
    expect(() => parseMembershipEntitlement({ ...validClaims, jti: noncanonicalJti })).toThrow();
    expect(() =>
      parseMembershipEntitlement({ ...validClaims, cnf: { jkt: noncanonicalJkt } }),
    ).toThrow();
  });

  it.each([
    { extra: true },
    { cnf: { ...validClaims.cnf, extra: true } },
    { cnf: {} },
    { cnf: undefined },
    { aud: 'other' },
    { entitlement: 'video' },
    { iat: now, exp: now + 901 },
    { iat: Number.NaN },
    { iat: now + 0.5 },
    { iat: Number.MAX_SAFE_INTEGER + 1 },
    { iss: 'did:example:alice' },
    { sub: 'did:plc:bcdefghijklmnopqrstuvwxy\0' },
    { jti: `${validClaims.jti}=` },
    { jti: 'a'.repeat(42) },
    { jti: '*'.repeat(43) },
    { cnf: { jkt: 'a'.repeat(42) } },
    { policyVersion: '-invalid' },
  ])('rejects invalid structural claim variants', (change) => {
    expect(() => parseMembershipEntitlement({ ...validClaims, ...change })).toThrow();
  });

  it('rejects an absent confirmation binding', () => {
    const absentCnf: Record<string, unknown> = { ...validClaims };
    delete absentCnf.cnf;
    expect(() => parseMembershipEntitlement(absentCnf)).toThrow();
  });

  it.each(['\n', '\r', '\r\n', '\u2028', '\u2029'])(
    'rejects a final line terminator in canonical claim strings %j',
    (suffix) => {
      expect(() => parseMembershipEntitlement({ ...validClaims, policyVersion: `${validClaims.policyVersion}${suffix}` })).toThrow();
      expect(() => parseMembershipEntitlement({ ...validClaims, jti: `${validClaims.jti}${suffix}` })).toThrow();
      expect(() => parseMembershipEntitlement({ ...validClaims, cnf: { jkt: `${validClaims.cnf.jkt}${suffix}` } })).toThrow();
    },
  );

  it('enforces chronology and injected authoritative clock boundaries', () => {
    expect(parseMembershipEntitlementAt({ ...validClaims, iat: now + 30, exp: now + 900 }, now)).toBeTruthy();
    for (const claims of [
      { ...validClaims, iat: now + 31 },
      { ...validClaims, exp: now },
      { ...validClaims, exp: now + 901 },
      { ...validClaims, iat: now, exp: now },
      { ...validClaims, iat: now, exp: now - 1 },
    ]) {
      expect(() => parseMembershipEntitlementAt(claims, now)).toThrow();
    }
  });

  it.each([Number.NaN, now + 0.5, Number.MAX_SAFE_INTEGER + 1])(
    'rejects an invalid authoritative now value %s',
    (invalidNow) => {
      expect(() => parseMembershipEntitlementAt(validClaims, invalidNow)).toThrow();
    },
  );
});
