import { describe, expect, it } from 'vitest';
import { derivePairwiseSubject, sectorSchema } from './pairwise-subject.js';

const key = Uint8Array.from({ length: 32 }, (_, index) => index);
const did = 'did:plc:abcdefghijklmnopqrstuvwx';
const sector = 'https://chat.example';

describe('derivePairwiseSubject', () => {
  it('is deterministic, does not mutate inputs, and emits unpadded base64url', () => {
    const originalKey = key.slice();
    const subject = derivePairwiseSubject(key, sector, did);
    expect(subject).toBe('9thtHTwF8MeFwwqgISpURLtzm8NL7Wy6UcsRk3Uwu7M');
    expect(derivePairwiseSubject(key, sector, did)).toBe(subject);
    expect(key).toEqual(originalKey);
    expect(subject).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('separates sectors', () => {
    expect(derivePairwiseSubject(key, sector, did)).not.toBe(
      derivePairwiseSubject(key, 'https://mas.example', did),
    );
  });

  it('accepts canonical non-default ports through 65535', () => {
    expect(sectorSchema.parse('https://chat.example:1')).toBe('https://chat.example:1');
    expect(sectorSchema.parse('https://chat.example:65535')).toBe('https://chat.example:65535');
    expect(sectorSchema.parse('https://xn--bcher-kva.example')).toBe('https://xn--bcher-kva.example');
  });

  it.each([
    'http://chat.example',
    'https://Chat.example',
    'https://chat.example:443',
    'https://chat.example:0',
    'https://chat.example:080',
    'https://chat.example:65536',
    'https://127.0.0.1',
    'https://127.1',
    'https://2130706433',
    'https://0177.0.0.1',
    'https://0x7f.1',
    'https://0x7f000001',
    'https://127.0x1',
    'https://[::1]',
    'https://chat.example.',
    'https://chat.example/path',
    'https://chat.example?query',
    'https://chat.example#fragment',
    'https://user@chat.example',
    'https://*.example',
    `https://chat.example\0evil`,
    `https://${'a'.repeat(256)}.example`,
  ])('rejects noncanonical sector %s', (invalidSector) => {
    expect(() => sectorSchema.parse(invalidSector)).toThrow();
  });

  it.each(['\n', '\r', '\r\n', '\u2028', '\u2029'])('rejects a final line terminator %j', (suffix) => {
    expect(() => sectorSchema.parse(`https://chat.example${suffix}`)).toThrow();
  });

  it('rejects key lengths other than exactly 32 bytes and invalid DIDs', () => {
    expect(() => derivePairwiseSubject(key.subarray(0, 31), sector, did)).toThrow();
    expect(() => derivePairwiseSubject(new Uint8Array(33), sector, did)).toThrow();
    expect(() => derivePairwiseSubject(key, sector, 'did:example:alice')).toThrow();
  });
});
