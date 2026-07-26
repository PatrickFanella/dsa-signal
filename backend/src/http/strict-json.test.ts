import { describe, expect, it } from 'vitest';
import { StrictJsonError, parseStrictJson } from './strict-json.js';

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);
describe('parseStrictJson', () => {
  it('accepts only lossless, complete JSON', () => {
    expect(parseStrictJson(bytes('{"nested":{"ok":[true,null,"x"]}}'))).toEqual({ nested: { ok: [true, null, 'x'] } });
  });
  it.each(['{"a":1,"\\u0061":2}', '{"outer":{"x":1,"\\u0078":2}}', '9007199254740992', '1.0', '1e3', '{} trailing'])('rejects %s', (text) => {
    expect(() => parseStrictJson(bytes(text))).toThrow(StrictJsonError);
  });
  it('rejects invalid UTF-8 before parsing', () => {
    expect(() => parseStrictJson(new Uint8Array([0xc3, 0x28]))).toThrow(StrictJsonError);
  });
});
