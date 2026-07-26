/** Security-bearing JSON must pass this scanner before it reaches JSON.parse.
 * It rejects duplicate object names using their decoded (therefore escaped-equivalent)
 * value and rejects numbers JSON cannot represent safely. */
const decoder = new TextDecoder('utf-8', { fatal: true });

export class StrictJsonError extends Error {}

export function decodeUtf8(bytes: Uint8Array): string {
  try { return decoder.decode(bytes); } catch { throw new StrictJsonError('invalid utf8'); }
}

export function parseStrictJson(bytes: Uint8Array): unknown {
  const text = decodeUtf8(bytes);
  let i = 0;
  const ws = (): void => { while (/\s/.test(text[i] ?? '')) i++; };
  const string = (): string => {
    const start = i++; let escaped = false;
    while (i < text.length) {
      const c = text[i++];
      if (c === '"' && !escaped) {
        try { return JSON.parse(text.slice(start, i)) as string; } catch { throw new StrictJsonError('invalid string'); }
      }
      if (c < ' ') throw new StrictJsonError('control character');
      if (c === '\\' && !escaped) escaped = true; else escaped = false;
    }
    throw new StrictJsonError('unterminated string');
  };
  const value = (): void => {
    ws(); const c = text[i];
    if (c === '"') { string(); return; }
    if (c === '{') { object(); return; }
    if (c === '[') { array(); return; }
    const match = /^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)/.exec(text.slice(i));
    if (!match) throw new StrictJsonError('invalid value');
    if (/^-/.test(match[0]) || /^[0-9]/.test(match[0])) {
      // JSON.parse silently rounds both large integer literals and decimal/exponent
      // literals.  Protocol JSON has no use for non-integer numbers, so reject
      // every representation which cannot round-trip as a safe integer.
      if (match[0].includes('.') || /[eE]/.test(match[0])) throw new StrictJsonError('non-integer number');
      const number = Number(match[0]);
      if (!Number.isSafeInteger(number)) throw new StrictJsonError('unsafe number');
    }
    i += match[0].length;
  };
  const object = (): void => {
    i++; ws(); const names = new Set<string>(); if (text[i] === '}') { i++; return; }
    for (;;) { ws(); if (text[i] !== '"') throw new StrictJsonError('object key'); const name = string(); if (names.has(name)) throw new StrictJsonError('duplicate member'); names.add(name); ws(); if (text[i++] !== ':') throw new StrictJsonError('missing colon'); value(); ws(); if (text[i] === '}') { i++; return; } if (text[i++] !== ',') throw new StrictJsonError('missing comma'); }
  };
  const array = (): void => { i++; ws(); if (text[i] === ']') { i++; return; } for (;;) { value(); ws(); if (text[i] === ']') { i++; return; } if (text[i++] !== ',') throw new StrictJsonError('missing comma'); } };
  value(); ws(); if (i !== text.length) throw new StrictJsonError('trailing input');
  try { return JSON.parse(text); } catch { throw new StrictJsonError('invalid json'); }
}
