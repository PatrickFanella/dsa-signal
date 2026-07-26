/* eslint-disable @typescript-eslint/no-explicit-any -- adversarial untrusted inputs */
import { describe, expect, test } from 'vitest';
import { posix as path } from 'node:path';
import ts from 'typescript';
import { G2_BROWSER_OBSERVATION_KIND, validateG2BrowserObservationsV1 } from './g2-browser-observation-contract';

const encoded = (value: number): string => btoa(String.fromCharCode(...Array.from({ length: 32 }, () => value))).replace(/=$/, '');
const master = encoded(7);
const profile = (character: string): string => character.repeat(64);
const base = (): Record<string, unknown> => ({
  declared: { firstAccountId: '@first:example.test', secondAccountId: '@second:example.test' },
  snapshots: {
    freshFirst: { accountId: '@first:example.test', deviceId: 'same-device', profileRef: profile('a'), crossSigningMasterRef: master, roomId: '!room:example.test' },
    freshSecond: { accountId: '@second:example.test', deviceId: 'same-device', profileRef: profile('b'), crossSigningMasterRef: encoded(8), roomId: '!room:example.test' },
    restartFirst: { accountId: '@first:example.test', deviceId: 'same-device', profileRef: profile('a'), crossSigningMasterRef: master, roomId: '!room:example.test' },
    restartSecond: { accountId: '@second:example.test', deviceId: 'same-device', profileRef: profile('b'), crossSigningMasterRef: encoded(8), roomId: '!room:example.test' },
  },
  facts: { fresh: { bothReadyUi: true, joinedLineUiBoth: true, sasComparisonUiBoth: true, humanConfirmedBoth: true, sendReadyUiBoth: true, firstToSecondReceiptUi: true }, restart: { bothReadyUi: true, joinedLineUiBoth: true, priorFirstMessageDecryptedUiOnSecond: true, sendReadyUiBoth: true, comparisonUiObserved: false, secondToFirstReceiptUi: true } },
});
const expectContractError = (execute: () => unknown, message: string): void => {
  try { execute(); } catch (error) { expect(error).toBeInstanceOf(Error); expect((error as Error).message).toBe(message); return; }
  throw new Error('expected contract error');
};
const invalid = (mutate: (value: any) => void, message: string): void => { const value = structuredClone(base()); mutate(value); expectContractError(() => validateG2BrowserObservationsV1(value), message); };
type Dependencies = { readonly static: string[]; readonly dynamic: string[]; readonly require: string[]; readonly nonliteralDynamic: boolean; readonly nonliteralRequire: boolean; readonly reexports: number };
const graph = (sources: Record<string, string>) => {
  const dependencies = (file: string): Dependencies => {
    const parsed = ts.createSourceFile(file, sources[file]!, ts.ScriptTarget.Latest, true);
    const result: { static: string[]; dynamic: string[]; require: string[]; nonliteralDynamic: boolean; nonliteralRequire: boolean; reexports: number } = { static: [], dynamic: [], require: [], nonliteralDynamic: false, nonliteralRequire: false, reexports: 0 };
    const literal = (node: ts.Expression | undefined): string | undefined => node !== undefined && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) ? node.text : undefined;
    const visit = (node: ts.Node): void => {
      if (ts.isImportDeclaration(node)) { const specifier = literal(node.moduleSpecifier); if (specifier !== undefined) result.static.push(specifier); }
      if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) { const specifier = literal(node.moduleSpecifier); if (specifier !== undefined) result.static.push(specifier); result.reexports += 1; }
      if (ts.isCallExpression(node)) {
        const specifier = literal(node.arguments[0]);
        if (node.expression.kind === ts.SyntaxKind.ImportKeyword) { if (specifier === undefined) result.nonliteralDynamic = true; else result.dynamic.push(specifier); }
        if (ts.isIdentifier(node.expression) && node.expression.text === 'require') { if (specifier === undefined) result.nonliteralRequire = true; else result.require.push(specifier); }
      }
      ts.forEachChild(node, visit);
    };
    visit(parsed);
    return result;
  };
  const resolveImport = (from: string, specifier: string): string[] => {
    if (!specifier.startsWith('.')) return [];
    const base = path.normalize(path.join(path.dirname(from), specifier));
    const sourceExtensions = [...new Set(Object.keys(sources).map(file => path.extname(file)).filter(Boolean))].sort();
    const tsExtensions = ['.ts', '.tsx', '.mts', '.cts', '.d.ts'];
    const indexExtensions = [...new Set([...sourceExtensions, ...tsExtensions])];
    const stem = /\.(?:js|jsx|mjs|cjs)$/.test(base) ? base.slice(0, base.lastIndexOf('.')) : undefined;
    const candidates = [base, ...(stem === undefined ? [] : tsExtensions.map(extension => `${stem}${extension}`)), ...(path.extname(base) === '' ? sourceExtensions.map(extension => `${base}${extension}`) : []), ...indexExtensions.map(extension => `${base}/index${extension}`)];
    return [...new Set(candidates)].filter(candidate => Object.hasOwn(sources, candidate));
  };
  const importsOf = (file: string, requireProven = false): string[] => {
    const found = dependencies(file);
    if (requireProven && (found.nonliteralDynamic || found.nonliteralRequire)) throw new Error(`unprovable dependency in ${file}`);
    return [...found.static, ...found.dynamic, ...found.require].flatMap(specifier => {
      const resolved = resolveImport(file, specifier);
      if (requireProven && specifier.startsWith('.') && resolved.length === 0) throw new Error(`unresolved dependency ${specifier} in ${file}`);
      return resolved;
    });
  };
  const reaches = (file: string, target: string, seen = new Set<string>(), requireProven = false): boolean => {
    if (seen.has(file)) return false;
    seen.add(file);
    return importsOf(file, requireProven).some(next => next === target || reaches(next, target, seen, requireProven));
  };
  return { dependencies, resolveImport, importsOf, reaches };
};

describe('G2 browser observation contract', () => {
  test('returns the sole frozen non-sensitive output', () => {
    const result = validateG2BrowserObservationsV1(base());
    expect(result).toEqual({ kind: G2_BROWSER_OBSERVATION_KIND, accepted: true });
    expect(Object.isFrozen(result)).toBe(true);
    expect(JSON.stringify(result)).not.toContain('first');
    expect(JSON.stringify(result)).not.toContain('room');
  });
  test('rejects every malformed reflection shape and primitive', () => {
    for (const mutate of [
      (v: any) => { v.extra = true; }, (v: any) => { v.declared = Object.create(null); }, (v: any) => { v.snapshots.freshFirst = []; },
      (v: any) => { Object.defineProperty(v.facts, 'fresh', { value: v.facts.fresh, enumerable: false }); }, (v: any) => { Object.defineProperty(v.declared, 'firstAccountId', { get: () => '@first:example.test', enumerable: true }); },
      (v: any) => { v.snapshots.freshFirst.roomId = 1; }, (v: any) => { v.facts.fresh.bothReadyUi = 'true'; },
    ]) invalid(mutate, 'G2_BROWSER_INPUT_INVALID');
  });
  test('preserves device UTF-16 semantics and rejects all invalid formats before rooms', () => {
    expect(validateG2BrowserObservationsV1(base()).accepted).toBe(true);
    const surrogate = base() as any; surrogate.snapshots.freshFirst.deviceId = '\ud800'; surrogate.snapshots.restartFirst.deviceId = '\ud800'; expect(validateG2BrowserObservationsV1(surrogate).accepted).toBe(true);
    for (const mutate of [(v: any) => { v.declared.firstAccountId = '@UPPER:example.test'; }, (v: any) => { v.snapshots.freshFirst.deviceId = ''; }, (v: any) => { v.snapshots.freshFirst.deviceId = '\u0000'; }, (v: any) => { v.snapshots.freshFirst.profileRef = 'A'.repeat(64); }, (v: any) => { v.snapshots.freshFirst.crossSigningMasterRef = 'a'.repeat(43); }]) invalid(mutate, 'G2_BROWSER_INPUT_INVALID');
    invalid(v => { v.snapshots.freshFirst.roomId = '! bad:example.test'; }, 'G2_BROWSER_ROOM_INVALID');
  });
  test('enforces every account binding and continuity rule in precedence order', () => {
    invalid(v => { v.declared.secondAccountId = v.declared.firstAccountId; v.snapshots.freshSecond.accountId = v.declared.firstAccountId; v.snapshots.restartSecond.accountId = v.declared.firstAccountId; v.snapshots.freshFirst.roomId = '!different:example.test'; }, 'G2_BROWSER_ACCOUNT_BINDING_INVALID');
    for (const mutate of [(v: any) => { v.snapshots.freshFirst.accountId = '@other:example.test'; }, (v: any) => { v.snapshots.restartFirst.accountId = '@other:example.test'; }, (v: any) => { v.snapshots.freshSecond.accountId = '@other:example.test'; }, (v: any) => { v.snapshots.restartSecond.accountId = '@first:example.test'; }]) invalid(mutate, 'G2_BROWSER_ACCOUNT_BINDING_INVALID');
    invalid(v => { v.snapshots.restartSecond.roomId = '!other:example.test'; }, 'G2_BROWSER_ROOM_INVALID');
    for (const mutate of [(v: any) => { v.snapshots.restartFirst.deviceId = 'other'; }, (v: any) => { v.snapshots.restartFirst.profileRef = profile('c'); }, (v: any) => { v.snapshots.restartFirst.crossSigningMasterRef = encoded(9); }, (v: any) => { v.snapshots.restartSecond.deviceId = 'other'; }, (v: any) => { v.snapshots.restartSecond.profileRef = profile('c'); }, (v: any) => { v.snapshots.restartSecond.crossSigningMasterRef = encoded(9); }, (v: any) => { v.snapshots.freshSecond.profileRef = v.snapshots.freshFirst.profileRef; v.snapshots.restartSecond.profileRef = v.snapshots.restartFirst.profileRef; }, (v: any) => { v.snapshots.freshSecond.crossSigningMasterRef = v.snapshots.freshFirst.crossSigningMasterRef; v.snapshots.restartSecond.crossSigningMasterRef = v.snapshots.restartFirst.crossSigningMasterRef; }]) invalid(mutate, 'G2_BROWSER_CONTINUITY_INVALID');
  });
  test('requires every fact at its frozen value', () => {
    for (const group of ['fresh', 'restart'] as const) for (const key of Object.keys((base().facts as any)[group])) invalid(v => { v.facts[group][key] = !v.facts[group][key]; }, 'G2_BROWSER_OBSERVATION_INCOMPLETE');
  });
  test('accepts reordered plain-record keys', () => {
    const reorder = (value: Record<string, unknown>): Record<string, unknown> => Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, item && typeof item === 'object' && !Array.isArray(item) ? reorder(item as Record<string, unknown>) : item]));
    expect(validateG2BrowserObservationsV1(reorder(base()))).toEqual({ kind: G2_BROWSER_OBSERVATION_KIND, accepted: true });
  });
  test('rejects deterministic reflection and proxy traps as input failures', () => {
    const reflected = base(); Object.defineProperty(reflected, 'declared', { get: () => reflected.declared, enumerable: true });
    expectContractError(() => validateG2BrowserObservationsV1(reflected), 'G2_BROWSER_INPUT_INVALID');
    const trapped = new Proxy(base(), { getPrototypeOf: () => { throw new Error('trap'); } });
    expectContractError(() => validateG2BrowserObservationsV1(trapped), 'G2_BROWSER_INPUT_INVALID');
    const nested = base() as any; nested.snapshots.freshFirst = new Proxy(nested.snapshots.freshFirst, { get(target, key, receiver) { if (key === 'profileRef') throw new Error('attacker message'); return Reflect.get(target, key, receiver); } });
    expectContractError(() => validateG2BrowserObservationsV1(nested), 'G2_BROWSER_INPUT_INVALID');
    const ownKeys = base() as any; let calls = 0; ownKeys.snapshots.freshFirst = new Proxy(ownKeys.snapshots.freshFirst, { ownKeys(target) { if (++calls > 1) throw new Error('attacker message'); return Reflect.ownKeys(target); } });
    expectContractError(() => validateG2BrowserObservationsV1(ownKeys), 'G2_BROWSER_INPUT_INVALID');
    const malformed = base() as any; malformed.snapshots.freshFirst.roomId = '!bad room:example.test';
    let staged: unknown;
    try { validateG2BrowserObservationsV1(malformed); } catch (error) { staged = error; }
    expect((staged as Error).message).toBe('G2_BROWSER_ROOM_INVALID');
    expectContractError(() => validateG2BrowserObservationsV1(new Proxy(base(), { getPrototypeOf: () => { throw staged; } })), 'G2_BROWSER_INPUT_INVALID');
    expectContractError(() => validateG2BrowserObservationsV1(new Proxy(base(), { getPrototypeOf: () => { throw new Proxy({}, { getPrototypeOf: () => { throw new Error('trap'); } }); } })), 'G2_BROWSER_INPUT_INVALID');
  });
  test.each([
    ['record shape', 0, 'G2_BROWSER_INPUT_INVALID'],
    ['identifier format', 1, 'G2_BROWSER_INPUT_INVALID'],
    ['room format', 2, 'G2_BROWSER_ROOM_INVALID'],
    ['account binding', 3, 'G2_BROWSER_ACCOUNT_BINDING_INVALID'],
    ['room agreement', 4, 'G2_BROWSER_ROOM_INVALID'],
    ['identity continuity', 5, 'G2_BROWSER_CONTINUITY_INVALID'],
    ['observation completeness', 6, 'G2_BROWSER_OBSERVATION_INCOMPLETE'],
  ] as const)('gives %s precedence over every later fault', (_name, index, expected) => {
    const faults = [
      (v: any) => { v.extra = true; },
      (v: any) => { v.snapshots.freshFirst.profileRef = 'A'.repeat(64); },
      (v: any) => { v.snapshots.freshFirst.roomId = '! bad:example.test'; },
      (v: any) => { v.snapshots.freshFirst.accountId = '@other:example.test'; },
      (v: any) => { v.snapshots.restartSecond.roomId = '!other:example.test'; },
      (v: any) => { v.snapshots.restartFirst.deviceId = 'other'; },
      (v: any) => { v.facts.fresh.bothReadyUi = false; },
    ];
    const earlier = faults[index]!;
    for (const later of faults.slice(index + 1)) invalid(value => { earlier(value); later(value); }, expected);
  });
});

test('graph resolver closes TypeScript-compatible relative dependency evasions', () => {
  const fixture = graph({
    './entry.ts': "import './typed.js'; export * from './directory'; import('./dynamic.js'); require('./required.js'); // import './ignored.js'",
    'typed.ts': '', 'directory/index.tsx': '', 'dynamic.tsx': '', 'required.ts': '', './comment.ts': "/* require('./missing.js') */",
    './module.ts': "export * from './folder';", 'folder/index.mjs': '', './missing.ts': "import './absent.js';",
    './ambiguous-entry.ts': "import './bridge.js';", 'bridge.js': '', 'bridge.ts': "import './target';", 'target.ts': '',
  });
  expect(fixture.importsOf('./entry.ts', true)).toEqual(['typed.ts', 'directory/index.tsx', 'dynamic.tsx', 'required.ts']);
  expect(fixture.importsOf('./comment.ts', true)).toEqual([]);
  expect(fixture.importsOf('./module.ts', true)).toEqual(['folder/index.mjs']);
  expect(fixture.importsOf('./ambiguous-entry.ts', true)).toEqual(['bridge.js', 'bridge.ts']);
  expect(fixture.reaches('./ambiguous-entry.ts', 'target.ts', new Set(), true)).toBe(true);
  expect(() => fixture.importsOf('./missing.ts', true)).toThrow('unresolved dependency ./absent.js in ./missing.ts');
});

test('source policy admits only identifiers and no authority sink', () => {
  const sources = import.meta.glob(['./*.{ts,tsx,mjs,js}', '../src/**/*', '../../scripts/**/*.{mjs,js}'], { eager: true, query: '?raw', import: 'default' }) as Record<string, string>;
  const contract = './g2-browser-observation-contract.ts';
  const sourceGraph = graph(sources);
  const authoritySinks = ['../../scripts/test-g2-encrypted-direct-chat.mjs', '../../scripts/g2-evidence-contract.mjs', '../../scripts/g2-evidence-fixture.mjs', './g2-reporter.mjs', './encrypted-vertical-slice.spec.ts'];
  const srcFiles = Object.keys(sources).filter(path => path.startsWith('../src/'));
  const contractDependencies = sourceGraph.dependencies(contract);
  expect(contractDependencies.static).toEqual(['../src/matrix/identifiers']);
  expect(contractDependencies.dynamic).toEqual([]);
  expect(contractDependencies.require).toEqual([]);
  expect(contractDependencies.nonliteralDynamic).toBe(false);
  expect(contractDependencies.nonliteralRequire).toBe(false);
  expect(contractDependencies.reexports).toBe(0);
  expect(sourceGraph.resolveImport(contract, '../src/matrix/identifiers')).toEqual(['../src/matrix/identifiers.ts']);
  expect(sourceGraph.importsOf('../../scripts/test-g2-encrypted-direct-chat.mjs')).toContain('../../scripts/g2-evidence-contract.mjs');
  expect(sourceGraph.importsOf('../../scripts/g2-evidence-fixture.mjs')).toContain('../../scripts/g2-evidence-contract.mjs');
  expect(srcFiles).toContain('../src/matrix/identifiers.ts');
  expect(sourceGraph.importsOf('../src/app-entry.tsx', true)).toContain('../src/styles.css');
  for (const sink of authoritySinks) expect(sourceGraph.reaches(sink, contract, new Set(), true)).toBe(false);
  for (const file of srcFiles) expect(sourceGraph.reaches(file, contract, new Set(), true)).toBe(false);
});
