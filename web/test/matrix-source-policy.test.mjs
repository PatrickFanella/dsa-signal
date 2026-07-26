import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ESLint } from 'eslint';
import { afterEach, describe, expect, it } from 'vitest';
import { checkProductionSourcePolicy, checkSourceText } from '../scripts/check-matrix-source-policy.mjs';

const temporaryDirectories = [];
const expectViolation = (source, expected, file = 'example.ts') => expect(checkSourceText(source, file).join('\n')).toContain(expected);
const temporarySource = (files) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'matrix-policy-'));
  temporaryDirectories.push(directory);
  const sourceFiles = files['auth/session-store.ts'] === undefined
    ? { 'auth/session-store.ts': "export class IndexedDbSessionStore { public prepareSasAuthorizationForStartup(expected) { return this.transaction([SAS_AUTHORIZATIONS, SESSIONS, LOCATOR], 'readwrite', () => expected); } }", ...files }
    : files;
  for (const [name, content] of Object.entries(sourceFiles)) {
    const file = path.join(directory, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
  }
  return directory;
};
afterEach(() => temporaryDirectories.splice(0).forEach((directory) => fs.rmSync(directory, { recursive: true, force: true })));

describe('Matrix import quarantine', () => {
  it('keeps production source within the quarantine', () => expect(checkProductionSourcePolicy()).toEqual([]));
  it('allows only static exact SDK root and crypto-api imports in the SDK seam', () => {
    expect(checkSourceText("import { createClient } from 'matrix-js-sdk';", 'matrix/internal/sdk.ts')).toEqual([]);
    expect(checkSourceText("import { OnlySignedDevicesIsolationMode } from 'matrix-js-sdk/lib/crypto-api';", 'matrix/internal/sdk.ts')).toEqual([]);
    for (const file of ['matrix/index.ts', 'matrix/contract.ts', 'feature.ts']) expectViolation("import { createClient } from 'matrix-js-sdk';", 'restricted', file);
    for (const source of ["import sdk from 'matrix-js-sdk/lib/oauth';", "export * from 'matrix-js-sdk'", "require('matrix-js-sdk')", "await import('matrix-js-sdk')", "import sdk = require('matrix-js-sdk')"]) expectViolation(source, 'matrix-js-sdk', 'matrix/internal/sdk.ts');
  });
  it('forbids SDK crypto modules through every module-loading form', () => {
    for (const name of ['@matrix-org/olm', '@matrix-org/olm/olm', '@matrix-org/matrix-sdk-crypto-wasm', '@matrix-org/matrix-sdk-crypto-wasm/lib']) {
      for (const source of [`import value from '${name}'`, `export * from '${name}'`, `require('${name}')`, `await import('${name}')`, `import crypto = require('${name}')`]) expectViolation(source, 'crypto module', 'matrix/internal/sdk.ts');
    }
  });
  it('canonicalizes module specifiers before applying Matrix package rules', () => {
    expect(checkSourceText("import sdk from 'matrix-js-sdk?raw';", 'matrix/internal/sdk.ts')).toEqual([]);
    for (const source of ["import sdk from 'matrix-js-sdk?raw';", "import sdk from 'matrix-js-sdk#x';", "import crypto from '@matrix-org/olm?raw';", "import crypto from '@matrix-org/matrix-sdk-crypto-wasm#x';"]) expectViolation(source, source.includes('matrix-js-sdk') ? 'restricted' : 'crypto module');
  });
  it('rejects local module specifiers that escape the scanned source root', () => {
    const root = path.resolve('/tmp/matrix-policy-src');
    const check = (source, file) => checkSourceText(source, file, root).join('\n');
    expect(check("import '../outside';", 'entry.ts')).toContain('source root');
    expect(check("import '../../../outside';", 'nested/deeper/entry.ts')).toContain('source root');
    for (const name of ['/tmp/outside.ts', 'file:///tmp/outside.ts', 'FILE:///tmp/outside.ts', 'FiLe:///tmp/outside.ts?raw#x', '/@fs/tmp/outside.ts']) expect(check(`import '${name}';`, 'entry.ts')).toContain('source root');
    expect(check("import './nested/../inside?raw#x';", 'entry.ts')).toBe('');
  });
  it('does not inspect module-looking comments', () => {
    expect(checkSourceText("// import sdk from 'matrix-js-sdk?raw'\n/* require('@matrix-org/olm#x') */", 'feature.ts')).toEqual([]);
  });
  it('permits internal imports only for the facade or internal implementation', () => {
    expect(checkSourceText("import './internal/sdk';", 'matrix/index.ts')).toEqual([]);
    expect(checkSourceText("import '../internal/sdk';", 'matrix/internal/adapter.ts')).toEqual([]);
    expectViolation("import 'matrix/internal/sdk';", 'matrix/internal imports', 'feature.ts');
    expectViolation("import './internal/sdk';", 'matrix/internal imports', 'matrix/contract.ts');
    for (const source of ["import '/src/matrix/internal/sdk';", "import 'src/matrix/internal/sdk';"]) expectViolation(source, 'matrix/internal imports', 'feature.ts');
  });
  it('requires explicit exports from the public facade', () => {
    expectViolation("export * from './contract';", 'explicit named exports', 'matrix/index.ts');
    expect(checkSourceText("export type { MatrixGateway } from './contract';", 'matrix/index.ts')).toEqual([]);
  });
  it('checks every Vite-loadable extension and leaves unrelated APIs alone', () => {
    const directory = temporarySource({ 'a.js': "import sdk from 'matrix-js-sdk'", 'b.jsx': "require('@matrix-org/olm')", 'c.test.tsx': "import sdk from 'matrix-js-sdk'", 'd.mjs': "await import('@matrix-org/matrix-sdk-crypto-wasm')", 'e.cjs': "require('matrix-js-sdk')", 'f.mts': "import sdk from 'matrix-js-sdk/lib/x'", 'g.cts': "export * from 'matrix-js-sdk'" });
    const result = checkProductionSourcePolicy(directory).join('\n');
    for (const file of ['a.js', 'b.jsx', 'c.test.tsx', 'd.mjs', 'e.cjs', 'f.mts', 'g.cts']) expect(result).toContain(file);
    expect(checkSourceText("await import('./lazy-feature'); require('unrelated-package'); client.sendEvent();", 'feature.ts')).toEqual([]);
  });

  it('rejects computed dynamic imports and require calls while allowing their text in data', () => {
    for (const source of ["await import(`./${name}`)", "await import('./' + name)", 'await import(name)', 'require(`./${name}`)', "require('./' + name)", 'require(name)']) {
      expect(checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;', 'entry.ts': source })).join('\n')).toContain('computed');
    }
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;', 'entry.ts': "const text = \"import(name); require(name)\"; // import(`./${name}`)" }))).toEqual([]);
  });

  it('forbids every executable require identifier in production ESM source', () => {
    const seam = 'export const deriveSasStableGrantBindingForTest = async () => undefined;';
    for (const source of ['(require)(name)', 'const load = require;', 'const { require: load } = modules;', 'const { require } = modules;', 'require?.(name)', 'require(name)']) {
      expect(checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': seam, 'entry.ts': source })).join('\n')).toContain('require is forbidden');
    }
    const controls = "const text = 'require'; const value = object.require; const data = { require: 'label' };";
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': seam, 'entry.ts': controls }))).toEqual([]);
  });

  it('enforces the stable-binding seam and v4 store quarantine across production source', () => {
    const seam = 'deriveSasStableGrantBindingForTest';
    const valid = `export const ${seam} = async () => undefined;`;
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': valid }))).toEqual([]);
    for (const source of [
      `import { ${seam} } from './sdk'; ${seam}();`,
      `const alias = { ${seam} }; alias.${seam}();`,
      `sdk['${seam}']();`,
      `sdk[\`${seam}\`]();`,
      `const { '${seam}': alias } = sdk;`,
      `Reflect.get(sdk, '${seam}');`,
    ]) {
      const result = checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': valid, 'nested/runtime.ts': source })).join('\n');
      expect(result).toContain('stable binding test seam');
    }
    const legacyStoreApis = ['getSasAuthorization', 'requireSasReverification', 'createOutgoingSasIntent', 'createIncomingSasAuthorization', 'bindOutgoingSasFlow', 'advanceSasAuthorizationStage', 'grantSasAuthorization'];
    for (const api of legacyStoreApis) {
      for (const source of [`store.${api}()`, `store['${api}']()`, `store[\`${api}\`]();`, `const { '${api}': alias } = store;`, `Reflect.get(store, '${api}');`]) {
        expect(checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': `${valid}\n${source}` })).join('\n')).toContain('v4 SAS store APIs');
      }
    }
    const controls = `const documentation = '${seam}'; const data = ['getSasAuthorization', \`grantSasAuthorization\`]; const unrelated = { label: 'bindOutgoingSasFlow' };`;
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': `${valid}\n${controls}` }))).toEqual([]);
  });

  it('quarantines the store-only startup SAS preparation API from production consumers', () => {
    const api = 'prepareSasAuthorizationForStartup';
    const declaration = `export class IndexedDbSessionStore { public ${api}(expected) { return this.transaction([SAS_AUTHORIZATIONS, SESSIONS, LOCATOR], 'readwrite', () => expected); } }`;
    expect(checkProductionSourcePolicy(temporarySource({ 'auth/session-store.ts': declaration, 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;' }))).toEqual([]);
    for (const source of [
      `store.${api}(expected);`,
      `store['${api}'](expected);`,
      `store[\`${api}\`](expected);`,
      `const { '${api}': prepare } = store; prepare(expected);`,
      `Reflect.get(store, '${api}')(expected);`,
      `import { ${api} } from './auth/session-store'; ${api}(expected);`,
      `export { ${api} } from './auth/session-store';`,
      `const indirect = store.${api}; indirect(expected);`,
    ]) {
      const result = checkProductionSourcePolicy(temporarySource({ 'auth/session-store.ts': declaration, 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;', 'entry.ts': source })).join('\n');
      expect(result).toContain('startup SAS preparation');
    }
    for (const source of [
      `export class IndexedDbSessionStore { public ${api}(expected) { return this.transaction([SAS_AUTHORIZATIONS], 'readwrite', () => expected); } }`,
      `export class IndexedDbSessionStore { public ${api}(expected) { return this.transaction([SAS_AUTHORIZATIONS, SESSIONS, LOCATOR, SAS_OPERATIONS], 'readwrite', () => expected); } }`,
    ]) expect(checkProductionSourcePolicy(temporarySource({ 'auth/session-store.ts': source, 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;' })).join('\n')).toContain('atomic authorization/session/locator transaction');
  });

  it('keeps the dormant grant mediator unreachable from production source', () => {
    for (const source of [
      "import value from './matrix/sas-grant-mediator';",
      "export { mediateSasGrantedEffect } from 'matrix/sas-grant-mediator?raw';",
      "await import('matrix/sas-grant-mediator#later');",
      "require('matrix/sas-grant-mediator');",
      "Reflect.get(matrix, 'sas-grant-mediator');",
      "matrix['sas-grant-mediator'];",
    ]) expect(checkProductionSourcePolicy(temporarySource({ 'entry.ts': source, 'matrix/sas-grant-mediator.ts': 'export {};' })).join('\n')).toContain('sas-grant-mediator');
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/sas-grant-mediator.ts': 'export {};', 'matrix/barrel.ts': "export * from './sas-grant-mediator';", 'entry.ts': "import './matrix/barrel';" })).join('\n')).toContain('sas-grant-mediator');
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;', 'matrix/sas-grant-mediator.ts': 'export {};', 'entry.ts': "const label = 'sas-grant-mediator documentation'; const value = matrix['unrelated'];" }))).toEqual([]);
  });

  it('keeps the dormant outgoing controller declaration-only and unreachable', () => {
    const controller = 'export async function beginDormantOutgoingSasFlow() {}';
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/sas-authorization-flow-controller.ts': controller, 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;' }))).toEqual([]);
    const seam = 'export const deriveSasStableGrantBindingForTest = async () => undefined;';
    for (const source of [
      "import { beginDormantOutgoingSasFlow } from './matrix/sas-authorization-flow-controller';",
      "export { beginDormantOutgoingSasFlow } from './matrix/sas-authorization-flow-controller#x';",
      "await import('./matrix/sas-authorization-flow-controller?raw')",
      "const load = () => import('./matrix/sas-authorization-flow-controller#later'); load();",
      "require('./matrix/sas-authorization-flow-controller');",
      "const load = require; load('./matrix/sas-authorization-flow-controller');",
      "Reflect.get(flow, 'beginDormantOutgoingSasFlow')",
      "flow['beginDormantOutgoingSasFlow']();",
      "flow[`beginDormantOutgoingSasFlow`]();",
      "const { beginDormantOutgoingSasFlow: run } = flow; run();",
      "import.meta.glob('./matrix/sas-authorization-flow-controller.ts');",
      "const glob = import.meta['glob']; glob('./matrix/sas-authorization-flow-controller.ts');",
    ]) expect(checkProductionSourcePolicy(temporarySource({ 'matrix/sas-authorization-flow-controller.ts': controller, 'matrix/internal/sdk.ts': seam, 'entry.ts': source })).join('\n')).toMatch(/dormant|require is forbidden|import\.meta\.glob/);
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/sas-authorization-flow-controller.ts': controller, 'matrix/controller-barrel.ts': "export * from './sas-authorization-flow-controller';", 'matrix/internal/sdk.ts': seam, 'entry.ts': "import './matrix/controller-barrel';" })).join('\n')).toContain('dormant');
  });

  it('forbids every import edge between the two dormant modules in both directions', () => {
    const seam = 'export const deriveSasStableGrantBindingForTest = async () => undefined;';
    for (const [from, to] of [['matrix/sas-grant-mediator.ts', './sas-authorization-flow-controller'], ['matrix/sas-authorization-flow-controller.ts', './sas-grant-mediator']]) {
      for (const source of [`import '${to}';`, `import value from '${to}';`, `export { value } from '${to}';`, `export * from '${to}';`, `await import('${to}');`]) {
        expect(checkProductionSourcePolicy(temporarySource({ [from]: source, 'matrix/internal/sdk.ts': seam })).join('\n')).toContain('may not import each other');
      }
    }
  });

  it('positively allowlists every dormant controller StorePort member and access form', () => {
    const apis = ['getSasAuthorization', 'createOutgoingSasIntent', 'bindOutgoingSasFlow', 'requireSasReverification'];
    const port = `interface StorePort { ${apis.map(api => `${api}(): void;`).join('')} } export async function beginDormantOutgoingSasFlow() {}`;
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/sas-authorization-flow-controller.ts': port, 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;' }))).toEqual([]);
    for (const source of [
      'store.unapproved()', "store['unapproved']()", 'store[`unapproved`]()', "const { 'unapproved': method } = store; method()", 'const { unapproved } = store; unapproved()', "Reflect.get(store, 'unapproved')()",
    ]) {
      const controller = `${port}\nexport const adversary = () => { ${source}; };`;
      expect(checkProductionSourcePolicy(temporarySource({ 'matrix/sas-authorization-flow-controller.ts': controller, 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;' })).join('\n')).toContain('positive allowlist');
    }
    const missing = `interface StorePort { getSasAuthorization(): void; } export async function beginDormantOutgoingSasFlow() {}`;
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/sas-authorization-flow-controller.ts': missing, 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;' })).join('\n')).toContain('StorePort');
  });

  it('fails closed for tainted dormant controller store aliases, casts, computed access, Reflect, and destructuring', () => {
    const port = 'interface StorePort { getSasAuthorization(): void; createOutgoingSasIntent(): void; bindOutgoingSasFlow(): void; requireSasReverification(): void; } export async function beginDormantOutgoingSasFlow() {}';
    for (const source of [
      'const alias = store as any; alias.future();',
      'const alias = supplied.store!; alias[computed]();',
      'const alias = (store); Reflect.get(alias, unknown)();',
      'const { future } = (store as StorePort); future();',
      'const { [computed]: method } = supplied.store; method();',
    ]) {
      expect(checkProductionSourcePolicy(temporarySource({ 'matrix/sas-authorization-flow-controller.ts': `${port}\nexport const adversary = () => { ${source} };`, 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;' })).join('\n')).toContain('positive allowlist');
    }
  });

  it('taints input.store like supplied.store', () => {
    const port = 'interface StorePort { getSasAuthorization(): void; createOutgoingSasIntent(): void; bindOutgoingSasFlow(): void; requireSasReverification(): void; } export async function beginDormantOutgoingSasFlow() {}';
    const source = 'input.store.unapproved(); const alias = input.store; alias[method]();';
    expect(checkProductionSourcePolicy(temporarySource({ 'matrix/sas-authorization-flow-controller.ts': `${port}\nexport const adversary = () => { ${source} };`, 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;' })).join('\n')).toContain('positive allowlist');
  });

  it('forbids eager Vite glob loading, including mediator glob aliases', () => {
    for (const source of [
      "import.meta.glob('./feature.ts')",
      "import.meta.globEager('./feature.ts')",
      "import.meta['glob']('./matrix/sas-grant-mediator.ts')",
      "import.meta[`globEager`]('./matrix/sas-grant-mediator.ts')",
      "const load = import.meta.glob; load('./matrix/sas-grant-mediator.ts')",
    ]) expect(checkProductionSourcePolicy(temporarySource({ 'matrix/internal/sdk.ts': 'export const deriveSasStableGrantBindingForTest = async () => undefined;', 'matrix/sas-grant-mediator.ts': 'export {};', 'entry.ts': source })).join('\n')).toContain('import.meta.glob');
  });

  it('forbids legacy crypto initialization names in destructuring', async () => {
    const eslint = new ESLint();
    const results = await eslint.lintText("const client = {}; const { initCrypto, initLegacyCrypto: legacy, 'initCrypto': stringLiteral, ['initCrypto']: computed, ['initLegacyCrypto']: computedLegacy } = client;", { filePath: 'src/matrix/internal/sdk.ts' });
    expect(results[0].messages.filter((message) => message.message === 'Legacy Matrix crypto initialization is forbidden.')).toHaveLength(5);
  });
});
