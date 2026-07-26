import js from '@eslint/js';
import tseslint from 'typescript-eslint';

const extensions = ['**/*.{js,jsx,ts,tsx,mjs,cjs,mts,cts}'];
const cryptoModules = {
  paths: [
    { name: '@matrix-org/olm', message: 'Direct Olm imports are forbidden.' },
    { name: '@matrix-org/matrix-sdk-crypto-wasm', message: 'Direct Matrix crypto WASM imports are forbidden.' },
  ],
  patterns: [
    { group: ['@matrix-org/olm/*'], message: 'Direct Olm imports are forbidden.' },
    { group: ['@matrix-org/matrix-sdk-crypto-wasm/*'], message: 'Direct Matrix crypto WASM imports are forbidden.' },
  ],
};
const quarantineImports = {
  paths: [...cryptoModules.paths, { name: 'matrix-js-sdk', message: 'matrix-js-sdk imports are restricted to matrix/internal/sdk.ts.' }],
  patterns: [...cryptoModules.patterns,
    { group: ['matrix-js-sdk/*'], message: 'matrix-js-sdk subpath imports are forbidden.' },
    { group: ['matrix/internal/**'], message: 'matrix/internal imports are restricted to matrix/index.ts and matrix/internal files.' },
  ],
};
const sdkSeamImports = {
  ...cryptoModules,
  patterns: [...cryptoModules.patterns, { group: ['matrix-js-sdk/*', '!matrix-js-sdk/lib/crypto-api'], message: 'matrix-js-sdk subpath imports are forbidden.' }],
};
const matrixModulePattern = '^(matrix-js-sdk|@matrix-org\\/olm|@matrix-org\\/matrix-sdk-crypto-wasm)(\\/|$)';
const moduleLoadingSyntax = [
  { selector: `CallExpression[callee.name='require'][arguments.0.value=/${matrixModulePattern}/]`, message: 'Matrix SDK and crypto require calls are forbidden.' },
  { selector: `ImportExpression[source.value=/${matrixModulePattern}/]`, message: 'Matrix SDK and crypto dynamic imports are forbidden.' },
  { selector: `ExportAllDeclaration[source.value=/${matrixModulePattern}/]`, message: 'Matrix SDK and crypto module re-exports are forbidden.' },
  { selector: `ExportNamedDeclaration[source.value=/${matrixModulePattern}/]`, message: 'Matrix SDK and crypto module re-exports are forbidden.' },
];

export default [
  { ignores: ['dist/**', 'build/**', '.next/**', 'node_modules/**', 'coverage/**', '.matrix-browser-harness/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: extensions,
    rules: {
      'no-restricted-imports': ['error', quarantineImports],
      'no-restricted-syntax': ['error', ...moduleLoadingSyntax],
    },
  },
  {
    files: ['src/matrix/index.ts', 'src/matrix/internal/**/*.{ts,tsx,js,jsx,mjs,cjs,mts,cts}'],
    rules: { 'no-restricted-imports': ['error', sdkSeamImports] },
  },
  // The injected browser probe is deliberately test-only and imports the real
  // SDK to exercise its Rust IndexedDB path; it is not a production seam.
  { files: ['e2e/browser-harness.ts'], rules: { 'no-restricted-imports': ['error', cryptoModules] } },
  {
    files: ['src/matrix/index.ts'],
    rules: {
      'no-restricted-syntax': ['error',
        ...moduleLoadingSyntax,
        { selector: 'ExportAllDeclaration', message: 'matrix/index.ts must use explicit named exports, not export *.' },
      ],
    },
  },
  {
    files: ['src/matrix/internal/sdk.ts'],
    rules: {
      // The AST source-policy checker below is exact about the two permitted
      // specifiers; eslint cannot express a single allowed subpath exception.
      'no-restricted-imports': ['error', cryptoModules],
      'no-restricted-syntax': ['error', ...moduleLoadingSyntax,
        { selector: "MemberExpression[property.name=/^(initCrypto|initLegacyCrypto)$/]", message: 'Legacy Matrix crypto initialization is forbidden.' },
        { selector: "MemberExpression[computed=true][property.value=/^(initCrypto|initLegacyCrypto)$/]", message: 'Legacy Matrix crypto initialization is forbidden.' },
        { selector: "Property[parent.type='ObjectPattern'][key.name=/^(initCrypto|initLegacyCrypto)$/]", message: 'Legacy Matrix crypto initialization is forbidden.' },
        { selector: "Property[parent.type='ObjectPattern'][key.value=/^(initCrypto|initLegacyCrypto)$/]", message: 'Legacy Matrix crypto initialization is forbidden.' },
        { selector: "Identifier[name='Olm']", message: 'Global or direct Olm references are forbidden.' },
      ],
    },
  },
  { files: ['scripts/**/*.mjs', 'test/**/*.mjs'], languageOptions: { globals: { console: 'readonly', process: 'readonly', URL: 'readonly' } } },
];
