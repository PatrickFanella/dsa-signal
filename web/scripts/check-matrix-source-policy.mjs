import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const sourceExtensions = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts']);
const normalized = (file) => file.replaceAll(path.sep, '/');
const canonicalModuleSpecifier = (name) => name.split(/[?#]/, 1)[0];
const scriptKind = (file) => ({ '.js': ts.ScriptKind.JS, '.jsx': ts.ScriptKind.JSX, '.ts': ts.ScriptKind.TS, '.tsx': ts.ScriptKind.TSX, '.mjs': ts.ScriptKind.JS, '.cjs': ts.ScriptKind.JS, '.mts': ts.ScriptKind.TS, '.cts': ts.ScriptKind.TS })[path.extname(file)] ?? ts.ScriptKind.TS;
const moduleName = (node) => ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : undefined;
const literalPropertyName = (node) => ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : undefined;
const referencedLiteralPropertyName = (node) => {
  if (ts.isElementAccessExpression(node)) return node.argumentExpression && literalPropertyName(node.argumentExpression);
  if (ts.isBindingElement(node)) return node.propertyName && literalPropertyName(node.propertyName);
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression) && node.expression.expression.text === 'Reflect' && node.expression.name.text === 'get') return node.arguments[1] && literalPropertyName(node.arguments[1]);
  return undefined;
};
const unwrap = (node) => {
  while (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node) || ts.isSatisfiesExpression(node)) node = node.expression;
  return node;
};
const isForbiddenCryptoModule = (name) => name === '@matrix-org/olm' || name.startsWith('@matrix-org/olm/') || name === '@matrix-org/matrix-sdk-crypto-wasm' || name.startsWith('@matrix-org/matrix-sdk-crypto-wasm/');
const isSdkSubpath = (name) => name.startsWith('matrix-js-sdk/');
const isInternalModule = (name, relativePath) => name.startsWith('matrix/internal/') || name.startsWith('/src/matrix/internal/') || name.startsWith('src/matrix/internal/') || (name.startsWith('.') && normalized(path.normalize(path.join(path.dirname(relativePath), name))).startsWith('matrix/internal/'));
const isContained = (root, target) => {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
};
const isLocalSpecifier = (name) => name.startsWith('.') || path.isAbsolute(name) || path.win32.isAbsolute(name) || name.toLowerCase().startsWith('file:') || name.startsWith('/@fs/');
const addPolicyViolation = (violations, relative, source, node, message) => {
  const sourceFile = ts.createSourceFile(relative, source, ts.ScriptTarget.Latest, true, scriptKind(relative));
  const point = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  violations.push(`${relative}:${point.line + 1}:${point.character + 1}: ${message}`);
};
const isRequireReference = (node) => {
  const parent = node.parent;
  return !(ts.isPropertyAccessExpression(parent) && parent.name === node)
    && !(ts.isPropertyAssignment(parent) && parent.name === node)
    && !(ts.isPropertyDeclaration(parent) && parent.name === node)
    && !(ts.isPropertySignature(parent) && parent.name === node)
    && !(ts.isMethodDeclaration(parent) && parent.name === node)
    && !(ts.isMethodSignature(parent) && parent.name === node);
};

export function checkSourceText(source, relativePath = 'example.ts', sourceRoot) {
  const sourceFile = ts.createSourceFile(relativePath, source, ts.ScriptTarget.Latest, true, scriptKind(relativePath));
  const file = normalized(relativePath);
  const violations = [];
  const add = (node, message) => {
    const { line, character } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    violations.push(`${file}:${line + 1}:${character + 1}: ${message}`);
  };
  for (const diagnostic of sourceFile.parseDiagnostics) add({ getStart: () => diagnostic.start ?? 0 }, `source could not be parsed: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')}`);
  const checkModule = (node, name, kind) => {
    const canonicalName = canonicalModuleSpecifier(name);
    if (sourceRoot && isLocalSpecifier(canonicalName)) {
      if (!canonicalName.startsWith('.') || !isContained(path.resolve(sourceRoot), path.resolve(sourceRoot, path.dirname(relativePath), canonicalName))) add(node, 'local module specifiers must remain within the source root');
    }
    name = canonicalName;
    if (isForbiddenCryptoModule(name)) add(node, 'direct Matrix crypto module imports are forbidden');
    if (isSdkSubpath(name) && !(file === 'matrix/internal/sdk.ts' && name === 'matrix-js-sdk/lib/crypto-api' && kind === 'static import')) add(node, 'matrix-js-sdk subpath imports are forbidden');
    if (name === 'matrix-js-sdk') {
      if (kind !== 'static import') add(node, 'matrix-js-sdk re-exports, require, and dynamic imports are forbidden');
      else if (file !== 'matrix/internal/sdk.ts') add(node, 'matrix-js-sdk imports are restricted to matrix/internal/sdk.ts');
    }
    if (isInternalModule(name, file) && file !== 'matrix/index.ts' && !file.startsWith('matrix/internal/')) add(node, 'matrix/internal imports are restricted to matrix/index.ts and matrix/internal files');
  };
  const walk = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      const name = moduleName(node.moduleSpecifier);
      if (name) checkModule(node, name, ts.isImportDeclaration(node) ? 'static import' : 're-export');
    }
    if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      const name = node.moduleReference.expression && moduleName(node.moduleReference.expression);
      if (name) checkModule(node, name, 'require');
    }
    if (file === 'matrix/index.ts' && ts.isExportDeclaration(node) && !node.exportClause) add(node, 'matrix/index.ts must use explicit named exports, not export *');
    if (ts.isCallExpression(node)) {
      const name = node.arguments[0] && moduleName(node.arguments[0]);
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword && !name) add(node, 'computed dynamic imports are forbidden in production source');
      if (ts.isIdentifier(node.expression) && node.expression.text === 'require' && !name) add(node, 'computed require calls are forbidden in production source');
      if (name && node.expression.kind === ts.SyntaxKind.ImportKeyword) checkModule(node, name, 'dynamic import');
      if (name && ts.isIdentifier(node.expression) && node.expression.text === 'require') checkModule(node, name, 'require');
    }
    ts.forEachChild(node, walk);
  };
  walk(sourceFile);
  return violations;
}

function sourceFiles(directory, root = directory) {
  let entries;
  try { entries = fs.readdirSync(directory, { withFileTypes: true }); } catch (error) { return [`!${path.relative(root, directory)}: ${error.message}`]; }
  return entries.flatMap((entry) => {
    const fullPath = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) return [`!${path.relative(root, fullPath)}: symbolic links are forbidden in source policy input`];
    if (entry.isDirectory()) return sourceFiles(fullPath, root);
    if (!entry.isFile()) return [`!${path.relative(root, fullPath)}: non-regular entries are forbidden in source policy input`];
    return sourceExtensions.has(path.extname(entry.name)) ? [fullPath] : [];
  });
}

export function checkProductionSourcePolicy(sourceDirectory = path.resolve('src')) {
  const files = sourceFiles(sourceDirectory);
  const violations = files.flatMap((file) => file.startsWith('!') ? [file.slice(1)] : checkSourceText(fs.readFileSync(file, 'utf8'), path.relative(sourceDirectory, file), sourceDirectory));
  const production = files.filter(file => !file.startsWith('!') && !/\.(?:test|spec)\.[^.]+$/.test(file));
  let stableDeclarations = 0;
  let stableReferences = 0;
  let startupPreparationDeclarations = 0;
  let startupPreparationReferences = 0;
  let atomicStartupPreparations = 0;
  const startupPreparation = 'prepareSasAuthorizationForStartup';
  const legacyStoreApis = new Set(['getSasAuthorization', 'requireSasReverification', 'createOutgoingSasIntent', 'createIncomingSasAuthorization', 'bindOutgoingSasFlow', 'advanceSasAuthorizationStage', 'grantSasAuthorization']);
  const mediator = 'matrix/sas-grant-mediator';
  const controller = 'matrix/sas-authorization-flow-controller';
  const controllerStoreApis = new Set(['getSasAuthorization', 'createOutgoingSasIntent', 'bindOutgoingSasFlow', 'requireSasReverification']);
  let controllerDeclarations = 0;
  let controllerReferences = 0;
  const loadedModules = new Map();
  const resolvesDormant = (name, relative, dormant) => {
    const canonical = canonicalModuleSpecifier(name);
    if (canonical === dormant || canonical === `src/${dormant}` || canonical === `/src/${dormant}`) return true;
    if (!canonical.startsWith('.')) return false;
    const resolved = normalized(path.normalize(path.join(path.dirname(relative), canonical))).replace(/\.(?:[cm]?[jt]sx?)$/, '');
    return resolved === dormant;
  };
  for (const file of production) {
    const relative = normalized(path.relative(sourceDirectory, file));
    const sourceFile = ts.createSourceFile(relative, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, scriptKind(file));
    const modules = [];
    const add = (node, message) => { const point = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)); violations.push(`${relative}:${point.line + 1}:${point.character + 1}: ${message}`); };
    const walk = (node) => {
      if (ts.isIdentifier(node) && node.text === 'require' && isRequireReference(node)) add(node, 'require is forbidden in production ESM source');
      if ((ts.isPropertyAccessExpression(node) && ts.isMetaProperty(node.expression) && node.expression.keywordToken === ts.SyntaxKind.ImportKeyword && node.expression.name.text === 'meta' && (node.name.text === 'glob' || node.name.text === 'globEager'))
        || (ts.isElementAccessExpression(node) && ts.isMetaProperty(node.expression) && node.expression.keywordToken === ts.SyntaxKind.ImportKeyword && node.expression.name.text === 'meta' && ['glob', 'globEager'].includes(literalPropertyName(node.argumentExpression)))) add(node, 'import.meta.glob and import.meta.globEager are forbidden in production source');
      if (ts.isIdentifier(node) && node.text === 'deriveSasStableGrantBindingForTest') {
        const declaration = ts.isVariableDeclaration(node.parent) && node.parent.name === node && ts.isVariableDeclarationList(node.parent.parent) && ts.isVariableStatement(node.parent.parent.parent) && node.parent.parent.parent.modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.ExportKeyword);
        if (declaration && relative === 'matrix/internal/sdk.ts') stableDeclarations += 1;
        else stableReferences += 1;
      }
      if (ts.isIdentifier(node) && node.text === startupPreparation) {
        const declaration = relative === 'auth/session-store.ts' && ts.isMethodDeclaration(node.parent) && node.parent.name === node;
        if (declaration) {
          startupPreparationDeclarations += 1;
          const calls = [];
          let touchesOperations = false;
          const inspect = (member) => {
            if (ts.isIdentifier(member) && member.text === 'SAS_OPERATIONS') touchesOperations = true;
            if (ts.isCallExpression(member) && ts.isPropertyAccessExpression(member.expression) && member.expression.expression.kind === ts.SyntaxKind.ThisKeyword && member.expression.name.text === 'transaction') calls.push(member);
            ts.forEachChild(member, inspect);
          };
          if (node.parent.body) inspect(node.parent.body);
          const atomic = calls.length === 1 && calls[0].arguments.length >= 2 && ts.isArrayLiteralExpression(calls[0].arguments[0]) && ts.isStringLiteral(calls[0].arguments[1]) && calls[0].arguments[1].text === 'readwrite'
            && calls[0].arguments[0].elements.length === 3 && new Set(calls[0].arguments[0].elements.filter(ts.isIdentifier).map(element => element.text)).size === 3
            && ['SAS_AUTHORIZATIONS', 'SESSIONS', 'LOCATOR'].every(store => calls[0].arguments[0].elements.some(element => ts.isIdentifier(element) && element.text === store));
          if (atomic && !touchesOperations) atomicStartupPreparations += 1;
        }
        else startupPreparationReferences += 1;
      }
      const literalProperty = referencedLiteralPropertyName(node);
      if (literalProperty === 'sas-grant-mediator') add(node, 'sas-grant-mediator is dormant and may not be accessed by production source');
      if (literalProperty === 'deriveSasStableGrantBindingForTest') stableReferences += 1;
      if (literalProperty === startupPreparation) startupPreparationReferences += 1;
      if (relative === 'matrix/internal/sdk.ts' && ((ts.isIdentifier(node) && legacyStoreApis.has(node.text)) || legacyStoreApis.has(literalProperty))) add(node, 'v4 SAS store APIs are forbidden in matrix/internal/sdk.ts');
      if (relative === 'matrix/sas-authorization-flow-controller.ts') {
        if ((ts.isIdentifier(node) && legacyStoreApis.has(node.text) && !controllerStoreApis.has(node.text)) || (literalProperty && legacyStoreApis.has(literalProperty) && !controllerStoreApis.has(literalProperty))) add(node, 'only the four outgoing v4 SAS store APIs are permitted in the dormant controller');
        if (ts.isInterfaceDeclaration(node) && node.name.text === 'StorePort') {
          const members = node.members.map(member => member.name && (ts.isIdentifier(member.name) ? member.name.text : literalPropertyName(member.name)));
          if (members.length !== controllerStoreApis.size || members.some(member => !member || !controllerStoreApis.has(member)) || controllerStoreApis.size !== new Set(members).size) add(node, 'dormant controller StorePort must declare exactly its positive allowlist');
        }
        if (ts.isIdentifier(node) && node.text === 'beginDormantOutgoingSasFlow') {
          const declaration = ts.isFunctionDeclaration(node.parent) && node.parent.name === node && node.parent.modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.ExportKeyword);
          if (declaration) controllerDeclarations += 1; else controllerReferences += 1;
        }
      } else if ((ts.isIdentifier(node) && node.text === 'beginDormantOutgoingSasFlow') || literalProperty === 'beginDormantOutgoingSasFlow') controllerReferences += 1;
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) { const name = moduleName(node.moduleSpecifier); if (name) modules.push({ node, name }); }
      if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) { const name = node.moduleReference.expression && moduleName(node.moduleReference.expression); if (name) modules.push({ node, name }); }
      if (ts.isCallExpression(node)) { const name = node.arguments[0] && moduleName(node.arguments[0]); if (name && (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === 'require'))) modules.push({ node, name }); }
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword && !(node.arguments[0] && moduleName(node.arguments[0]))) add(node, 'computed dynamic imports are forbidden in production source');
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require' && !(node.arguments[0] && moduleName(node.arguments[0]))) add(node, 'computed require calls are forbidden in production source');
      ts.forEachChild(node, walk);
    };
    walk(sourceFile);
    if (relative === 'matrix/sas-authorization-flow-controller.ts') {
      const tainted = new Set(['store']);
      const isTainted = (expression) => {
        expression = unwrap(expression);
        const isStoreSeed = (target, name) => ts.isIdentifier(target) && ['supplied', 'input'].includes(target.text) && name === 'store';
        return ts.isIdentifier(expression) && tainted.has(expression.text)
          || ts.isPropertyAccessExpression(expression) && isStoreSeed(expression.expression, expression.name.text)
          || ts.isElementAccessExpression(expression) && isStoreSeed(expression.expression, literalPropertyName(expression.argumentExpression));
      };
      const property = (name) => ts.isIdentifier(name) ? name.text : literalPropertyName(name);
      const inspectStore = (node) => {
        if (ts.isVariableDeclaration(node) && node.initializer && isTainted(node.initializer)) {
          if (ts.isIdentifier(node.name)) tainted.add(node.name.text);
          if (ts.isObjectBindingPattern(node.name)) for (const element of node.name.elements) {
            const name = element.propertyName ? property(element.propertyName) : ts.isIdentifier(element.name) ? element.name.text : undefined;
            if (!name || !controllerStoreApis.has(name)) add(element, 'dormant controller store access is restricted to its positive allowlist');
          }
        }
        if (ts.isPropertyAccessExpression(node) && isTainted(node.expression) && !controllerStoreApis.has(node.name.text)) add(node, 'dormant controller store access is restricted to its positive allowlist');
        if (ts.isElementAccessExpression(node) && isTainted(node.expression)) {
          const name = literalPropertyName(node.argumentExpression);
          if (!name || !controllerStoreApis.has(name)) add(node, 'dormant controller store access is restricted to its positive allowlist');
        }
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression) && node.expression.expression.text === 'Reflect' && node.expression.name.text === 'get' && isTainted(node.arguments[0])) {
          const name = literalPropertyName(node.arguments[1]);
          if (!name || !controllerStoreApis.has(name)) add(node, 'dormant controller store access is restricted to its positive allowlist');
        }
        ts.forEachChild(node, inspectStore);
      };
      inspectStore(sourceFile);
    }
    loadedModules.set(relative, modules);
  }
  const infected = new Set([mediator, controller]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [relative, modules] of loadedModules) {
      if (infected.has(relative.replace(/\.(?:[cm]?[jt]sx?)$/, ''))) continue;
      if (modules.some(({ name }) => resolvesDormant(name, relative, mediator) || resolvesDormant(name, relative, controller) || (name.startsWith('.') && infected.has(normalized(path.normalize(path.join(path.dirname(relative), canonicalModuleSpecifier(name)))).replace(/\.(?:[cm]?[jt]sx?)$/, ''))))) { infected.add(relative.replace(/\.(?:[cm]?[jt]sx?)$/, '')); changed = true; }
    }
  }
  for (const [relative, modules] of loadedModules) {
    const moduleName = relative.replace(/\.(?:[cm]?[jt]sx?)$/, '');
    if ((moduleName === mediator && modules.some(({ name }) => resolvesDormant(name, relative, controller)) || moduleName === controller && modules.some(({ name }) => resolvesDormant(name, relative, mediator)))) {
      for (const { node, name } of modules) if (resolvesDormant(name, relative, moduleName === mediator ? controller : mediator)) addPolicyViolation(violations, relative, fs.readFileSync(path.join(sourceDirectory, relative), 'utf8'), node, 'sas-grant-mediator and the dormant controller may not import each other');
    }
    if (relative === 'matrix/sas-grant-mediator.ts' || relative === 'matrix/sas-authorization-flow-controller.ts') continue;
    if (!infected.has(relative.replace(/\.(?:[cm]?[jt]sx?)$/, ''))) continue;
    for (const { node } of modules) addPolicyViolation(violations, relative, fs.readFileSync(path.join(sourceDirectory, relative), 'utf8'), node, 'sas-grant-mediator and the dormant controller may not be loaded by production source');
  }
  if (stableDeclarations !== 1 || stableReferences !== 0) violations.push(`matrix/internal/sdk.ts: stable binding test seam must have exactly one exported declaration and no production references`);
  if (startupPreparationDeclarations !== 1 || startupPreparationReferences !== 0) violations.push(`auth/session-store.ts: startup SAS preparation must have exactly one declaration and no production consumers`);
  if (atomicStartupPreparations !== 1) violations.push(`auth/session-store.ts: startup SAS preparation must use exactly one atomic authorization/session/locator transaction and never touch sasOperations`);
  if (production.some(file => normalized(path.relative(sourceDirectory, file)) === 'matrix/sas-authorization-flow-controller.ts') && (controllerDeclarations !== 1 || controllerReferences !== 0)) violations.push(`matrix/sas-authorization-flow-controller.ts: dormant controller must have exactly one exported declaration and no production consumers`);
  return violations;
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const violations = checkProductionSourcePolicy();
  if (violations.length) { console.error(violations.join('\n')); process.exitCode = 1; }
}
