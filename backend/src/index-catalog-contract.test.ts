import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const indexUrl = new URL('./index.ts', import.meta.url);

async function indexSource(): Promise<ts.SourceFile> {
  return ts.createSourceFile(indexUrl.pathname, await readFile(indexUrl, 'utf8'), ts.ScriptTarget.Latest, true);
}

function isProcessEnvironmentAccess(node: ts.Expression, name: string): boolean {
  return ts.isPropertyAccessExpression(node)
    && node.name.text === name
    && ts.isPropertyAccessExpression(node.expression)
    && node.expression.name.text === 'env'
    && ts.isIdentifier(node.expression.expression)
    && node.expression.expression.text === 'process';
}

describe('startup catalog contract', () => {
  it('does not query migration ledger state from the runtime startup role', async () => {
    const source = await indexSource();
    expect(source.getFullText()).not.toContain('schema_migrations');
  });

  it('does not import or call migration checksum validation', async () => {
    const source = await indexSource();
    const checksumImports: ts.ImportSpecifier[] = [];
    const checksumCalls: ts.CallExpression[] = [];
    const visit = (node: ts.Node): void => {
      if (ts.isImportSpecifier(node) && (node.name.text === 'expectedControlPlaneMigrationChecksum' || node.propertyName?.text === 'expectedControlPlaneMigrationChecksum')) checksumImports.push(node);
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'expectedControlPlaneMigrationChecksum') checksumCalls.push(node);
      ts.forEachChild(node, visit);
    };
    visit(source);

    expect(checksumImports).toEqual([]);
    expect(checksumCalls).toEqual([]);
  });

  it('uses the current allowlisted catalog and configured revocation claimant without executing startup', async () => {
    const source = await indexSource();
    const dbImport = source.statements.find((statement): statement is ts.ImportDeclaration => ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier) && statement.moduleSpecifier.text === './db.js');
    const importedCatalog = dbImport?.importClause?.namedBindings && ts.isNamedImports(dbImport.importClause.namedBindings)
      && dbImport.importClause.namedBindings.elements.some(specifier => specifier.name.text === 'LATEST_CONTROL_PLANE_CATALOG');
    expect(importedCatalog).toBe(true);

    const revocationDeclaration = source.statements.find((statement): statement is ts.VariableStatement => ts.isVariableStatement(statement) && statement.declarationList.declarations.some(declaration => ts.isIdentifier(declaration.name) && declaration.name.text === 'revocationRole' && declaration.initializer && isProcessEnvironmentAccess(declaration.initializer, 'CONTROL_PLANE_REVOCATION_ROLE')));
    expect(revocationDeclaration).toBeDefined();

    const catalogAssertions: ts.CallExpression[] = [];
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'assertCatalogManifest') catalogAssertions.push(node);
      ts.forEachChild(node, visit);
    };
    visit(source);
    expect(catalogAssertions.some(call => call.arguments[3]?.kind === ts.SyntaxKind.Identifier && (call.arguments[3] as ts.Identifier).text === 'LATEST_CONTROL_PLANE_CATALOG' && call.arguments[4]?.kind === ts.SyntaxKind.Identifier && (call.arguments[4] as ts.Identifier).text === 'revocationRole')).toBe(true);

    const historicalCatalogs: string[] = [];
    const findHistoricalCatalogs = (node: ts.Node): void => {
      if (ts.isStringLiteral(node) && /^000[3-9]-post\.json$/.test(node.text)) historicalCatalogs.push(node.text);
      ts.forEachChild(node, findHistoricalCatalogs);
    };
    findHistoricalCatalogs(source);
    expect(historicalCatalogs).toEqual([]);
  });
});
