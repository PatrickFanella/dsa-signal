import { createDecipheriv, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Pool } from 'pg';
import type { PoolClient } from 'pg';
import type { Config } from './config.js';
import { validateDid } from './entitlements/claims.js';

const migrations = ['0002_identity_control_plane', '0003_entitlement_session_binding', '0004_mas_upstream_oidc', '0005_access_revocation_foundation', '0006_access_revocation_enforcement', '0007_access_revocation_source_set_guard', '0008_access_revocation_local_enforcement_fix', '0009_access_revocation_reconciliation_fix', '0010_access_revocation_worker'] as const;
const immutableMigrationChecksums: Readonly<Partial<Record<(typeof migrations)[number], string>>> = {
  '0002_identity_control_plane': '176cacc0b4a0972421bda9335e3b10ce8cfbb1b50d68147d3c076aca780bdb04',
  '0003_entitlement_session_binding': '32e021c6cd07d9aad2e7a2a64fcebabf16724cfcc3dfc77c7d2b1a0c68995faf',
  '0004_mas_upstream_oidc': 'bc44318b770e09f909243dd91732638a610f3fdf876e69b2b4f8f4a60d5bcc7a',
  '0005_access_revocation_foundation': 'c6e012af98b2c7316937e9943dd7a50a2fe81bff2ed489c60bd1970e901a7153',
  '0006_access_revocation_enforcement': 'e284fdd6b1b1649936ecba25095a964e15c47036c05cde686e2ca9861e04c91e',
  '0007_access_revocation_source_set_guard': '5ae58b678817c16c6b52474fab300e58776316fe312f33353eb73cf1a4d432ba',
  '0008_access_revocation_local_enforcement_fix': 'aa05e9af63c1bde4fe97f7b48751b630c7a63ff3014deeb62ef9ad9cdb1fe87f',
  '0009_access_revocation_reconciliation_fix': '56a7444e0c95df564d9bfe957a9a30e29b518df6b807db5b8817ea8715e50559',
  '0010_access_revocation_worker': '934a72f909b87c4ced1744f4b6402deb78383bab233c863e59138f5db5f52b56',
};
export const OIDC_MAINTENANCE_LOCK = 8_004;
export const acquireRuntimeWriteFence = async (client: Readonly<{ query(sql: string, values?: readonly unknown[]): Promise<unknown> }>): Promise<void> => {
  await client.query('SELECT pg_advisory_xact_lock_shared($1)', [OIDC_MAINTENANCE_LOCK]);
};
const catalogNames = ['0003-pre.json', '0004-post.json', '0005-post.json', '0006-post.json', '0007-post.json', '0008-post.json', '0009-post.json', '0010-post.json'] as const;
type CatalogName = (typeof catalogNames)[number];
export const LATEST_CONTROL_PLANE_CATALOG = '0010-post.json' satisfies CatalogName;
type CatalogValue = string | number | boolean | null | readonly string[];
type CatalogTuple = readonly CatalogValue[];
export type CatalogManifest = Readonly<{
  version: string;
  postgres: 17;
  schemas: readonly string[];
  schemaOwners: readonly CatalogTuple[];
  forbiddenSchemas?: readonly string[];
  relations: readonly CatalogTuple[];
  columns: readonly CatalogTuple[];
  constraints: readonly CatalogTuple[];
  indexes: readonly CatalogTuple[];
  triggers: readonly CatalogTuple[];
  functions: readonly CatalogTuple[];
  types: readonly CatalogTuple[];
  policies: readonly CatalogTuple[];
  acl: readonly CatalogTuple[];
  columnAcl: readonly CatalogTuple[];
  defaultAcl: readonly CatalogTuple[];
}>;
type CatalogRoles = Readonly<{ owner: string; runtime: string; retention: string; claimant: string }>;

async function readCatalogManifest(name: CatalogName): Promise<CatalogManifest> {
  if (!catalogNames.includes(name)) throw new Error(`Unknown catalog manifest ${name}`);
  const here = dirname(fileURLToPath(import.meta.url));
  for (const path of [resolve(here, `migrations/catalog/${name}`), resolve(here, `catalog/${name}`), resolve(here, `../../migrations/catalog/${name}`), resolve(here, `../migrations/catalog/${name}`)]) {
    try {
      return JSON.parse(await readFile(path, 'utf8')) as CatalogManifest;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  throw new Error(`Catalog manifest ${name} is unavailable`);
}

const sortTuples = (rows: readonly CatalogTuple[]): CatalogTuple[] => [...rows].sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
const symbolicRole = (role: string, roles: CatalogRoles): string => role === roles.owner ? '$owner' : role === roles.runtime ? '$runtime' : role === roles.retention ? '$retention' : role === roles.claimant ? '$claimant' : role === 'PUBLIC' ? 'PUBLIC' : `role:${role}`;
const normalizeConfig = (value: string[] | null): readonly string[] => value ? [...value] : [];

/** Captures the complete auditable PostgreSQL catalog boundary used by the checked-in manifests. */
export async function captureCatalogManifest(client: PoolClient, version: string, schemas: readonly string[], forbiddenSchemas: readonly string[], roles: CatalogRoles): Promise<CatalogManifest> {
  const server = await client.query<{ major: number }>('SELECT current_setting(\'server_version_num\')::int / 10000 AS major');
  if (server.rows[0]?.major !== 17) throw new Error('Catalog assertions require PostgreSQL 17');
  const params = [[...schemas]];
  const schemaRows = await client.query<{ schema: string; owner: string }>("SELECT n.nspname schema,r.rolname owner FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname=ANY($1) ORDER BY 1", params);
  const relationRows = await client.query<{ schema: string; name: string; kind: string; persistence: string; rls: boolean; force_rls: boolean; owner: string }>("SELECT n.nspname schema,c.relname name,c.relkind::text kind,c.relpersistence::text persistence,c.relrowsecurity rls,c.relforcerowsecurity force_rls,r.rolname owner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname=ANY($1) AND c.relkind IN ('r','p','v','m','f','S') ORDER BY 1,2", params);
  const columnRows = await client.query<{ schema: string; relation: string; position: number; name: string; type: string; not_null: boolean; default: string | null }>("SELECT n.nspname schema,c.relname relation,a.attnum::int position,a.attname name,pg_catalog.format_type(a.atttypid,a.atttypmod) type,a.attnotnull not_null,pg_catalog.pg_get_expr(d.adbin,d.adrelid) default FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname=ANY($1) AND c.relkind IN ('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped ORDER BY 1,2,3", params);
  const constraintRows = await client.query<{ schema: string; relation: string; name: string; type: string; deferred: boolean; initially_deferred: boolean; validated: boolean; definition: string }>("SELECT n.nspname schema,c.relname relation,x.conname name,x.contype::text type,x.condeferrable deferred,x.condeferred initially_deferred,x.convalidated validated,pg_catalog.pg_get_constraintdef(x.oid,true) definition FROM pg_catalog.pg_constraint x JOIN pg_catalog.pg_class c ON c.oid=x.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($1) ORDER BY 1,2,3", params);
  const indexRows = await client.query<{ schema: string; relation: string; name: string; unique: boolean; primary: boolean; valid: boolean; ready: boolean; definition: string; predicate: string | null }>("SELECT n.nspname schema,t.relname relation,i.relname name,x.indisunique unique,x.indisprimary primary,x.indisvalid valid,x.indisready ready,pg_catalog.pg_get_indexdef(i.oid) definition,pg_catalog.pg_get_expr(x.indpred,x.indrelid) predicate FROM pg_catalog.pg_index x JOIN pg_catalog.pg_class i ON i.oid=x.indexrelid JOIN pg_catalog.pg_class t ON t.oid=x.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=ANY($1) ORDER BY 1,2,3", params);
  const triggerRows = await client.query<{ schema: string; relation: string; name: string; enabled: string; definition: string }>("SELECT n.nspname schema,c.relname relation,t.tgname name,t.tgenabled::text enabled,pg_catalog.pg_get_triggerdef(t.oid,true) definition FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($1) AND NOT t.tgisinternal ORDER BY 1,2,3", params);
  const functionRows = await client.query<{ schema: string; name: string; args: string; result: string; language: string; volatility: string; security_definer: boolean; strict: boolean; parallel: string; config: string[] | null; source: string; owner: string }>("SELECT n.nspname schema,p.proname name,pg_catalog.pg_get_function_identity_arguments(p.oid) args,pg_catalog.pg_get_function_result(p.oid) result,l.lanname language,p.provolatile::text volatility,p.prosecdef security_definer,p.proisstrict strict,p.proparallel::text parallel,p.proconfig config,p.prosrc source,r.rolname owner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_roles r ON r.oid=p.proowner WHERE n.nspname=ANY($1) ORDER BY 1,2,3", params);
  const typeRows = await client.query<{ schema: string; name: string; type: string; category: string; not_null: boolean; base: string; default: string | null; owner: string }>("SELECT n.nspname schema,t.typname name,t.typtype::text type,t.typcategory::text category,t.typnotnull not_null,CASE WHEN t.typbasetype=0 THEN '-' ELSE pg_catalog.format_type(t.typbasetype,t.typtypmod) END base,t.typdefault default,r.rolname owner FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace JOIN pg_catalog.pg_roles r ON r.oid=t.typowner WHERE n.nspname=ANY($1) AND t.typrelid=0 AND t.typelem=0 AND t.typname NOT LIKE '\\_%' ESCAPE '\\' ORDER BY 1,2", params);
  const policyRows = await client.query<{ schema: string; relation: string; name: string; permissive: boolean; roles: string[]; command: string; using: string | null; check: string | null }>("SELECT n.nspname schema,c.relname relation,p.polname name,p.polpermissive permissive,ARRAY(SELECT coalesce(r.rolname,'PUBLIC')::text FROM unnest(p.polroles) role_oid LEFT JOIN pg_catalog.pg_roles r ON r.oid=role_oid ORDER BY 1)::text[] roles,p.polcmd::text command,pg_catalog.pg_get_expr(p.polqual,p.polrelid) using,pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) check FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($1) ORDER BY 1,2,3", params);
  const aclRows = await client.query<{ kind: string; schema: string; object: string; grantee: string; grantor: string; privilege: string; grantable: boolean }>(`WITH entries AS (
    SELECT 'schema' kind,n.nspname schema,n.nspname object,n.nspowner owner,e.* FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) e WHERE n.nspname=ANY($1)
    UNION ALL SELECT CASE WHEN c.relkind='S' THEN 'sequence' ELSE 'relation' END,n.nspname,c.relname,c.relowner,e.* FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) e WHERE n.nspname=ANY($1) AND c.relkind IN ('r','p','v','m','f','S')
    UNION ALL SELECT 'function',n.nspname,p.proname||'('||pg_catalog.pg_get_function_identity_arguments(p.oid)||')',p.proowner,e.* FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) e WHERE n.nspname=ANY($1)
  ) SELECT x.kind,x.schema,x.object,coalesce(g.rolname,'PUBLIC') grantee,coalesce(o.rolname,'PUBLIC') grantor,x.privilege_type privilege,x.is_grantable grantable FROM entries x LEFT JOIN pg_catalog.pg_roles g ON g.oid=x.grantee LEFT JOIN pg_catalog.pg_roles o ON o.oid=x.grantor WHERE x.grantee<>x.owner ORDER BY 1,2,3,4,6`, params);
  const columnAclRows = await client.query<{ schema: string; relation: string; column: string; grantee: string; grantor: string; privilege: string; grantable: boolean }>("SELECT n.nspname schema,c.relname relation,a.attname column,coalesce(g.rolname,'PUBLIC') grantee,coalesce(o.rolname,'PUBLIC') grantor,e.privilege_type privilege,e.is_grantable grantable FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) e LEFT JOIN pg_catalog.pg_roles g ON g.oid=e.grantee LEFT JOIN pg_catalog.pg_roles o ON o.oid=e.grantor WHERE n.nspname=ANY($1) AND a.attnum>0 AND NOT a.attisdropped ORDER BY 1,2,3,4,6", params);
  const defaultAclRows = await client.query<{ schema: string; object_type: string; owner: string; grantee: string; grantor: string; privilege: string; grantable: boolean }>("SELECT coalesce(n.nspname,'<global>') schema,d.defaclobjtype::text object_type,owner.rolname owner,coalesce(g.rolname,'PUBLIC') grantee,coalesce(o.rolname,'PUBLIC') grantor,e.privilege_type privilege,e.is_grantable grantable FROM pg_catalog.pg_default_acl d LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace JOIN pg_catalog.pg_roles owner ON owner.oid=d.defaclrole CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) e LEFT JOIN pg_catalog.pg_roles g ON g.oid=e.grantee LEFT JOIN pg_catalog.pg_roles o ON o.oid=e.grantor WHERE d.defaclnamespace=0 OR n.nspname=ANY($1) ORDER BY 1,2,3,4,6", params);
  return {
    version,
    postgres: 17,
    schemas: [...schemas],
    schemaOwners: sortTuples(schemaRows.rows.map((row) => [row.schema, symbolicRole(row.owner, roles)])),
    ...(forbiddenSchemas.length ? { forbiddenSchemas: [...forbiddenSchemas] } : {}),
    relations: sortTuples(relationRows.rows.map((row) => [row.schema, row.name, row.kind, row.persistence, row.rls, row.force_rls, symbolicRole(row.owner, roles)])),
    columns: sortTuples(columnRows.rows.map((row) => [row.schema, row.relation, row.position, row.name, row.type, row.not_null, row.default])),
    constraints: sortTuples(constraintRows.rows.map((row) => [row.schema, row.relation, row.name, row.type, row.deferred, row.initially_deferred, row.validated, row.definition])),
    indexes: sortTuples(indexRows.rows.map((row) => [row.schema, row.relation, row.name, row.unique, row.primary, row.valid, row.ready, row.definition, row.predicate])),
    triggers: sortTuples(triggerRows.rows.map((row) => [row.schema, row.relation, row.name, row.enabled, row.definition])),
    functions: sortTuples(functionRows.rows.map((row) => [row.schema, row.name, row.args, row.result, row.language, row.volatility, row.security_definer, row.strict, row.parallel, normalizeConfig(row.config), row.source, symbolicRole(row.owner, roles)])),
    types: sortTuples(typeRows.rows.map((row) => [row.schema, row.name, row.type, row.category, row.not_null, row.base, row.default, symbolicRole(row.owner, roles)])),
    policies: sortTuples(policyRows.rows.map((row) => [row.schema, row.relation, row.name, row.permissive, row.roles.map((role) => symbolicRole(role, roles)), row.command, row.using, row.check])),
    acl: sortTuples(aclRows.rows.map((row) => [row.kind, row.schema, row.object, symbolicRole(row.grantee, roles), symbolicRole(row.grantor, roles), row.privilege, row.grantable])),
    columnAcl: sortTuples(columnAclRows.rows.map((row) => [row.schema, row.relation, row.column, symbolicRole(row.grantee, roles), symbolicRole(row.grantor, roles), row.privilege, row.grantable])),
    defaultAcl: sortTuples(defaultAclRows.rows.map((row) => [row.schema, row.object_type, symbolicRole(row.owner, roles), symbolicRole(row.grantee, roles), symbolicRole(row.grantor, roles), row.privilege, row.grantable])),
  };
}

const manifestFields = ['schemas', 'schemaOwners', 'relations', 'columns', 'constraints', 'indexes', 'triggers', 'functions', 'types', 'policies', 'acl', 'columnAcl', 'defaultAcl'] as const;
const firstDifference = (actual: unknown, expected: unknown): string => {
  const left = JSON.stringify(actual); const right = JSON.stringify(expected);
  if (left === right) return '';
  const actualRows = Array.isArray(actual) ? actual : [actual]; const expectedRows = Array.isArray(expected) ? expected : [expected];
  const index = actualRows.findIndex((row, offset) => JSON.stringify(row) !== JSON.stringify(expectedRows[offset]));
  return `${actualRows.length}/${expectedRows.length} at ${index}: ${JSON.stringify(actualRows[index])} != ${JSON.stringify(expectedRows[index])}`;
};

export async function assertCatalogManifest(client: PoolClient, runtimeRole: string, retentionRole: string, name: CatalogName, claimantRole: string): Promise<void> {
  const expected = await readCatalogManifest(name);
  const owner = (await client.query<{ owner: string }>("SELECT r.rolname owner FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner WHERE n.nspname='control_plane'")).rows[0]?.owner;
  if (!owner) throw new Error(`Control-plane catalog drift: manifest ${expected.version} owner unavailable`);
  const actual = await captureCatalogManifest(client, expected.version, expected.schemas, expected.forbiddenSchemas ?? [], { owner, runtime: runtimeRole, retention: retentionRole, claimant: claimantRole });
  for (const schema of expected.forbiddenSchemas ?? []) {
    if ((await client.query<{ exists: boolean }>('SELECT to_regnamespace($1) IS NOT NULL AS exists', [schema])).rows[0]!.exists) throw new Error(`Control-plane catalog drift: manifest ${expected.version} forbidden schema ${schema}`);
  }
  for (const field of manifestFields) {
    const difference = firstDifference(actual[field], expected[field]);
    if (difference) throw new Error(`Control-plane catalog drift: manifest ${expected.version} ${field} ${difference}`);
  }
  const privacy = await client.query<{ relation: string; column: string; type: string }>("SELECT n.nspname||'.'||c.relname relation,a.attname column,pg_catalog.format_type(a.atttypid,a.atttypmod) type FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid WHERE n.nspname=ANY($1) AND c.relkind IN ('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped", [[...expected.schemas]]);
  if (privacy.rows.some((row) => /jsonb?/i.test(row.type) || (!/(?:_fingerprint|_key_id|_id|_expires_at)$/.test(row.column) && row.column !== 'error_code' && row.column !== 'blocked_code' && row.column !== 'lease_token' && /(^|_)(payload|credential|refresh_token|matrix_token|body|code|token|secret|jwk|signature|plaintext|roster|message|room_state)($|_)/i.test(row.column)))) throw new Error(`Control-plane catalog drift: manifest ${expected.version} prohibited column or type`);
}

export function createRuntimePool(config: Pick<Config, 'DATABASE_URL'>): Pool {
  return new Pool({ connectionString: config.DATABASE_URL, statement_timeout: 15_000, lock_timeout: 10_000, idle_in_transaction_session_timeout: 15_000, query_timeout: 20_000 });
}
const quoteIdent = (value: string): string => {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(value)) throw new Error('Invalid runtime role');
  return `"${value}"`;
};
async function readMigrationSource(id: string): Promise<string> {
  const here = dirname(fileURLToPath(import.meta.url));
  if (!migrations.includes(id as typeof migrations[number])) throw new Error('Unknown migration');
  for (const path of [resolve(here, `migrations/${id}.sql`), resolve(here, `../../migrations/${id}.sql`), resolve(here, `../migrations/${id}.sql`)]) {
    try { return await readFile(path, 'utf8'); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  throw new Error('Control-plane migration source is unavailable');
}

/** Returns the immutable expected checksum for a checked-in control-plane migration. */
export async function expectedControlPlaneMigrationChecksum(id: (typeof migrations)[number]): Promise<Buffer> {
  const result = createHash('sha256').update(await readMigrationSource(id)).digest();
  const immutable = immutableMigrationChecksums[id];
  if (immutable && result.toString('hex') !== immutable) throw new Error('Immutable migration source changed');
  return result;
}

async function installCatalogAcls(client: PoolClient, runtimeRole: string, retentionRole: string): Promise<void> {
  const runtime = quoteIdent(runtimeRole); const retention = quoteIdent(retentionRole);
  await client.query(`REVOKE ALL ON SCHEMA control_plane FROM PUBLIC, ${runtime}, ${retention}`);
  await client.query(`REVOKE ALL ON ALL TABLES IN SCHEMA control_plane FROM PUBLIC, ${runtime}, ${retention}`);
  await client.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_plane FROM PUBLIC, ${runtime}, ${retention}`);
  await client.query(`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_plane FROM PUBLIC, ${runtime}, ${retention}`);
  await client.query(`GRANT USAGE ON SCHEMA control_plane TO ${runtime}, ${retention}`);
  const foundationExists = (await client.query<{ exists: boolean }>("SELECT to_regclass('control_plane.membership_access_states') IS NOT NULL AS exists")).rows[0]!.exists;
  await client.query(`GRANT SELECT, INSERT ON control_plane.encrypted_envelopes, control_plane.did_mappings, control_plane.login_states, control_plane.identity_sessions, control_plane.proof_challenges, control_plane.policy_snapshots, control_plane.active_policy, control_plane.jti_uses, control_plane.jti_key_aliases, control_plane.idempotency_results, control_plane.idempotency_key_aliases, control_plane.entitlements${foundationExists ? ', control_plane.entitlement_evidence_aliases, control_plane.membership_access_states' : ''} TO ${runtime}`);
  await client.query(`GRANT UPDATE ON control_plane.login_states, control_plane.identity_sessions, control_plane.proof_challenges, control_plane.active_policy, control_plane.entitlements${foundationExists ? ', control_plane.membership_access_states' : ''} TO ${runtime}`);
  if (foundationExists) {
    await client.query(`GRANT UPDATE, DELETE ON control_plane.entitlement_evidence_aliases TO ${runtime}`);
    await client.query(`GRANT SELECT ON control_plane.revocation_evidence_key_ids, control_plane.membership_access_source_selector_aliases, control_plane.membership_access_source_cause_aliases TO ${runtime}`);
    await client.query(`GRANT EXECUTE ON FUNCTION control_plane.replace_entitlement_evidence_aliases(uuid,jsonb) TO ${runtime}`);
    await client.query(`GRANT EXECUTE ON FUNCTION control_plane.membership_access_source_set_fence(boolean) TO ${runtime}`);
    if ((await client.query<{ exists: boolean }>("SELECT to_regprocedure('control_plane.enforce_published_source_target(uuid,uuid)') IS NOT NULL AS exists")).rows[0]!.exists) await client.query(`GRANT EXECUTE ON FUNCTION control_plane.enforce_published_source_target(uuid,uuid) TO ${runtime}`);
  }
  await client.query(`GRANT INSERT ON control_plane.security_audit_events TO ${runtime}`);
  await client.query(`GRANT EXECUTE ON FUNCTION control_plane.is_canonical_origin(text) TO ${runtime}`);
  await client.query(`GRANT EXECUTE ON FUNCTION control_plane.cleanup_expired(timestamptz) TO ${retention}`);
  if ((await client.query<{ exists: boolean }>("SELECT to_regnamespace('oidc') IS NOT NULL AS exists")).rows[0]!.exists) {
    await client.query(`REVOKE ALL ON SCHEMA oidc FROM PUBLIC, ${runtime}, ${retention}`);
    await client.query(`REVOKE ALL ON ALL TABLES IN SCHEMA oidc FROM PUBLIC, ${runtime}, ${retention}`);
    await client.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA oidc FROM PUBLIC, ${runtime}, ${retention}`);
    await client.query(`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA oidc FROM PUBLIC, ${runtime}, ${retention}`);
    await client.query(`GRANT USAGE ON SCHEMA oidc TO ${runtime}, ${retention}`);
    await client.query(`GRANT SELECT, INSERT, UPDATE ON oidc.provider_artifacts, oidc.authorization_contexts, oidc.interaction_csrf TO ${runtime}`);
    await client.query(`GRANT EXECUTE ON FUNCTION oidc.cleanup_expired(timestamptz) TO ${retention}`);
  }
}

export async function applyControlPlaneMigration(pool: Pool, runtimeRole: string, retentionRole: string, sql: string | undefined, revocationRole: string, evidenceKeyIds: readonly string[]): Promise<void> {
  if (evidenceKeyIds.length === 0 || new Set(evidenceKeyIds).size !== evidenceKeyIds.length) throw new Error('Configured revocation evidence keys are required');
  quoteIdent(runtimeRole); quoteIdent(retentionRole); quoteIdent(revocationRole);
  if (evidenceKeyIds.some((keyId) => !/^[a-z][a-z0-9_-]{0,31}$/.test(keyId))) throw new Error('Invalid revocation evidence key id');
  if (runtimeRole === retentionRole || revocationRole === runtimeRole || revocationRole === retentionRole) throw new Error('Runtime, retention, and revocation roles must differ');
  const client = await pool.connect(); let releaseError: Error | undefined; let commitAttempted = false;
  try {
    await client.query('BEGIN'); await client.query("SET LOCAL search_path = pg_catalog, public"); await client.query('SELECT pg_advisory_xact_lock($1)', [8_002]); await client.query('SELECT pg_advisory_xact_lock($1)', [OIDC_MAINTENANCE_LOCK]);
    const roleNames = [runtimeRole, retentionRole, revocationRole]; const roles = await client.query<{ rolname: string; owns: boolean; rolsuper: boolean; rolbypassrls: boolean; rolcanlogin: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolreplication: boolean; membership_edge: boolean }>("SELECT r.rolname,r.rolsuper,r.rolbypassrls,r.rolcanlogin,r.rolcreaterole,r.rolcreatedb,r.rolreplication,(EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner=r.oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspowner=r.oid AND n.nspname IN ('control_plane','oidc')) OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner=r.oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_type t WHERE t.typowner=r.oid)) AS owns,EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid) AS membership_edge FROM pg_catalog.pg_roles r WHERE r.rolname=ANY($1)", [roleNames]);
    const currentUser = (await client.query<{ current_user: string }>('SELECT current_user')).rows[0]!.current_user;
    if (roles.rowCount !== roleNames.length || roles.rows.some((item) => item.owns || item.rolsuper || item.rolbypassrls || !item.rolcanlogin || item.rolcreaterole || item.rolcreatedb || item.rolreplication || item.membership_edge) || roleNames.includes(currentUser)) throw new Error('Invalid control-plane role separation');
    const ledgerExists = (await client.query<{ exists: boolean }>("SELECT to_regclass('control_plane.schema_migrations') IS NOT NULL AS exists")).rows[0]!.exists;
    let migrated = false;
    for (const id of migrations) {
      const source = id === '0002_identity_control_plane' && sql ? sql : await readMigrationSource(id);
      const checksum = createHash('sha256').update(source).digest();
      const immutable = immutableMigrationChecksums[id];
      if (immutable && checksum.toString('hex') !== immutable) throw new Error('Immutable migration source changed');
      const prior = ledgerExists ? await client.query<{ checksum: Buffer }>('SELECT checksum FROM control_plane.schema_migrations WHERE id=$1', [id]) : { rowCount: 0, rows: [] as { checksum: Buffer }[] };
      if (prior.rowCount && !prior.rows[0]!.checksum.equals(checksum)) throw new Error('Migration checksum mismatch');
      if (id === '0004_mas_upstream_oidc' && !prior.rowCount && ledgerExists) await assertCatalogManifest(client, runtimeRole, retentionRole, '0003-pre.json', revocationRole);
      if (id === '0004_mas_upstream_oidc' && prior.rowCount && !(await client.query<{ exists: boolean }>("SELECT EXISTS(SELECT 1 FROM control_plane.schema_migrations WHERE id='0005_access_revocation_foundation') AS exists")).rows[0]!.exists) await assertCatalogManifest(client, runtimeRole, retentionRole, '0004-post.json', revocationRole);
      if (id === '0005_access_revocation_foundation' && !prior.rowCount) { await installCatalogAcls(client, runtimeRole, retentionRole); await assertCatalogManifest(client, runtimeRole, retentionRole, '0004-post.json', revocationRole); }
      if (!prior.rowCount) { if (id === '0005_access_revocation_foundation' || id === '0010_access_revocation_worker') await client.query(`SET LOCAL control_plane.revocation_role = '${revocationRole}'`); await client.query(source); if (id === '0005_access_revocation_foundation') await client.query('INSERT INTO control_plane.revocation_evidence_key_ids(key_id,enabled) SELECT key_id,true FROM unnest($1::text[]) AS key_id', [evidenceKeyIds]); await client.query('INSERT INTO control_plane.schema_migrations(id,checksum) VALUES($1,$2)', [id, checksum]); migrated = true; }
    }
    if (!migrated) await assertCatalogManifest(client, runtimeRole, retentionRole, LATEST_CONTROL_PLANE_CATALOG, revocationRole);
    await installCatalogAcls(client, runtimeRole, retentionRole);
    await assertCatalogManifest(client, runtimeRole, retentionRole, LATEST_CONTROL_PLANE_CATALOG, revocationRole);
    commitAttempted = true;
    await client.query('COMMIT');
  } catch (error) {
    if (commitAttempted) releaseError = error instanceof Error ? error : new Error('Migration commit outcome unknown');
    else try { await client.query('ROLLBACK'); } catch (rollbackError) { releaseError = rollbackError instanceof Error ? rollbackError : new Error('Migration rollback failed'); }
    throw error;
  } finally { client.release(releaseError); }
}

/** Backward-compatible entry point now backed exclusively by the versioned JSON manifests. */
export async function assertControlPlaneCatalog(client: PoolClient, runtimeRole: string, retentionRole: string, claimantRole: string): Promise<void> {
  const latest = (await client.query<{ id: string }>('SELECT id FROM control_plane.schema_migrations ORDER BY id DESC LIMIT 1')).rows[0]?.id;
  await assertCatalogManifest(client, runtimeRole, retentionRole, latest === '0010_access_revocation_worker' ? LATEST_CONTROL_PLANE_CATALOG : latest === '0009_access_revocation_reconciliation_fix' ? '0009-post.json' : latest === '0008_access_revocation_local_enforcement_fix' ? '0008-post.json' : latest === '0007_access_revocation_source_set_guard' ? '0007-post.json' : latest === '0006_access_revocation_enforcement' ? '0006-post.json' : latest === '0005_access_revocation_foundation' ? '0005-post.json' : latest === '0004_mas_upstream_oidc' ? '0004-post.json' : '0003-pre.json', claimantRole);
}

type FingerprintKeySet = Readonly<{ active: string; retained: readonly string[] }>;
export type RetainedKeys = Readonly<{ subject: Readonly<Record<string, Uint8Array>>; envelope: Readonly<Record<string, Uint8Array>>; challenge: readonly string[]; binding: readonly string[]; jti: FingerprintKeySet; idempotency: FingerprintKeySet; request: readonly string[]; evidence: readonly string[]; oidc: Readonly<{ epoch: string; adapter: Readonly<Record<string, Uint8Array>>; index: readonly string[] }> }>;
/** Validates retained identifiers and authenticates every live encrypted envelope. */
export async function assertRetainedKeys(client: PoolClient, keys: RetainedKeys): Promise<void> {
  const envelopeIds = Object.keys(keys.envelope); const subjectIds = Object.keys(keys.subject);
  const evidenceRegistry = await client.query<{ count: number }>(`SELECT count(*)::int AS count FROM control_plane.revocation_evidence_key_ids WHERE NOT enabled OR NOT key_id=ANY($1) UNION ALL SELECT count(*)::int FROM unnest($1::text[]) configured(key_id) WHERE NOT EXISTS (SELECT 1 FROM control_plane.revocation_evidence_key_ids registry WHERE registry.key_id=configured.key_id AND registry.enabled)`, [keys.evidence]);
  if (evidenceRegistry.rows.some((row) => row.count > 0)) throw new Error('Required retained key is unavailable');
  const result = await client.query<{ count: number }>(`SELECT count(*)::int AS count FROM control_plane.did_mappings d JOIN control_plane.encrypted_envelopes e ON e.id=d.envelope_id WHERE NOT d.subject_key_id=ANY($1) OR NOT e.envelope_key_id=ANY($2) UNION ALL SELECT count(*)::int FROM control_plane.policy_snapshots p JOIN control_plane.encrypted_envelopes e ON e.id=p.envelope_id WHERE NOT e.envelope_key_id=ANY($2) UNION ALL SELECT count(*)::int FROM control_plane.login_states WHERE expires_at>clock_timestamp() AND NOT binding_key_id=ANY($4) UNION ALL SELECT count(*)::int FROM control_plane.proof_challenges WHERE expires_at>clock_timestamp() AND (NOT challenge_key_id=ANY($3) OR NOT binding_key_id=ANY($4)) UNION ALL SELECT count(*)::int FROM control_plane.identity_sessions WHERE absolute_expires_at+interval '30 seconds'>clock_timestamp() AND NOT binding_key_id=ANY($4) UNION ALL SELECT count(*)::int FROM control_plane.entitlements WHERE NOT session_binding_key_id=ANY($4) UNION ALL SELECT count(*)::int FROM control_plane.entitlement_evidence_aliases a WHERE NOT fingerprint_key_id=ANY($10) OR EXISTS (SELECT 1 FROM control_plane.revocation_evidence_key_ids k WHERE k.enabled AND NOT EXISTS (SELECT 1 FROM control_plane.entitlement_evidence_aliases x WHERE x.entitlement_id=a.entitlement_id AND x.evidence_kind=a.evidence_kind AND x.fingerprint_key_id=k.key_id)) UNION ALL SELECT count(*)::int FROM control_plane.membership_access_source_selector_aliases a WHERE NOT fingerprint_key_id=ANY($10) UNION ALL SELECT count(*)::int FROM control_plane.membership_access_source_cause_aliases a WHERE NOT fingerprint_key_id=ANY($10) UNION ALL SELECT count(*)::int FROM control_plane.idempotency_results r WHERE expires_at>clock_timestamp() AND (NOT binding_key_id=ANY($4) OR NOT request_key_id=ANY($9) OR NOT EXISTS(SELECT 1 FROM control_plane.idempotency_key_aliases a WHERE a.result_id=r.id AND a.key_id=$7) OR EXISTS(SELECT 1 FROM control_plane.idempotency_key_aliases a WHERE a.result_id=r.id AND NOT a.key_id=ANY($8))) UNION ALL SELECT count(*)::int FROM control_plane.jti_uses j WHERE retained_until>clock_timestamp() AND (NOT EXISTS(SELECT 1 FROM control_plane.jti_key_aliases a WHERE a.jti_use_id=j.id AND a.key_id=$5) OR EXISTS(SELECT 1 FROM control_plane.jti_key_aliases a WHERE a.jti_use_id=j.id AND NOT a.key_id=ANY($6)))`, [subjectIds, envelopeIds, keys.challenge, keys.binding, keys.jti.active, keys.jti.retained, keys.idempotency.active, keys.idempotency.retained, keys.request, keys.evidence]);
  if (result.rows.some((row) => row.count > 0)) throw new Error('Required retained key is unavailable');
  try {
    const envelopes = await client.query<{ parent_id: string; envelope_key_id: string; nonce: Buffer; ciphertext: Buffer; purpose: 'did' | 'policy'; sector: string | null; version: string | null; subject_key_id: string | null; subject: string | null }>(`SELECT d.id AS parent_id,e.envelope_key_id,e.nonce,e.ciphertext,e.purpose,d.sector,NULL::text AS version,d.subject_key_id,d.subject FROM control_plane.did_mappings d JOIN control_plane.encrypted_envelopes e ON e.id=d.envelope_id UNION ALL SELECT p.id AS parent_id,e.envelope_key_id,e.nonce,e.ciphertext,e.purpose,NULL,p.version,NULL::text,NULL::text FROM control_plane.policy_snapshots p JOIN control_plane.encrypted_envelopes e ON e.id=p.envelope_id`);
    for (const row of envelopes.rows) {
      const key = keys.envelope[row.envelope_key_id]; if (!key || key.length !== 32) throw new Error('invalid retained envelope');
      const keyCopy = Buffer.from(key); const ciphertext = Buffer.from(row.ciphertext.subarray(0, -16)); const tag = Buffer.from(row.ciphertext.subarray(-16)); const associated = Buffer.from(row.purpose === 'did' ? `dsa-signal-did-mapping:v1\0${row.parent_id}\0${row.sector}` : `dsa-signal-policy-snapshot:v1\0${row.parent_id}\0${row.version}`); let plaintext: Buffer | undefined;
      try {
        const decipher = createDecipheriv('aes-256-gcm', keyCopy, row.nonce); decipher.setAAD(associated); decipher.setAuthTag(tag); plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        if (row.purpose === 'did') {
          const did = plaintext.toString('utf8'); const subjectKey = row.subject_key_id && keys.subject[row.subject_key_id];
          if (!row.sector || !row.subject || !subjectKey || subjectKey.length !== 32 || !validateDid(did)) throw new Error('invalid retained mapping');
          const subjectCopy = Buffer.from(subjectKey); let actual: Buffer | undefined;
          try { actual = createHmac('sha256', subjectCopy).update('dsa-signal-subject:v1\0').update(row.sector).update('\0').update(did).digest(); const expected = Buffer.from(row.subject, 'base64url'); try { if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new Error('subject mismatch'); } finally { expected.fill(0); } } finally { subjectCopy.fill(0); actual?.fill(0); }
        }
      } finally { keyCopy.fill(0); ciphertext.fill(0); tag.fill(0); associated.fill(0); plaintext?.fill(0); }
    }
    const oidcAdapterIds = Object.keys(keys.oidc.adapter);
    const oidcReferences = await client.query<{ count: number }>(`SELECT count(*)::int count FROM control_plane.entitlements WHERE oidc_epoch<>$1
      UNION ALL SELECT count(*)::int FROM oidc.provider_artifacts WHERE epoch<>$1 OR NOT cipher_key_id=ANY($2) OR NOT artifact_key_id=ANY($3) OR (session_uid_key_id IS NOT NULL AND NOT session_uid_key_id=ANY($3)) OR (grant_key_id IS NOT NULL AND NOT grant_key_id=ANY($3))
      UNION ALL SELECT count(*)::int FROM oidc.authorization_contexts WHERE epoch<>$1 OR NOT client_key_id=ANY($3) OR NOT grant_key_id=ANY($3) OR NOT interaction_chain_key_id=ANY($3) OR NOT interaction_uid_key_id=ANY($3) OR (provider_session_uid_key_id IS NOT NULL AND NOT provider_session_uid_key_id=ANY($3)) OR (authorization_code_key_id IS NOT NULL AND NOT authorization_code_key_id=ANY($3)) OR NOT control_session_key_id=ANY($4)
      UNION ALL SELECT count(*)::int FROM oidc.interaction_csrf WHERE epoch<>$1 OR NOT csrf_key_id=ANY($3) OR NOT client_key_id=ANY($3) OR NOT interaction_chain_key_id=ANY($3) OR NOT interaction_uid_key_id=ANY($3)`, [keys.oidc.epoch, oidcAdapterIds, keys.oidc.index, keys.binding]);
    if (oidcReferences.rows.some((row) => row.count > 0)) throw new Error('invalid OIDC retained reference');
    const oidcArtifacts = await client.query<{ id: string; epoch: string; model: string; artifact_fingerprint: Buffer; cipher_key_id: string; nonce: Buffer; ciphertext: Buffer }>('SELECT id,epoch,model,artifact_fingerprint,cipher_key_id,nonce,ciphertext FROM oidc.provider_artifacts');
    for (const row of oidcArtifacts.rows) {
      const source = keys.oidc.adapter[row.cipher_key_id];
      if (!source || source.length !== 32 || row.epoch !== keys.oidc.epoch) throw new Error('invalid OIDC retained artifact');
      const key = Buffer.from(source); const encrypted = Buffer.from(row.ciphertext.subarray(0, -16)); const tag = Buffer.from(row.ciphertext.subarray(-16)); const aad = Buffer.from(`dsa-signal-oidc-adapter:v1\0${row.id}\0${row.model}\0${row.artifact_fingerprint.toString('base64url')}\0${row.epoch}`); let plain: Buffer | undefined;
      try { const decipher = createDecipheriv('aes-256-gcm', key, row.nonce); decipher.setAAD(aad); decipher.setAuthTag(tag); plain = Buffer.concat([decipher.update(encrypted), decipher.final()]); const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain)); if (!value || typeof value !== 'object' || Array.isArray(value) || plain.length > 32_768) throw new Error('invalid OIDC retained payload'); }
      finally { key.fill(0); encrypted.fill(0); tag.fill(0); aad.fill(0); plain?.fill(0); }
    }
  } catch { throw new Error('Required retained key is unavailable'); }
}
