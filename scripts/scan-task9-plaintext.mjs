/** Bounded, secret-safe scanners used only to create local Task 9 evidence. */
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, opendir, open, realpath } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

const digest = value => createHash('sha256').update(value).digest('hex');
const surfaces = ['capture', 'synapsePostgres', 'controlPostgres', 'logs', 'media'];
const types = ['text', 'varchar', 'citext', 'json', 'jsonb', 'bytea'];
// These are the long-lived, owned services in the locked Task 7 full profile.
export const OWNED_G2_LOG_SERVICES = Object.freeze(['control-db', 'matrix-db', 'migrate', 'api', 'web', 'synapse', 'synapse-data-init', 'mas', 'mas-ready', 'mas-migrate', 'gateway', 'gateway-ca-export']);
const authorities = new WeakSet();
const controlData = new WeakMap();
const runs = new WeakMap();
const dedicatedClients = new WeakSet();
const postgresSessions = new WeakMap();
const LIMITS = { bytes: 4 * 1024 * 1024, logBytes: 4 * 1024 * 1024, files: 1000, dirs: 1000, captureEntries: 1000, catalogColumns: 1000, chunkBytes: 64 * 1024 };
const safeIdentifier = value => typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(value);
const bounded = (value, limit) => { if (!(typeof value === 'string' || Buffer.isBuffer(value))) throw new Error('scan body must be a string or Buffer'); const length = Buffer.isBuffer(value) ? value.length : Buffer.byteLength(value, 'utf8'); if (length > limit) throw new Error('scan input exceeds global bound'); return Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8'); };
const occurrences = (bytes, needle) => { let at = 0; let matches = 0; const value = Buffer.from(needle); while ((at = bytes.indexOf(value, at)) !== -1) { matches++; at += Math.max(1, value.length); } return matches; };
const result = (surface, matches, inventory, extra = {}, needle, run) => { if (!runs.has(run)) throw new Error('invalid scanner run authority'); const value = Object.freeze({ surface, matches, needleHash: digest(needle), inventory: Object.freeze(inventory.map(Object.freeze)), run, ...extra }); authorities.add(value); return value; };
const normalizedType = row => row.udt_name === 'citext' ? 'citext' : row.udt_name === 'jsonb' || row.data_type === 'jsonb' ? 'jsonb' : row.udt_name === 'json' || row.data_type === 'json' ? 'json' : row.data_type === 'character varying' || row.udt_name === 'varchar' ? 'varchar' : row.data_type === 'bytea' || row.udt_name === 'bytea' ? 'bytea' : row.data_type === 'text' || row.udt_name === 'text' ? 'text' : undefined;

/** The private authority and exact marker digest make controls non-forgeable. */
export function validatePositiveControl(surface, marker, scan) {
  if (!surfaces.includes(surface) || typeof marker !== 'string' || !marker || !authorities.has(scan) || !runs.has(scan.run) || scan.surface !== surface || scan.needleHash !== digest(marker) || scan.matches < 1) throw new Error(`missing positive control for ${surface}`);
  if ((surface === 'synapsePostgres' || surface === 'controlPostgres') && !types.every(type => scan.inventory.some(row => row.type === type && row.matches > 0))) throw new Error(`incomplete postgres positive control for ${surface}`);
  const control = Object.freeze({ surface, markerHash: digest(marker), matches: scan.matches });
  controlData.set(control, { scan, markerHash: digest(marker), run: scan.run });
  if (scan.inventory.some(row => row.matches > 0) && scan.matches < 1) throw new Error(`missing positive control for ${surface}`); return control;
}

/** Opaque authority binding every scan and control to one exact canary. */
export const issueScanRun = (canary, marker) => { if (typeof canary !== 'string' || !canary || Buffer.byteLength(canary, 'utf8') > 4096 || (marker !== undefined && (typeof marker !== 'string' || !marker || marker === canary))) throw new Error('invalid scan canary'); const run = Object.freeze({}); runs.set(run, { canaryHash: digest(canary), markerHash: marker === undefined ? undefined : digest(marker) }); return run; };
const runFor = (run, needle) => { const data = runs.get(run); const hash = digest(needle); if (!data || (data.canaryHash !== hash && data.markerHash !== hash)) throw new Error('scan run does not authorize this needle'); return run; };

/** Test-only seam. Production callers must pass a Pool-like object with connect(). */
export const dedicatedPgClient = client => { if (!client?.query || typeof client.query !== 'function') throw new Error('invalid dedicated postgres client'); dedicatedClients.add(client); return client; };

export function scanCapturedBodies(capture, canary, run) {
  runFor(run, canary); if (!Array.isArray(capture) || capture.length > LIMITS.captureEntries || typeof canary !== 'string' || !canary || Buffer.byteLength(canary, 'utf8') > 4096) throw new Error('invalid captured body scan input');
  let matches = 0; let total = 0; const inventory = [];
  for (const item of capture) { if (!item || typeof item !== 'object' || !['request', 'response'].includes(item.direction) || !Object.hasOwn(item, 'body') || Object.keys(item).some(key => /header|token|authorization|cookie/i.test(key))) throw new Error('capture must contain bodies only'); const body = bounded(item.body, LIMITS.bytes - total); total += body.length; matches += occurrences(body, canary); inventory.push({ direction: item.direction, status: Number.isInteger(item.status) ? item.status : null, bytes: body.length, matches: occurrences(body, canary) }); }
  return result('capture', matches, inventory, {}, canary, runFor(run, canary));
}

export async function scanPostgresCatalog(pool, canary, surface = 'synapsePostgres', run) {
  runFor(run, canary); if ((!pool?.connect && !dedicatedClients.has(pool)) || typeof canary !== 'string' || !canary || Buffer.byteLength(canary, 'utf8') > 4096 || !['synapsePostgres', 'controlPostgres'].includes(surface)) throw new Error('invalid postgres scan input');
  const client = dedicatedClients.has(pool) ? pool : await pool.connect();
  try {
    if (!client?.query || typeof client.release !== 'function' && !dedicatedClients.has(client)) throw new Error('pool did not provide a dedicated client');
    if (client.inTransaction === true || client.transactionStatus === 'in-transaction') throw new Error('postgres scanner requires an idle dedicated client');
    await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ');
    await client.query("SET LOCAL statement_timeout = '30s'"); await client.query("SET LOCAL lock_timeout = '5s'"); await client.query("SET LOCAL idle_in_transaction_session_timeout = '30s'");
    const identity = await client.query("SELECT current_database() AS database, (SELECT system_identifier::text FROM pg_control_system()) AS system_identifier");
    const identityRow = identity.rows?.[0];
    if (!identityRow || typeof identityRow.database !== 'string' || typeof identityRow.system_identifier !== 'string' || !identityRow.system_identifier) throw new Error('missing postgres cluster identity');
    const catalog = await client.query(`SELECT n.nspname AS table_schema, c.relname AS table_name, a.attname AS column_name, t.typname AS udt_name, CASE WHEN t.typname = 'varchar' THEN 'character varying' WHEN t.typname IN ('text', 'json', 'jsonb', 'bytea') THEN t.typname ELSE t.typname END AS data_type FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN pg_catalog.pg_type t ON t.oid = a.atttypid WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_toast' AND t.typname IN ('text','varchar','citext','json','jsonb','bytea') ORDER BY n.nspname, c.relname, a.attnum LIMIT ${LIMITS.catalogColumns + 1}`);
    if (!Array.isArray(catalog.rows) || catalog.rows.length > LIMITS.catalogColumns) throw new Error('postgres catalog exceeds column cap');
    let matches = 0; const inventory = [];
    for (const row of catalog.rows ?? []) {
      const type = normalizedType(row); const { table_schema: schema, table_name: table, column_name: column } = row;
      if (![schema, table, column].every(safeIdentifier) || !type) throw new Error('unsafe catalog identifier or type');
      const id = `"${schema}"."${table}"."${column}"`;
      const sql = type === 'bytea' ? `SELECT count(*)::bigint AS values, count(*) FILTER (WHERE position(convert_to($1::text, 'UTF8') in ${id}) > 0)::bigint AS matches FROM "${schema}"."${table}"` : `SELECT count(*)::bigint AS values, count(*) FILTER (WHERE position($1::text in ${id}::text) > 0)::bigint AS matches FROM "${schema}"."${table}"`;
      const aggregate = await client.query(sql, [canary]); const rowResult = aggregate.rows?.[0] ?? {}; const values = Number(rowResult.values); const found = Number(rowResult.matches);
      if (!Number.isSafeInteger(values) || values < 0 || !Number.isSafeInteger(found) || found < 0 || found > values) throw new Error('invalid postgres aggregate');
      matches += found; inventory.push({ columnHash: digest(`${schema}.${table}.${column}`), type, values, matches: found });
    }
    if (!types.every(type => inventory.some(row => row.type === type))) throw new Error('postgres catalog lacks required representation type');
    await client.query('ROLLBACK');
    return result(surface, matches, inventory, { databaseIdentityHash: digest(identityRow.database), clusterIdentityHash: digest(identityRow.system_identifier) }, canary, runFor(run, canary));
  } catch (error) { try { await client.query('ROLLBACK'); } catch {} throw error; } finally { if (!dedicatedClients.has(pool)) client.release(); }
}

/**
 * Scan a Postgres surface and its representation controls on one client and one
 * repeatable-read transaction.  The controls are TEMP data only: application
 * tables are never written.  Callers must use this rather than combining a
 * separately obtained positive control with a zero scan.
 */
export async function scanPostgresSession(pool, canary, surface = 'synapsePostgres', run) {
  const markerHash = runs.get(run)?.markerHash;
  if (!markerHash) throw new Error('postgres session requires a run marker');
  const marker = postgresSessions.get(run)?.marker;
  if (!marker) throw new Error('postgres marker is opaque; create the session with issuePostgresScanRun');
  // scanPostgresCatalog deliberately owns transaction cleanup, so use the
  // specialized implementation below for the single-transaction proof.
  runFor(run, canary);
  if (!pool?.connect || !['synapsePostgres', 'controlPostgres'].includes(surface)) throw new Error('postgres session requires a pool');
  const client = await pool.connect();
  let began = false;
  try {
    await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ'); began = true;
    await client.query("SET LOCAL statement_timeout = '30s'");
    const identity = (await client.query("SELECT current_database() AS database, (SELECT system_identifier::text FROM pg_control_system()) AS system_identifier")).rows?.[0];
    if (!identity?.database || !identity?.system_identifier) throw new Error('missing postgres cluster identity');
    const catalog = await client.query(`SELECT n.nspname AS table_schema, c.relname AS table_name, a.attname AS column_name, t.typname AS udt_name, t.typname AS data_type FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace JOIN pg_catalog.pg_type t ON t.oid = a.atttypid WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_toast' AND t.typname IN ('text','varchar','citext','json','jsonb','bytea') ORDER BY n.nspname, c.relname, a.attnum LIMIT ${LIMITS.catalogColumns + 1}`);
    if (!Array.isArray(catalog.rows) || catalog.rows.length > LIMITS.catalogColumns) throw new Error('postgres catalog exceeds column cap');
    const inventory = catalog.rows.map(row => {
      const type = normalizedType(row); if (![row.table_schema, row.table_name, row.column_name].every(safeIdentifier) || !type) throw new Error('unsafe catalog identifier or type');
      return { schema: row.table_schema, table: row.table_name, column: row.column_name, type };
    });
    if (!types.every(type => inventory.some(row => row.type === type))) throw new Error('postgres catalog lacks required representation type');
    await client.query('CREATE TEMP TABLE task9_marker_control (t text, v varchar, c citext, j json, jb jsonb, b bytea) ON COMMIT DROP');
    await client.query('INSERT INTO task9_marker_control VALUES ($1, $1, $1::citext, to_json($1::text), to_jsonb($1::text), convert_to($1, \'UTF8\'))', [marker]);
    const controls = [];
    for (const type of types) {
      const expression = { text: 't', varchar: 'v', citext: 'c', json: 'j::text', jsonb: 'jb::text', bytea: "encode(b, 'escape')" }[type];
      const found = Number((await client.query(`SELECT count(*)::bigint AS matches FROM task9_marker_control WHERE position($1::text in ${expression}::text) > 0`, [marker])).rows?.[0]?.matches);
      if (!Number.isSafeInteger(found) || found < 1) throw new Error(`missing postgres ${type} positive control`);
      controls.push({ type, matches: found });
    }
    let matches = 0; const zeroInventory = [];
    for (const item of inventory) {
      const id = `"${item.schema}"."${item.table}"."${item.column}"`;
      const sql = item.type === 'bytea' ? `SELECT count(*)::bigint AS values, count(*) FILTER (WHERE position(convert_to($1::text, 'UTF8') in ${id}) > 0)::bigint AS matches FROM "${item.schema}"."${item.table}"` : `SELECT count(*)::bigint AS values, count(*) FILTER (WHERE position($1::text in ${id}::text) > 0)::bigint AS matches FROM "${item.schema}"."${item.table}"`;
      const found = (await client.query(sql, [canary])).rows?.[0] ?? {}; const values = Number(found.values); const count = Number(found.matches);
      if (!Number.isSafeInteger(values) || !Number.isSafeInteger(count) || values < 0 || count < 0 || count > values) throw new Error('invalid postgres aggregate');
      matches += count; zeroInventory.push({ columnHash: digest(`${item.schema}.${item.table}.${item.column}`), type: item.type, values, matches: count });
    }
    const session = Object.freeze({ client, inventoryHash: digest(JSON.stringify(inventory)), databaseHash: digest(identity.database), clusterHash: digest(identity.system_identifier) });
    const zero = result(surface, matches, zeroInventory, { databaseIdentityHash: session.databaseHash, clusterIdentityHash: session.clusterHash, catalogHash: session.inventoryHash }, canary, run);
    const positive = result(surface, controls.reduce((n, x) => n + x.matches, 0), controls, { databaseIdentityHash: session.databaseHash, clusterIdentityHash: session.clusterHash, catalogHash: session.inventoryHash }, marker, run);
    const control = validatePositiveControl(surface, marker, positive); controlData.set(control, { scan: positive, markerHash, run, session, zero });
    await client.query('ROLLBACK'); began = false;
    return Object.freeze({ zero, positiveControl: control });
  } catch (error) { if (began) try { await client.query('ROLLBACK'); } catch {} throw error; } finally { client.release(); }
}

/** Creates a run whose marker is retained privately for same-session controls. */
export function issuePostgresScanRun(canary, marker) { const run = issueScanRun(canary, marker); postgresSessions.set(run, { marker }); return run; }

export function scanServiceLogs(logs, canary, run) {
  runFor(run, canary); if (!logs || typeof logs !== 'object' || Array.isArray(logs) || typeof canary !== 'string' || !canary || Buffer.byteLength(canary, 'utf8') > 4096) throw new Error('invalid log scan input');
  const actual = Object.keys(logs); const expected = OWNED_G2_LOG_SERVICES;
  if (actual.length !== expected.length || actual.some(service => !expected.includes(service))) throw new Error('owned service inventory mismatch');
  let matches = 0; let total = 0; const inventory = [];
  for (const service of expected) { const bytes = bounded(logs[service], Math.min(LIMITS.logBytes, LIMITS.logBytes - total)); total += bytes.length; const found = occurrences(bytes, canary); matches += found; inventory.push({ service, bytes: bytes.length, matches: found }); }
  return result('logs', matches, inventory, {}, canary, runFor(run, canary));
}

export async function scanMediaTree(root, canary, run) {
  runFor(run, canary); if (typeof canary !== 'string' || !canary || Buffer.byteLength(canary, 'utf8') > 4096) throw new Error('invalid media scan input');
  const rootReal = await realpath(root); let matches = 0; let files = 0; let dirs = 0; let total = 0; const inventory = [];
  const contained = path => path === rootReal || path.startsWith(`${rootReal}${sep}`);
  async function visit(directory) {
    if (++dirs > LIMITS.dirs || !contained(await realpath(directory))) throw new Error('media directory escaped root');
    const handle = await opendir(directory);
    for await (const entry of handle) {
      const path = join(directory, entry.name); const before = await lstat(path);
      if (before.isSymbolicLink() || (!before.isFile() && !before.isDirectory())) throw new Error('media tree contains non-regular entry');
      if (before.isDirectory()) { await visit(path); continue; }
      if (++files > LIMITS.files || before.size > LIMITS.bytes - total) throw new Error('media scan exceeds bound');
      const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const same = stat => stat.isFile() && stat.dev === before.dev && stat.ino === before.ino && stat.mode === before.mode && stat.size === before.size && stat.mtimeMs === before.mtimeMs && stat.ctimeMs === before.ctimeMs;
        if (!same(await file.stat())) throw new Error('media file changed during scan');
        let offset = 0; let found = 0; let carry = Buffer.alloc(0); const overlap = Math.max(0, Buffer.byteLength(canary, 'utf8') - 1);
        while (offset < before.size) { const length = Math.min(LIMITS.chunkBytes, before.size - offset); const chunk = Buffer.allocUnsafe(length); const read = await file.read(chunk, 0, length, offset); if (read.bytesRead !== length) throw new Error('media file changed during scan'); const joined = Buffer.concat([carry, chunk]); found += occurrences(joined, canary) - occurrences(carry, canary); carry = joined.subarray(Math.max(0, joined.length - overlap)); offset += length; }
        if (!same(await file.stat())) throw new Error('media file changed during scan');
        total += before.size; matches += found; inventory.push({ bytes: before.size, matches: found });
      } finally { await file.close(); }
    }
  }
  await visit(rootReal); return result('media', matches, inventory, {}, canary, runFor(run, canary));
}

export function assertNoCanary(results, expectedCanary, expectedRun) {
  if (!results || typeof results !== 'object' || typeof expectedCanary !== 'string' || !expectedCanary || !runs.has(expectedRun) || runs.get(expectedRun).canaryHash !== digest(expectedCanary)) throw new Error('missing scan results');
  for (const surface of surfaces) { const scan = results[surface]; const control = results.positiveControls?.[surface]; const data = controlData.get(control); if (!authorities.has(scan) || scan.run !== expectedRun || scan.needleHash !== digest(expectedCanary) || scan.surface !== surface || !control || control.surface !== surface || !data || data.scan.run !== expectedRun || data.scan.surface !== surface || control.markerHash !== data.markerHash || control.matches !== data.scan.matches || data.scan.matches < 1 || data.markerHash === digest(expectedCanary)) throw new Error(`missing positive control for ${surface}`); if (scan.matches !== 0) throw new Error(`canary found in ${surface}`); }
  for (const surface of ['synapsePostgres', 'controlPostgres']) { const data = controlData.get(results.positiveControls[surface]); if (!data?.session || data.zero !== results[surface] || !results[surface].catalogHash || !results[surface].databaseIdentityHash || !results[surface].clusterIdentityHash) throw new Error('postgres control and zero scan must share one session'); }
  if (results.synapsePostgres.clusterIdentityHash === results.controlPostgres.clusterIdentityHash || results.synapsePostgres.databaseIdentityHash === results.controlPostgres.databaseIdentityHash) throw new Error('postgres database and cluster identities must differ');
  for (const surface of ['push', 'metricsTracesSupport', 'backups']) if (!results[surface] || Object.keys(results[surface]).length !== 2 || !['disabled', 'not-configured', 'scanned'].includes(results[surface].status) || !Number.isSafeInteger(results[surface].count) || results[surface].count < 0) throw new Error(`missing ${surface} policy inventory`);
  return true;
}

export function buildTask9Evidence(results, expectedCanary, expectedRun) { assertNoCanary(results, expectedCanary, expectedRun); return { verdict: 'PASS_LOCAL_TASK9_PENDING_G2', surfaces: Object.fromEntries(surfaces.map(surface => [surface, { inventoryHash: digest(JSON.stringify(results[surface].inventory)), count: results[surface].inventory.length, canaryMatches: 0, positiveControl: { markerHash: results.positiveControls[surface].markerHash, matches: results.positiveControls[surface].matches } }])), auxiliary: ['push', 'metricsTracesSupport', 'backups'].map(name => ({ name, status: results[name].status, count: results[name].count })) }; }
