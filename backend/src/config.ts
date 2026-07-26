import { z } from 'zod';
import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { isCanonicalDnsHostname, validateDid } from './entitlements/claims.js';
import { sectorSchema } from './subjects/pairwise-subject.js';

const key = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const keyId = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/);
const ringSchema = z.object({ active: keyId, keys: z.record(keyId, key) }).strict();
const narrowKeyId = z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/);
const narrowRingSchema = z.object({ active: narrowKeyId, keys: z.record(narrowKeyId, key) }).strict();
export type KeyRing = Readonly<{ active: string; keys: Readonly<Record<string, Uint8Array>> }>;
export type Config = Readonly<{
  APP_ENV: 'test' | 'development' | 'production'; PORT: number; DATABASE_URL: string;
  CONTROL_PLANE_RUNTIME_ROLE: string; PUBLIC_BASE_URL: string; FOUNDATION_BASE_URL: string; PWA_ORIGIN: string;
  OIDC_ISSUER: string; OIDC_SECTOR: string; OIDC_EPOCH: string; OIDC_TRUSTED_PROXY_ADDRESS: string; MAS_CLIENT_ID: string; MAS_REDIRECT_URI: string;
  OIDC_SIGNING_JWKS_PATH: string; MAS_CLIENT_SECRET_PATH: string; OIDC_COOKIE_KEYS_PATH: string; OIDC_RESTORE_FLOOR_DIR?: string; OIDC_RESTORE_FLOOR_HEAD?: string;
  COOKIE_SECURE: boolean; COOKIE_KEY: Uint8Array; SUBJECT_KEY_RING: KeyRing; ENVELOPE_KEY_RING: KeyRing;
  CHALLENGE_KEY_RING: KeyRing; SESSION_BINDING_KEY_RING: KeyRing; JTI_KEY_RING: KeyRing;
  OIDC_ADAPTER_KEY_RING: KeyRing; OIDC_INDEX_KEY_RING: KeyRing; REVOCATION_EVIDENCE_KEY_RING: KeyRing;
  IDEMPOTENCY_KEY_RING: KeyRing; REQUEST_FINGERPRINT_KEY_RING: KeyRing; ROOT_DIDS: readonly string[];
  AUTHORITY_POLICY_VERSION: string; POLICY_MAX_STALENESS_SECONDS: number; ROOT_PUBLIC_JWKS: Readonly<Record<string, Readonly<{ kty: 'EC'; crv: 'P-256'; x: string; y: string }>>>;
}>;
export type MigrationConfig = Readonly<{ MIGRATION_DATABASE_URL: string; CONTROL_PLANE_RUNTIME_ROLE: string; CONTROL_PLANE_RETENTION_ROLE: string; CONTROL_PLANE_REVOCATION_ROLE: string; REVOCATION_EVIDENCE_KEY_IDS: readonly string[] }>;

const testKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const testRing = (name: string): string => JSON.stringify({ active: 'v1', keys: { v1: Buffer.alloc(32, ['SUBJECT_KEY_RING', 'ENVELOPE_KEY_RING', 'CHALLENGE_KEY_RING', 'SESSION_BINDING_KEY_RING', 'JTI_KEY_RING', 'IDEMPOTENCY_KEY_RING', 'REQUEST_FINGERPRINT_KEY_RING', 'OIDC_ADAPTER_KEY_RING', 'OIDC_INDEX_KEY_RING', 'REVOCATION_EVIDENCE_KEY_RING'].indexOf(name) + 1).toString('base64url') } });
/** Reject normalization: configured public URLs are protocol identifiers, not user input. Paths are allowed for issuers and bases. */
const publicUrl = (value: string, name: string, originOnly = false): string => {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`Invalid ${name}`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !isCanonicalDnsHostname(url.hostname) || url.port === '0' || url.port === '443') throw new Error(`Invalid ${name}`);
  const canonical = `${url.origin}${url.pathname === '/' ? '' : url.pathname}`;
  if (value !== canonical || (originOnly && !sectorSchema.safeParse(value).success)) throw new Error(`Invalid ${name}`);
  return value;
};
function bytes(encoded: string, name: string): Uint8Array {
  const decoded = Buffer.from(encoded, 'base64url');
  if (decoded.length !== 32 || decoded.toString('base64url') !== encoded) throw new Error(`Invalid ${name}`);
  return new Uint8Array(decoded);
}
function parseRing(raw: string, name: string): KeyRing {
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new Error(`Invalid ${name}`); }
  const parsed = (['SESSION_BINDING_KEY_RING', 'OIDC_ADAPTER_KEY_RING', 'OIDC_INDEX_KEY_RING'].includes(name) ? narrowRingSchema : ringSchema).safeParse(value);
  if (!parsed.success || !Object.hasOwn(parsed.data.keys, parsed.data.active) || Object.keys(parsed.data.keys).length === 0) throw new Error(`Invalid ${name}`);
  const decoded = Object.fromEntries(Object.entries(parsed.data.keys).map(([id, encoded]) => [id, bytes(encoded, name)]));
  const values = Object.values(parsed.data.keys);
  if (new Set(values).size !== values.length) throw new Error(`Invalid ${name}`);
  return { active: parsed.data.active, keys: decoded };
}
function databaseUrl(value: string, name: string, production: boolean): string {
  let url: URL; try { url = new URL(value); } catch { throw new Error(`Invalid ${name}`); }
  const parameters = [...url.searchParams.keys()]; const sslModes = url.searchParams.getAll('sslmode');
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname || url.hash || parameters.some((key) => key !== 'sslmode') || sslModes.length > 1 || (sslModes[0] !== undefined && !['disable', 'require', 'verify-ca', 'verify-full'].includes(sslModes[0])) || (production && sslModes[0] !== 'verify-full')) throw new Error(`Invalid ${name}`);
  return value;
}
function canonicalIp(value: string): string | undefined {
  if (isIP(value) === 4) return /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value) && value.split('.').every((part) => Number(part) <= 255) ? value : undefined;
  if (isIP(value) === 6) {
    try { return new URL(`http://[${value}]`).hostname.slice(1, -1) === value ? value : undefined; } catch { return undefined; }
  }
  return undefined;
}
/** Parses external environment without including secret values in thrown errors. */
export function getConfig(env: NodeJS.ProcessEnv = process.env): Config {
  if (env.OIDC_ISSUER_URL !== undefined) throw new Error('Legacy OIDC_ISSUER_URL is not supported');
  if (env.MAS_REDIRECT_URIS !== undefined) throw new Error('Legacy MAS_REDIRECT_URIS is not supported');
  const appEnv = z.enum(['test', 'development', 'production']).default('development').safeParse(env.APP_ENV);
  if (!appEnv.success) throw new Error('Invalid APP_ENV');
  const test = appEnv.data === 'test';
  const required = (name: string, fallback?: string): string => {
    const value = env[name] ?? (test ? fallback : undefined);
    if (!value) throw new Error(`Missing ${name}`);
    return value;
  };
  const port = z.coerce.number().int().min(1).max(65535).safeParse(env.PORT ?? (test ? '8080' : '8080'));
  if (!port.success) throw new Error('Invalid PORT');
  const role = required('CONTROL_PLANE_RUNTIME_ROLE', 'control_plane_runtime');
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(role)) throw new Error('Invalid CONTROL_PLANE_RUNTIME_ROLE');
  const ring = (name: string): KeyRing => parseRing(required(name, testRing(name)), name);
  const secure = required('COOKIE_SECURE', 'true');
  if (secure !== 'true' && secure !== 'false') throw new Error('Invalid COOKIE_SECURE');
  if (!test && secure !== 'true') throw new Error('Invalid COOKIE_SECURE');
  const roots = required('ROOT_DIDS', '["did:plc:abcdefghijklmnopqrstuvwx"]');
  let rootDids: unknown; try { rootDids = JSON.parse(roots); } catch { throw new Error('Invalid ROOT_DIDS'); }
  if (!Array.isArray(rootDids) || rootDids.length === 0 || rootDids.some((x) => typeof x !== 'string' || !validateDid(x)) || new Set(rootDids).size !== rootDids.length) throw new Error('Invalid ROOT_DIDS');
  let rootJwks: unknown; try { rootJwks = JSON.parse(required('ROOT_PUBLIC_JWKS', '{"did:plc:abcdefghijklmnopqrstuvwx#v1":{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}')); } catch { throw new Error('Invalid ROOT_PUBLIC_JWKS'); }
  const jwk = z.object({ kty: z.literal('EC'), crv: z.literal('P-256'), x: key, y: key }).strict();
  if (!rootJwks || typeof rootJwks !== 'object' || Array.isArray(rootJwks) || Object.keys(rootJwks).length === 0 || Object.entries(rootJwks).some(([kid, value]) => !/^did:(?:plc|web):.+#[A-Za-z0-9._-]{1,64}$/.test(kid) || !rootDids.some((did) => kid.startsWith(`${did}#`)) || !jwk.safeParse(value).success) || !rootDids.every((did) => Object.keys(rootJwks as object).some((kid) => kid.startsWith(`${did}#`)))) throw new Error('Invalid ROOT_PUBLIC_JWKS');
  const staleness = z.coerce.number().int().min(1).max(86_400).safeParse(required('POLICY_MAX_STALENESS_SECONDS', '300'));
  if (!staleness.success) throw new Error('Invalid POLICY_MAX_STALENESS_SECONDS');
  const policy = required('AUTHORITY_POLICY_VERSION', 'v1'); if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(policy)) throw new Error('Invalid AUTHORITY_POLICY_VERSION');
  const production = appEnv.data === 'production';
  const database = databaseUrl(required('DATABASE_URL', 'postgres://control_plane_runtime:test@localhost/test'), 'DATABASE_URL', production);
  if (new URL(database).username !== role) throw new Error('Invalid database role separation');
  const rings = ['SUBJECT_KEY_RING', 'ENVELOPE_KEY_RING', 'CHALLENGE_KEY_RING', 'SESSION_BINDING_KEY_RING', 'JTI_KEY_RING', 'IDEMPOTENCY_KEY_RING', 'REQUEST_FINGERPRINT_KEY_RING', 'OIDC_ADAPTER_KEY_RING', 'OIDC_INDEX_KEY_RING', 'REVOCATION_EVIDENCE_KEY_RING'].map(ring);
  const cookie = bytes(required('COOKIE_KEY', testKey), 'COOKIE_KEY');
  const allKeys = [cookie, ...rings.flatMap((item) => Object.values(item.keys))].map((item) => Buffer.from(item).toString('base64url'));
  if (new Set(allKeys).size !== allKeys.length) throw new Error('Invalid key material reuse');
  const clientId = required('MAS_CLIENT_ID', 'dsa-signal');
  // OIDC client IDs are opaque protocol identifiers, not DID subjects.
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(clientId)) throw new Error('Invalid MAS_CLIENT_ID');
  const oidcSector = sectorSchema.safeParse(required('OIDC_SECTOR', 'https://mas.example'));
  if (!oidcSector.success) throw new Error('Invalid OIDC_SECTOR');
  const redirect = required('MAS_REDIRECT_URI', 'https://mas.example/upstream/callback/01J00000000000000000000000');
  if (!new RegExp(`^${oidcSector.data.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/upstream/callback/[0-9A-HJKMNP-TV-Z]{26}$`).test(redirect)) throw new Error('Invalid MAS_REDIRECT_URI');
  const oidcEpoch = required('OIDC_EPOCH', 'AAAAAAAAAAAAAAAAAAAAAA');
  if (!/^[A-Za-z0-9_-]{22}$/.test(oidcEpoch) || Buffer.from(oidcEpoch, 'base64url').length !== 16 || Buffer.from(oidcEpoch, 'base64url').toString('base64url') !== oidcEpoch) throw new Error('Invalid OIDC_EPOCH');
  const trustedProxyAddress = canonicalIp(required('OIDC_TRUSTED_PROXY_ADDRESS', '127.0.0.1'));
  if (!trustedProxyAddress) throw new Error('Invalid OIDC_TRUSTED_PROXY_ADDRESS');
  const publicBase = publicUrl(required('PUBLIC_BASE_URL', 'https://chat.example'), 'PUBLIC_BASE_URL', true);
  const pwaOrigin = publicUrl(required('PWA_ORIGIN', 'https://chat.example'), 'PWA_ORIGIN', true);
  if (publicBase !== pwaOrigin) throw new Error('Invalid PUBLIC_BASE_URL');
  const path = (name: string): string => {
    const value = required(name, `/run/secrets/${name.toLowerCase()}`);
    if (!value.startsWith('/') || value.includes('\0')) throw new Error(`Invalid ${name}`);
    return value;
  };
  const floorDirectory = required('OIDC_RESTORE_FLOOR_DIR', '/tmp/dsa-signal-oidc-restore-floor');
  if (!floorDirectory.startsWith('/') || floorDirectory.includes('\0') || resolve(floorDirectory) !== floorDirectory) throw new Error('Invalid OIDC_RESTORE_FLOOR_DIR');
  const floorHead = required('OIDC_RESTORE_FLOOR_HEAD', 'BQSLpPDcieO3Yt-iBZbnZTblaCULvwaJAAxi4Pd8TtA');
  if (!/^[A-Za-z0-9_-]{43}$/.test(floorHead) || Buffer.from(floorHead, 'base64url').length !== 32 || Buffer.from(floorHead, 'base64url').toString('base64url') !== floorHead) throw new Error('Invalid OIDC_RESTORE_FLOOR_HEAD');
  return { APP_ENV: appEnv.data, PORT: port.data, DATABASE_URL: database, CONTROL_PLANE_RUNTIME_ROLE: role, PUBLIC_BASE_URL: publicBase, FOUNDATION_BASE_URL: publicUrl(required('FOUNDATION_BASE_URL', 'https://foundation.example'), 'FOUNDATION_BASE_URL'), PWA_ORIGIN: pwaOrigin, OIDC_ISSUER: `${pwaOrigin}/oidc`, OIDC_SECTOR: oidcSector.data, OIDC_EPOCH: oidcEpoch, OIDC_TRUSTED_PROXY_ADDRESS: trustedProxyAddress, MAS_CLIENT_ID: clientId, MAS_REDIRECT_URI: redirect, OIDC_SIGNING_JWKS_PATH: path('OIDC_SIGNING_JWKS_PATH'), MAS_CLIENT_SECRET_PATH: path('MAS_CLIENT_SECRET_PATH'), OIDC_COOKIE_KEYS_PATH: path('OIDC_COOKIE_KEYS_PATH'), OIDC_RESTORE_FLOOR_DIR: floorDirectory, OIDC_RESTORE_FLOOR_HEAD: floorHead, COOKIE_SECURE: secure === 'true', COOKIE_KEY: cookie, SUBJECT_KEY_RING: rings[0], ENVELOPE_KEY_RING: rings[1], CHALLENGE_KEY_RING: rings[2], SESSION_BINDING_KEY_RING: rings[3], JTI_KEY_RING: rings[4], IDEMPOTENCY_KEY_RING: rings[5], REQUEST_FINGERPRINT_KEY_RING: rings[6], OIDC_ADAPTER_KEY_RING: rings[7], OIDC_INDEX_KEY_RING: rings[8], REVOCATION_EVIDENCE_KEY_RING: rings[9], ROOT_DIDS: rootDids, AUTHORITY_POLICY_VERSION: policy, POLICY_MAX_STALENESS_SECONDS: staleness.data, ROOT_PUBLIC_JWKS: rootJwks as Config['ROOT_PUBLIC_JWKS'] };
}

/** Parses migration-only credentials separately so the API process never receives or retains them. */
export function getMigrationConfig(env: NodeJS.ProcessEnv = process.env): MigrationConfig {
  const runtime = env.CONTROL_PLANE_RUNTIME_ROLE;
  const retention = env.CONTROL_PLANE_RETENTION_ROLE;
  const claimant = env.CONTROL_PLANE_REVOCATION_ROLE;
  const evidenceKeyIds = env.REVOCATION_EVIDENCE_KEY_IDS?.split(',');
  const migrationUrl = env.MIGRATION_DATABASE_URL;
  if (!runtime || !/^[a-z_][a-z0-9_]{0,62}$/.test(runtime)) throw new Error('Invalid CONTROL_PLANE_RUNTIME_ROLE');
  if (!retention || !/^[a-z_][a-z0-9_]{0,62}$/.test(retention) || retention === runtime) throw new Error('Invalid CONTROL_PLANE_RETENTION_ROLE');
  if (!claimant || !/^[a-z_][a-z0-9_]{0,62}$/.test(claimant) || claimant === runtime || claimant === retention) throw new Error('Invalid CONTROL_PLANE_REVOCATION_ROLE');
  if (!evidenceKeyIds || evidenceKeyIds.length === 0 || new Set(evidenceKeyIds).size !== evidenceKeyIds.length || evidenceKeyIds.some((keyId) => !/^[a-z][a-z0-9_-]{0,31}$/.test(keyId))) throw new Error('Invalid REVOCATION_EVIDENCE_KEY_IDS');
  if (!migrationUrl) throw new Error('Missing MIGRATION_DATABASE_URL');
  const parsed = databaseUrl(migrationUrl, 'MIGRATION_DATABASE_URL', env.APP_ENV === 'production');
  const owner = new URL(parsed).username;
  if (!owner || owner === runtime || owner === retention || owner === claimant) throw new Error('Invalid database role separation');
  return { MIGRATION_DATABASE_URL: parsed, CONTROL_PLANE_RUNTIME_ROLE: runtime, CONTROL_PLANE_RETENTION_ROLE: retention, CONTROL_PLANE_REVOCATION_ROLE: claimant, REVOCATION_EVIDENCE_KEY_IDS: evidenceKeyIds };
}
