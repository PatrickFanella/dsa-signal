import { describe, expect, it } from 'vitest';
import { getConfig, getMigrationConfig } from './config.js';

describe('configuration', () => {
  it('has deterministic explicit test defaults and copies secrets', () => {
    const config = getConfig({ APP_ENV: 'test' });
    config.COOKIE_KEY[0] = 99;
    expect(getConfig({ APP_ENV: 'test' }).COOKIE_KEY[0]).toBe(0);
  });
  it('rejects malformed rings without exposing their secret', () => {
    const secret = 'not-a-real-secret';
    expect(() => getConfig({ APP_ENV: 'test', SUBJECT_KEY_RING: secret })).toThrow('Invalid SUBJECT_KEY_RING');
    try { getConfig({ APP_ENV: 'test', SUBJECT_KEY_RING: secret }); } catch (error) { expect(String(error)).not.toContain(secret); }
    const key = Buffer.alloc(32, 99).toString('base64url');
    for (const active of ['constructor', 'toString']) expect(() => getConfig({ APP_ENV: 'test', SUBJECT_KEY_RING: JSON.stringify({ active, keys: { v1: key } }) })).toThrow('Invalid SUBJECT_KEY_RING');
  });
  it('rejects duplicate ring keys', () => {
    const key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const ring = JSON.stringify({ active: 'a', keys: { a: key, b: key } });
    expect(() => getConfig({ APP_ENV: 'test', SUBJECT_KEY_RING: ring })).toThrow('Invalid SUBJECT_KEY_RING');
  });
  it('requires canonical persisted key IDs without tightening unrelated rings', () => {
    const bindingRing = (active: string, ids: readonly string[] = [active]) => JSON.stringify({ active, keys: Object.fromEntries(ids.map((id, index) => [id, Buffer.alloc(32, 90 + index).toString('base64url')])) });
    for (const id of ['V1', 'v.1', `v${'a'.repeat(32)}`, '1v']) {
      expect(() => getConfig({ APP_ENV: 'test', SESSION_BINDING_KEY_RING: bindingRing(id) })).toThrow('Invalid SESSION_BINDING_KEY_RING');
      expect(() => getConfig({ APP_ENV: 'test', SESSION_BINDING_KEY_RING: bindingRing('valid', [id]) })).toThrow('Invalid SESSION_BINDING_KEY_RING');
      expect(() => getConfig({ APP_ENV: 'test', OIDC_ADAPTER_KEY_RING: bindingRing(id) })).toThrow('Invalid OIDC_ADAPTER_KEY_RING');
      expect(() => getConfig({ APP_ENV: 'test', OIDC_INDEX_KEY_RING: bindingRing(id) })).toThrow('Invalid OIDC_INDEX_KEY_RING');
    }
    const config = getConfig({ APP_ENV: 'test', SESSION_BINDING_KEY_RING: bindingRing('binding-1_x', ['binding-1_x', 'retained_2']) });
    expect(config.SESSION_BINDING_KEY_RING.active).toBe('binding-1_x');
    expect(Object.keys(config.SESSION_BINDING_KEY_RING.keys)).toEqual(['binding-1_x', 'retained_2']);
    expect(getConfig({ APP_ENV: 'test', SUBJECT_KEY_RING: bindingRing('Task.3', ['Task.3']) }).SUBJECT_KEY_RING.active).toBe('Task.3');
  });
  it('rejects key material reused across different purposes and URL normalization', () => {
    const key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    expect(() => getConfig({ APP_ENV: 'test', SUBJECT_KEY_RING: JSON.stringify({ active: 'a', keys: { a: key } }) })).toThrow('Invalid key material reuse');
    expect(() => getConfig({ APP_ENV: 'test', PWA_ORIGIN: 'https://CHAT.example' })).toThrow('Invalid PWA_ORIGIN');
    for (const origin of ['https://éxample.test', 'https://chat.example:443', 'https://chat.example:0001', 'https://chat.example:0', 'https://chat.example:65536', 'https://chat.example/a/../b', 'https://127.1', 'https://2130706433', 'https://0177.0.0.1', 'https://0x7f.1', 'https://0x7f000001', 'https://127.0x1']) {
      expect(() => getConfig({ APP_ENV: 'test', PWA_ORIGIN: origin })).toThrow('Invalid PWA_ORIGIN');
    }
    expect(() => getConfig({ APP_ENV: 'test', ROOT_DIDS: '["did:plc:ABC"]' })).toThrow('Invalid ROOT_DIDS');
  });
  it('accepts an opaque OIDC client ID and rejects wildcard or control characters', () => {
    expect(getConfig({ APP_ENV: 'test', MAS_CLIENT_ID: 'dsa-signal.client_1' }).MAS_CLIENT_ID).toBe('dsa-signal.client_1');
    for (const clientId of ['*', 'dsa signal', 'dsa\nsignal']) expect(() => getConfig({ APP_ENV: 'test', MAS_CLIENT_ID: clientId })).toThrow('Invalid MAS_CLIENT_ID');
  });
  it('derives the issuer and accepts exactly one sector callback ULID', () => {
    const config = getConfig({ APP_ENV: 'test', PWA_ORIGIN: 'https://chat.example', PUBLIC_BASE_URL: 'https://chat.example', OIDC_SECTOR: 'https://mas.example', MAS_REDIRECT_URI: 'https://mas.example/upstream/callback/01J00000000000000000000000' });
    expect(config.OIDC_ISSUER).toBe('https://chat.example/oidc');
    for (const redirect of ['https://other.example/upstream/callback/01J00000000000000000000000', 'https://mas.example/callback/01J00000000000000000000000', 'https://mas.example/upstream/callback/01j00000000000000000000000']) expect(() => getConfig({ APP_ENV: 'test', MAS_REDIRECT_URI: redirect })).toThrow('Invalid MAS_REDIRECT_URI');
  });
  it('requires one canonical trusted proxy IP address', () => {
    expect(getConfig({ APP_ENV: 'test', OIDC_TRUSTED_PROXY_ADDRESS: '127.0.0.1' }).OIDC_TRUSTED_PROXY_ADDRESS).toBe('127.0.0.1');
    for (const value of ['localhost', ' 127.0.0.1', '127.1', '0177.0.0.1', '0x7f.0.0.1', '127.0.0.01', '0:0:0:0:0:0:0:1', '2001:0DB8::1']) expect(() => getConfig({ APP_ENV: 'test', OIDC_TRUSTED_PROXY_ADDRESS: value })).toThrow('Invalid OIDC_TRUSTED_PROXY_ADDRESS');
  });
  it('rejects removed independent issuer and plural redirect inputs', () => {
    expect(() => getConfig({ APP_ENV: 'test', OIDC_ISSUER_URL: 'https://ignored.example' })).toThrow('Legacy OIDC_ISSUER_URL');
    expect(() => getConfig({ APP_ENV: 'test', MAS_REDIRECT_URIS: '[]' })).toThrow('Legacy MAS_REDIRECT_URIS');
  });
  it('rejects URL normalization, unsafe ports, wildcards, paths on origins, and IP aliases', () => {
    for (const value of ['https://CHAT.example', 'https://bücher.example', 'https://chat.example:443', 'https://chat.example:0', 'https://chat.example:0001', 'https://chat.example:65536', 'https://chat.example/a/../b', 'https://*.example']) {
      expect(() => getConfig({ APP_ENV: 'test', PUBLIC_BASE_URL: value })).toThrow('Invalid PUBLIC_BASE_URL');
    }
    for (const value of ['https://chat.example/path', 'https://127.1', 'https://2130706433', 'https://0177.0.0.1', 'https://0x7f.1', 'https://0x7f000001', 'https://127.0x1']) {
      expect(() => getConfig({ APP_ENV: 'test', PWA_ORIGIN: value })).toThrow('Invalid PWA_ORIGIN');
    }
  });
  it('uses the strict configured DID profile for pinned roots', () => {
    expect(() => getConfig({ APP_ENV: 'test', ROOT_DIDS: '["did:example:alice"]' })).toThrow('Invalid ROOT_DIDS');
  });
  it('fails closed outside test mode instead of supplying secrets', () => {
    expect(() => getConfig({ APP_ENV: 'production' })).toThrow('Missing CONTROL_PLANE_RUNTIME_ROLE');
  });
  it('requires a canonical absolute restore-floor directory outside test', () => {
    expect(getConfig({ APP_ENV: 'test', OIDC_RESTORE_FLOOR_DIR: '/var/lib/floors' }).OIDC_RESTORE_FLOOR_DIR).toBe('/var/lib/floors');
    expect(() => getConfig({ APP_ENV: 'test', OIDC_RESTORE_FLOOR_DIR: 'relative' })).toThrow('Invalid OIDC_RESTORE_FLOOR_DIR');
  });
  it('keeps migration-owner configuration separate from runtime configuration', () => {
    const migration = getMigrationConfig({
      APP_ENV: 'development',
      MIGRATION_DATABASE_URL: 'postgresql://migration_owner:secret@postgres/dsa_signal',
      CONTROL_PLANE_RUNTIME_ROLE: 'control_plane_runtime',
      CONTROL_PLANE_RETENTION_ROLE: 'control_plane_retention',
      CONTROL_PLANE_REVOCATION_ROLE: 'control_plane_revocation',
      REVOCATION_EVIDENCE_KEY_IDS: 'v1',
    });
    expect(migration.MIGRATION_DATABASE_URL).toContain('migration_owner');
    expect('MIGRATION_DATABASE_URL' in getConfig({ APP_ENV: 'test' })).toBe(false);
    expect(() => getMigrationConfig({ MIGRATION_DATABASE_URL: 'postgresql://control_plane_runtime:secret@postgres/dsa_signal', CONTROL_PLANE_RUNTIME_ROLE: 'control_plane_runtime', CONTROL_PLANE_RETENTION_ROLE: 'control_plane_retention', CONTROL_PLANE_REVOCATION_ROLE: 'control_plane_revocation', REVOCATION_EVIDENCE_KEY_IDS: 'v1' })).toThrow('Invalid database role separation');
    expect(() => getMigrationConfig({ MIGRATION_DATABASE_URL: 'postgresql://migration_owner:secret@postgres/dsa_signal', CONTROL_PLANE_RUNTIME_ROLE: 'control_plane_runtime', CONTROL_PLANE_RETENTION_ROLE: 'control_plane_retention' })).toThrow('Invalid CONTROL_PLANE_REVOCATION_ROLE');
  });
  it('rejects connection-string identity and TLS overrides', () => {
    for (const query of ['user=migration_owner', 'sslmode=require&sslmode=disable', 'uselibpqcompat=true&sslmode=require', 'ssl=true']) expect(() => getConfig({ APP_ENV: 'test', DATABASE_URL: `postgresql://control_plane_runtime:test@localhost/test?${query}` })).toThrow('Invalid DATABASE_URL');
    const migration = { APP_ENV: 'production', CONTROL_PLANE_RUNTIME_ROLE: 'control_plane_runtime', CONTROL_PLANE_RETENTION_ROLE: 'control_plane_retention', CONTROL_PLANE_REVOCATION_ROLE: 'control_plane_revocation', REVOCATION_EVIDENCE_KEY_IDS: 'v1' };
    expect(() => getMigrationConfig({ ...migration, MIGRATION_DATABASE_URL: 'postgresql://migration_owner:secret@postgres/dsa_signal?sslmode=require' })).toThrow('Invalid MIGRATION_DATABASE_URL');
    expect(getMigrationConfig({ ...migration, MIGRATION_DATABASE_URL: 'postgresql://migration_owner:secret@postgres/dsa_signal?sslmode=verify-full' }).MIGRATION_DATABASE_URL).toContain('verify-full');
  });
});
