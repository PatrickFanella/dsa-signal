import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, lstatSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { createPrivateKey } from 'node:crypto';
import { generateMatrixLocalSecrets, main } from './generate-matrix-local-secrets.mjs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = mkdtempSync(join(tmpdir(), 'matrix-secrets-'));
const upstream = join(root, 'upstream');
const secret = 'A'.repeat(43);
writeFileSync(upstream, secret, { mode: 0o400 }); chmodSync(upstream, 0o400);
const out = join(root, 'out');
const result = await main(['--upstream-client-secret', upstream, '--output', out]);
assert.equal(result, 0);
const names = [
  'control-owner-db-password', 'control-runtime-db-password', 'control-retention-db-password', 'control-revocation-db-password',
  'matrix-root-password', 'synapse-db-password', 'mas-db-password',
  'synapse-mas-shared-secret', 'synapse-macaroon-secret', 'synapse-form-secret',
  'mas-encryption-key', 'mas-signing-key.pem', 'synapse-signing-key',
  'mas-upstream-client-secret', 'synapse-secrets.yaml', 'mas-secrets.yaml',
];
assert.deepEqual(readdirSync(out).sort(), [...names].sort());
assert.equal(lstatSync(out).mode & 0o777, 0o700);
for (const name of names) assert.equal(lstatSync(join(out, name)).mode & 0o777, 0o444);
const values = Object.fromEntries(names.map((name) => [name, readFileSync(join(out, name), 'utf8')]));
const generatedCanonicalSecrets = [
  'control-owner-db-password', 'control-runtime-db-password', 'control-retention-db-password', 'control-revocation-db-password',
  'matrix-root-password', 'synapse-db-password', 'mas-db-password',
  'synapse-mas-shared-secret', 'synapse-macaroon-secret', 'synapse-form-secret',
];
for (const name of [...generatedCanonicalSecrets, 'mas-upstream-client-secret']) assert.match(values[name], /^[A-Za-z0-9_-]{43}$/);
assert.equal(values['mas-upstream-client-secret'], secret);
assert.equal(new Set([...generatedCanonicalSecrets.map((name) => values[name]), secret]).size, generatedCanonicalSecrets.length + 1);
assert.match(values['mas-encryption-key'], /^[a-f0-9]{64}$/);
assert.match(values['mas-signing-key.pem'], /^-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----\n$/);
assert.doesNotThrow(() => createPrivateKey(values['mas-signing-key.pem']));
assert.match(values['synapse-signing-key'], /^ed25519 a_[a-f0-9]{8} [A-Za-z0-9+/]{43}\n$/);
assert.equal(values['synapse-secrets.yaml'], `database:\n  name: psycopg2\n  args:\n    host: matrix-db\n    database: synapse\n    user: synapse\n    password: ${values['synapse-db-password']}\nmacaroon_secret_key: ${values['synapse-macaroon-secret']}\nform_secret: ${values['synapse-form-secret']}\nsigning_key_path: /run/secrets/synapse-signing-key\n`);
assert.equal(values['mas-secrets.yaml'], `database:\n  uri: postgresql://mas:${values['mas-db-password']}@matrix-db/mas?sslmode=disable\n`);
assert.throws(() => execFileSync('node', ['scripts/generate-matrix-local-secrets.mjs', '--upstream-client-secret', upstream, '--output', out], { encoding: 'utf8', stdio: 'pipe' }));
const loose = join(root, 'loose'); writeFileSync(loose, secret); chmodSync(loose, 0o644);
assert.throws(() => execFileSync('node', ['scripts/generate-matrix-local-secrets.mjs', '--upstream-client-secret', loose, '--output', join(root, 'other')], { stdio: 'pipe' }));
const linked = join(root, 'linked'); symlinkSync(upstream, linked);
assert.throws(() => execFileSync('node', ['scripts/generate-matrix-local-secrets.mjs', '--upstream-client-secret', linked, '--output', join(root, 'third')], { stdio: 'pipe' }));
assert.equal(await main(['--output', out]), 1);
const failed = spawnSync('node', ['scripts/generate-matrix-local-secrets.mjs', '--upstream-client-secret', loose, '--output', join(root, 'fourth')], { encoding: 'utf8' });
assert.equal(failed.stderr, 'secret generation failed\n');
assert.doesNotMatch(failed.stderr, new RegExp(root));
assert.equal(typeof generateMatrixLocalSecrets, 'function');
