import { chmod, lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { dirname, resolve } from 'node:path';

const canonical = /^[A-Za-z0-9_-]{43}$/;
const usage = 'usage: node scripts/generate-matrix-local-secrets.mjs --upstream-client-secret <path> [--output <empty-directory>]';

const parseArgs = (args) => {
  const known = new Set(['--upstream-client-secret', '--output']);
  const values = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]; const value = args[index + 1];
    if (!known.has(name) || value === undefined || values[name] !== undefined) throw new Error(usage);
    values[name] = value;
  }
  if (!values['--upstream-client-secret']) throw new Error(usage);
  return { upstream: values['--upstream-client-secret'], output: resolve(values['--output'] ?? 'secrets/matrix-local') };
};
async function regularOwnerOnly(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) throw new Error('invalid secret input');
}
const b64 = () => randomBytes(32).toString('base64url');
const synapseKey = () => `ed25519 a_${randomBytes(4).toString('hex')} ${generateKeyPairSync('ed25519').privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('base64').replace(/=+$/, '')}\n`;
const yaml = (database, password) => `database:\n  name: psycopg2\n  args:\n    host: matrix-db\n    database: ${database}\n    user: ${database}\n    password: ${password}\n`;

export async function generateMatrixLocalSecrets({ upstream, output }) {
  await regularOwnerOnly(upstream);
  const upstreamBytes = await readFile(upstream);
  if (upstreamBytes.length !== 43 || !canonical.test(upstreamBytes.toString('ascii'))) throw new Error('invalid secret input');
  const parent = dirname(output);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const parentStat = await lstat(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() || (parentStat.mode & 0o077) !== 0) throw new Error('invalid output directory');
  await chmod(parent, 0o700);
  try { await mkdir(output, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const dir = await lstat(output);
  if (!dir.isDirectory() || dir.isSymbolicLink() || (dir.mode & 0o077) !== 0 || (await readdir(output)).length !== 0) throw new Error('invalid output directory');
  await chmod(output, 0o700);
  const put = async (name, content) => {
    const path = resolve(output, name);
    await writeFile(path, content, { mode: 0o444, flag: 'wx' });
    await chmod(path, 0o444); // Named Compose file mounts limit these readable files to their intended services.
  };
  for (const name of ['control-owner-db-password', 'control-runtime-db-password', 'control-retention-db-password', 'control-revocation-db-password', 'matrix-root-password', 'synapse-db-password', 'mas-db-password', 'synapse-mas-shared-secret', 'synapse-macaroon-secret', 'synapse-form-secret']) await put(name, b64());
  await put('mas-encryption-key', randomBytes(32).toString('hex'));
  const { privateKey: rsa } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  await put('mas-signing-key.pem', rsa.export({ type: 'pkcs8', format: 'pem' }));
  await put('synapse-signing-key', synapseKey());
  await put('mas-upstream-client-secret', upstreamBytes);
  const read = async (name) => readFile(resolve(output, name), 'utf8');
  await put('synapse-secrets.yaml', `${yaml('synapse', await read('synapse-db-password'))}macaroon_secret_key: ${await read('synapse-macaroon-secret')}\nform_secret: ${await read('synapse-form-secret')}\nsigning_key_path: /run/secrets/synapse-signing-key\n`);
  await put('mas-secrets.yaml', `database:\n  uri: postgresql://mas:${await read('mas-db-password')}@matrix-db/mas?sslmode=disable\n`);
}

export async function main(args = process.argv.slice(2)) {
  try { await generateMatrixLocalSecrets(parseArgs(args)); process.stdout.write('created Matrix local secrets\n'); return 0; } catch { process.stderr.write('secret generation failed\n'); return 1; }
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], 'file:').href) process.exitCode = await main();
