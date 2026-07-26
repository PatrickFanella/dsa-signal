/** Secret material solely for the Task 8 metadata fixture. */
import { chmod, lstat, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { dirname, join, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { generateMatrixLocalSecrets } from './generate-matrix-local-secrets.mjs';

const marker = '.dsa-signal-task8-browser-fixture';
const permitted = root => {
  const path = resolve(root);
  if (path === resolve(tmpdir()) || (path !== '/tmp/opencode' && !path.startsWith(`/tmp/opencode${sep}`) && !path.startsWith(`${resolve(tmpdir())}${sep}`))) throw new Error('unsafe fixture root');
  return path;
};
async function secureDirectory(path, empty = false) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077) || (empty && (await readdir(path)).length)) throw new Error('unsafe fixture directory');
}
export async function generateTask8BrowserEnvironment({ root = '/tmp/opencode', output, generateSecrets = generateMatrixLocalSecrets } = {}) {
  root = permitted(root); await mkdir(root, { recursive: true, mode: 0o700 }); await chmod(root, 0o700); await secureDirectory(root);
  const dir = output ? resolve(output) : await mkdtemp(join(root, 'dsa-signal-task8-'));
  if (output) { if (dirname(dir) !== root) throw new Error('unsafe fixture output'); await mkdir(dir, { mode: 0o700 }); await secureDirectory(dir, true); }
  let marked = false;
  try {
    await chmod(dir, 0o700); await writeFile(join(dir, marker), 'task8 metadata fixture\n', { mode: 0o600, flag: 'wx' }); marked = true;
    const upstream = join(dir, '.upstream-client-secret'); const secrets = join(dir, 'matrix-local');
    await writeFile(upstream, randomBytes(32).toString('base64url'), { mode: 0o600, flag: 'wx' });
    await generateSecrets({ upstream, output: secrets }); await rm(upstream);
    const envFile = join(dir, 'environment.env');
    await writeFile(envFile, `MATRIX_LOCAL_SECRETS_DIR=${secrets}\n`, { mode: 0o600, flag: 'wx' });
    return { dir, envFile, secrets };
  } catch (error) {
    if (marked) await rm(dir, { recursive: true, force: true });
    throw error;
  }
}
export async function cleanupTask8BrowserEnvironment(dir, { root = '/tmp/opencode' } = {}) {
  root = permitted(root); dir = resolve(dir); if (dirname(dir) !== root) throw new Error('unsafe fixture cleanup');
  await secureDirectory(dir); const mark = join(dir, marker); const stat = await lstat(mark);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid()) throw new Error('unsafe fixture cleanup');
  await rm(dir, { recursive: true });
}
if (process.argv[1] === new URL(import.meta.url).pathname) generateTask8BrowserEnvironment().then(({ envFile }) => process.stdout.write(`${envFile}\n`)).catch(() => { process.stderr.write('task8 fixture generation failed\n'); process.exitCode = 1; });
