import { constants, chmodSync, mkdtempSync, mkdirSync, openSync, closeSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const G2_CHILD_ENV_ALLOWLIST = Object.freeze(['LANG', 'LC_ALL', 'TZ']);
export function g2FutureChildEnv(env = process.env) { return Object.fromEntries(G2_CHILD_ENV_ALLOWLIST.flatMap(key => env[key] === undefined ? [] : [[key, env[key]]])); }
export function createG2RunDirectory() {
  const root = mkdtempSync(join(tmpdir(), 'g2-private-'), { encoding: 'utf8' }); chmodSync(root, 0o700); mkdirSync(join(root, 'home'), { mode: 0o700 }); mkdirSync(join(root, 'xdg-config'), { mode: 0o700 }); mkdirSync(join(root, 'xdg-cache'), { mode: 0o700 }); mkdirSync(join(root, 'profile-one'), { mode: 0o700 }); mkdirSync(join(root, 'profile-two'), { mode: 0o700 });
  return root;
}
export function createG2Artifact(root, name) { const path = join(root, name); const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); closeSync(fd); return path; }
export function destroyG2RunDirectory(root) { rmSync(root, { recursive: true, force: true, maxRetries: 2, retryDelay: 20 }); try { statSync(root); throw new Error('G2 private run directory survived cleanup'); } catch (error) { if (error?.code !== 'ENOENT') throw error; } }
