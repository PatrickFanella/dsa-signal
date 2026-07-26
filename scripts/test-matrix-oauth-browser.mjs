/** Fixture-owned, secret-safe Matrix browser gate. */
import { rm, readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { generateTask8BrowserEnvironment, cleanupTask8BrowserEnvironment } from './generate-task8-browser-environment.mjs';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const lockedCaddy = () => /^CADDY_IMAGE=(.+)$/m.exec(readFileSync(resolve(root, 'deploy/locks/images.env'), 'utf8'))?.[1] ?? (() => { throw new Error('missing Caddy lock'); })();
export const ORIGIN = 'https://chat.localhost:8443';
const evidencePath = resolve(root, 'web/test-results/task8-browser-evidence.json');
export const browserServices = ['api', 'matrix-db', 'synapse-data-init', 'synapse', 'mas-migrate', 'gateway', 'gateway-ca-export', 'mas', 'mas-ready', 'web'];
export function validateFixtureComposition(rendered, caddyImage) { const api = JSON.parse(rendered).services.api; if (api.image !== caddyImage || api.build || api.user || api.secrets || api.depends_on?.migrate || api.depends_on?.['control-db'] || Object.hasOwn(api, 'ports') || JSON.stringify(Object.keys(api.networks ?? {}).sort()) !== JSON.stringify(['control-internal']) || (api.volumes ?? []).length !== 1 || api.volumes[0].target !== '/etc/caddy/Caddyfile' || !api.volumes[0].read_only) throw new Error('invalid Task 8 fixture composition'); return true; }
export function modeFromEnv(env) { if (env.MATRIX_BROWSER_BASE_URL && env.MATRIX_BROWSER_BASE_URL !== ORIGIN) throw new Error('Task 8 browser gate only permits https://chat.localhost:8443'); if (env.MATRIX_BROWSER_ENV_FILE) throw new Error('Task 8 uses its fixture-owned environment'); return 'fixture'; }
export function validateBrowserEvidence(value) { if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid Task 8 browser evidence'); const expected = { callbackCompletion: 'pending-pre-g2-live-login', ownerPageClose: true, followerTakeover: 'owner', reloadReinject: true, identityContinuity: true, databaseContinuity: true, rustInitOpenReopen: true, idbOpenFailure: { status: 'blocked', openIntercepted: true, startClientCalled: false }, idbConnectionVersionchange: { status: 'closed-after-versionchange', blocked: true, versionchange: true, closed: true }, dcrRouteCapture: true, corsWildcardWithoutCredentials: true }; if (JSON.stringify(value) !== JSON.stringify(expected)) throw new Error('invalid Task 8 browser evidence'); return true; }
export function projectName() { return `dsa-signal-task8-${randomBytes(8).toString('hex')}`; }
export function checkoutMarker() { const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], { cwd: root, encoding: 'utf8' }).split('\n').filter(Boolean).sort(); const hash = createHash('sha256'); for (const file of files) { hash.update(file); hash.update('\0'); hash.update(readFileSync(resolve(root, file))); hash.update('\0'); } return hash.digest('hex'); }
export const allowedEnv = env => Object.fromEntries(Object.entries(env).filter(([key]) => /^(PATH|HOME|USER|TMPDIR|XDG_.+|DOCKER_.+|CONTAINER_.+|MATRIX_BROWSER_BASE_URL|PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH)$/.test(key)));
export function run(command, args, env, timeout = 180_000, { spawnImpl = spawn, kill = process.kill, signal: abortSignal, setTimer = setTimeout, clearTimer = clearTimeout, terminationGrace = 5_000, forcedSettlement = 1_000, maxOutput = 1_000_000 } = {}) { return new Promise((ok, no) => {
  const child = spawnImpl(command, args, { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'], detached: true }); let done = false; let closed = false; let output = ''; let timer; let graceTimer; let forceTimer; let failure; let killFailed = false;
  const clearTimers = () => { for (const id of [timer, graceTimer, forceTimer]) if (id !== undefined) clearTimer(id); };
  const finish = error => { if (done) return; done = true; clearTimers(); abortSignal?.removeEventListener('abort', abort); error ? no(error) : ok(output); };
  const signalGroup = signal => { if (closed || !child.pid) return; try { kill(-child.pid, signal); } catch { killFailed = true; } };
  const terminate = error => { if (failure || closed) return; failure = error; signalGroup('SIGTERM'); graceTimer = setTimer(() => { if (closed) return; signalGroup('SIGKILL'); forceTimer = setTimer(() => finish(killFailed ? new Error(`${failure.message}; process group termination failed`) : failure), forcedSettlement); }, terminationGrace); };
  const abort = () => terminate(new Error('Task 8 browser gate aborted'));
  timer = setTimer(() => terminate(new Error('Task 8 browser gate timed out')), timeout);
  child.stdout?.on('data', chunk => { if (output.length < maxOutput) output += String(chunk).slice(0, maxOutput - output.length); });
  child.stderr?.resume();
  abortSignal?.addEventListener('abort', abort, { once: true });
  if (abortSignal?.aborted) abort();
  child.once('error', () => finish(new Error('Task 8 browser gate command unavailable')));
  child.once('close', code => { closed = true; finish(failure ?? (code === 0 ? undefined : new Error('Task 8 browser gate command failed'))); });
}); }
export async function gate(env = process.env, execute = run, { marker = checkoutMarker, makeProject = projectName, fixture = generateTask8BrowserEnvironment, cleanupFixture = cleanupTask8BrowserEnvironment, remove = rm, readEvidence = readFile, signal } = {}) {
  modeFromEnv(env); const project = makeProject(); const buildMarker = marker(); const owned = await fixture(); const gateEnv = { ...allowedEnv(env), MATRIX_LOCAL_SECRETS_DIR: owned.secrets, VITE_BUILD_MARKER: buildMarker, MATRIX_BROWSER_BUILD_MARKER: buildMarker };
  const compose = ['compose', '--env-file', 'deploy/locks/images.env', '--env-file', owned.envFile, '--project-name', project, '--project-directory', 'deploy/local', '-f', 'deploy/local/compose.yaml', '-f', 'deploy/local/browser/compose.override.yaml', '--profile', 'full']; let primary; let cleanup; let stage = 'render';
  try {
    const rendered = await execute('docker', [...compose, 'config', '--format', 'json'], gateEnv, undefined, { signal });
    if (typeof rendered === 'string') validateFixtureComposition(rendered, lockedCaddy());
    stage = 'startup';
    await execute('docker', [...compose, 'up', '-d', '--build', '--wait', ...browserServices], gateEnv, 720000, { signal });
    stage = 'browser assertions';
    await remove(evidencePath, { force: true });
    await execute('npm', ['--prefix', 'web', 'run', 'test:matrix-browser'], gateEnv, undefined, { signal });
    validateBrowserEvidence(JSON.parse(await readEvidence(evidencePath, 'utf8')));
  } catch { primary = new Error(`Task 8 ${stage} failed`); }
  const cleanupSignal = new AbortController().signal;
  try { await execute('docker', [...compose, 'down', '-v', '--remove-orphans'], gateEnv, undefined, { signal: cleanupSignal }); } catch { cleanup = true; }
  try { await remove(resolve(root, 'web/.matrix-browser-harness'), { recursive: true, force: true }); await cleanupFixture(owned.dir); } catch { cleanup = true; }
  if (primary && cleanup) throw new Error('Task 8 browser gate and cleanup failed'); if (primary) throw primary; if (cleanup) throw new Error('Task 8 browser cleanup failed'); return 'PASS_LOCAL_CALLBACK_PENDING_LIVE_LOGIN';
}
export async function runCli({ gateImpl = gate, processImpl = process } = {}) { const controller = new AbortController(); const abort = () => controller.abort(); processImpl.on('SIGINT', abort); processImpl.on('SIGTERM', abort); try { const result = await gateImpl(processImpl.env, run, { signal: controller.signal }); processImpl.stdout.write(`${result}\n`); } catch (error) { processImpl.stderr.write(`Task 8 browser gate failed: ${error.message}\n`); processImpl.exitCode = 1; } finally { processImpl.removeListener('SIGINT', abort); processImpl.removeListener('SIGTERM', abort); } }
if (process.argv[1] === fileURLToPath(import.meta.url)) runCli();
