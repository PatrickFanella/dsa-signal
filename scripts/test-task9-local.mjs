/** Local-only Task 9 gate: subprocess output is bounded and never replayed. */
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const commands = [['node', ['--test', 'scripts/scan-task9-plaintext.test.mjs', 'scripts/test-g2-encrypted-direct-chat.test.mjs', 'scripts/test-task9-local.test.mjs']], ['npm', ['--prefix', 'web', 'run', 'test']]];
export function localVerdict(checks) { if (!checks || Object.values(checks).some(value => value !== true)) throw new Error('Task 9 local checks failed'); return 'PASS_LOCAL_TASK9_PENDING_G2'; }
export function runLocal(execute = (command, args) => execFileSync(command, args, { cwd: root, stdio: 'pipe', timeout: 120_000, maxBuffer: 1024 * 1024 })) { for (const [command, args] of commands) execute(command, args); return localVerdict({ scanner: true, runner: true, web: true }); }
if (process.argv[1] === fileURLToPath(import.meta.url)) { try { process.stdout.write(`${runLocal()}\n`); } catch { process.stderr.write('Task 9 local checks failed\n'); process.exitCode = 1; } }
