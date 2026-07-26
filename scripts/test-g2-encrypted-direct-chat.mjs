/** External G2 stays fail-closed until the entitled live contract exists. */
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { G2_PASS } from './g2-evidence-contract.mjs';
export { G2_PASS } from './g2-evidence-contract.mjs';
export const PENDING = 'PENDING_EXTERNAL_G2_MISSING_TWO_ENTITLED_ACCOUNTS';
export const DISABLED = 'DISABLED_EXTERNAL_G2_COLLECTORS_UNAVAILABLE';
export const G2_PRODUCTION_STATE = Object.freeze({ disabled: true });
const required = ['G2_ACCOUNT_ONE', 'G2_ACCOUNT_TWO', 'G2_ACCOUNT_ONE_ENTITLED', 'G2_ACCOUNT_TWO_ENTITLED', 'G2_WIRE_CAPTURE_ACCESS', 'G2_POSTGRES_ACCESS', 'G2_LOG_ACCESS', 'G2_MEDIA_ACCESS'];
export function g2Prerequisites(env = process.env) { const one = env.G2_ACCOUNT_ONE?.trim(); const two = env.G2_ACCOUNT_TWO?.trim(); return { accounts: Boolean(one && two && one !== two && env.G2_ACCOUNT_ONE_ENTITLED?.trim() === 'authorized' && env.G2_ACCOUNT_TWO_ENTITLED?.trim() === 'authorized'), access: required.slice(4).every(name => env[name]?.trim() === 'authorized') }; }
export function g2Verdict(env = process.env) { const state = g2Prerequisites(env); return state.accounts && state.access ? undefined : PENDING; }
const ARTIFACT_MAX = 1024 * 1024;
export async function readStableArtifact(file) { const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW); try { const before = await handle.stat(); const same = stat => stat.isFile() && stat.dev === before.dev && stat.ino === before.ino && stat.mode === before.mode && stat.size === before.size && stat.mtimeMs === before.mtimeMs && stat.ctimeMs === before.ctimeMs; if (!same(before) || before.size < 1 || before.size > ARTIFACT_MAX) throw new Error('unsafe G2 artifact'); const bytes = Buffer.alloc(before.size); const read = await handle.read(bytes, 0, bytes.length, 0); if (read.bytesRead !== bytes.length || !same(await handle.stat())) throw new Error('G2 artifact changed during read'); return bytes.toString('utf8'); } finally { await handle.close(); } }
export async function runG2(env = process.env) { if (g2Verdict(env)) return PENDING; if (G2_PRODUCTION_STATE.disabled) throw new Error(DISABLED); throw new Error('absolute executable resolution and repository-owned collectors required before enabling'); }
export async function runCli({ env = process.env, stdout = process.stdout } = {}) { const pending = g2Verdict(env); if (pending) { stdout.write(`${PENDING}\n`); process.exitCode = 1; return PENDING; } stdout.write(`${DISABLED}\n`); process.exitCode = 1; return DISABLED; }
if (process.argv[1] === fileURLToPath(import.meta.url)) runCli().catch(() => { process.stderr.write('External G2 evidence unavailable\n'); process.exitCode = 1; });
