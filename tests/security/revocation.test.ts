import { createHash, randomBytes } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { access, chmod, mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { expect, test } from 'vitest';

const execFileAsync = promisify(execFile);
const root = resolve(import.meta.dirname, '../..');
const verdictDigest = '80dbd9ffb0bf081d5e9de4f79c8719ff8ba5e0af0d449dcf4aafe1b6947735a9';
const childTimeoutMs = 90_000;
const dockerTimeoutMs = 10_000;
const outputCap = 1024 * 1024;
const owner = createHash('sha256').update(root).digest('hex').slice(0, 32);

type Manifest = {
  schemaVersion: number;
  localVerdict: string;
  child: { cwd: string; files: string[]; expectedTotal: number };
  externalStatus: { status: string; task9G2SatisfiesTask10: boolean };
  fullNames: string[];
};
type Assertion = { fullName: string; status: string };
type Report = {
  success: boolean;
  startTime: number;
  numTotalTests: number;
  numPassedTests: number;
  numFailedTests: number;
  numPendingTests: number;
  numTodoTests: number;
  numFailedTestSuites: number;
  numPendingTestSuites: number;
  testResults: Array<{ name: string; status?: string; assertionResults: Assertion[] }>;
};

const exists = async (path: string): Promise<boolean> => access(path).then(() => true, () => false);

async function docker(command: string[]): Promise<string> {
  const { stdout } = await execFileAsync('docker', command, {
    timeout: dockerTimeoutMs,
    windowsHide: true,
    maxBuffer: 64 * 1024,
  });
  return stdout;
}

type Drill = { runId: string; ownerPid: string; ownerStart: string; directory: string; reportPath: string; child?: ReturnType<typeof spawn> };

type ProcIdentity = { kind: 'absent' } | { kind: 'present'; start: string };
type LockMarker = { runId: string; pid: string; start: string };
const lockPath = join(tmpdir(), `dsa-signal-security-drill-${owner}.lock`);
const markerPath = (path: string): string => join(path, 'owner');

async function procIdentity(pid: string): Promise<ProcIdentity> {
  if (!/^[1-9][0-9]*$/.test(pid)) throw new Error(`invalid /proc pid ${pid}`);
  try {
    const contents = await readFile(`/proc/${pid}/stat`, 'utf8');
    const close = contents.lastIndexOf(')');
    const fields = close < 0 ? [] : contents.slice(close + 2).trim().split(/\s+/);
    const start = fields[19];
    if (!/^[1-9][0-9]*$/.test(start ?? '')) throw new Error(`malformed /proc/${pid}/stat`);
    return { kind: 'present', start };
  } catch (error: unknown) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') return { kind: 'absent' };
    throw error;
  }
}

function encodeMarker(marker: LockMarker): string { return `${marker.runId}|${marker.pid}|${marker.start}\n`; }
function parseMarker(contents: string): LockMarker {
  const [runId, pid, start, extra] = contents.trimEnd().split('|');
  if (extra !== undefined || !/^[a-f0-9]{32}$/.test(runId ?? '') || !/^[1-9][0-9]*$/.test(pid ?? '') || !/^[1-9][0-9]*$/.test(start ?? '')) throw new Error('refusing malformed security-drill lock marker');
  return { runId: runId!, pid: pid!, start: start! };
}
async function readMarker(path: string): Promise<{ marker: LockMarker; raw: string }> { const raw = await readFile(markerPath(path), 'utf8'); return { marker: parseMarker(raw), raw }; }
async function createLock(marker: LockMarker, path = lockPath): Promise<void> {
  await mkdir(path, { mode: 0o700 });
  try { await writeFile(markerPath(path), encodeMarker(marker), { mode: 0o600, flag: 'wx' }); } catch (error) { await rm(path, { recursive: true, force: true }); throw error; }
}
async function removeExactLock(marker: LockMarker, path = lockPath): Promise<void> {
  const current = await readMarker(path);
  if (current.raw !== encodeMarker(marker)) throw new Error('refusing to remove another security-drill lock');
  await rm(path, { recursive: true });
}
async function acquireLock(marker: LockMarker, identity: (pid: string) => Promise<ProcIdentity> = procIdentity, path = lockPath): Promise<void> {
  try { await createLock(marker, path); return; } catch (error: unknown) { if (!(typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST')) throw error; }
  const existing = await readMarker(path); // malformed and unreadable markers intentionally fail closed
  const ownerIdentity = await identity(existing.marker.pid);
  if (ownerIdentity.kind === 'present' && ownerIdentity.start === existing.marker.start) throw new Error('concurrent security drill owns repository lock');
  const quarantine = `${path}.recover-${randomBytes(16).toString('hex')}`;
  await rename(path, quarantine); // atomic: only one stale-lock recoverer can win
  try {
    const moved = await readMarker(quarantine);
    if (moved.raw !== existing.raw) throw new Error('security-drill lock changed during recovery');
    await rm(quarantine, { recursive: true });
  } catch (error) { await rm(quarantine, { recursive: true, force: true }); throw error; }
  await createLock(marker, path);
}

type ContainerIdentity = Pick<Drill, 'runId' | 'ownerPid' | 'ownerStart'>;

async function inspected(id: string, expected: ContainerIdentity): Promise<{ id: string; name: string; runId: string; owner: string; pid: string; start: string }> {
  if (!/^[a-f0-9]{64}$/.test(id) || !/^[a-z0-9][a-z0-9_-]{0,47}$/.test(expected.runId) || !/^[1-9][0-9]*$/.test(expected.ownerPid) || !/^[1-9][0-9]*$/.test(expected.ownerStart)) throw new Error(`refusing malformed security-drill container ${id}`);
  const parsed: unknown = JSON.parse(await docker(['inspect', '--format', '[{{json .Id}},{{json .Name}},{{json .Config.Labels}}]', id]));
  if (!Array.isArray(parsed) || parsed.length !== 3 || typeof parsed[0] !== 'string' || typeof parsed[1] !== 'string' || typeof parsed[2] !== 'object' || parsed[2] === null || Array.isArray(parsed[2])) throw new Error(`refusing malformed security-drill container ${id}`);
  const [actualId, name, labels] = parsed as [string, string, Record<string, unknown>];
  const expectedLabels = {
    'dsa-signal.security-drill': expected.runId,
    'dsa-signal.security-drill-owner': owner,
    'dsa-signal.security-drill-owner-pid': expected.ownerPid,
    'dsa-signal.security-drill-owner-start': expected.ownerStart,
  };
  if (actualId !== id || name !== `/dsa-signal-security-drill-${expected.runId}` || JSON.stringify(Object.keys(labels).sort()) !== JSON.stringify(Object.keys(expectedLabels).sort()) || Object.entries(expectedLabels).some(([key, value]) => labels[key] !== value)) throw new Error(`refusing malformed security-drill container ${id}`);
  return { id: actualId, name, runId: expected.runId, owner, pid: expected.ownerPid, start: expected.ownerStart };
}

async function assertContainerAbsent(id: string): Promise<void> {
  try {
    await docker(['inspect', id]);
  } catch (error: unknown) {
    const stderr = typeof error === 'object' && error !== null && 'stderr' in error ? String(error.stderr) : '';
    if ([`Error response from daemon: No such object: ${id}`, `Error response from daemon: No such container: ${id}`, `error: no such object: ${id}`, `error: no such container: ${id}`].some(diagnostic => stderr === diagnostic || stderr === `${diagnostic}\n`)) return;
    throw new Error(`docker inspect for removed container ${id} failed for a reason other than absence: ${stderr}`);
  }
  throw new Error(`removed security-drill container remains inspectable: ${id}`);
}

async function staleIdentity(id: string): Promise<ContainerIdentity> {
  const parsed: unknown = JSON.parse(await docker(['inspect', '--format', '{{json .Config.Labels}}', id]));
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error(`refusing malformed security-drill container ${id}`);
  const labels = parsed as Record<string, unknown>;
  if (typeof labels['dsa-signal.security-drill'] !== 'string' || typeof labels['dsa-signal.security-drill-owner-pid'] !== 'string' || typeof labels['dsa-signal.security-drill-owner-start'] !== 'string') throw new Error(`refusing malformed security-drill container ${id}`);
  return { runId: labels['dsa-signal.security-drill'], ownerPid: labels['dsa-signal.security-drill-owner-pid'], ownerStart: labels['dsa-signal.security-drill-owner-start'] };
}

async function cleanupContainer(drill: Pick<Drill, 'runId' | 'ownerPid' | 'ownerStart'>): Promise<void> {
  const { runId } = drill;
  const name = `dsa-signal-security-drill-${runId}`;
  const ids = (await docker(['ps', '-aq', '--no-trunc', '--filter', `name=^/${name}$`, '--filter', `label=dsa-signal.security-drill=${runId}`, '--filter', `label=dsa-signal.security-drill-owner=${owner}`, '--filter', `label=dsa-signal.security-drill-owner-pid=${drill.ownerPid}`, '--filter', `label=dsa-signal.security-drill-owner-start=${drill.ownerStart}`]))
    .trim().split(/\s+/).filter(Boolean);
  for (const id of ids) {
    const candidate = await inspected(id, drill);
    await docker(['rm', '-f', id]);
    await assertContainerAbsent(candidate.id);
  }
  const remaining = await docker(['ps', '-aq', '--no-trunc', '--filter', `name=^/${name}$`, '--filter', `label=dsa-signal.security-drill=${runId}`, '--filter', `label=dsa-signal.security-drill-owner=${owner}`, '--filter', `label=dsa-signal.security-drill-owner-pid=${drill.ownerPid}`, '--filter', `label=dsa-signal.security-drill-owner-start=${drill.ownerStart}`]);
  expect(remaining.trim(), 'matching drill container remains after cleanup').toBe('');
}

async function recoverStaleDrills(): Promise<void> {
  const ids = (await docker(['ps', '-aq', '--no-trunc', '--filter', `label=dsa-signal.security-drill-owner=${owner}`])).trim().split(/\s+/).filter(Boolean);
  for (const id of ids) {
    const candidate = await inspected(id, await staleIdentity(id));
    const identity = await procIdentity(candidate.pid);
    if (identity.kind === 'present' && identity.start === candidate.start) throw new Error(`concurrent security drill owns ${candidate.name}`);
    await docker(['rm', '-f', candidate.id]);
    await assertContainerAbsent(candidate.id);
  }
}

function isErrno(error: unknown, code: string): boolean { return typeof error === 'object' && error !== null && 'code' in error && error.code === code; }
async function groupGone(pid: number): Promise<boolean> { try { process.kill(-pid, 0); return false; } catch (error: unknown) { if (isErrno(error, 'ESRCH')) return true; throw error; } }
async function stopChild(drill: Drill): Promise<void> {
  const child = drill.child;
  if (!child?.pid) return;
  try { process.kill(-child.pid, 'SIGTERM'); } catch (error: unknown) { if (!isErrno(error, 'ESRCH')) throw error; }
  for (let i = 0; i < 50 && !(await groupGone(child.pid)); i += 1) await new Promise(resolve => setTimeout(resolve, 100));
  if (!(await groupGone(child.pid))) {
    try { process.kill(-child.pid, 'SIGKILL'); } catch (error: unknown) { if (!isErrno(error, 'ESRCH')) throw error; }
    for (let i = 0; i < 50 && !(await groupGone(child.pid)); i += 1) await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (!(await groupGone(child.pid))) throw new Error('child process group survived termination');
}
async function rehearseInterruptedChildCleanup(drill: Drill): Promise<void> {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { detached: true, stdio: 'ignore' });
  const rehearsal: Drill = { ...drill, child };
  try {
    if (!child.pid) throw new Error('could not start interrupted-child cleanup rehearsal');
    await stopChild(rehearsal);
    expect(await groupGone(child.pid), 'interrupted child process group survived cleanup rehearsal').toBe(true);
  } finally {
    await stopChild(rehearsal);
  }
}
async function runChild(drill: Drill, start: number): Promise<void> {
  const child = spawn('pnpm', ['exec', 'vitest', 'run', 'src/db.integration.test.ts', 'src/entitlements/revocation-worker.test.ts', '--reporter=json', `--outputFile=${drill.reportPath}`], {
    cwd: join(root, 'backend'),
    detached: true,
    env: { ...process.env, DSA_SECURITY_DRILL_RUN_ID: drill.runId, DSA_SECURITY_DRILL_OWNER: owner, DSA_SECURITY_DRILL_OWNER_PID: drill.ownerPid, DSA_SECURITY_DRILL_OWNER_START: drill.ownerStart },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  drill.child = child;
  let output = ''; let outputBytes = 0; let overflow = false;
  const append = (chunk: Buffer): void => { if (overflow) return; const remaining = outputCap - outputBytes; const retained = chunk.subarray(0, Math.max(0, remaining)); output += retained.toString(); outputBytes += retained.length; if (chunk.length > remaining) { overflow = true; void stopChild(drill); } };
  child.stdout.on('data', append);
  child.stderr.on('data', append);
  type ChildResult = { code: number | null; signal: NodeJS.Signals | null; error?: Error; timedOut?: boolean };
  const settled = new Promise<ChildResult>((resolveResult) => {
    child.once('exit', (code, signal) => resolveResult({ code, signal }));
    child.once('error', error => resolveResult({ code: null, signal: null, error }));
  });
  let deadlineTimer: NodeJS.Timeout | undefined;
  const deadline = new Promise<ChildResult>((resolveDeadline) => { deadlineTimer = setTimeout(() => resolveDeadline({ code: null, signal: null, timedOut: true }), childTimeoutMs); });
  const result = await Promise.race([settled, deadline]);
  if (deadlineTimer) clearTimeout(deadlineTimer);
  if (result.timedOut || overflow || result.error || result.code !== 0 || result.signal !== null) {
    await stopChild(drill);
    throw new Error(`backend drill failed or timed out (code=${result.code}, signal=${result.signal}, error=${result.error?.message ?? 'none'}): ${output.slice(-4000)}`);
  }
  if (!child.pid || !(await groupGone(child.pid))) { await stopChild(drill); throw new Error('child process group survived successful exit'); }
  const reportStat = await stat(drill.reportPath);
  expect(reportStat.mtimeMs).toBeGreaterThanOrEqual(start);
}

function assertReport(report: Report, manifest: Manifest, startedAt: number): void {
  expect(report.success).toBe(true);
  expect(report.startTime).toBeGreaterThanOrEqual(startedAt);
  expect(report.numTotalTests).toBe(manifest.child.expectedTotal);
  expect(report.numPassedTests).toBe(manifest.child.expectedTotal);
  expect(report.numFailedTests).toBe(0);
  expect(report.numPendingTests).toBe(0);
  expect(report.numTodoTests).toBe(0);
  expect(report.numFailedTestSuites).toBe(0);
  expect(report.numPendingTestSuites).toBe(0);
  const expectedFiles = manifest.child.files.map((file) => resolve(root, manifest.child.cwd, file)).sort();
  expect(report.testResults.map((result) => resolve(result.name)).sort()).toEqual(expectedFiles);
  expect(report.testResults.every((result) => result.status === undefined || result.status === 'passed')).toBe(true);
  const actual = report.testResults.flatMap((result) => result.assertionResults);
  expect(actual).toHaveLength(manifest.child.expectedTotal);
  expect(actual.every((item) => item.status === 'passed')).toBe(true);
  const expected = [...manifest.fullNames].sort();
  const observed = actual.map((item) => item.fullName).sort();
  expect(new Set(manifest.fullNames).size).toBe(manifest.child.expectedTotal);
  expect(new Set(observed).size).toBe(manifest.child.expectedTotal);
  expect(observed).toEqual(expected);
}

test('Task 10 revocation drill pins the complete local reconciler evidence', async () => {
  const manifest = JSON.parse(await readFile(join(root, 'tests/security/revocation.manifest.json'), 'utf8')) as Manifest;
  expect(manifest.schemaVersion).toBe(1);
  expect(createHash('sha256').update(manifest.localVerdict).digest('hex')).toBe(verdictDigest);
  expect(manifest.child).toEqual({ cwd: 'backend', files: ['src/db.integration.test.ts', 'src/entitlements/revocation-worker.test.ts'], expectedTotal: 88 });
  expect(manifest.externalStatus).toEqual({ status: 'pending_task10_room_crypto_g2', task9G2SatisfiesTask10: false });
  expect(manifest.fullNames).toHaveLength(88);
  const lifecycle = [
    'control-plane migration enforces published-source lifecycle: entitlement_expiry / entitlement_expired',
    'control-plane migration enforces published-source lifecycle: signed_policy_revocation / policy_revoked',
    'control-plane migration enforces published-source lifecycle: authenticated_issuer_revocation / issuer_revoked',
    'control-plane migration enforces published-source lifecycle: authenticated_key_compromise / issuer_key_compromise',
    'control-plane migration enforces published-source lifecycle: authenticated_lost_device / lost_device',
  ];
  expect(new Set(lifecycle).size).toBe(5);
  for (const identity of [...lifecycle,
    'control-plane migration limits claimants to claim/result execution and fences concurrent claims',
    'control-plane migration is checksum-idempotent, rejects catalog and ACL drift, and grants append-only access',
    'revocation worker strictly validates each claim discriminant and target: mas_lock',
    'revocation worker records success, retryable, permanent, and stale CAS outcomes',
    'control-plane migration enforces runtime and retention effective privileges',
    'control-plane migration incrementally upgrades a checked-in 0009 catalog to 0010',
  ]) expect(manifest.fullNames).toContain(identity);
  const runId = randomBytes(16).toString('hex');
  expect(runId).toMatch(/^[a-f0-9]{32}$/);
  const ownIdentity = await procIdentity(String(process.pid));
  if (ownIdentity.kind !== 'present') throw new Error('cannot establish Linux /proc owner identity');
  const ownerStart = ownIdentity.start;
  const directory = await mkdtemp(join(tmpdir(), `dsa-signal-security-drill-${runId}-`));
  await chmod(directory, 0o700);
  const drill: Drill = { runId, ownerPid: String(process.pid), ownerStart, directory, reportPath: join(directory, 'vitest-report.json') };
  expect(await exists(drill.reportPath), 'stale report path').toBe(false);
  const startedAt = Date.now();
  let cleaning: Promise<void> | undefined;
  let locked = false;
  const cleanup = (): Promise<void> => cleaning ??= (async () => { try { await stopChild(drill); } finally { try { await cleanupContainer(drill); } finally { try { if (locked) await removeExactLock({ runId, pid: drill.ownerPid, start: drill.ownerStart }); } finally { await rm(drill.directory, { recursive: true, force: true }); } } } })();
  const signal = (received: NodeJS.Signals): void => { void cleanup().finally(() => { process.off('SIGINT', onInt); process.off('SIGTERM', onTerm); process.kill(process.pid, received); }); };
  const onInt = (): void => signal('SIGINT');
  const onTerm = (): void => signal('SIGTERM');
  process.on('SIGINT', onInt); process.on('SIGTERM', onTerm);
  try {
    // Exercise fail-closed marker handling and stale-lock recovery in this root run.
    const fixtureLock = join(tmpdir(), `dsa-signal-security-drill-fixture-${runId}.lock`);
    await mkdir(fixtureLock, { mode: 0o700 });
    await writeFile(markerPath(fixtureLock), 'not-a-marker\n', { mode: 0o600 });
    await expect(acquireLock({ runId, pid: drill.ownerPid, start: drill.ownerStart }, procIdentity, fixtureLock)).rejects.toThrow('malformed');
    await rm(fixtureLock, { recursive: true, force: true }); // this fixture was created solely by this invocation
    const stale: LockMarker = { runId: randomBytes(16).toString('hex'), pid: drill.ownerPid, start: ownerStart === '1' ? '2' : '1' };
    await createLock(stale, fixtureLock);
    await expect(acquireLock({ runId, pid: drill.ownerPid, start: drill.ownerStart }, async () => { throw new Error('simulated /proc I/O failure'); }, fixtureLock)).rejects.toThrow('simulated /proc I/O failure');
    await removeExactLock(stale, fixtureLock);
    await createLock(stale, fixtureLock);
    await acquireLock({ runId, pid: drill.ownerPid, start: drill.ownerStart }, procIdentity, fixtureLock);
    await removeExactLock({ runId, pid: drill.ownerPid, start: drill.ownerStart }, fixtureLock);
    await acquireLock({ runId, pid: drill.ownerPid, start: drill.ownerStart });
    locked = true;
    await rehearseInterruptedChildCleanup(drill);
    await recoverStaleDrills();
    await runChild(drill, startedAt);
    const report = JSON.parse(await readFile(drill.reportPath, 'utf8')) as Report;
    assertReport(report, manifest, startedAt);
    const [plan, contract, runbook, manifestText] = await Promise.all([
      readFile(join(root, 'docs/superpowers/plans/2026-07-16-membership-gated-e2ee-chat.md'), 'utf8'), readFile(join(root, 'docs/reference/privacy-and-threat-contract.md'), 'utf8'), readFile(join(root, 'docs/runbooks/revoke-member.md'), 'utf8'), readFile(join(root, 'tests/security/revocation.manifest.json'), 'utf8'),
    ]);
    for (const step of ['- [ ] **Step 1: Write lifecycle tests**', '- [ ] **Step 2: Explicitly test the irreversible boundary**', '- [ ] **Step 4: Run the revocation drill**']) expect(plan).toContain(step);
    expect(contract).toMatch(/plaintext or keys previously downloaded[\s\S]*irreversible/i);
    expect(runbook).toMatch(/previously downloaded or decrypted/i);
    expect(runbook).toContain('Task 9 G2 cannot satisfy the Task-10 revocation G2');
    expect(runbook).toMatch(/only after the entire compound command[\s\S]*make verify[\s\S]*succeeds/i);
    expect(`${manifestText}\n${runbook}`).not.toContain('PASS_EXTERNAL_TASK10');
  } finally {
    try { await cleanup(); } finally { process.off('SIGINT', onInt); process.off('SIGTERM', onTerm); }
  }
}, 190_000);
