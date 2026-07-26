/**
 * Dormant source snapshot preparation.  This module deliberately has no runner
 * entry point and never returns a capability usable by the G2 runner.
 */
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmod, lstat, mkdtemp, mkdir, open, readFile, realpath, rm, stat, writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { g2BuildMarker, g2PreliminaryMarker, inspectGitArchive } from "./g2-provenance-preparation.mjs";

export const SNAPSHOT_LIMITS = Object.freeze({ outputBytes: 4 * 1024 * 1024, timeoutMs: 60_000, installOutputBytes: 16 * 1024 * 1024, installTimeoutMs: 600_000, termGraceMs: 500, postKillVerificationPolls: 100 });
export const SNAPSHOT_ENV_NAMES = Object.freeze(["LANG", "LC_ALL", "TZ"]);
export const SNAPSHOT_REJECTED_ENV_NAMES = Object.freeze([
  "NODE_OPTIONS", "NODE_PATH", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
  "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy",
  "NO_PROXY", "no_proxy", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "BUILDX_CONFIG", "BUILDKIT_HOST",
  "NPM_CONFIG_USERCONFIG", "npm_config_userconfig", "NPM_CONFIG_CACHE", "npm_config_cache",
  "NPM_CONFIG_STORE_DIR", "npm_config_store_dir", "NPM_CONFIG_PREFIX", "npm_config_prefix",
  "PNPM_HOME", "PNPM_STORE_PATH", "pnpm_config_store_dir", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "HOME",
]);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const G2_SERVICES = Object.freeze(["control-db", "matrix-db", "migrate", "api", "web", "synapse", "synapse-data-init", "mas", "mas-ready", "mas-migrate", "gateway", "gateway-ca-export"]);
export const G2_SNAPSHOT_DISABLED_ERROR = "DISABLED_NON_AUTHORITATIVE_G2_SNAPSHOT";
export const G2_PROCESS_GROUP_CLEANUP_ERROR = "G2_PROCESS_GROUP_CLEANUP_UNCONTAINED";
const PRIVATE_PREFIX = "dsa-g2-snapshot-";

function fail(message) { throw new Error(message); }
function inside(root, path) { return path === root || path.startsWith(`${root}${sep}`); }
function digest(bytes) { return `sha256:${createHash("sha256").update(bytes).digest("hex")}`; }

/** Reject explicit launch-time overrides before a future entrypoint has side effects. */
export function assertSafeG2LaunchEnv(env) {
  for (const name of SNAPSHOT_REJECTED_ENV_NAMES) if (Object.hasOwn(env, name)) fail(`rejected launch-time environment variable: ${name}`);
  for (const name of Object.keys(env)) if (/^npm_config(?:_|$)/i.test(name) || /^pnpm_(?:config|home|store|cache)(?:_|$)/i.test(name)) fail(`rejected launch-time environment variable: ${name}`);
}

/** Pure fixed-limit check retained as a deterministic verification seam. */
export function assertPostKillGroupVerification(polls) {
  if (polls >= SNAPSHOT_LIMITS.postKillVerificationPolls) fail(G2_PROCESS_GROUP_CLEANUP_ERROR);
}

/** A deliberately small child environment that strips rejected launch-time overrides. */
export function snapshotChildEnv(env = process.env, root) {
  if (!root || !resolve(root).startsWith(`${resolve(tmpdir())}${sep}${PRIVATE_PREFIX}`)) fail("invalid private root");
  const value = Object.fromEntries(SNAPSHOT_ENV_NAMES.flatMap((name) => env[name] === undefined ? [] : [[name, env[name]]]));
  // Absolute executables do not require PATH.  Keep it only for fixed shebang
  // interpreters (for example pnpm's env-based launcher), never ambient PATH.
  return Object.freeze({ ...value, HOME: join(root, "home"), TMPDIR: join(root, "tmp"), XDG_CONFIG_HOME: join(root, "xdg-config"), XDG_CACHE_HOME: join(root, "xdg-cache"), npm_config_userconfig: join(root, "npmrc"), npm_config_cache: join(root, "npm-cache"), npm_config_store_dir: join(root, "npm-store"), pnpm_config_store_dir: join(root, "pnpm-store"), PNPM_HOME: join(root, "pnpm-home"), DOCKER_CONFIG: join(root, "docker-config"), GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", PATH: "/usr/bin:/bin" });
}

export async function executableIdentity(path) {
  if (typeof path !== "string" || !path.startsWith("/")) fail("executable must be absolute");
  const resolved = await realpath(path);
  const info = await stat(resolved);
  if (!info.isFile() || (info.mode & 0o111) === 0) fail("unsafe executable");
  return Object.freeze({ path: resolved, sha256: digest(await readFile(resolved)) });
}

/**
 * Bounded primitive for trusted fixed commands: it owns one POSIX process group,
 * not hostile setsid/double-fork/namespaced children or host-loss containment.
 */
export async function runBounded(executable, args, { cwd, env, timeoutMs = SNAPSHOT_LIMITS.timeoutMs, outputBytes = SNAPSHOT_LIMITS.outputBytes } = {}) {
  const identity = await executableIdentity(executable);
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) fail("invalid subprocess arguments");
  return await new Promise((resolveResult, reject) => {
    let child; let timer; let graceTimer; let pollTimer; let closeSeen = false; let terminating = false; let killed = false; let postKillPolls = 0; let settled = false; let reason;
    const stdout = []; const stderr = []; let bytes = 0;
    const cleanup = () => { clearTimeout(timer); clearTimeout(graceTimer); clearInterval(pollTimer); process.off("SIGINT", onSignal); process.off("SIGTERM", onSignal); };
    const settle = (error = reason) => { if (settled) return; settled = true; cleanup(); if (error) reject(error); else resolveResult(Object.freeze({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), identity })); };
    const groupGone = () => {
      if (!Number.isSafeInteger(child?.pid) || child.pid <= 0) return true;
      try { process.kill(-child.pid, 0); return false; } catch (error) { if (error?.code === "ESRCH") return true; throw error; }
    };
    const signalGroup = (signal) => {
      if (!Number.isSafeInteger(child?.pid) || child.pid <= 0) return;
      try { process.kill(-child.pid, signal); } catch (error) { if (error?.code !== "ESRCH") throw error; }
    };
    const inspectTermination = () => {
      if (settled) return;
      try {
        const gone = groupGone();
        if (closeSeen && gone) settle();
        else if (killed && !gone) assertPostKillGroupVerification(++postKillPolls);
      } catch (error) { settle(error); }
    };
    const terminate = (why) => {
      if (why && !reason) reason = why;
      if (terminating) return;
      terminating = true;
      try { signalGroup("SIGTERM"); } catch (error) { settle(error); return; }
      graceTimer = setTimeout(() => {
        try { if (!groupGone()) { signalGroup("SIGKILL"); killed = true; } } catch (error) { settle(error); return; }
        inspectTermination();
      }, SNAPSHOT_LIMITS.termGraceMs);
      pollTimer = setInterval(inspectTermination, 10);
      inspectTermination();
    };
    // The primitive owns its child group through interruption as well; callers
    // never receive completion before that group is gone.
    const onSignal = (signal) => terminate(new Error(`subprocess interrupted: ${signal}`));
    process.on("SIGINT", onSignal); process.on("SIGTERM", onSignal);
    try { child = spawn(identity.path, args, { cwd, env, detached: true, stdio: ["ignore", "pipe", "pipe"] }); } catch (error) { settle(error); return; }
    const append = (target) => (chunk) => { if (terminating) return; bytes += chunk.length; if (bytes > outputBytes) terminate(new Error("subprocess output limit")); else target.push(Buffer.from(chunk)); };
    child.stdout.on("data", append(stdout)); child.stderr.on("data", append(stderr));
    child.once("error", (error) => { reason ??= error; closeSeen = true; terminate(); });
    // `close` waits for inherited pipe descriptors held by descendants.  Start
    // group cleanup at `exit`, but do not settle until the late close arrives.
    child.once("exit", (code, signal) => { if (code !== 0) reason ??= new Error(`subprocess failed: ${code ?? signal}`); terminate(); });
    child.once("close", () => { closeSeen = true; terminate(); });
    timer = setTimeout(() => terminate(new Error("subprocess timeout")), timeoutMs);
  });
}

export async function createPrivateSnapshotRoot() {
  const root = await mkdtemp(join(tmpdir(), PRIVATE_PREFIX));
  await chmodVerified(root, 0o700, "private root", "directory");
  for (const name of ["home", "tmp", "xdg-config", "xdg-cache", "npm-cache", "npm-store", "pnpm-home", "pnpm-store", "docker-config"]) {
    const path = join(root, name); await mkdir(path, { mode: 0o700 }); await chmodVerified(path, 0o700, "private directory", "directory");
  }
  await writeFile(join(root, "npmrc"), "", { flag: "wx", mode: 0o600 }); await chmodVerified(join(root, "npmrc"), 0o600, "private file", "file");
  return root;
}
export async function destroyPrivateSnapshotRoot(root) {
  if (!resolve(root).startsWith(`${resolve(tmpdir())}${sep}${PRIVATE_PREFIX}`)) fail("refusing private-root cleanup");
  await rm(root, { recursive: true, force: true, maxRetries: 2, retryDelay: 20 });
  try { await lstat(root); fail("private root survived cleanup"); } catch (error) { if (error?.code !== "ENOENT") throw error; }
}

/** Writes only entries accepted by inspectGitArchive; no tar program is invoked. */
export async function extractGitArchive(bytes, destination) {
  // Own bytes before any await: callers may retain and mutate their Buffer.
  bytes = Buffer.from(bytes);
  const inspected = inspectGitArchive(bytes);
  const directoryModes = new Map(inspected.files.filter((entry) => entry.type === "5").map((entry) => [entry.path, entry.mode]));
  const root = resolve(destination);
  try { await mkdir(root, { mode: 0o700 }); } catch (error) { if (error?.code === "EEXIST") fail("snapshot destination exists"); throw error; }
  await chmodVerified(root, 0o700, "extraction root", "directory");
  for (const entry of inspected.files) {
    const target = resolve(root, entry.path);
    if (!inside(root, target)) fail("archive extraction traversal");
    const parts = relative(root, target).split(sep); let cursor = root;
    for (const part of parts.slice(0, -1)) { cursor = join(cursor, part); const mode = directoryModes.get(relative(root, cursor).split(sep).join("/")) ?? 0o700; try { await mkdir(cursor, { mode }); } catch (error) { if (error?.code !== "EEXIST") throw error; } await chmodVerified(cursor, mode, "extraction parent", "directory"); }
    if (entry.type === "5") { await mkdir(target, { mode: entry.mode }); await chmodVerified(target, entry.mode, "extracted directory", "directory"); continue; }
    const handle = await open(target, "wx", entry.mode); try { await handle.writeFile(bytes.subarray(entry.offset, entry.offset + entry.size)); } finally { await handle.close(); }
    await chmodVerified(target, entry.mode, "extracted file", "file");
  }
  return Object.freeze({ root, archiveHash: inspected.archiveHash, entries: inspected.materialEntries });
}

async function chmodVerified(path, mode, label, type) {
  const before = await lstat(path);
  if (before.isSymbolicLink() || (type === "directory" && !before.isDirectory()) || (type === "file" && !before.isFile())) fail(`unsafe ${label}`);
  await chmod(path, mode);
  const info = await lstat(path);
  if (info.isSymbolicLink() || (type === "directory" && !info.isDirectory()) || (type === "file" && !info.isFile()) || (info.mode & 0o777) !== mode) fail(`unsafe ${label} mode`);
  return info;
}

async function checkedExecutable(candidates) {
  for (const candidate of candidates) try { return await executableIdentity(candidate); } catch {}
  fail("required fixed executable unavailable");
}
async function runChecked(expected, args, options) {
  const result = await runBounded(expected.path, args, options);
  if (result.identity.path !== expected.path || result.identity.sha256 !== expected.sha256) fail("executable identity changed");
  return result;
}
async function gitCleanArchive(git, repository, env) {
  const head = (await runChecked(git, ["rev-parse", "--verify", "HEAD^{commit}"], { cwd: repository, env })).stdout.toString("utf8").trim();
  if (!/^[0-9a-f]{40}$/.test(head)) fail("source is not an exact commit");
  const status = (await runChecked(git, ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: repository, env })).stdout;
  if (status.length) fail("source checkout is dirty");
  const archive = (await runChecked(git, ["archive", "--format=tar", head], { cwd: repository, env, outputBytes: 64 * 1024 * 1024 })).stdout;
  return Object.freeze({ head, archive, inspected: inspectGitArchive(archive) });
}
function canonical(value) { if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`; if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`; return JSON.stringify(value); }
export function normalizeFullRender(render, { extractionRoot, project, marker }) {
  const text = Buffer.isBuffer(render) ? render.toString("utf8") : String(render);
  let parsed; try { parsed = JSON.parse(text); } catch { fail("Compose render must be JSON"); }
  if (JSON.stringify(Object.keys(parsed).sort()) !== JSON.stringify(["name", "networks", "secrets", "services", "volumes"])) fail("full render top-level contract drift");
  if (!parsed.services || JSON.stringify(Object.keys(parsed.services).sort()) !== JSON.stringify([...G2_SERVICES].sort())) fail("full render service contract drift");
  if (!extractionRoot || !project || !marker) fail("normalization inputs required");
  const root = resolve(extractionRoot); const copy = structuredClone(parsed);
  const snapshotPath = (value) => { if (typeof value !== "string" || !value.startsWith("/") || !inside(root, resolve(value))) fail("snapshot path drift"); return `<snapshot>${value.slice(root.length)}`; };
  if (copy.name !== project) fail("project name drift"); copy.name = "<project>";
  for (const kind of ["networks", "volumes", "secrets"]) for (const [name, item] of Object.entries(copy[kind] ?? {})) {
    if (!item || item.name !== `${project}_${name}`) fail("project resource name drift"); item.name = `<project>_${name}`;
  }
  for (const item of Object.values(copy.secrets ?? {})) { if (!Object.hasOwn(item, "file")) fail("secret file drift"); item.file = snapshotPath(item.file); }
  const markerArgs = { migrate: ["BUILD_MARKER"], api: ["BUILD_MARKER"], web: ["BUILD_MARKER", "VITE_BUILD_MARKER"] };
  for (const [name, service] of Object.entries(copy.services)) {
    if (service.build) { if (!Object.hasOwn(markerArgs, name)) fail("unexpected build service"); service.build.context = snapshotPath(service.build.context); for (const arg of markerArgs[name]) { if (service.build.args?.[arg] !== marker) fail("build marker drift"); service.build.args[arg] = "<marker>"; } }
    for (const volume of service.volumes ?? []) if (volume.type === "bind") volume.source = snapshotPath(volume.source);
  }
  const forbidden = [root, project, marker];
  const scan = (value) => { if (Array.isArray(value)) return value.forEach(scan); if (value && typeof value === "object") return Object.values(value).forEach(scan); if (typeof value === "string" && forbidden.some((part) => value.includes(part))) fail("normalization outside approved location"); };
  scan(copy);
  return Buffer.from(canonical(copy));
}

/** Pure two-pass comparison only; it neither invokes Compose nor grants authority. */
export function compareTwoPassRender({ preliminary, final, extractionRoot, project, preliminaryMarker, finalMarker, runId, sourceCommit, archiveHash, golden }) {
  const expectedPreliminary = g2PreliminaryMarker({ runId, sourceCommit, archiveHash });
  if (preliminaryMarker !== expectedPreliminary) fail("preliminary build marker drift");
  const first = normalizeFullRender(preliminary, { extractionRoot, project, marker: preliminaryMarker });
  const renderHash = digest(first); const expectedFinal = g2BuildMarker({ runId, sourceCommit, archiveHash, renderHash });
  if (finalMarker !== expectedFinal) fail("final build marker drift");
  const second = normalizeFullRender(final, { extractionRoot, project, marker: finalMarker });
  if (!first.equals(second)) fail("two-pass render drift");
  if (!Buffer.isBuffer(golden) || !second.equals(golden)) fail("full render golden drift");
  return Object.freeze({ renderHash, markerInputHash: renderHash });
}

/** Fixed production orchestration only. It stops at the intentionally absent reviewed render golden. */
export async function prepareG2Snapshot() {
  // This is a code gate, intentionally before root creation, executable lookup,
  // or any child process.  A golden file can never enable this dormant utility.
  fail(G2_SNAPSHOT_DISABLED_ERROR);
  /* c8 ignore start -- retained design sketch, unreachable by contract. */
  const root = await createPrivateSnapshotRoot();
  try {
    const env = snapshotChildEnv(process.env, root);
    const git = await checkedExecutable(["/usr/bin/git", "/bin/git"]);
    const node = await checkedExecutable([process.execPath]);
    const pnpm = await checkedExecutable(["/usr/local/bin/pnpm", "/usr/bin/pnpm"]);
    const docker = await checkedExecutable(["/usr/bin/docker", "/usr/local/bin/docker"]);
    const compose = await checkedExecutable(["/usr/lib/docker/cli-plugins/docker-compose", "/usr/local/lib/docker/cli-plugins/docker-compose"]);
    const pnpmVersion = (await runChecked(pnpm, ["--version"], { env })).stdout.toString("utf8").trim();
    if (pnpmVersion !== "10.33.0") fail("required pnpm@10.33.0 unavailable");
    const source = await gitCleanArchive(git, ROOT, env);
    const snapshot = await extractGitArchive(source.archive, join(root, "snapshot"));
    await runChecked(pnpm, ["install", "--frozen-lockfile", "--ignore-scripts"], { cwd: snapshot.root, env, timeoutMs: SNAPSHOT_LIMITS.installTimeoutMs, outputBytes: SNAPSHOT_LIMITS.installOutputBytes });
    await runChecked(node, ["scripts/check-matrix-policy.mjs"], { cwd: snapshot.root, env });
    return Object.freeze({ sourceCommit: source.head, archiveHash: source.inspected.archiveHash, executableIdentities: Object.freeze({ git, node, pnpm, docker, compose }) });
  } finally { await destroyPrivateSnapshotRoot(root); }
  /* c8 ignore stop */
}
