import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { assertPostKillGroupVerification, assertSafeG2LaunchEnv, compareTwoPassRender, createPrivateSnapshotRoot, destroyPrivateSnapshotRoot, executableIdentity, extractGitArchive, G2_PROCESS_GROUP_CLEANUP_ERROR, normalizeFullRender, prepareG2Snapshot, runBounded, SNAPSHOT_LIMITS, SNAPSHOT_REJECTED_ENV_NAMES, snapshotChildEnv } from "./g2-provenance-snapshot.mjs";
import { G2_PRODUCTION_STATE, runG2 } from "./test-g2-encrypted-direct-chat.mjs";
import { g2BuildMarker, g2PreliminaryMarker } from "./g2-provenance-preparation.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function entry(path, body = Buffer.from("x"), type = "0", mode = type === "5" ? "0000755" : "0000644") {
  const h = Buffer.alloc(512); Buffer.from(path).copy(h); Buffer.from(mode + "\0").copy(h, 100); Buffer.from(body.length.toString(8).padStart(11, "0") + "\0").copy(h, 124); h.fill(32, 148, 156); h[156] = type.charCodeAt(); Buffer.from("ustar\0").copy(h, 257); Buffer.from("00").copy(h, 263); let sum = 0; for (const byte of h) sum += byte; Buffer.from(sum.toString(8).padStart(6, "0") + "\0 ").copy(h, 148); return Buffer.concat([h, body, Buffer.alloc(Math.ceil(body.length / 512) * 512 - body.length)]);
}
const archive = (...items) => Buffer.concat([...items, Buffer.alloc(1024)]);

test("private extraction accepts only inspected regular entries and cleanup is verified", async () => {
  const root = await createPrivateSnapshotRoot();
  try {
    const source = archive(entry("dir/", Buffer.alloc(0), "5"), entry("dir/file", Buffer.from("safe")), entry("run", Buffer.from("x"), "0", "0000755")); const snapshot = await extractGitArchive(source, join(root, "snapshot")); source.fill(0);
    assert.equal(await readFile(join(snapshot.root, "dir/file"), "utf8"), "safe");
    assert.equal((await (await import("node:fs/promises")).stat(join(snapshot.root, "run"))).mode & 0o777, 0o755);
    await assert.rejects(extractGitArchive(archive(entry("../escape")), join(root, "bad")));
    await symlink("/tmp", join(root, "link")); await assert.rejects(extractGitArchive(archive(entry("link/file")), join(root, "link")));
  } finally { await destroyPrivateSnapshotRoot(root); }
});

test("private and extracted modes are independent of restrictive or permissive umask", async () => {
  const originalUmask = process.umask();
  try {
    for (const mask of [0o077, 0o000]) {
      process.umask(mask);
      const root = await createPrivateSnapshotRoot();
      try {
        for (const name of ["home", "tmp", "xdg-config", "xdg-cache", "npm-cache", "npm-store", "pnpm-home", "pnpm-store", "docker-config"]) assert.equal((await stat(join(root, name))).mode & 0o777, 0o700);
        assert.equal((await stat(join(root, "npmrc"))).mode & 0o777, 0o600);
        const snapshot = await extractGitArchive(archive(entry("nested/", Buffer.alloc(0), "5"), entry("nested/file", Buffer.from("safe")), entry("run", Buffer.from("x"), "0", "0000755")), join(root, `snapshot-${mask}`));
        assert.equal((await stat(snapshot.root)).mode & 0o777, 0o700);
        assert.equal((await stat(join(snapshot.root, "nested"))).mode & 0o777, 0o755);
        assert.equal((await stat(join(snapshot.root, "nested/file"))).mode & 0o777, 0o644);
        assert.equal((await stat(join(snapshot.root, "run"))).mode & 0o777, 0o755);
      } finally { await destroyPrivateSnapshotRoot(root); }
    }
  } finally { process.umask(originalUmask); }
});

test("child environment strips hostile launch-time overrides and fixes private values", () => {
  const root = "/tmp/dsa-g2-snapshot-test"; const hostile = Object.fromEntries(SNAPSHOT_REJECTED_ENV_NAMES.map((name) => [name, "hostile"])); const env = snapshotChildEnv({ ...hostile, npm_config_registry: "bad", LANG: "C" }, root);
  assert.equal(env.LANG, "C"); assert.equal(env.npm_config_registry, undefined); assert.equal(env.PNPM_HOME, root + "/pnpm-home"); assert.equal(env.TMPDIR, root + "/tmp");
  for (const name of SNAPSHOT_REJECTED_ENV_NAMES) if (!["HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "DOCKER_CONFIG", "PNPM_HOME", "npm_config_userconfig", "npm_config_cache", "npm_config_store_dir", "pnpm_config_store_dir"].includes(name)) assert.equal(env[name], undefined, `${name} crossed into child`);
});

test("launch environment assertion rejects exact and patterned overrides, including empty values", () => {
  for (const name of SNAPSHOT_REJECTED_ENV_NAMES) {
    assert.throws(() => assertSafeG2LaunchEnv({ [name]: "hostile" }), new RegExp(name));
    assert.throws(() => assertSafeG2LaunchEnv({ [name]: "" }), new RegExp(name));
  }
  for (const name of ["npm_config_registry", "NPM_CONFIG_UNKNOWN_OVERRIDE", "PnPm_CoNfIg_Registry", "PNPM_HOME_ALT", "pnpm_store_custom", "PnPm_CaChE_Alt"]) {
    assert.throws(() => assertSafeG2LaunchEnv({ [name]: "hostile" }), new RegExp(name));
    assert.throws(() => assertSafeG2LaunchEnv({ [name]: "" }), new RegExp(name));
  }
  assert.doesNotThrow(() => assertSafeG2LaunchEnv({ LANG: "C", TZ: "UTC" }));
});

test("post-SIGKILL group verification has a fixed fail-closed limit", () => {
  assert.doesNotThrow(() => assertPostKillGroupVerification(SNAPSHOT_LIMITS.postKillVerificationPolls - 1));
  assert.throws(() => assertPostKillGroupVerification(SNAPSHOT_LIMITS.postKillVerificationPolls), new RegExp(G2_PROCESS_GROUP_CLEANUP_ERROR));
});

test("bounded subprocess records identity and bounds output, timeout, and spawn error", async () => {
  const shell = await executableIdentity("/bin/sh"); assert.match(shell.sha256, /^sha256:/);
  await assert.rejects(runBounded("/bin/sh", ["-c", "yes x"], { outputBytes: 128 }));
  await assert.rejects(runBounded("/bin/sh", ["-c", "sleep 2 & wait"], { timeoutMs: 10 }));
  await assert.rejects(runBounded("/bin/sh", ["-c", "true"], { cwd: "/definitely-not-a-directory", timeoutMs: 100 }));
});

test("bounded subprocess does not leave a timed-out descendant process group", async () => {
  const root = await mkdtemp(join(tmpdir(), "g2-child-")); const pidFile = join(root, "pid");
  try {
    await assert.rejects(runBounded("/bin/sh", ["-c", `sleep 30 & echo $! > ${pidFile}; wait`], { timeoutMs: 20 }));
    const pid = Number(await readFile(pidFile, "utf8"));
    assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("TERM-ignoring group is SIGKILLed and normal close reaps a background descendant", async () => {
  const root = await mkdtemp(join(tmpdir(), "g2-kill-")); const pidFile = join(root, "pid");
  try {
    await assert.rejects(runBounded("/bin/sh", ["-c", `trap '' TERM; (trap '' TERM; sleep 30) & echo $! > ${pidFile}; wait`], { timeoutMs: 20 }));
    const killedPid = Number(await readFile(pidFile, "utf8")); assert.throws(() => process.kill(killedPid, 0), { code: "ESRCH" });
    const result = await runBounded("/bin/sh", ["-c", `sleep 30 & echo $! > ${pidFile}`], { timeoutMs: 500 });
    const backgroundPid = Number(await readFile(pidFile, "utf8")); assert.equal(result.stdout.length, 0); assert.throws(() => process.kill(backgroundPid, 0), { code: "ESRCH" });
  } finally { await rm(root, { recursive: true, force: true }); }
});

const renderHash = (render) => `sha256:${createHash("sha256").update(render).digest("hex")}`;
const markerInputs = Object.freeze({ runId: "a".repeat(32), sourceCommit: "c".repeat(40), archiveHash: `sha256:${"d".repeat(64)}` });
function materializeGolden(golden, project, marker) {
  const replace = (value) => Array.isArray(value) ? value.map(replace) : value && typeof value === "object" ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replace(item)])) : typeof value === "string" ? value.replaceAll("<snapshot>", ROOT).replaceAll("<project>", project).replaceAll("<marker>", marker) : value;
  return JSON.stringify(replace(JSON.parse(golden)));
}

test("two-pass fixture validates checked-in golden and marker contract", async () => {
  const golden = await readFile(join(ROOT, "deploy/local/policy-fixtures/g2-full-render.golden.json"));
  const project = `dsa-g2-${markerInputs.runId}`;
  const preliminaryMarker = g2PreliminaryMarker(markerInputs);
  const preliminary = materializeGolden(golden, project, preliminaryMarker);
  const normalized = normalizeFullRender(preliminary, { extractionRoot: ROOT, project, marker: preliminaryMarker });
  assert.deepEqual(normalized, golden);
  const finalMarker = g2BuildMarker({ ...markerInputs, renderHash: renderHash(normalized) });
  const final = materializeGolden(golden, project, finalMarker);
  assert.equal(compareTwoPassRender({ preliminary, final, extractionRoot: ROOT, project, preliminaryMarker, finalMarker, ...markerInputs, golden }).renderHash, renderHash(normalized));
  assert.throws(() => compareTwoPassRender({ preliminary, final, extractionRoot: ROOT, project, preliminaryMarker: `sha256:${"e".repeat(64)}`, finalMarker, ...markerInputs, golden }), /preliminary build marker drift/);
  assert.throws(() => compareTwoPassRender({ preliminary, final, extractionRoot: ROOT, project, preliminaryMarker, finalMarker: `sha256:${"e".repeat(64)}`, ...markerInputs, golden }), /final build marker drift/);
  const structuralDrift = JSON.parse(final); structuralDrift.services.api.image = "drift";
  assert.throws(() => compareTwoPassRender({ preliminary, final: JSON.stringify(structuralDrift), extractionRoot: ROOT, project, preliminaryMarker, finalMarker, ...markerInputs, golden }), /two-pass render drift/);
  const goldenDrift = Buffer.from(golden); goldenDrift[0] ^= 1;
  assert.throws(() => compareTwoPassRender({ preliminary, final, extractionRoot: ROOT, project, preliminaryMarker, finalMarker, ...markerInputs, golden: goldenDrift }), /full render golden drift/);
});

test("full Compose render exactly normalizes to the reviewed golden", async (t) => {
  const docker = spawnSync("/usr/bin/docker", ["compose", "version"], { encoding: "utf8", timeout: 5_000 });
  if (docker.error || docker.status !== 0) return t.skip("docker compose explicitly unavailable");
  const project = `dsa-g2-${markerInputs.runId}`; const preliminaryMarker = g2PreliminaryMarker(markerInputs);
  const parseEnv = (text) => Object.fromEntries(text.split(/\n/).filter((line) => /^[A-Z_]+=/.test(line)).map((line) => line.split("=", 2)));
  const locks = await readFile(join(ROOT, "deploy/locks/images.env"), "utf8"); const policy = await readFile(join(ROOT, "deploy/local/policy.env"), "utf8");
  const compose = (marker) => spawnSync("/usr/bin/docker", ["compose", "-p", project, "--env-file", join(ROOT, "deploy/locks/images.env"), "--env-file", join(ROOT, "deploy/local/policy.env"), "--profile", "full", "-f", join(ROOT, "deploy/local/compose.yaml"), "config", "--format", "json"], { cwd: ROOT, env: { PATH: "/usr/bin:/bin", ...parseEnv(locks), ...parseEnv(policy), VITE_BUILD_MARKER: marker }, encoding: "buffer", timeout: 20_000 });
  const preliminary = compose(preliminaryMarker); assert.equal(preliminary.status, 0, preliminary.stderr?.toString()); const golden = await readFile(join(ROOT, "deploy/local/policy-fixtures/g2-full-render.golden.json"));
  assert.deepEqual(normalizeFullRender(preliminary.stdout, { extractionRoot: ROOT, project, marker: preliminaryMarker }), golden);
  const drift = JSON.parse(preliminary.stdout); drift.name = "wrong"; assert.throws(() => normalizeFullRender(JSON.stringify(drift), { extractionRoot: ROOT, project, marker: preliminaryMarker }));
  drift.name = project; drift.services["egress-canary"] = {}; assert.throws(() => normalizeFullRender(JSON.stringify(drift), { extractionRoot: ROOT, project, marker: preliminaryMarker }));
  delete drift.services["egress-canary"]; drift.services.api.build.context = "/outside"; assert.throws(() => normalizeFullRender(JSON.stringify(drift), { extractionRoot: ROOT, project, marker: preliminaryMarker }));
  drift.services.api.build.context = ROOT; drift.services.api.build.args.BUILD_MARKER = "wrong"; assert.throws(() => normalizeFullRender(JSON.stringify(drift), { extractionRoot: ROOT, project, marker: preliminaryMarker }));
  const normalized = normalizeFullRender(preliminary.stdout, { extractionRoot: ROOT, project, marker: preliminaryMarker }); const finalMarker = g2BuildMarker({ ...markerInputs, renderHash: renderHash(normalized) });
  const final = compose(finalMarker); assert.equal(final.status, 0, final.stderr?.toString());
  assert.equal(compareTwoPassRender({ preliminary: preliminary.stdout, final: final.stdout, extractionRoot: ROOT, project, preliminaryMarker, finalMarker, ...markerInputs, golden }).renderHash, renderHash(normalized));
});

test("real git distinguishes committed source from dirty and non-commit source", async () => {
  const repo = await mkdtemp(join(tmpdir(), "g2-snapshot-git-"));
  try {
    spawnSync("/usr/bin/git", ["init", "-q"], { cwd: repo, check: true }); await writeFile(join(repo, "a"), "a");
    assert.notEqual(spawnSync("/usr/bin/git", ["rev-parse", "--verify", "HEAD^{commit}"], { cwd: repo }).status, 0);
    spawnSync("/usr/bin/git", ["add", "."], { cwd: repo, check: true }); spawnSync("/usr/bin/git", ["-c", "user.name=x", "-c", "user.email=x@y", "commit", "-qm", "x"], { cwd: repo, check: true });
    await writeFile(join(repo, "a"), "dirty"); assert.notEqual(spawnSync("/usr/bin/git", ["status", "--porcelain"], { cwd: repo }).stdout.length, 0);
  } finally { await rm(repo, { recursive: true, force: true }); }
});

test("snapshot preparation does not make production G2 runnable", async () => {
  await assert.rejects(prepareG2Snapshot(), /DISABLED_NON_AUTHORITATIVE_G2_SNAPSHOT/);
  assert.equal(G2_PRODUCTION_STATE.disabled, true);
  await assert.rejects(runG2({ G2_ACCOUNT_ONE: "one", G2_ACCOUNT_TWO: "two", G2_ACCOUNT_ONE_ENTITLED: "authorized", G2_ACCOUNT_TWO_ENTITLED: "authorized", G2_WIRE_CAPTURE_ACCESS: "authorized", G2_POSTGRES_ACCESS: "authorized", G2_LOG_ACCESS: "authorized", G2_MEDIA_ACCESS: "authorized" }), /DISABLED_EXTERNAL_G2_COLLECTORS_UNAVAILABLE/);
});
