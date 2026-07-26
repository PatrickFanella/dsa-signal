import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { appendFile, chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { generateMatrixLocalSecrets } from "./generate-matrix-local-secrets.mjs";

const ROOT = resolve(new URL("../", import.meta.url).pathname);
const COMPOSE_FILE = "deploy/local/compose.yaml";
const LOCK_ENV = "deploy/locks/images.env";
const EXAMPLE_ENV = "deploy/local/example.env";
const COMMAND_TIMEOUT_MS = 180_000;
const HTTP_TIMEOUT_MS = 5_000;
const HTTP_DEADLINE_MS = 10_000;
const HTTP_MAX_BODY_BYTES = 64 * 1024;
const COMMAND_KILL_GRACE_MS = 100;

export const SYNAPSE_EXPECTATIONS = Object.freeze({
  guestRegistration: { status: 403, errcode: "M_FORBIDDEN" },
  publicDirectory: { status: 401, errcode: "M_MISSING_TOKEN" },
  urlPreview: { status: 401, errcode: "M_MISSING_TOKEN" },
  passwordLogin: { status: 404, errcode: "M_UNRECOGNIZED" },
});

export class StageError extends Error {
  constructor(stage, cause) {
    super(`negative validation failed at ${stage}`, { cause });
    this.name = "StageError";
    this.stage = stage;
  }
}

const redact = (value, secrets = []) => {
  let result = String(value);
  for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) result = result.replaceAll(secret, "[secret]");
  return result.replace(/(?:[A-Fa-f0-9]{64}|[A-Za-z0-9_-]{43}|[A-Za-z0-9+/]{43}={0,2})/g, "[secret]").replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[secret]");
};

export async function defaultCommand(file, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? COMMAND_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? 8 * 1024 * 1024;
  return new Promise((resolveCommand, rejectCommand) => {
    const grouped = process.platform === "linux";
    const child = spawn(file, args, { cwd: ROOT, detached: grouped, env: { ...process.env, ...options.env }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = ""; let stderr = ""; let settled = false; let limited = false;
    const finish = (fn, value) => { if (!settled) { settled = true; clearTimeout(timer); fn(value); } };
    const signal = (name) => { try { grouped ? process.kill(-child.pid, name) : child.kill(name); } catch { /* Already exited or process groups unsupported. */ } };
    const limit = () => {
      if (limited) return;
      limited = true;
      child.stdout.resume(); child.stderr.resume();
      signal("SIGTERM");
      setTimeout(() => signal("SIGKILL"), COMMAND_KILL_GRACE_MS).unref();
      const error = new Error("command failed"); error.stdout = stdout; error.stderr = stderr;
      finish(rejectCommand, error);
    };
    const collect = (key) => (chunk) => {
      if (limited) return;
      if (key === "stdout") stdout += chunk; else stderr += chunk;
      if (Buffer.byteLength(key === "stdout" ? stdout : stderr) > maxBytes) limit();
    };
    child.stdout.on("data", collect("stdout")); child.stderr.on("data", collect("stderr"));
    const timer = setTimeout(limit, timeoutMs);
    child.on("error", (error) => { error.stdout ??= stdout; error.stderr ??= stderr; finish(rejectCommand, error); });
    child.on("close", (code) => code === 0 && !limited ? finish(resolveCommand, { stdout, stderr, code }) : finish(rejectCommand, Object.assign(new Error("command failed"), { stdout, stderr })));
  });
}

export function candidateSubnetTriples() {
  return Array.from({ length: 80 }, (_, index) => {
    const base = 160 + index;
    return [`10.253.${base}.0/24`, `10.253.${base + 1}.0/24`, `10.253.${base + 2}.0/24`];
  }).filter((triple) => Number(triple[2].split(".")[2]) <= 254);
}

function ipv4ToInt(address) {
  const pieces = address.split(".").map(Number);
  if (pieces.length !== 4 || pieces.some((piece) => !Number.isInteger(piece) || piece < 0 || piece > 255)) return undefined;
  return pieces.reduce((value, piece) => ((value << 8) | piece) >>> 0, 0);
}

function cidrRange(cidr) {
  const [address, bitsText] = String(cidr).split("/");
  const bits = Number(bitsText);
  const ip = ipv4ToInt(address);
  if (ip === undefined || !Number.isInteger(bits) || bits < 0 || bits > 32) return undefined;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const first = (ip & mask) >>> 0;
  return [first, (first | (~mask >>> 0)) >>> 0];
}

function overlaps(left, right) {
  const a = cidrRange(left);
  const b = cidrRange(right);
  return a && b ? a[0] <= b[1] && b[0] <= a[1] : false;
}

export function selectCollisionFreeSubnets(existing, triples = candidateSubnetTriples()) {
  const occupied = existing.filter((cidr) => cidrRange(cidr));
  const selected = triples.find((triple) => triple.length === 3 && triple.every((cidr) => cidrRange(cidr) && occupied.every((used) => !overlaps(cidr, used))) && triple.every((cidr, index) => triple.slice(index + 1).every((other) => !overlaps(cidr, other))));
  if (!selected) throw new Error("no collision-free subnet trio");
  return selected;
}

export function extractDockerSubnets(networks) {
  return networks.flatMap((network) => network?.IPAM?.Config ?? []).map((entry) => entry?.Subnet).filter(Boolean);
}

export async function unusedLoopbackPort() {
  return new Promise((resolvePort, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close((error) => error ? reject(error) : resolvePort(address.port));
    });
  });
}

export async function localHttpsRequest({ port, servername, path, method = "GET", body, deadlineMs = HTTP_DEADLINE_MS, maxBodyBytes = HTTP_MAX_BODY_BYTES }) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("invalid local HTTPS port");
  if (!new Set(["chat.localhost", "matrix.localhost", "auth.localhost"]).has(servername)) throw new Error("invalid local SNI");
  return new Promise((resolveRequest, reject) => {
    let settled = false;
    const finish = (fn, value) => { if (!settled) { settled = true; clearTimeout(deadline); fn(value); } };
    const request = https.request({
      hostname: "127.0.0.1",
      port,
      servername,
      method,
      path,
      rejectUnauthorized: false, // Deliberately scoped to Caddy's loopback-only local CA endpoint above.
      headers: { Host: `${servername}:8443`, ...(body ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } : {}) },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => { size += chunk.length; if (size > maxBodyBytes) request.destroy(new Error("HTTPS response body too large")); else chunks.push(chunk); });
      response.on("end", () => finish(resolveRequest, { status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.setTimeout(HTTP_TIMEOUT_MS, () => request.destroy(new Error("HTTPS request timed out")));
    const deadline = setTimeout(() => request.destroy(new Error("HTTPS request deadline exceeded")), deadlineMs);
    request.once("error", (error) => finish(reject, error));
    if (body) request.write(body);
    request.end();
  });
}

export function assertGatewayResponses(responses) {
  for (const name of ["federation", "key", "admin", "serverWellKnown"]) {
    assert.equal(responses[name]?.status, 404, `${name} must return exactly 404`);
  }
  const client = responses.clientWellKnown;
  assert.equal(client?.status, 200, "client well-known status");
  assert.match(String(client.headers?.["content-type"] ?? ""), /^application\/json(?:;|$)/i, "client well-known content type");
  assert.equal(client.headers?.["access-control-allow-origin"], "https://chat.localhost:8443", "client well-known CORS origin");
  const parsed = JSON.parse(client.body);
  assert.deepEqual(parsed, { "m.homeserver": { base_url: "https://matrix.localhost:8443" } }, "client well-known body");
  assert.equal(parsed["m.identity_server"], undefined, "identity server must be absent");
  assert.equal(parsed["org.matrix.msc2965.authentication"], undefined, "experimental authentication must be absent");
}

function assertMatrixError(response, expected, label) {
  assert.equal(response.status, expected.status, `${label} status`);
  assert.equal(response.json?.errcode, expected.errcode, `${label} error code`);
}

export function assertSynapseResponses(responses) {
  assertMatrixError(responses.guestRegistration, SYNAPSE_EXPECTATIONS.guestRegistration, "guest registration");
  assertMatrixError(responses.publicDirectory, SYNAPSE_EXPECTATIONS.publicDirectory, "public directory");
  assertMatrixError(responses.urlPreview, SYNAPSE_EXPECTATIONS.urlPreview, "URL preview");
  assert.equal(responses.loginFlow.status, 404, "login flow status");
  assert.equal(responses.loginFlow.json?.flows, undefined, "login flows must be absent");
  assertMatrixError(responses.passwordLogin, SYNAPSE_EXPECTATIONS.passwordLogin, "password login");
  assert.equal(responses.federationDirect.status, 404, "Synapse federation resource must return exactly 404");
}

const pythonRequest = String.raw`import json,sys,urllib.error,urllib.request
method,path,raw=sys.argv[1:4]
request=urllib.request.Request("http://127.0.0.1:8008"+path,data=(raw.encode() if raw else None),method=method,headers={"Content-Type":"application/json"})
try:
 response=urllib.request.urlopen(request,timeout=5); body=response.read().decode(); status=response.status
except urllib.error.HTTPError as error:
 status=error.code; body=error.read().decode()
try: parsed=json.loads(body)
except Exception: parsed=None
print(json.dumps({"status":status,"json":parsed}))`;

const canaryProbe = String.raw`import json,sys,urllib.request
try:
 response=urllib.request.urlopen("http://"+sys.argv[1]+":8080/"+sys.argv[2],timeout=2)
 print(json.dumps({"reachable":True,"status":response.status,"body":response.read().decode()}))
except Exception as error:
 print(json.dumps({"reachable":False,"error":type(error).__name__}))`;

function composeArgs(project, ...args) {
  return ["compose", "--env-file", LOCK_ENV, "--env-file", EXAMPLE_ENV, "-p", project, "-f", COMPOSE_FILE, "--profile", "negative", ...args];
}

function gatewayRequests(httpRequest, port) {
  return Promise.all([
    ["federation", "matrix.localhost", "/_matrix/federation/v1/version"],
    ["key", "matrix.localhost", "/_matrix/key/v2/server"],
    ["admin", "matrix.localhost", "/_synapse/admin/v1/server_version"],
    ["serverWellKnown", "matrix.localhost", "/.well-known/matrix/server"],
    ["clientWellKnown", "chat.localhost", "/.well-known/matrix/client"],
  ].map(async ([name, servername, path]) => [name, await httpRequest({ port, servername, path })])).then(Object.fromEntries);
}

function parseJsonOutput(result, label) {
  try { return JSON.parse(result.stdout.trim()); } catch { throw new Error(`${label} returned invalid JSON`); }
}

async function callSynapse(run, compose, options, method, path, body = "") {
  const result = await run("docker", [...compose, "exec", "-T", "synapse", "python", "-c", pythonRequest, method, path, body], options);
  return parseJsonOutput(result, "Synapse probe");
}

async function discoverSubnets(run) {
  const listed = await run("docker", ["network", "ls", "--format", "{{.ID}}"]) ;
  const ids = listed.stdout.trim().split(/\s+/).filter(Boolean);
  if (!ids.length) return [];
  const inspected = await run("docker", ["network", "inspect", ...ids]);
  return extractDockerSubnets(JSON.parse(inspected.stdout));
}

function defaultRuntime() {
  return {
    root: ROOT,
    command: defaultCommand,
    httpRequest: localHttpsRequest,
    findPort: unusedLoopbackPort,
    makeTemp: () => mkdtemp(join(tmpdir(), "dsa-matrix-negative-")),
    generateSecrets: generateMatrixLocalSecrets,
    readFile,
    writeFile,
    chmod,
    appendFile, readdir,
    remove: (path) => rm(path, { recursive: true, force: true }),
    random: (size) => randomBytes(size),
    stderr: (text) => process.stderr.write(text),
    debug: process.env.MATRIX_NEGATIVE_DEBUG === "1",
  };
}

export async function runNegativeMatrix(overrides = {}) {
  const runtime = { ...defaultRuntime(), ...overrides };
  const temp = await runtime.makeTemp();
  await runtime.chmod(temp, 0o700);
  const logPath = join(temp, "commands.log");
  const project = `dsa-negative-${runtime.random(6).toString("hex")}`;
  let stage = "prepare";
  let compose = composeArgs(project);
  let composeOptions = { timeoutMs: overrides.commandTimeoutMs ?? COMMAND_TIMEOUT_MS };
  let secretValues = [];
  let redactionReady = false;
  const log = async (text) => { if (!redactionReady) return; try { await runtime.appendFile(logPath, `${redact(text, secretValues)}\n`, { mode: 0o600 }); } catch { /* Logging must never affect teardown or evidence. */ } };
  const run = async (file, args, options) => {
    await log(`$ ${file} ${args.join(" ")}`);
    try {
      const result = await runtime.command(file, args, options);
      await log(`stdout:\n${result.stdout ?? ""}\nstderr:\n${result.stderr ?? ""}`);
      return result;
    } catch (error) {
      await log(`command failed\nstdout:\n${error.stdout ?? ""}\nstderr:\n${error.stderr ?? ""}`);
      throw error;
    }
  };
  let failure;
  try {
    stage = "secrets";
    const upstream = join(temp, "upstream-client-secret");
    await runtime.writeFile(upstream, runtime.random(32).toString("base64url"), { mode: 0o600, flag: "wx" });
    await runtime.chmod(upstream, 0o600);
    const secretDir = join(temp, "matrix-secrets");
    await runtime.generateSecrets({ upstream, output: secretDir });
    const names = await runtime.readdir(secretDir);
    secretValues = await Promise.all(names.map(async (name) => (await runtime.readFile(join(secretDir, name), "utf8")).trim()));
    redactionReady = true;

    stage = "network-discovery";
    const existing = overrides.existingSubnets ?? await discoverSubnets(run);
    const [matrixSubnet, controlSubnet, canarySubnet] = selectCollisionFreeSubnets(existing, overrides.subnetTriples);
    const port = await runtime.findPort();
    const env = {
      MATRIX_LOCAL_SECRETS_DIR: secretDir,
      MATRIX_HTTPS_PORT: String(port),
      MATRIX_INTERNAL_SUBNET: matrixSubnet,
      MATRIX_INTERNAL_GATEWAY: matrixSubnet.replace(/\.0\/24$/, ".1"),
      GATEWAY_MATRIX_ADDRESS: matrixSubnet.replace(/\.0\/24$/, ".10"),
      CONTROL_INTERNAL_SUBNET: controlSubnet,
      CONTROL_INTERNAL_GATEWAY: controlSubnet.replace(/\.0\/24$/, ".1"),
      GATEWAY_CONTROL_ADDRESS: controlSubnet.replace(/\.0\/24$/, ".10"),
      CANARY_SUBNET: canarySubnet,
      CANARY_GATEWAY: canarySubnet.replace(/\.0\/24$/, ".1"),
      CANARY_ADDRESS: canarySubnet.replace(/\.0\/24$/, ".10"),
    };
    const commandOptions = { env, timeoutMs: overrides.commandTimeoutMs ?? COMMAND_TIMEOUT_MS };
    composeOptions = commandOptions;

    stage = "compose-up";
    await run("docker", [...compose, "up", "-d", "--wait"], commandOptions);

    stage = "gateway";
    assertGatewayResponses(await gatewayRequests(runtime.httpRequest, port));

    stage = "synapse-policy";
    const probes = {
      guestRegistration: ["POST", "/_matrix/client/v3/register?kind=guest", "{}"],
      publicDirectory: ["GET", "/_matrix/client/v3/publicRooms", ""],
      urlPreview: ["GET", "/_matrix/media/v3/preview_url?url=http%3A%2F%2Fexample.invalid", ""],
      loginFlow: ["GET", "/_matrix/client/v3/login", ""],
      passwordLogin: ["POST", "/_matrix/client/v3/login", JSON.stringify({ type: "m.login.password", identifier: { type: "m.id.user", user: "nobody" }, password: "not-a-secret" })],
      federationDirect: ["GET", "/_matrix/federation/v1/version", ""],
    };
    const synapseResponses = Object.fromEntries(await Promise.all(Object.entries(probes).map(async ([name, probe]) => [name, await callSynapse(run, compose, commandOptions, ...probe)])));
    assertSynapseResponses(synapseResponses);

    stage = "canary-positive-control";
    const locks = Object.fromEntries((await runtime.readFile(resolve(runtime.root, LOCK_ENV), "utf8")).split(/\r?\n/).filter((line) => /^[A-Z_]+=/.test(line)).map((line) => { const at = line.indexOf("="); return [line.slice(0, at), line.slice(at + 1)]; }));
    assert.ok(locks.CADDY_IMAGE, "CADDY_IMAGE lock is required");
    const positiveNonce = `control-${runtime.random(12).toString("hex")}`;
    const positive = await run("docker", ["run", "--rm", "--network", `${project}_canary`, locks.CADDY_IMAGE, "wget", "-q", "-T", "3", "-O", "-", `http://${env.CANARY_ADDRESS}:8080/${positiveNonce}`], commandOptions);
    assert.equal(positive.stdout, "canary", "canary positive control response");
    const positiveLogs = (await run("docker", [...compose, "logs", "--no-color", "egress-canary"], commandOptions)).stdout;
    assert.equal(positiveLogs.includes(positiveNonce), true, "canary logs must contain positive-control nonce");

    stage = "canary-isolation";
    const nonce = `probe-${runtime.random(12).toString("hex")}`;
    const isolation = parseJsonOutput(await run("docker", [...compose, "exec", "-T", "synapse", "python", "-c", canaryProbe, env.CANARY_ADDRESS, nonce], commandOptions), "canary isolation probe");
    assert.equal(isolation.reachable, false, "Synapse unexpectedly reached canary");
    const canaryLogs = (await run("docker", [...compose, "logs", "--no-color", "egress-canary"], commandOptions)).stdout;
    assert.equal(canaryLogs.includes(nonce), false, "canary logs contain blocked nonce");

    return { project, port, subnets: [matrixSubnet, controlSubnet, canarySubnet], synapseResponses, logPath };
  } catch (error) {
    failure = error instanceof StageError ? error : new StageError(stage, error);
    if (redactionReady) try {
      await log(`diagnostics for ${stage}`);
      await runtime.command("docker", [...compose, "ps", "-a"], { ...composeOptions, timeoutMs: 30_000 });
      await runtime.command("docker", [...compose, "logs", "--no-color", "--tail", "200"], { ...composeOptions, timeoutMs: 30_000 });
    } catch { /* Detailed diagnostics are best-effort. */ }
    throw failure;
  } finally {
    let cleanupError;
    try {
      await runtime.command("docker", [...compose, "down", "-v", "--remove-orphans"], { ...composeOptions, timeoutMs: 60_000 });
    } catch (downError) {
      cleanupError = downError;
    }
    try {
      await runtime.remove(temp);
    } catch (removeError) {
      cleanupError = cleanupError ? new AggregateError([cleanupError, removeError], "cleanup failed") : removeError;
    }
    if (cleanupError) {
      if (failure) throw new StageError("cleanup", new AggregateError([failure, cleanupError], "primary and cleanup failed"));
      throw new StageError("cleanup", cleanupError);
    }
  }
}

export async function main(_args = process.argv.slice(2), overrides = {}) {
  const stderr = overrides.stderr ?? ((text) => process.stderr.write(text));
  try {
    const result = await runNegativeMatrix(overrides);
    process.stdout.write(`Matrix negative validation passed (HTTPS ${result.port})\n`);
    return 0;
  } catch (error) {
    stderr(`Matrix negative validation failed (${error.stage ?? "unknown"})\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], "file:").href) process.exitCode = await main();
