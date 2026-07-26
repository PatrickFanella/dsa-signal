import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  StageError,
  assertGatewayResponses,
  assertSynapseResponses,
  extractDockerSubnets,
  defaultCommand,
  localHttpsRequest,
  main,
  runNegativeMatrix,
  selectCollisionFreeSubnets,
} from "./test-matrix-negative.mjs";

const okGateway = () => ({
  federation: { status: 404 }, key: { status: 404 }, admin: { status: 404 }, serverWellKnown: { status: 404 },
  clientWellKnown: { status: 200, headers: { "content-type": "application/json", "access-control-allow-origin": "https://chat.localhost:8443" }, body: '{"m.homeserver":{"base_url":"https://matrix.localhost:8443"}}' },
});
const okSynapse = () => ({
  guestRegistration: { status: 403, json: { errcode: "M_FORBIDDEN" } },
  publicDirectory: { status: 401, json: { errcode: "M_MISSING_TOKEN" } },
  urlPreview: { status: 401, json: { errcode: "M_MISSING_TOKEN" } },
  loginFlow: { status: 404, json: { errcode: "M_UNRECOGNIZED" } },
  passwordLogin: { status: 404, json: { errcode: "M_UNRECOGNIZED" } },
  federationDirect: { status: 404, json: { errcode: "M_UNRECOGNIZED" } },
});

function harness({ failAt, gateway = okGateway(), synapse = okSynapse(), positive = "canary", isolation = { reachable: false }, logs = "request control-070707070707070707070707" } = {}) {
  const calls = [];
  let synapseIndex = 0;
  const temporary = "/tmp/dsa-matrix-negative-unit";
  const runtime = {
    root: "/repo",
    makeTemp: async () => temporary,
    chmod: async () => {}, writeFile: async () => {}, appendFile: async () => {}, remove: async () => {},
    generateSecrets: async () => { if (failAt === "secrets") throw new Error("secret-value-that-must-not-leak"); },
    random: (size) => Buffer.alloc(size, 7), findPort: async () => 49152,
    readFile: async () => "CADDY_IMAGE=caddy@sha256:abc\n",
    readdir: async () => [],
    httpRequest: async ({ path }) => {
      const names = { "/_matrix/federation/v1/version": "federation", "/_matrix/key/v2/server": "key", "/_synapse/admin/v1/server_version": "admin", "/.well-known/matrix/server": "serverWellKnown", "/.well-known/matrix/client": "clientWellKnown" };
      return gateway[names[path]];
    },
    command: async (file, args, options) => {
      calls.push({ file, args, options });
      const joined = args.join(" ");
      if (joined.includes("network ls")) return { stdout: "", stderr: "" };
      if (joined.includes(" up ") && failAt === "compose-up") throw Object.assign(new Error("upstream-secret-value"), { stderr: "details" });
      if (joined.includes(" up ")) return { stdout: "", stderr: "" };
      if (joined.includes("python -c") && joined.includes("127.0.0.1:8008")) return { stdout: JSON.stringify(Object.values(synapse)[synapseIndex++]), stderr: "" };
      if (joined.includes("docker run") || args[0] === "run") return { stdout: positive, stderr: "" };
      if (joined.includes("python -c")) return { stdout: JSON.stringify(isolation), stderr: "" };
      if (joined.includes("logs --no-color egress-canary")) return { stdout: logs, stderr: "" };
      return { stdout: "", stderr: "" };
    },
  };
  return { runtime, calls };
}

test("selects a non-overlapping subnet trio including supernet collisions", () => {
  const triples = [["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"], ["10.30.1.0/24", "10.30.2.0/24", "10.30.3.0/24"]];
  assert.deepEqual(selectCollisionFreeSubnets(["10.20.0.0/16"], triples), triples[1]);
  assert.deepEqual(extractDockerSubnets([{ IPAM: { Config: [{ Subnet: "172.20.0.0/16" }] } }]), ["172.20.0.0/16"]);
  assert.throws(() => selectCollisionFreeSubnets(["10.20.0.0/16", "10.30.0.0/16"], triples), /no collision-free/);
  assert.throws(() => selectCollisionFreeSubnets([], [["10.40.0.0/23", "10.40.1.0/24", "10.42.0.0/24"]]), /no collision-free/);
});

test("gateway assertions require exact denials, JSON, CORS, and safe keys", () => {
  assert.doesNotThrow(() => assertGatewayResponses(okGateway()));
  for (const mutate of [
    (x) => { x.federation.status = 403; },
    (x) => { x.clientWellKnown.headers["content-type"] = "text/plain"; },
    (x) => { x.clientWellKnown.headers["access-control-allow-origin"] = "*"; },
    (x) => { x.clientWellKnown.body = '{"m.homeserver":{"base_url":"https://matrix.localhost:8443"},"m.identity_server":{}}'; },
  ]) { const value = structuredClone(okGateway()); mutate(value); assert.throws(() => assertGatewayResponses(value)); }
});

test("Synapse assertions pin statuses and exclude password and guest flows", () => {
  assert.doesNotThrow(() => assertSynapseResponses(okSynapse()));
  const wrongStatus = structuredClone(okSynapse()); wrongStatus.publicDirectory.status = 403;
  assert.throws(() => assertSynapseResponses(wrongStatus), /public directory status/);
  const passwordFlow = structuredClone(okSynapse()); passwordFlow.loginFlow.json.flows = [{ type: "m.login.password" }];
  assert.throws(() => assertSynapseResponses(passwordFlow), /must be absent/);
});

test("orders lifecycle commands and always cleans up", async () => {
  const { runtime, calls } = harness();
  await runNegativeMatrix(runtime);
  const commands = calls.map((call) => call.args.join(" "));
  assert.ok(commands.findIndex((x) => x.includes("network ls")) < commands.findIndex((x) => x.includes(" up -d --wait")));
  assert.ok(commands.findIndex((x) => x.includes(" up -d --wait")) < commands.findIndex((x) => x.includes("exec -T synapse")));
  assert.match(commands.at(-1), /down -v --remove-orphans$/);
  const up = calls.find((call) => call.args.includes("up"));
  assert.equal(up.options.env.MATRIX_LOCAL_SECRETS_DIR, "/tmp/dsa-matrix-negative-unit/matrix-secrets");
  assert.ok(up.args.includes("deploy/locks/images.env") && up.args.includes("deploy/local/example.env"));
});

for (const failure of ["secrets", "compose-up"]) {
  test(`cleanup runs after ${failure} failure`, async () => {
    const { runtime, calls } = harness({ failAt: failure });
    await assert.rejects(runNegativeMatrix(runtime), (error) => error instanceof StageError);
    assert.match(calls.at(-1).args.join(" "), /down -v --remove-orphans$/);
  });
}

test("command timeout is bounded and forwarded to compose up", async () => {
  const { runtime, calls } = harness();
  await runNegativeMatrix({ ...runtime, commandTimeoutMs: 1234 });
  assert.equal(calls.find((call) => call.args.includes("up")).options.timeoutMs, 1234);
});

test("append and diagnostic failures cannot prevent cleanup", async () => {
  const { runtime, calls } = harness({ failAt: "compose-up" });
  runtime.appendFile = async () => { throw new Error("append failed"); };
  const original = runtime.command;
  runtime.command = async (...args) => {
    if (args[1].includes("ps") || args[1].includes("logs")) throw new Error("diagnostic failed");
    return original(...args);
  };
  await assert.rejects(runNegativeMatrix(runtime), (error) => error.stage === "compose-up");
  assert.ok(calls.some((call) => /down -v --remove-orphans$/.test(call.args.join(" "))));
});

test("cleanup failure is retained with a primary failure", async () => {
  const { runtime } = harness({ failAt: "compose-up" });
  let removed = false;
  runtime.remove = async () => { removed = true; };
  const original = runtime.command;
  runtime.command = async (...args) => {
    if (args[1].includes("down")) throw new Error("down failed");
    return original(...args);
  };
  await assert.rejects(runNegativeMatrix(runtime), (error) => error.stage === "cleanup" && error.cause instanceof AggregateError && error.cause.errors.length === 2);
  assert.equal(removed, true, "temporary secret tree is removed even when down fails");
});

test("cleanup failure after success is never swallowed", async () => {
  const { runtime } = harness();
  const original = runtime.command;
  runtime.command = async (...args) => args[1].includes("down") ? Promise.reject(new Error("down failed")) : original(...args);
  await assert.rejects(runNegativeMatrix(runtime), (error) => error.stage === "cleanup");
});

test("CLI reports only coarse stage and no nested secret", async () => {
  const { runtime } = harness({ failAt: "compose-up" });
  let stderr = "";
  assert.equal(await main([], { ...runtime, stderr: (text) => { stderr += text; } }), 1);
  assert.match(stderr, /failed \(compose-up\)/);
  assert.doesNotMatch(stderr, /upstream-secret|details|sha256/);
});

test("retained diagnostics redact generated hex, Base64, PEM, and multiline secrets", async () => {
  const { runtime } = harness({ failAt: "compose-up" });
  const hex = "a".repeat(64); const base64 = "A".repeat(43); const pem = "-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----";
  const retained = [];
  runtime.readdir = async () => ["hex", "base64", "pem"];
  runtime.readFile = async (path) => path.endsWith("images.env") ? "CADDY_IMAGE=caddy@sha256:abc\n" : path.endsWith("hex") ? hex : path.endsWith("base64") ? base64 : pem;
  runtime.appendFile = async (_path, text) => { retained.push(text); };
  const original = runtime.command;
  runtime.command = async (...args) => {
    if (args[1].includes("up")) throw Object.assign(new Error("failed"), { stdout: `${hex} ${base64} ${pem}`, stderr: pem });
    return original(...args);
  };
  await assert.rejects(runNegativeMatrix(runtime));
  const output = retained.join("\n");
  for (const secret of [hex, base64, pem, "secret-key-material"]) assert.doesNotMatch(output, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("a secret inventory read failure skips diagnostics, runs down, and removes raw files", async () => {
  const { runtime, calls } = harness();
  const temporary = await mkdtemp(join(tmpdir(), "matrix-negative-cleanup-"));
  const raw = "raw-secret-must-not-remain";
  runtime.makeTemp = async () => temporary;
  runtime.writeFile = writeFile;
  runtime.remove = (path) => rm(path, { recursive: true, force: true });
  runtime.generateSecrets = async ({ upstream, output }) => {
    await mkdir(output, { recursive: true });
    await writeFile(upstream, raw);
    await writeFile(join(output, "unreadable"), raw);
  };
  runtime.readdir = async () => ["unreadable"];
  runtime.readFile = async () => { throw new Error("cannot read generated secret"); };
  await assert.rejects(runNegativeMatrix(runtime), (error) => error.stage === "secrets");
  assert.ok(calls.some((call) => /down -v --remove-orphans$/.test(call.args.join(" "))));
  assert.equal(calls.some((call) => call.args.includes("ps") || call.args.includes("logs")), false, "unsafe diagnostics must be skipped");
  await assert.rejects(readdir(temporary));
});

test("debug success removes generated raw secret directory after teardown", async () => {
  const { runtime, calls } = harness();
  const temporary = await mkdtemp(join(tmpdir(), "matrix-negative-debug-cleanup-"));
  const raw = "raw-secret-must-not-remain";
  runtime.makeTemp = async () => temporary;
  runtime.writeFile = writeFile;
  runtime.remove = (path) => rm(path, { recursive: true, force: true });
  runtime.generateSecrets = async ({ upstream, output }) => {
    await mkdir(output, { recursive: true });
    await writeFile(upstream, raw);
    await writeFile(join(output, "secret"), raw);
  };
  runtime.readdir = readdir;
  runtime.readFile = async (path) => path.endsWith("images.env") ? "CADDY_IMAGE=caddy@sha256:abc\n" : readFile(path, "utf8");
  await runNegativeMatrix({ ...runtime, debug: true });
  assert.match(calls.at(-1).args.join(" "), /down -v --remove-orphans$/);
  await assert.rejects(readdir(temporary));
});

test("default command bounds descendant output without waiting for close", async () => {
  const script = "require('node:child_process').spawn(process.execPath,['-e',\"setInterval(()=>process.stdout.write('x'.repeat(1024)),1)\"],{stdio:'inherit'}); setTimeout(()=>process.exit(0),10)";
  const started = Date.now();
  await assert.rejects(defaultCommand(process.execPath, ["-e", script], { timeoutMs: 200, maxBytes: 4096 }), (error) => {
    assert.ok(error.stdout.length < 16 * 1024, "output must stop accumulating at the limit");
    return true;
  });
  assert.ok(Date.now() - started < 500, "command must not wait for inherited descendant pipes");
});

test("positive control must return exact canary response", async () => {
  const { runtime, calls } = harness({ positive: "wrong" });
  await assert.rejects(runNegativeMatrix(runtime), (error) => error.stage === "canary-positive-control");
  assert.match(calls.at(-1).args.join(" "), /down -v --remove-orphans$/);
});

test("positive-control nonce must appear in canary access logs", async () => {
  const { runtime } = harness({ logs: "" });
  await assert.rejects(runNegativeMatrix(runtime), (error) => error.stage === "canary-positive-control");
});

test("reachable canary fails isolation and still cleans up", async () => {
  const { runtime, calls } = harness({ isolation: { reachable: true, status: 200, body: "canary" } });
  await assert.rejects(runNegativeMatrix(runtime), (error) => error.stage === "canary-isolation" && /unexpectedly reached/.test(error.cause.message));
  assert.match(calls.at(-1).args.join(" "), /down -v --remove-orphans$/);
});

test("nonce in canary logs fails isolation", async () => {
  const nonce = "probe-070707070707070707070707";
  const { runtime, calls } = harness({ logs: `request control-070707070707070707070707 request ${nonce}` });
  await assert.rejects(runNegativeMatrix(runtime), (error) => error.stage === "canary-isolation" && /blocked nonce/.test(error.cause.message));
  assert.match(calls.at(-1).args.join(" "), /down -v --remove-orphans$/);
});
