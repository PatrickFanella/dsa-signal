import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, readFileSync } from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { PROVENANCE_LIMITS, sha256 } from "./g2-provenance-preparation.mjs";
import { collectOciImageChain, isPublicIp, nodeRequest, normalizeRegistryReference, OciTransport } from "./g2-oci-transport.mjs";

const indexType = "application/vnd.oci.image.index.v1+json";
const manifestType = "application/vnd.oci.image.manifest.v1+json";
const configType = "application/vnd.oci.image.config.v1+json";
const digest = (bytes) => sha256(bytes);
async function* stream(bytes) { yield bytes; }
function chain(architecture = "amd64") {
  const config = Buffer.from(JSON.stringify({ os: "linux", architecture }));
  const child = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: manifestType,
    config: { mediaType: configType, digest: digest(config), size: config.length }, layers: [] }));
  const index = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: indexType, manifests: [{ mediaType: manifestType,
    digest: digest(child), size: child.length, platform: { os: "linux", architecture } }] }));
  return { index, child, config, lock: { registry: "registry-1.docker.io", repository: "library/node", indexDigest: digest(index), children: { amd64: architecture === "amd64" ? digest(child) : "sha256:" + "0".repeat(64), arm64: architecture === "arm64" ? digest(child) : "sha256:" + "0".repeat(64) } } };
}
function response(status, body = Buffer.alloc(0), headers = {}) { return { status, headers, body: stream(body) }; }
function server(c, { auth = false, mutate = (x) => x } = {}) {
  const calls = []; let tokenCalls = 0;
  return { calls, tokenCalls: () => tokenCalls, request: async ({ url, headers, pinned }) => {
    calls.push({ url: url.href, headers, pinned, host: url.hostname });
    // The injected connection seam sees the validated address while preserving
    // the intended HTTPS hostname (equivalent to Host/SNI in nodeRequest).
    assert.equal(pinned.address, "8.8.8.8");
    if (url.hostname !== "auth.example") assert.equal(url.hostname, "registry-1.docker.io");
    if (url.hostname === "auth.example") { tokenCalls++; return response(200, Buffer.from(JSON.stringify({ token: "opaque-token", expires_in: 60 })), { "content-type": "application/json" }); }
    if (auth && headers.Authorization !== "Bearer opaque-token") return response(401, Buffer.alloc(0), { "www-authenticate": 'Bearer realm="https://auth.example/token",service="registry",scope="repository:library/node:pull"' });
    const bytes = url.pathname.includes(c.lock.indexDigest) ? c.index : url.pathname.includes(c.lock.children.amd64) || url.pathname.includes(c.lock.children.arm64) ? c.child : c.config;
    const actual = mutate(bytes, url);
    return response(200, actual, { "content-type": url.pathname.includes("blobs") ? configType : (bytes === c.index ? indexType : manifestType), "content-length": String(actual.length), "docker-content-digest": digest(bytes) });
  }};
}
function seam(s) { return { resolver: async () => [{ address: "8.8.8.8", family: 4 }], request: s.request, random: () => 0 }; }

test("normalizes exact Docker Hub and GHCR paths", () => {
  const d = "sha256:" + "a".repeat(64);
  assert.deepEqual(normalizeRegistryReference(`node@${d}`), { registry: "registry-1.docker.io", repository: "library/node", digest: d });
  assert.equal(normalizeRegistryReference(`matrixdotorg/synapse@${d}`).repository, "matrixdotorg/synapse");
  assert.equal(normalizeRegistryReference(`ghcr.io/element-hq/mas@${d}`).repository, "element-hq/mas");
});

test("nodeRequest pins TLS transport while preserving host, SNI, validation, and fresh sockets", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "oci-tls-")), key = path.join(directory, "key.pem"), cert = path.join(directory, "cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=registry.test", "-addext", "subjectAltName=DNS:registry.test"], { stdio: "ignore" });
  const seen = [], sockets = new Set(), tls = https.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (req, res) => { seen.push({ host: req.headers.host, sni: req.socket.servername, remote: req.socket.remoteAddress }); sockets.add(req.socket); res.end("ok"); });
  await new Promise((resolve) => tls.listen(0, "127.0.0.1", resolve));
  try {
    const url = new URL(`https://registry.test:${tls.address().port}/v2/test`);
    for (let i = 0; i < 2; i++) { const result = await nodeRequest({ url, method: "GET", headers: {}, pinned: { address: "127.0.0.1", family: 4 }, ca: readFileSync(cert) }); for await (const _ of result.body) {} }
    assert.deepEqual(seen.map((x) => x.host), [url.host, url.host]); assert.deepEqual(seen.map((x) => x.sni), ["registry.test", "registry.test"]); assert.deepEqual(seen.map((x) => x.remote), ["127.0.0.1", "127.0.0.1"]); assert.equal(sockets.size, 2);
  } finally { await new Promise((resolve) => tls.close(resolve)); }
});

test("real IncomingMessage closes before an OCI retry opens its next request", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "oci-close-")), key = path.join(directory, "key.pem"), cert = path.join(directory, "cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=registry.test", "-addext", "subjectAltName=DNS:registry.test"], { stdio: "ignore" });
  let serverCalls = 0, firstClosed = false;
  const tls = https.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (_req, res) => { res.statusCode = ++serverCalls === 1 ? 503 : 500; res.end("locally received"); });
  await new Promise((resolve) => tls.listen(0, "127.0.0.1", resolve));
  try {
    const url = new URL(`https://registry.test:${tls.address().port}/v2/test`), descriptor = "sha256:" + "a".repeat(64); let requests = 0;
    const client = new OciTransport({ resolver: async () => [{ address: "8.8.8.8", family: 4 }], sleep: async () => {}, request: async (args) => { if (++requests === 2) assert.equal(firstClosed, true, "retry began before IncomingMessage close"); const result = await nodeRequest({ ...args, pinned: { address: "127.0.0.1", family: 4 }, ca: readFileSync(cert) }); if (requests === 1) result.body.once("close", () => { firstClosed = true; }); return result; } });
    await assert.rejects(client.getDescriptor(url, descriptor, undefined, new Set([indexType]), { repository: "library/node" }), /registry status/);
    assert.equal(requests, 2);
  } finally { await new Promise((resolve) => tls.close(resolve)); }
});

test("collects pinned amd64 and arm64 chains and keeps bearer token secret", async () => {
  for (const arch of ["amd64", "arm64"]) {
    const c = chain(arch), s = server(c, { auth: true });
    const result = await collectOciImageChain({ lock: c.lock, platform: `linux/${arch}`, ...seam(s) });
    assert.equal(result.platform, `linux/${arch}`); assert.equal(s.tokenCalls(), 1);
    assert.ok(s.calls.some((x) => x.url.includes(`/blobs/${digest(c.config)}`)));
    assert.ok(!JSON.stringify(result).includes("opaque-token"));
  }
});

test("rejects rebinding/special addresses, descriptor/header/media and JSON drift", async () => {
  const c = chain(), s = server(c);
  await assert.rejects(collectOciImageChain({ lock: c.lock, platform: "linux/amd64", request: s.request, resolver: async () => [{ address: "127.0.0.1", family: 4 }] }), /public/);
  for (const ip of ["127.0.0.1", "10.0.0.1", "169.254.1.1", "192.0.2.1", "224.0.0.1", "::1", "fc00::1", "fe80::1", "2001:db8::1", "ff02::1"]) assert.equal(isPublicIp(ip), false);
  await assert.rejects(collectOciImageChain({ lock: c.lock, platform: "linux/amd64", ...seam(server(c, { mutate: (b, u) => u.pathname.includes("blobs") ? Buffer.concat([b, Buffer.from("x")]) : b })) }), /content length|digest/);
  const bad = server(c); const original = bad.request; bad.request = async (args) => { const r = await original(args); if (args.url.pathname.includes("manifests")) r.headers["content-type"] = "text/plain"; return r; };
  await assert.rejects(collectOciImageChain({ lock: c.lock, platform: "linux/amd64", ...seam(bad) }), /content type/);
});

test("manifest redirects are same-origin only; transient statuses use injected sleep", async () => {
  const c = chain(); let redirects = 0, retries = 0;
  const requests = [];
  const request = async ({ url, headers, pinned }) => {
    requests.push({ url: url.href, headers, pinned });
    if (url.hostname === "auth.example") return response(200, Buffer.from('{"access_token":"opaque-token","expires_in":60}'), { "content-type": "application/json" });
    if (url.hostname === "registry-1.docker.io" && !headers.Authorization) return response(401, Buffer.alloc(0), { "www-authenticate": 'Bearer realm="https://auth.example/token",service="registry",scope="repository:library/node:pull"' });
    if (redirects++ === 0) return response(307, Buffer.alloc(0), { location: "https://cdn.example/x" });
    if (url.hostname === "cdn.example") assert.equal(headers.Authorization, undefined);
    if (retries++ === 0) return response(503, Buffer.alloc(0));
    const bytes = url.pathname.includes(c.lock.indexDigest) || url.pathname === "/x" ? c.index : url.pathname.includes("blobs") ? c.config : c.child;
    return response(200, bytes, { "content-type": url.pathname.includes("blobs") ? configType : bytes === c.index ? indexType : manifestType, "content-length": String(bytes.length), "docker-content-digest": digest(bytes) });
  };
  const sleeps = [];
  await assert.rejects(collectOciImageChain({ lock: c.lock, platform: "linux/amd64", resolver: async () => [{ address: "8.8.8.8", family: 4 }], request, random: () => 0, sleep: async (ms) => sleeps.push(ms) }), /redirect not permitted/);
  assert.equal(requests.some((x) => x.url === "https://cdn.example/x"), false);
  assert.deepEqual(sleeps, []);
});

test("bounds redirect loops and stalled bodies without using ambient DNS", async () => {
  const url = new URL("https://registry-1.docker.io/v2/library/node/manifests/sha256:" + "a".repeat(64));
  const resolver = async () => [{ address: "8.8.8.8", family: 4 }];
  const looping = new OciTransport({ resolver, request: async () => response(307, Buffer.alloc(0), { location: url.href }) });
  await assert.rejects(looping.getDescriptor(url, "sha256:" + "a".repeat(64), undefined, new Set([indexType]), { repository: "library/node" }), /redirect limit/);
  async function* stalled() { await new Promise(() => {}); }
  const timeout = new OciTransport({ resolver, timeoutMs: 1, chainTimeoutMs: 1, request: async () => ({ status: 200, headers: { "content-type": indexType }, body: stalled() }) });
  await assert.rejects(timeout.getDescriptor(url, "sha256:" + "a".repeat(64), undefined, new Set([indexType]), { repository: "library/node" }), /chain deadline/);
});

test("chain deadlines use the monotonic seam even when wall time goes backward", async () => {
  const url = new URL("https://registry-1.docker.io/x"), resolver = async () => [{ address: "8.8.8.8", family: 4 }], descriptor = "sha256:" + "a".repeat(64);
  let monotonic = 0, wall = 10_000, calls = 0;
  const client = new OciTransport({ resolver, now: () => monotonic, wallNow: () => wall, chainTimeoutMs: 5, sleep: async () => { monotonic = 5; wall -= 60_000; }, request: async () => { calls++; return response(503); } });
  await assert.rejects(client.getDescriptor(url, descriptor, undefined, new Set([indexType]), { repository: "library/node" }), /chain deadline/);
  assert.equal(calls, 1);
});

test("redirects and retries wait for EventEmitter response close", async () => {
  const url = new URL("https://registry-1.docker.io/x"), resolver = async () => [{ address: "8.8.8.8", family: 4 }], descriptor = "sha256:" + "a".repeat(64);
  let closed = false, calls = 0;
  const body = new EventEmitter(); body.closed = false; body.destroy = () => setTimeout(() => { closed = true; body.closed = true; body.emit("close"); }, 5); body[Symbol.asyncIterator] = async function* () { yield Buffer.from("locally received"); };
  const client = new OciTransport({ resolver, request: async () => { calls++; if (calls === 2) assert.equal(closed, true, "request 2 began before response 1 closed"); return calls === 1 ? { status: 307, headers: { location: url.href }, body } : response(500); } });
  await assert.rejects(client.getDescriptor(url, descriptor, undefined, new Set([indexType]), { repository: "library/node" }), /registry status/);
  assert.equal(calls, 2);
});

test("close stalls consume the chain deadline before a retry can start", async () => {
  const url = new URL("https://registry-1.docker.io/x"), resolver = async () => [{ address: "8.8.8.8", family: 4 }], descriptor = "sha256:" + "a".repeat(64);
  const body = new EventEmitter(); body.closed = false; body.destroy = () => {}; body[Symbol.asyncIterator] = async function* () { yield Buffer.from("locally received"); };
  let calls = 0;
  const client = new OciTransport({ resolver, chainTimeoutMs: 5, request: async () => { calls++; return { status: 503, headers: {}, body }; } });
  await assert.rejects(client.getDescriptor(url, descriptor, undefined, new Set([indexType]), { repository: "library/node" }), /chain deadline/);
  assert.equal(calls, 1);
});

test("disposes received response bytes on redirect, authentication, retry, error, and deadline", async () => {
  const url = new URL("https://registry-1.docker.io/x"), resolver = async () => [{ address: "8.8.8.8", family: 4 }], digest = "sha256:" + "a".repeat(64);
  const tracked = () => { const state = { bytes: 0, destroyed: false }; return { state, body: { async *[Symbol.asyncIterator]() { state.bytes += 3; yield Buffer.from("abc"); }, destroy() { state.destroyed = true; } } }; };
  for (const [status, headers, expected] of [[307, { location: "https://evil.example/x" }, /redirect not permitted/], [401, {}, /missing bearer/], [500, {}, /registry status/] ]) {
    const item = tracked(), client = new OciTransport({ resolver, request: async () => ({ status, headers, body: item.body }) });
    await assert.rejects(client.getDescriptor(url, digest, undefined, new Set([indexType]), { repository: "library/node" }), expected); assert.equal(item.state.bytes, 3); assert.equal(item.state.destroyed, true);
  }
  const retry = tracked(); let calls = 0; const retryClient = new OciTransport({ resolver, sleep: async () => {}, request: async () => ({ status: calls++ ? 500 : 503, headers: {}, body: retry.body }) });
  await assert.rejects(retryClient.getDescriptor(url, digest, undefined, new Set([indexType]), { repository: "library/node" }), /registry status/); assert.equal(retry.state.bytes, 6);
  const stalled = { destroyed: false, async *[Symbol.asyncIterator]() { yield Buffer.from("abc"); await new Promise(() => {}); }, destroy() { this.destroyed = true; } };
  const deadline = new OciTransport({ resolver, chainTimeoutMs: 5, request: async () => ({ status: 500, headers: {}, body: stalled }) });
  await assert.rejects(deadline.getDescriptor(url, digest, undefined, new Set([indexType]), { repository: "library/node" }), /chain deadline/); assert.equal(stalled.destroyed, true);
});

test("discarded response accounting and default retry sleep fail closed", async () => {
  const url = new URL("https://registry-1.docker.io/x"), resolver = async () => [{ address: "8.8.8.8", family: 4 }], descriptor = "sha256:" + "a".repeat(64);
  const overLimit = { destroyed: false, async *[Symbol.asyncIterator]() { yield Buffer.alloc(PROVENANCE_LIMITS.registryTotalBytes + 1); }, destroy() { this.destroyed = true; } };
  const discard = new OciTransport({ resolver, request: async () => ({ status: 500, headers: {}, body: overLimit }) });
  await assert.rejects(discard.getDescriptor(url, descriptor, undefined, new Set([indexType]), { repository: "library/node" }), /byte limit/); assert.equal(overLimit.destroyed, true);
  let calls = 0;
  const retry = new OciTransport({ resolver, chainTimeoutMs: 5, request: async () => { calls++; return response(503); } });
  await assert.rejects(retry.getDescriptor(url, descriptor, undefined, new Set([indexType]), { repository: "library/node" }), /chain deadline/);
  await new Promise((resolve) => setTimeout(resolve, 60)); assert.equal(calls, 1);
});

test("an edge-scheduled chain abort rejects default retry sleep before another request", async () => {
  const url = new URL("https://registry-1.docker.io/x"), resolver = async () => [{ address: "8.8.8.8", family: 4 }], descriptor = "sha256:" + "a".repeat(64);
  const originalSetTimeout = globalThis.setTimeout, originalClearTimeout = globalThis.clearTimeout, timers = [];
  globalThis.setTimeout = (callback, ms, ...args) => { const timer = { callback: () => callback(...args), ms, cleared: false }; timers.push(timer); return timer; };
  globalThis.clearTimeout = (timer) => { if (timer) timer.cleared = true; };
  try {
    let calls = 0;
    const client = new OciTransport({ resolver, chainTimeoutMs: 1, now: () => 0, random: () => .5, request: async () => { calls++; if (calls > 1) throw new Error("unexpected retry"); return response(503); } });
    const pending = client.getDescriptor(url, descriptor, undefined, new Set([indexType]), { repository: "library/node" });
    for (let i = 0; i < 100 && !timers.some((timer) => timer.ms === 25 && !timer.cleared); i++) await Promise.resolve();
    assert.ok(timers.some((timer) => timer.ms === 25 && !timer.cleared), "default retry sleep was scheduled");
    const deadline = timers.find((timer) => timer.ms === 1 && !timer.cleared);
    assert.ok(deadline, "retry deadline timer was scheduled");
    deadline.callback();
    await assert.rejects(pending, /chain deadline/);
    assert.equal(calls, 1);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
  }
});

test("rejects mixed DNS, expanded IANA specials, and never exposes mutable bytes", async () => {
  for (const ip of ["192.88.99.1", "198.18.1.1", "::ffff:127.0.0.1", "2001:2::1", "2001:10::1", "2001:20::1", "3fff::1", "64:ff9b:1::1"]) assert.equal(isPublicIp(ip), false);
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"]) assert.equal(isPublicIp(ip), true);
  const c = chain(), s = server(c);
  await assert.rejects(collectOciImageChain({ lock: c.lock, platform: "linux/amd64", request: s.request, resolver: async () => [{ address: "8.8.8.8", family: 4 }, { address: "127.0.0.1", family: 4 }] }), /non-public/);
  const result = await collectOciImageChain({ lock: c.lock, platform: "linux/amd64", ...seam(s) });
  assert.deepEqual(Object.keys(result).sort(), ["childDigest", "configDigest", "indexDigest", "platform"]);
  assert.equal(Object.isFrozen(result), true);
});

test("token defaults expiry and rejects malformed bearer challenge", async () => {
  const c = chain(); let tokenCalls = 0;
  const request = async ({ url, headers }) => {
    if (url.hostname === "auth.example") { tokenCalls++; return response(200, Buffer.from('{"token":"opaque-token"}'), { "content-type": "application/json" }); }
    if (!headers.Authorization) return response(401, Buffer.from("challenge-body"), { "www-authenticate": 'Bearer realm="https://auth.example/token",service="registry",scope="repository:library/node:pull"' });
    const bytes = url.pathname.includes(c.lock.indexDigest) ? c.index : url.pathname.includes("blobs") ? c.config : c.child;
    return response(200, bytes, { "content-type": url.pathname.includes("blobs") ? configType : bytes === c.index ? indexType : manifestType });
  };
  await collectOciImageChain({ lock: c.lock, platform: "linux/amd64", resolver: async () => [{ address: "8.8.8.8", family: 4 }], request });
  assert.equal(tokenCalls, 1);
  const bad = new OciTransport({ resolver: async () => [{ address: "8.8.8.8", family: 4 }], request: async () => response(401, Buffer.from("x"), { "www-authenticate": 'Bearer realm="https://auth.example/token",service="registry",scope="repository:library/node:pull",oops="x"' }) });
  await assert.rejects(bad.getDescriptor(new URL("https://registry-1.docker.io/x"), digest(Buffer.from("x")), undefined, new Set([indexType]), { repository: "library/node" }), /malformed bearer/);
});
