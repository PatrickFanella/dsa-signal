import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  checkMatrixPolicy,
  caddyAdaptArgs,
  checkSecretOverlay,
  canonicalJson,
  main,
  normalizeCaddy,
  normalizeCompose,
  parseImageLocks,
  parseYaml,
  run,
} from "./check-matrix-policy.mjs";

const root = new URL("../", import.meta.url).pathname;
const read = (file) => readFile(new URL(`../${file}`, import.meta.url), "utf8");
const copy = (x) => structuredClone(x);
function visit(value, predicate) {
  if (!value || typeof value !== "object") return undefined;
  if (predicate(value)) return value;
  for (const child of Object.values(value)) {
    const found = visit(child, predicate);
    if (found) return found;
  }
  return undefined;
}
let cached;
async function fixture() {
  if (cached) return copy(cached);
  const [st, mt, wk, lockText, provenance, composeGolden, caddyGolden] = await Promise.all(
    [
      "deploy/local/synapse/homeserver.yaml",
      "deploy/local/mas/config.yaml",
      "deploy/local/well-known/matrix-client.json",
      "deploy/locks/images.env",
      "deploy/locks/images.provenance.json",
      "deploy/local/policy-fixtures/compose.rendered.json",
      "deploy/local/policy-fixtures/caddy.adapted.json",
    ].map(read),
  );
  const locks = parseImageLocks(lockText);
  const compose = JSON.parse(
    execFileSync(
      "docker",
      [
        "compose",
        "--env-file",
        "deploy/locks/images.env",
        "--env-file",
        "deploy/local/policy.env",
        "-f",
        "deploy/local/compose.yaml",
        "--profile",
        "full",
        "--profile",
        "negative",
        "config",
        "--format",
        "json",
      ],
      { cwd: root, encoding: "utf8" },
    ),
  );
  const adaptedCaddy = JSON.parse(
    execFileSync(
      "docker",
      caddyAdaptArgs(locks.CADDY_IMAGE),
      { encoding: "utf8", input: await read("deploy/local/gateway/Caddyfile") },
    ),
  );
  cached = {
    synapse: parseYaml(st),
    mas: parseYaml(mt),
    compose,
    locks,
    wellKnown: wk,
    provenance: JSON.parse(provenance),
    provenanceBytes: provenance,
    composeGolden: JSON.parse(composeGolden),
    caddyGolden: JSON.parse(caddyGolden),
    adaptedCaddy,
    synapseOverlay: {
      database: {
        name: "psycopg2",
        args: {
          host: "matrix-db",
          database: "synapse",
          user: "synapse",
          password: "x",
        },
      },
      macaroon_secret_key: "x",
      form_secret: "x",
      signing_key_path: "/run/secrets/synapse-signing-key",
    },
    masOverlay: {
      database: { uri: "postgresql://mas:x@matrix-db/mas?sslmode=disable" },
    },
  };
  return copy(cached);
}
test("accepts rendered full and negative policy and CLI renderer", async () => {
  const f = await fixture();
  assert.equal(checkMatrixPolicy(f), true);
  const runner = async (_command, args, _cwd, options) => JSON.stringify(args[0] === "compose" ? f.compose : (options?.input === await read("deploy/local/canary/Caddyfile")) ? JSON.parse(await read("deploy/local/policy-fixtures/canary.adapted.json")) : f.adaptedCaddy);
  const prior = process.env.MATRIX_POLICY_ENV_FILE;
  process.env.MATRIX_POLICY_ENV_FILE = "/tmp/unreviewed-policy.env";
  try {
    assert.equal(await main({ root, runner }), 0);
  } finally {
    if (prior === undefined) delete process.env.MATRIX_POLICY_ENV_FILE;
    else process.env.MATRIX_POLICY_ENV_FILE = prior;
  }
});
test("goldens are canonical, normalized, and reject rendered-policy drift", async () => {
  const f = await fixture();
  assert.equal(canonicalJson(f.composeGolden), await read("deploy/local/policy-fixtures/compose.rendered.json"));
  assert.equal(canonicalJson(f.caddyGolden), await read("deploy/local/policy-fixtures/caddy.adapted.json"));
  assert.deepEqual(normalizeCompose(f.composeGolden, root), f.composeGolden);
  assert.deepEqual(normalizeCaddy(f.caddyGolden, root), f.caddyGolden);
  const reject = async (mutate, caddy = false) => {
    const changed = copy(f);
    mutate(caddy ? changed.adaptedCaddy : changed.compose);
    const runner = async (_command, args, _cwd, options) => JSON.stringify(args[0] === "compose" ? changed.compose : (options?.input === await read("deploy/local/canary/Caddyfile")) ? JSON.parse(await read("deploy/local/policy-fixtures/canary.adapted.json")) : changed.adaptedCaddy);
    assert.equal(await main({ root, runner }), 1);
  };
  await reject((x) => { x.services.gateway.volumes[0].source = "/tmp/evil"; });
  await reject((x) => { x.services.gateway.volumes[0].type = "volume"; });
  await reject((x) => { x.services.gateway.volumes[0].read_only = false; });
  await reject((x) => { x.services.gateway.networks["matrix-internal"].aliases[0] = "evil"; });
  await reject((x) => { x.services.gateway.networks["matrix-internal"].ipv4_address = "10.77.30.99"; });
  await reject((x) => { x.services.api.secrets[1].mode = 0; });
  await reject((x) => { x.services.web.command = ["evil"]; });
  await reject((x) => { x.services.api.environment.CHALLENGE_KEY_RING = "evil"; });
  await reject((x) => { delete x.services.api.environment.CONTROL_PLANE_REVOCATION_ROLE; });
  await reject((x) => { x.services.api.secrets.push("control-revocation-db-password"); });
  await reject((x) => { x.apps.http.servers.srv0.routes.reverse(); }, true);
  await reject((x) => { x.apps.tls.extra = {}; }, true);
  await reject((x) => {
    const deny = visit(x, (r) => r.handle?.some((h) => h.status_code === 404));
    deny.handle = [{ handler: "reverse_proxy", upstreams: [{ dial: "evil:80" }] }];
  }, true);
  const changed = copy(f);
  changed.provenanceBytes += " ";
  assert.throws(() => checkMatrixPolicy(changed));
});
test("rejects locks, provenance, overlays, rendered canary and policy lanes", async () => {
  const f = await fixture();
  const mutations = [
    (x) => {
      x.locks.EXTRA_IMAGE = x.locks.CADDY_IMAGE;
    },
    (x) => {
      x.locks.CADDY_IMAGE = x.locks.POSTGRES_IMAGE;
    },
    (x) => {
      x.locks.CADDY_IMAGE = "caddy:latest";
    },
    (x) => {
      delete x.compose.services.api.build.args.NODE_IMAGE;
    },
    (x) => {
      x.compose.services.web.build.args.NGINX_IMAGE = x.locks.CADDY_IMAGE;
    },
    (x) => {
      x.provenance.images[0].indexDigest = "sha256:bad";
    },
    (x) => {
      x.provenance.images[0].children.amd64 = "sha256:bad";
    },
    (x) => {
      x.provenance.images[0].sourceCommit = "bad";
    },
    (x) => {
      x.provenance.images[0].signature.bundles[0].subjectDigest = "sha256:bad";
    },
    (x) => {
      x.provenance.images[0].signature.identityRegex = "^evil$";
    },
    (x) => {
      x.provenance.images[1].signature.issuer = "https://evil.example";
    },
    (x) => {
      x.provenance.images[2].verification.approvalDate = "2026-07-22";
    },
    (x) => {
      delete x.provenance.images[2].verification.approver;
    },
    (x) => {
      x.provenance.images[3].verification.status = "pending-operator-approval-before-commit";
    },
    (x) => {
      x.provenance.reviewer = "operator-approved";
    },
    (x) => {
      x.compose.services["synapse-data-init"].image = x.locks.CADDY_IMAGE;
    },
    (x) => {
      x.compose.services["egress-canary"].networks.canary.ipv4_address =
        undefined;
    },
    (x) => {
      x.compose.services.bridge = {};
    },
    (x) => {
      x.compose.networks.bridge = {};
    },
    (x) => {
      x.compose.services.synapse.unexpected = true;
    },
    (x) => {
      x.compose.services.api.networks["matrix-internal"] = {};
    },
    (x) => {
      x.compose.services.api.secrets.push("synapse-db-password");
    },
    (x) => {
      x.compose.services.synapse.ports = [{ target: 8008 }];
    },
    (x) => {
      x.compose.services.mas.volumes.push("matrix-db-data:/unexpected");
    },
    (x) => {
      x.compose.services.synapse.command[0] = "shell";
    },
    (x) => {
      x.compose.services.api.environment.MAS_REDIRECT_URI = "https://evil.example/callback";
    },
    (x) => {
      x.compose.services.api.secrets[1].target = "/run/secrets/evil";
    },
    (x) => {
      x.synapse.trusted_key_servers = ["x"];
    },
    (x) => {
      x.mas.account.enabled = true;
    },
    (x) => {
      x.synapseOverlay.database.args.extra = "x";
    },
    (x) => {
      x.masOverlay.database.uri = "postgresql://bad";
    },
    (x) => {
      visit(x.adaptedCaddy, (r) =>
        r.match?.[0]?.path?.includes("/v1/*"),
      ).match[0].path.push("/_matrix/client/*");
    },
    (x) => {
      visit(x.adaptedCaddy, (r) =>
        r.match?.[0]?.path?.includes("/v1/*"),
      ).match[0].path = ["/*"];
    },
    (x) => {
      visit(
        x.adaptedCaddy,
        (r) => r.upstreams?.[0]?.dial === "api:8080",
      ).upstreams[0].dial = "synapse:8008";
    },
    (x) => {
      x.adaptedCaddy.apps.tls.automation.policies[0].issuers[0].module = "acme";
    },
    (x) => {
      visit(x.adaptedCaddy, (r) =>
        r.handle?.some((h) => h.status_code === 204),
      ).handle[0].response.set["Access-Control-Allow-Methods"] = ["GET"];
    },
    (x) => {
      visit(x.adaptedCaddy, (r) =>
        r.handle?.some((h) => h.handler === "rewrite"),
      ).handle.find((h) => h.handler === "rewrite").uri = "/wrong.json";
    },
    (x) => {
      const fallback = visit(x.adaptedCaddy, (r) =>
        r.handle?.some((h) => h.upstreams?.[0]?.dial === "web:80"),
      );
      fallback.match = [{ path: ["/*"] }];
    },
    (x) => {
      x.adaptedCaddy.apps.http.servers.srv0.routes.push(
        copy(x.adaptedCaddy.apps.http.servers.srv0.routes[0]),
      );
    },
    (x) => {
      const health = visit(x.adaptedCaddy, (r) => r.handle?.some((h) => h.status_code === 200));
      health.handle.unshift({ handler: "headers", response: { set: { "X-Evil": ["1"] } } });
    },
  ];
  for (const [index, mutate] of mutations.entries()) {
    const changed = copy(f);
    mutate(changed);
    assert.throws(() => checkMatrixPolicy(changed), `mutation ${index}`);
  }
});
test("CLI reads only the rendered top-level overlay bindings", async () => {
  const f = await fixture();
  const directory = await mkdtemp(join(tmpdir(), "matrix-overlay-"));
  const bad = `${directory}/malicious.yaml`;
  await writeFile(bad, "database: {uri: postgresql://evil}\n");
  for (const path of ["/missing.yaml", bad]) {
    const changed = copy(f);
    changed.compose.secrets["synapse-secrets.yaml"].file = path;
    const runner = async (_command, args, _cwd, options) => JSON.stringify(args[0] === "compose" ? changed.compose : (options?.input === await read("deploy/local/canary/Caddyfile")) ? JSON.parse(await read("deploy/local/policy-fixtures/canary.adapted.json")) : changed.adaptedCaddy);
    assert.equal(await main({ root, runner }), 1);
  }
});
test("parsers fail closed and overlay schema is exported", () => {
  assert.throws(() => parseYaml("x: 1\nx: 2\n"));
  assert.throws(() =>
    parseImageLocks(
      "SYNAPSE_IMAGE=x@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nSYNAPSE_IMAGE=x@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nMAS_IMAGE=x@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nPOSTGRES_IMAGE=x@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ),
  );
  assert.throws(() => checkSecretOverlay("synapse", { database: {} }));
});
test("subprocess runner has absolute deadline and bounded drained output", async () => {
  await assert.rejects(run(process.execPath, ["-e", "setTimeout(()=>{}, 1000)"], root, { timeoutMs: 20 }));
  await assert.rejects(run(process.execPath, ["-e", "process.stdout.write('x'.repeat(100)); process.stderr.write('y'.repeat(100))"], root, { maxBytes: 10 }));
});
test("subprocess runner settles despite a descendant retaining pipes", async () => {
  const script = "require('node:child_process').spawn(process.execPath,['-e',\"setInterval(()=>process.stdout.write('x'.repeat(1024)),1)\"],{stdio:'inherit'}); setTimeout(()=>process.exit(0),10)";
  const started = Date.now();
  await assert.rejects(run(process.execPath, ["-e", script], root, { timeoutMs: 200, maxBytes: 4096 }));
  assert.ok(Date.now() - started < 500, "runner must not wait for inherited descendant pipes");
});
test("CLI rejects a mutated canary adapted configuration", async () => {
  const f = await fixture();
  const canary = JSON.parse(await read("deploy/local/policy-fixtures/canary.adapted.json"));
  canary.apps.http.servers.srv0.routes[0].handle[0].body = "open";
  const runner = async (_command, args, _cwd, options) => JSON.stringify(args[0] === "compose" ? f.compose : (options?.input === await read("deploy/local/canary/Caddyfile")) ? canary : f.adaptedCaddy);
  assert.equal(await main({ root, runner }), 1);
});

test("subprocess runner forwards supplied configuration through stdin", async () => {
  const input = "fixture configuration\n";
  const output = await run(process.execPath, ["-e", "process.stdin.pipe(process.stdout)"], root, { input });
  assert.equal(output, input);
});
