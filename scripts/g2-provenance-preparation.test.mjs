import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import {
  g2BuildMarker,
  g2ProjectName,
  hostPlatform,
  inspectGitArchive,
  normalizeImageReference,
  parseImageLocks,
  selectLockedImage,
  sha256,
  verifyOciChain,
} from "./g2-provenance-preparation.mjs";

const locks = await readFile(
  new URL("../deploy/locks/images.env", import.meta.url),
  "utf8",
);
const provenance = JSON.parse(
  await readFile(
    new URL("../deploy/locks/images.provenance.json", import.meta.url),
    "utf8",
  ),
);

function tarEntry(
  path = "safe.txt",
  type = "0",
  body = Buffer.from("x"),
  prefix = "",
  mode = type === "5" ? "0000755" : "0000644",
) {
  const header = Buffer.alloc(512);
  Buffer.from(path).copy(header, 0);
  Buffer.from(`${mode}\0`).copy(header, 100);
  Buffer.from(`${body.length.toString(8).padStart(11, "0")}\0`).copy(
    header,
    124,
  );
  header.fill(32, 148, 156);
  header[156] = type.charCodeAt(0);
  Buffer.from("ustar\0").copy(header, 257);
  Buffer.from("00").copy(header, 263);
  Buffer.from(prefix).copy(header, 345);
  let sum = 0;
  for (const byte of header) sum += byte;
  Buffer.from(`${sum.toString(8).padStart(6, "0")}\0 `).copy(header, 148);
  return Buffer.concat([
    header,
    body,
    Buffer.alloc(Math.ceil(body.length / 512) * 512 - body.length),
  ]);
}

function archive(...entries) {
  return Buffer.concat([...entries, Buffer.alloc(1024)]);
}
function pax(path) {
  const value = `path=${path}\n`;
  for (let n = value.length + 2; ; n++) {
    const line = `${n} ${value}`;
    if (line.length === n)
      return tarEntry("PaxHeaders.x", "x", Buffer.from(line));
  }
}

test("lock grammar, provenance tags, and exact normalization vectors are fixed", () => {
  const parsed = parseImageLocks(locks, provenance);
  assert.deepEqual(
    parsed.map(({ name, registry, repository }) => [
      name,
      registry,
      repository,
    ]),
    [
      ["SYNAPSE_IMAGE", "registry-1.docker.io", "matrixdotorg/synapse"],
      ["MAS_IMAGE", "ghcr.io", "element-hq/matrix-authentication-service"],
      ["POSTGRES_IMAGE", "registry-1.docker.io", "library/postgres"],
      ["CADDY_IMAGE", "registry-1.docker.io", "library/caddy"],
      ["NODE_IMAGE", "registry-1.docker.io", "library/node"],
      ["NGINX_IMAGE", "registry-1.docker.io", "library/nginx"],
    ],
  );
  for (const row of parsed) {
    const checkedIn = provenance.images.find(({ name }) => name === row.name);
    assert.ok(checkedIn);
    assert.equal(
      selectLockedImage(row, "linux/amd64").childDigest,
      checkedIn.children.amd64,
    );
    assert.equal(
      selectLockedImage(row, "linux/arm64").childDigest,
      checkedIn.children.arm64,
    );
  }
  for (const text of [
    locks + "\n",
    locks.replace("NODE_IMAGE=", "OTHER_IMAGE="),
    `${locks}\nX=y`,
    locks.replace("\n", "\nSYNAPSE_IMAGE=x\n"),
  ])
    assert.throws(() => parseImageLocks(text, provenance));
  for (const tag of [
    "matrixdotorg/synapse:",
    "matrixdotorg/synapse:v1@sha256:" + "a".repeat(64),
    "other/synapse:v1",
    "ghcr.io/element-hq/matrix-authentication-service:one:two",
  ]) {
    const altered = structuredClone(provenance);
    altered.images[0].tag = tag;
    assert.throws(() => parseImageLocks(locks, altered));
  }
});

test("real clean git archive and strict tar adversaries", async () => {
  const repo = await mkdtemp(join(tmpdir(), "g2-archive-"));
  try {
    spawnSync("/usr/bin/git", ["init", "-q"], { cwd: repo, check: true });
    await writeFile(join(repo, "safe.txt"), "safe");
    spawnSync("/usr/bin/git", ["add", "."], { cwd: repo, check: true });
    spawnSync(
      "/usr/bin/git",
      ["-c", "user.email=x@y.z", "-c", "user.name=x", "commit", "-qm", "x"],
      { cwd: repo, check: true },
    );
    const result = spawnSync(
      "/usr/bin/git",
      ["archive", "--format=tar", "HEAD"],
      { cwd: repo, encoding: null, check: true },
    );
    const inspected = inspectGitArchive(result.stdout);
    assert.equal(inspected.entries, 2);
    assert.equal(inspected.materialEntries, 1);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
  assert.deepEqual(
    inspectGitArchive(archive(pax("long/name"), tarEntry("x"))).entries,
    2,
  );
  assert.equal(
    inspectGitArchive(archive(pax("long/name"), tarEntry("x"))).materialEntries,
    1,
  );
  assert.equal(
    inspectGitArchive(
      archive(tarEntry("dir/", "5", Buffer.alloc(0)), tarEntry("dir/a")),
    ).entries,
    2,
  );
  const padded = archive(tarEntry("a", "0", Buffer.from("x")));
  padded[512 + 1] = 1;
  for (const bad of [
    archive(tarEntry("../x")),
    archive(tarEntry("link", "2")),
    archive(tarEntry("a"), tarEntry("a")),
    padded,
    Buffer.concat([archive(tarEntry("a")), Buffer.alloc(512, 1)]),
  ])
    assert.throws(() => inspectGitArchive(bad));
  const corrupt = archive(tarEntry("a"));
  corrupt[0] ^= 1;
  assert.throws(() => inspectGitArchive(corrupt));
  assert.throws(() => inspectGitArchive(archive(pax("../x"), tarEntry("x"))));
});

test("marker and platform helpers reject invalid inputs", () => {
  assert.throws(() => hostPlatform("mips"));
  assert.equal(hostPlatform("x86_64"), "linux/amd64");
  assert.equal(g2ProjectName("a".repeat(32)), "dsa-g2-" + "a".repeat(32));
  assert.throws(() => g2ProjectName("bad"));
  assert.match(
    g2BuildMarker({
      runId: "a".repeat(32),
      sourceCommit: "b".repeat(40),
      archiveHash: "sha256:" + "c".repeat(64),
      renderHash: "sha256:" + "d".repeat(64),
    }),
    /^sha256:/,
  );
  assert.throws(() =>
    normalizeImageReference("bad//name@sha256:" + "a".repeat(64)),
  );
});

function oci({
  architecture = "amd64",
  config = (value) => value,
  manifest = (value) => value,
  index = (value) => value,
} = {}) {
  const configBytes = Buffer.from(
    JSON.stringify(config({ os: "linux", architecture })),
  );
  const childValue = manifest({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      digest: sha256(configBytes),
      size: configBytes.length,
    },
    layers: [],
  });
  const childBytes = Buffer.from(JSON.stringify(childValue));
  const indexValue = index({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [
      {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: sha256(childBytes),
        size: childBytes.length,
        platform: { os: "linux", architecture },
      },
    ],
  });
  const indexBytes = Buffer.from(JSON.stringify(indexValue));
  return {
    lock: {
      indexDigest: sha256(indexBytes),
      children: {
        amd64:
          architecture === "amd64"
            ? sha256(childBytes)
            : "sha256:" + "0".repeat(64),
        arm64:
          architecture === "arm64"
            ? sha256(childBytes)
            : "sha256:" + "0".repeat(64),
      },
    },
    index: indexBytes,
    child: childBytes,
    config: configBytes,
  };
}

function verify(chain, platform = "linux/amd64") {
  return verifyOciChain({
    lock: chain.lock,
    platform,
    indexBytes: chain.index,
    childBytes: chain.child,
    configBytes: chain.config,
  });
}

test("OCI verifier reaches each recomputed structural check", () => {
  const good = oci();
  assert.equal(verify(good).configDigest, sha256(good.config));
  const arm64 = oci({ architecture: "arm64" });
  assert.equal(
    verify(arm64, "linux/arm64").childDigest,
    arm64.lock.children.arm64,
  );
  for (const tampered of [
    { ...good, index: Buffer.concat([good.index, Buffer.from(" ")]) },
    { ...good, child: Buffer.concat([good.child, Buffer.from(" ")]) },
    { ...good, config: Buffer.concat([good.config, Buffer.from(" ")]) },
  ]) {
    assert.strictEqual(tampered.lock, good.lock);
    assert.throws(() => verify(tampered));
  }
  const cases = [
    oci({ index: (value) => ({ ...value, schemaVersion: 1 }) }),
    oci({ index: (value) => ({ ...value, mediaType: "bad" }) }),
    oci({
      index: (value) => ({
        ...value,
        manifests: [
          { ...value.manifests[0], size: value.manifests[0].size + 1 },
        ],
      }),
    }),
    oci({
      index: (value) => ({
        ...value,
        manifests: [
          {
            ...value.manifests[0],
            platform: { os: "darwin", architecture: "amd64" },
          },
        ],
      }),
    }),
    oci({
      index: (value) => ({
        ...value,
        manifests: [value.manifests[0], value.manifests[0]],
      }),
    }),
    oci({ config: (value) => ({ ...value, architecture: "arm64" }) }),
    oci({ manifest: (value) => ({ ...value, schemaVersion: 1 }) }),
    oci({ manifest: (value) => ({ ...value, mediaType: "bad" }) }),
    oci({
      manifest: (value) => ({
        ...value,
        config: { ...value.config, size: value.config.size + 1 },
      }),
    }),
    oci({
      manifest: (value) => ({
        ...value,
        layers: [
          {
            mediaType: "application/vnd.oci.image.layer.v1.tar",
            digest: sha256("layer"),
            size: -1,
          },
        ],
      }),
    }),
  ];
  for (const chain of cases) assert.throws(() => verify(chain));
});
