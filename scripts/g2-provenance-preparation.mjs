/** Dormant, repository-owned G2 provenance preparation primitives. */
import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

export const PROVENANCE_LIMITS = Object.freeze({
  archiveBytes: 64 * 1024 * 1024,
  archiveEntries: 20_000,
  pathBytes: 255,
  registryDocumentBytes: 4 * 1024 * 1024,
  configBytes: 1024 * 1024,
  registryTotalBytes: 32 * 1024 * 1024,
});
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const LOCK_NAMES = [
  "SYNAPSE_IMAGE",
  "MAS_IMAGE",
  "POSTGRES_IMAGE",
  "CADDY_IMAGE",
  "NODE_IMAGE",
  "NGINX_IMAGE",
];
const INDEX_TYPES = new Set([
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
]);
const MANIFEST_TYPES = new Set([
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
]);
const CONFIG_TYPES = new Set([
  "application/vnd.oci.image.config.v1+json",
  "application/vnd.docker.container.image.v1+json",
]);
const LAYER_TYPES = new Set([
  "application/vnd.oci.image.layer.v1.tar",
  "application/vnd.oci.image.layer.v1.tar+gzip",
  "application/vnd.oci.image.layer.v1.tar+zstd",
  "application/vnd.docker.image.rootfs.diff.tar",
  "application/vnd.docker.image.rootfs.diff.tar.gzip",
]);
const utf8 = new TextDecoder("utf-8", { fatal: true });

export function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
export function hostPlatform(uname) {
  const value = String(uname).trim();
  if (value === "x86_64" || value === "amd64") return "linux/amd64";
  if (value === "aarch64" || value === "arm64") return "linux/arm64";
  throw new Error("unsupported host architecture");
}
export function g2ProjectName(runId) {
  if (!/^[0-9a-f]{32}$/.test(runId)) throw new Error("invalid G2 run id");
  return `dsa-g2-${runId}`;
}
export function g2PreliminaryMarker({ runId, sourceCommit, archiveHash }) {
  if (
    !/^[0-9a-f]{32}$/.test(runId) ||
    !/^[0-9a-f]{40}$/.test(sourceCommit) ||
    !SHA256.test(archiveHash)
  )
    throw new Error("invalid preliminary provenance marker input");
  return sha256(
    `dsa-g2-preliminary-marker-v1\0${runId}\0${sourceCommit}\0${archiveHash}`,
  );
}
export function g2BuildMarker({
  runId,
  sourceCommit,
  archiveHash,
  renderHash,
}) {
  if (
    !/^[0-9a-f]{32}$/.test(runId) ||
    !/^[0-9a-f]{40}$/.test(sourceCommit) ||
    !SHA256.test(archiveHash) ||
    !SHA256.test(renderHash)
  )
    throw new Error("invalid provenance marker input");
  return sha256(
    `dsa-g2-build-marker-v1\0${runId}\0${sourceCommit}\0${archiveHash}\0${renderHash}`,
  );
}
export function normalizeImageReference(reference) {
  const match =
    /^([a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)@(sha256:[0-9a-f]{64})$/.exec(
      String(reference),
    );
  if (!match) throw new Error("image reference must be digest pinned");
  let [, name, digest] = match;
  const parts = name.split("/");
  const explicit =
    parts.length > 1 &&
    (parts[0].includes(".") ||
      parts[0].includes(":") ||
      parts[0] === "localhost");
  const registry = explicit ? parts.shift() : "registry-1.docker.io";
  if (!explicit && parts.length === 1) parts.unshift("library");
  if (
    !parts.length ||
    parts.some((part) => !/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/.test(part))
  )
    throw new Error("invalid repository");
  return { registry, repository: parts.join("/"), digest };
}
function normalizeImageTag(reference) {
  const match = /^(.*):([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$/.exec(
    String(reference),
  );
  if (!match || match[1].includes("@"))
    throw new Error("image tag must be canonical");
  return normalizeImageReference(`${match[1]}@sha256:${"0".repeat(64)}`);
}
export function parseImageLocks(envText, provenance) {
  const lines = String(envText).split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  if (lines.length !== LOCK_NAMES.length)
    throw new Error("exact six image locks required");
  const locks = new Map();
  lines.forEach((line, index) => {
    const match = /^([A-Z_]+)=([^\s=]+)$/.exec(line);
    if (!match || match[1] !== LOCK_NAMES[index] || locks.has(match[1]))
      throw new Error("invalid image lock grammar");
    locks.set(match[1], match[2]);
  });
  const rows = provenance?.images;
  if (!Array.isArray(rows) || rows.length !== LOCK_NAMES.length)
    throw new Error("exact six provenance rows required");
  const byName = new Map(rows.map((row) => [row?.name, row]));
  if (
    byName.size !== LOCK_NAMES.length ||
    LOCK_NAMES.some((name) => !byName.has(name))
  )
    throw new Error("provenance names drift");
  return LOCK_NAMES.map((name) => {
    const row = byName.get(name);
    const parsed = normalizeImageReference(locks.get(name));
    const tag = normalizeImageTag(row?.tag);
    if (
      parsed.digest !== row.indexDigest ||
      tag.registry !== parsed.registry ||
      tag.repository !== parsed.repository ||
      !SHA256.test(row.indexDigest) ||
      !SHA256.test(row.children?.amd64) ||
      !SHA256.test(row.children?.arm64)
    )
      throw new Error("lock/provenance drift");
    return {
      name,
      ...parsed,
      tag: row.tag,
      indexDigest: row.indexDigest,
      children: row.children,
    };
  });
}
export function selectLockedImage(lock, platform) {
  if (!["linux/amd64", "linux/arm64"].includes(platform))
    throw new Error("unsupported platform");
  const architecture = platform.slice(6);
  if (!lock?.children?.[architecture])
    throw new Error("missing platform child");
  return { ...lock, platform, childDigest: lock.children[architecture] };
}
function parseJson(bytes, label, max) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > max)
    throw new Error(`${label} bounds`);
  try {
    return JSON.parse(utf8.decode(bytes));
  } catch {
    throw new Error(`${label} JSON`);
  }
}
function descriptor(value, types, digest, size) {
  return (
    value &&
    types.has(value.mediaType) &&
    value.digest === digest &&
    Number.isSafeInteger(value.size) &&
    value.size === size
  );
}
function anyDescriptor(value, types) {
  return (
    value &&
    types.has(value.mediaType) &&
    SHA256.test(value.digest) &&
    Number.isSafeInteger(value.size) &&
    value.size >= 0
  );
}
/** Verifies raw bytes obtained by a future fixed HTTPS OCI client; it performs no I/O, token handling, or authority grant. */
export function verifyOciChain({
  lock,
  platform,
  indexBytes,
  childBytes,
  configBytes,
}) {
  const selected = selectLockedImage(lock, platform);
  if (
    ![indexBytes, childBytes, configBytes].every(Buffer.isBuffer) ||
    indexBytes.length + childBytes.length + configBytes.length >
      PROVENANCE_LIMITS.registryTotalBytes
  )
    throw new Error("OCI total bounds");
  if (
    sha256(indexBytes) !== selected.indexDigest ||
    sha256(childBytes) !== selected.childDigest
  )
    throw new Error("OCI digest mismatch");
  const index = parseJson(
    indexBytes,
    "index",
    PROVENANCE_LIMITS.registryDocumentBytes,
  );
  if (
    index.schemaVersion !== 2 ||
    !INDEX_TYPES.has(index.mediaType) ||
    !Array.isArray(index.manifests)
  )
    throw new Error("invalid index");
  const arch = platform.slice(6);
  const choices = index.manifests.filter(
    (item) =>
      item?.platform?.os === "linux" && item?.platform?.architecture === arch,
  );
  if (
    choices.length !== 1 ||
    !descriptor(
      choices[0],
      MANIFEST_TYPES,
      selected.childDigest,
      childBytes.length,
    )
  )
    throw new Error("index child mismatch");
  const manifest = parseJson(
    childBytes,
    "manifest",
    PROVENANCE_LIMITS.registryDocumentBytes,
  );
  if (
    manifest.schemaVersion !== 2 ||
    manifest.mediaType !== choices[0].mediaType ||
    !Array.isArray(manifest.layers) ||
    !manifest.layers.every((layer) => anyDescriptor(layer, LAYER_TYPES)) ||
    !descriptor(
      manifest.config,
      CONFIG_TYPES,
      sha256(configBytes),
      configBytes.length,
    )
  )
    throw new Error("invalid manifest");
  const config = parseJson(
    configBytes,
    "config",
    PROVENANCE_LIMITS.configBytes,
  );
  if (config.os !== "linux" || config.architecture !== arch)
    throw new Error("config platform mismatch");
  return Object.freeze({
    indexDigest: selected.indexDigest,
    childDigest: selected.childDigest,
    configDigest: sha256(configBytes),
    platform,
  });
}

// Deliberately a pure alias: the dormant transport may verify collected bytes,
// but it cannot turn them into G2 authority.
export const verifyOciImageChain = verifyOciChain;
function field(block, start, length) {
  const bytes = block.subarray(start, start + length);
  const nul = bytes.indexOf(0);
  if (nul >= 0 && bytes.subarray(nul).some((value) => value !== 0))
    throw new Error("invalid tar field");
  try {
    return utf8.decode(bytes.subarray(0, nul < 0 ? length : nul));
  } catch {
    throw new Error("invalid tar UTF-8");
  }
}
function number(block, start, length, label) {
  const raw = block
    .subarray(start, start + length)
    .toString("ascii")
    .replace(/[\0 ]+$/g, "")
    .trim();
  if (!/^[0-7]+$/.test(raw)) throw new Error(`invalid tar ${label}`);
  const value = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value)) throw new Error(`unsafe tar ${label}`);
  return value;
}
function canonicalPath(value, directory = false) {
  if (
    typeof value !== "string" ||
    !value ||
    Buffer.byteLength(value) > PROVENANCE_LIMITS.pathBytes ||
    value.includes("\0") ||
    value.startsWith("/")
  )
    throw new Error("unsafe tar path");
  const slash = value.endsWith("/");
  if (slash && !directory) throw new Error("unsafe tar path");
  const path = slash ? value.slice(0, -1) : value;
  if (
    !path ||
    path.split("/").some((part) => !part || part === "." || part === "..")
  )
    throw new Error("unsafe tar path");
  return path;
}
function checksum(header) {
  const claimed = number(header, 148, 8, "checksum");
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : header[i];
  if (sum !== claimed) throw new Error("invalid tar checksum");
}
function paxRecords(body) {
  let offset = 0;
  const records = new Map();
  while (offset < body.length) {
    const space = body.indexOf(32, offset);
    if (space < 0) throw new Error("invalid PAX record");
    const countText = body.subarray(offset, space).toString("ascii");
    if (!/^[1-9][0-9]*$/.test(countText)) throw new Error("invalid PAX record");
    const count = Number(countText);
    if (
      !Number.isSafeInteger(count) ||
      count > body.length - offset ||
      count < space - offset + 3
    )
      throw new Error("invalid PAX record");
    const record = body.subarray(space + 1, offset + count);
    if (record.at(-1) !== 10) throw new Error("invalid PAX record");
    let text;
    try {
      text = utf8.decode(record.subarray(0, -1));
    } catch {
      throw new Error("invalid PAX UTF-8");
    }
    const equal = text.indexOf("=");
    const key = text.slice(0, equal);
    if (equal < 1 || records.has(key) || !["path", "comment"].includes(key))
      throw new Error("unsupported PAX record");
    records.set(key, text.slice(equal + 1));
    offset += count;
  }
  return records;
}
/** Strictly inspects POSIX/ustar streams produced by git archive before a future extractor may write them. */
export function inspectGitArchive(bytes) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length < 1024 ||
    bytes.length > PROVENANCE_LIMITS.archiveBytes ||
    bytes.length % 512
  )
    throw new Error("archive bounds");
  const paths = new Set();
  const files = [];
  let entries = 0;
  let materialEntries = 0;
  let pendingPax;
  let offset = 0;
  while (offset < bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((value) => value === 0)) {
      if (
        offset + 1024 > bytes.length ||
        !bytes
          .subarray(offset + 512, offset + 1024)
          .every((value) => value === 0) ||
        !bytes.subarray(offset + 1024).every((value) => value === 0)
      )
        throw new Error("invalid tar termination");
      if (pendingPax !== undefined) throw new Error("orphan PAX record");
      return Object.freeze({
        entries,
        materialEntries,
        archiveHash: sha256(bytes),
        files: Object.freeze(files),
      });
    }
    if (offset + 512 > bytes.length || field(header, 257, 6) !== "ustar")
      throw new Error("invalid tar header");
    checksum(header);
    const size = number(header, 124, 12, "size");
    const blocks = Math.ceil(size / 512);
    const payloadStart = offset + 512;
    const next = payloadStart + blocks * 512;
    if (!Number.isSafeInteger(next) || next > bytes.length)
      throw new Error("truncated tar payload");
    if (
      !bytes.subarray(payloadStart + size, next).every((value) => value === 0)
    )
      throw new Error("nonzero tar padding");
    if (++entries > PROVENANCE_LIMITS.archiveEntries)
      throw new Error("archive entry limit");
    const type = String.fromCharCode(header[156] || 48);
    const rawPath = field(header, 345, 155)
      ? `${field(header, 345, 155)}/${field(header, 0, 100)}`
      : field(header, 0, 100);
    const payload = bytes.subarray(payloadStart, payloadStart + size);
    if (type === "x" || type === "g") {
      const records = paxRecords(payload);
      if (type === "g") {
        if (
          records.size !== 1 ||
          !records.has("comment") ||
          records.get("comment").length > 1024
        )
          throw new Error("unsupported global PAX metadata");
      } else {
        if (
          pendingPax !== undefined ||
          records.size !== 1 ||
          !records.has("path") ||
          size > PROVENANCE_LIMITS.pathBytes + 32
        )
          throw new Error("invalid PAX metadata");
        pendingPax = records.get("path");
      }
      offset = next;
      continue;
    }
    const directory = type === "5";
    const path = canonicalPath(pendingPax ?? rawPath, directory);
    pendingPax = undefined;
    if (!["0", "\0", "5"].includes(type))
      throw new Error("unsupported tar entry");
    if (paths.has(path)) throw new Error("duplicate tar path");
    paths.add(path);
    // Git uses only these two ordinary modes.  Carry this metadata so a future
    // extractor need not infer permissions from the host umask.
    const tarMode = number(header, 100, 8, "mode");
    // git archive serializes ordinary tracked modes as 0666/0777 (subject to
    // tar convention); normalize only those exact encodings to Git's 0644/0755.
    const mode = [0o644, 0o664, 0o666].includes(tarMode) ? 0o644 : [0o755, 0o775, 0o777].includes(tarMode) ? 0o755 : tarMode;
    if (directory ? mode !== 0o755 : ![0o644, 0o755].includes(mode))
      throw new Error("unsupported Git tar mode");
    files.push(Object.freeze({ path, type, mode, offset: payloadStart, size }));
    if (++materialEntries > PROVENANCE_LIMITS.archiveEntries)
      throw new Error("archive entry limit");
    offset = next;
  }
  throw new Error("missing tar termination");
}
