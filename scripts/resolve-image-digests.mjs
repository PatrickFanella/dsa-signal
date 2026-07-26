import { createHash, randomBytes } from 'node:crypto';
import { constants as fsConstants, promises as nodeFs } from 'node:fs';
import { hostname as nodeHostname } from 'node:os';
import { dirname, resolve } from 'node:path';
import { execFile as nodeExecFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFile = promisify(nodeExecFile);
const INDEX_TYPES = new Set(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json']);
const MANIFEST_TYPES = new Set(['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json']);
const LAYER_TYPES = new Set(['application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.oci.image.layer.nondistributable.v1.tar', 'application/vnd.oci.image.layer.nondistributable.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar', 'application/vnd.docker.image.rootfs.diff.tar.gzip', 'application/vnd.docker.image.rootfs.foreign.diff.tar.gzip']);
const CONFIG_TYPES = new Set(['application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json']);
const DIGEST = /^sha256:[a-f0-9]{64}$/;

export const IMAGES = Object.freeze([
  Object.freeze({ name: 'SYNAPSE_IMAGE', repository: 'matrixdotorg/synapse', tag: 'matrixdotorg/synapse:v1.156.0', indexDigest: 'sha256:d2215c4a0e0bbd304489af228345b31d6857c1a228175471358d3fda187c0d91', children: Object.freeze({ amd64: 'sha256:09eaa18f837182d03196a6617a61fbafc0c16ce74de7f9b107f9b511d4703e2b', arm64: 'sha256:3a023fa952f7411d8999df0300fc54e8e379b46196c03ee5d9e26f0564d44282' }) }),
  Object.freeze({ name: 'MAS_IMAGE', repository: 'ghcr.io/element-hq/matrix-authentication-service', tag: 'ghcr.io/element-hq/matrix-authentication-service:1.20.0', indexDigest: 'sha256:1b0cc87ca6bd6186172a123228cfc3be4c94522d5ecc71e7baeaf23e48ce883a', children: Object.freeze({ amd64: 'sha256:3a4e496eb5ab35d331661ebfd1f2a6720213115414c29b8942fb8c68a4503fbe', arm64: 'sha256:6e7b9313e7e19999434f66f4d21c4eb988db2737fdb456d1800d243ef3f6efc6' }) }),
  Object.freeze({ name: 'POSTGRES_IMAGE', repository: 'postgres', tag: 'postgres:17.10-bookworm', indexDigest: 'sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394', children: Object.freeze({ amd64: 'sha256:67870dc097790edf2bd6726658db995dcc830f799d41bb2b78ef07c9a2d5f010', arm64: 'sha256:656bfcd185379cf9eaeea576e1555587c4413f7bbe0e2a55a9b34c8843f8b8ea' }) }),
  Object.freeze({ name: 'CADDY_IMAGE', repository: 'caddy', tag: 'caddy:2.11.4-alpine', indexDigest: 'sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648', children: Object.freeze({ amd64: 'sha256:98eb57d882ccd5213d1688764db10c1ca2c58a1ca3a6717a3411ad798f7a423a', arm64: 'sha256:1172d4213087d3fc30bafc7ff2c2896180eb0c41ff7f75f315568fb36cabdcba' }) }),
  Object.freeze({ name: 'NODE_IMAGE', repository: 'node', tag: 'node:24.18.0-alpine3.24', indexDigest: 'sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd', children: Object.freeze({ amd64: 'sha256:4ba75f835bb8802193e4c114572113d4b26f95f6f094f4b5229d2a77773e0afc', arm64: 'sha256:eef73a25205e27bd016ce672af71560ad6b681142ddf00ff63c7b3098eafcd4d' }) }),
  Object.freeze({ name: 'NGINX_IMAGE', repository: 'nginx', tag: 'nginx:1.29.8-alpine3.23', indexDigest: 'sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de', children: Object.freeze({ amd64: 'sha256:3bcf852aed06467cf075c6105892e4d5a6ebbbafa0ce22d35062db9e90ddef4c', arm64: 'sha256:7dd09a6c4f8cab9a2d2cb98fb39790f220e8bc2ea106b2cebde64b90405e0be8' }) }),
]);

function fail(message) { throw new Error(`image resolution failed: ${message}`); }
function sha256(value) { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
function parseJson(value, label) { try { return JSON.parse(value); } catch { fail(`${label} returned malformed JSON`); } }
function validDescriptor(value) { return value && DIGEST.test(value.digest) && Number.isSafeInteger(value.size) && value.size > 0; }
function repositoryFromTag(tag) {
  if (typeof tag !== 'string' || tag.includes('@')) fail('tag must be a tagged repository reference');
  const colon = tag.lastIndexOf(':');
  if (colon <= tag.lastIndexOf('/') || colon === tag.length - 1) fail(`cannot derive repository from ${tag}`);
  return tag.slice(0, colon).toLowerCase();
}
function validateImages(images) {
  const names = new Set(); const tags = new Set(); const repositories = new Set();
  let approvedPosition = -1;
  for (const image of images) {
    const repository = repositoryFromTag(image.tag);
    if (image.repository !== repository) fail(`${image.name} repository does not match its approved tag`);
    for (const [set, value, label] of [[names, image.name, 'name'], [tags, image.tag, 'tag'], [repositories, repository, 'repository']]) {
      if (set.has(value)) fail(`duplicate image ${label}: ${value}`); set.add(value);
    }
    if (!DIGEST.test(image.indexDigest) || !DIGEST.test(image.children?.amd64) || !DIGEST.test(image.children?.arm64)) fail(`${image.name} has a non-canonical approved digest`);
    const position = IMAGES.findIndex((approved) => approved.name === image.name);
    if (position !== -1 && position <= approvedPosition) fail('approved images are not in fixed order');
    if (position !== -1) approvedPosition = position;
  }
}
async function inspectRaw(reference, run) {
  const { stdout } = await run('docker', ['buildx', 'imagetools', 'inspect', reference, '--raw'], { encoding: 'buffer' });
  return Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
}
async function inspectPlatform(reference, run) {
  const { stdout } = await run('docker', ['buildx', 'imagetools', 'inspect', reference, '--format', '{{json .Image}}'], { encoding: 'utf8' });
  return parseJson(String(stdout), reference);
}
function validateChild(raw, descriptor, name, architecture) {
  if (raw.length !== descriptor.size) fail(`${name} ${architecture} raw manifest size differs from its descriptor`);
  if (sha256(raw) !== descriptor.digest) fail(`${name} ${architecture} raw manifest digest differs from its descriptor`);
  const manifest = parseJson(raw.toString('utf8'), `${name} ${architecture}`);
  if (manifest?.schemaVersion !== 2 || manifest?.mediaType !== descriptor.mediaType || !MANIFEST_TYPES.has(manifest?.mediaType)) fail(`${name} ${architecture} is not an image manifest`);
  if (!validDescriptor(manifest.config) || !CONFIG_TYPES.has(manifest.config.mediaType)) fail(`${name} ${architecture} has an invalid config descriptor`);
  if (!Array.isArray(manifest.layers) || manifest.layers.length === 0 || manifest.layers.some((layer) => !validDescriptor(layer) || !LAYER_TYPES.has(layer.mediaType))) fail(`${name} ${architecture} has invalid layers`);
}

/** Resolve every approved image before returning any publishable lock content. */
export async function resolveImages(images = IMAGES, { run = execFile } = {}) {
  validateImages(images);
  for (const image of images) {
    let raw; try { raw = await inspectRaw(image.tag, run); } catch { fail(`could not inspect ${image.tag}`); }
    if (sha256(raw) !== image.indexDigest) fail(`${image.name} index digest differs from approved digest`);
    const index = parseJson(raw.toString('utf8'), image.tag);
    if (index?.schemaVersion !== 2 || !INDEX_TYPES.has(index?.mediaType) || !Array.isArray(index.manifests)) fail(`${image.name} is not an OCI/Docker image index`);
    for (const architecture of ['amd64', 'arm64']) {
      const matches = index.manifests.filter((manifest) => manifest?.platform?.os === 'linux' && manifest?.platform?.architecture === architecture);
      if (matches.length !== 1 || !MANIFEST_TYPES.has(matches[0]?.mediaType) || !validDescriptor(matches[0])) fail(`${image.name} must contain one valid linux/${architecture} descriptor`);
      if (matches[0].digest !== image.children[architecture]) fail(`${image.name} linux/${architecture} digest differs from approved digest`);
      const reference = `${image.repository}@${matches[0].digest}`;
      let childRaw; try { childRaw = await inspectRaw(reference, run); } catch { fail(`could not inspect ${reference}`); }
      validateChild(childRaw, matches[0], image.name, architecture);
      let platform; try { platform = await inspectPlatform(reference, run); } catch { fail(`could not inspect platform for ${reference}`); }
      if (platform?.os !== 'linux' || platform?.architecture !== architecture) fail(`${image.name} child ${architecture} reports the wrong platform`);
    }
  }
  return `${images.map((image) => `${image.name}=${image.repository}@${image.indexDigest}`).join('\n')}\n`;
}

const recovery = 'manual recovery required: verify guard hostname and process start/PID identity (protect PID reuse), inspect target content, ensure no resolver is running, then remove the exact guard and fsync its parent; never age-reclaim';
async function syncDirectory(fs, directory) { const dir = await fs.open(directory, 'r'); try { await dir.sync(); } finally { await dir.close(); } }
function sameGuard(stat, identity) { return stat.isFile() && stat.uid === identity.uid && (stat.mode & 0o777) === identity.mode && stat.dev === identity.dev && stat.ino === identity.ino; }
async function verifiedGuard(fs, path, identity, metadata) {
  let handle;
  try {
    const before = await fs.lstat(path);
    if (!sameGuard(before, identity)) return false;
    handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const actual = await handle.stat();
    if (!sameGuard(actual, identity)) return false;
    const parsed = JSON.parse(await handle.readFile('utf8'));
    return parsed?.ownerToken === metadata.ownerToken && parsed?.hostname === metadata.hostname && parsed?.pid === metadata.pid && parsed?.startTime === metadata.startTime;
  } catch { return false; } finally { await handle?.close().catch(() => {}); }
}
/** Atomically replace lockPath while holding an owned, durable adjacent guard lock. */
export async function writeLockAtomic(lockPath, content, { fs = nodeFs, random = randomBytes, hostname = nodeHostname(), pid = process.pid, now = () => new Date().toISOString() } = {}) {
  const absolute = resolve(lockPath); const directory = dirname(absolute); const guardPath = `${absolute}.lock`;
  let guard; let identity; let metadata; let tempPath; let published = false; let primaryError;
  try {
    try { guard = await fs.open(guardPath, 'wx', 0o600); } catch (error) { if (error?.code === 'EEXIST') fail(`lock is busy: ${guardPath}; ${recovery}`); fail(`could not acquire guard ${guardPath}`); }
    metadata = { ownerToken: random(16).toString('hex'), pid, hostname, startTime: now() };
    await guard.writeFile(`${JSON.stringify(metadata)}\n`, 'utf8'); await guard.sync(); identity = await guard.stat(); identity = { uid: identity.uid, mode: identity.mode & 0o777, dev: identity.dev, ino: identity.ino }; await syncDirectory(fs, directory);
    const candidate = `${absolute}.${random(16).toString('hex')}.tmp`;
    const temp = await fs.open(candidate, 'wx', 0o600); tempPath = candidate;
    try { await temp.writeFile(content, 'utf8'); await temp.sync(); } finally { await temp.close(); }
    await fs.rename(tempPath, absolute); tempPath = undefined; published = true; await syncDirectory(fs, directory);
  } catch (error) { primaryError = error; }
  if (published) {
    await guard?.close().catch(() => {});
    if (primaryError) fail(`indeterminate publication/guard state after rename; guard preserved; ${recovery}`);
  }
  let cleanupError;
  try { if (tempPath) { await fs.unlink(tempPath); await syncDirectory(fs, directory); } } catch (error) { cleanupError = error; }
  try {
    await guard?.close();
    if (guard && !(await verifiedGuard(fs, guardPath, identity, metadata))) fail(`guard ownership is indeterminate; guard preserved; ${recovery}`);
    if (guard) { await fs.unlink(guardPath); await syncDirectory(fs, directory); }
  } catch (error) { cleanupError ??= error; }
  if (cleanupError) fail(`${published ? 'indeterminate publication/guard state after rename' : 'could not clean up verified guard/temporary state'}; ${recovery}`);
  if (primaryError) throw primaryError;
}
export async function main({ lockPath = 'deploy/locks/images.env', images = IMAGES, run = execFile, fs = nodeFs } = {}) { const content = await resolveImages(images, { run }); await writeLockAtomic(lockPath, content, { fs }); }
if (process.argv[1] && import.meta.url === new URL(process.argv[1], 'file:').href) main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
