import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { IMAGES, resolveImages, writeLockAtomic } from './resolve-image-digests.mjs';

const sha256 = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const approved = {
  NODE_IMAGE: ['node:24.18.0-alpine3.24', 'sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd', 'sha256:4ba75f835bb8802193e4c114572113d4b26f95f6f094f4b5229d2a77773e0afc', 'sha256:eef73a25205e27bd016ce672af71560ad6b681142ddf00ff63c7b3098eafcd4d'],
  NGINX_IMAGE: ['nginx:1.29.8-alpine3.23', 'sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de', 'sha256:3bcf852aed06467cf075c6105892e4d5a6ebbbafa0ce22d35062db9e90ddef4c', 'sha256:7dd09a6c4f8cab9a2d2cb98fb39790f220e8bc2ea106b2cebde64b90405e0be8'],
};
const descriptor = (raw, mediaType) => ({ digest: sha256(raw), size: Buffer.byteLength(raw), mediaType });
function mockedSix() {
  const responses = new Map();
  const images = IMAGES.map((approvedImage, index) => {
    const repository = `example/image-${index}`;
    const tag = `${repository}:1`;
    const children = {};
    for (const architecture of ['amd64', 'arm64']) {
      const config = JSON.stringify({ architecture, os: 'linux' });
      const manifest = JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', config: descriptor(config, 'application/vnd.oci.image.config.v1+json'), layers: [{ digest: sha256(`layer-${index}-${architecture}`), size: 1, mediaType: 'application/vnd.oci.image.layer.v1.tar' }] });
      children[architecture] = descriptor(manifest, 'application/vnd.oci.image.manifest.v1+json').digest;
      responses.set(`${repository}@${children[architecture]}`, Buffer.from(manifest));
    }
    const descriptors = ['amd64', 'arm64'].map((architecture) => ({ digest: children[architecture], size: responses.get(`${repository}@${children[architecture]}`).length, mediaType: 'application/vnd.oci.image.manifest.v1+json', platform: { os: 'linux', architecture } }));
    const raw = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: descriptors }));
    responses.set(tag, raw);
    return { name: approvedImage.name, repository, tag, indexDigest: sha256(raw), children };
  });
  const run = async (_command, args) => {
    const reference = args[3];
    if (args.includes('--format')) return { stdout: JSON.stringify({ os: reference.endsWith(images.find((x) => reference.includes(x.repository))?.children.arm64) ? 'linux' : 'linux', architecture: images.find((x) => reference.includes(x.repository)) && Object.values(images.find((x) => reference.includes(x.repository)).children).findIndex((digest) => reference.endsWith(digest)) === 1 ? 'arm64' : 'amd64' }) };
    return { stdout: responses.get(reference) };
  };
  return { images, responses, run };
}

test('six approved locks are ordered and exact', async () => {
  assert.deepEqual(IMAGES.map((x) => x.name), ['SYNAPSE_IMAGE', 'MAS_IMAGE', 'POSTGRES_IMAGE', 'CADDY_IMAGE', 'NODE_IMAGE', 'NGINX_IMAGE']);
  for (const image of IMAGES.slice(-2)) assert.deepEqual([image.tag, image.indexDigest, image.children.amd64, image.children.arm64], approved[image.name]);
  const lock = await readFile(new URL('../deploy/locks/images.env', import.meta.url), 'utf8');
  assert.equal(lock, `${IMAGES.map((x) => `${x.name}=${x.repository}@${x.indexDigest}`).join('\n')}\n`);
  const provenance = JSON.parse(await readFile(new URL('../deploy/locks/images.provenance.json', import.meta.url), 'utf8'));
  assert.equal(provenance.images.length, 6);
  for (const row of provenance.images.slice(-2)) {
    assert.deepEqual([row.tag, row.indexDigest, row.children.amd64, row.children.arm64], approved[row.name]);
    assert.match(row.imageSourceCommit, /^[a-f0-9]{40}$/);
    assert.match(row.officialImagesMappingCommit, /^[a-f0-9]{40}$/);
    assert.equal(row.verification.approvalDate, '2026-07-23');
    assert.match(row.verification.reason, /No documented index-level Cosign signatures/);
  }
});

test('resolution is fail-closed before atomic publication', async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'image-lock-'));
  try {
    const image = { name: 'TEST_IMAGE', repository: 'example/test', tag: 'example/test:1', indexDigest: sha256('wrong'), children: { amd64: `sha256:${'a'.repeat(64)}`, arm64: `sha256:${'b'.repeat(64)}` } };
    await assert.rejects(resolveImages([image], { run: async () => ({ stdout: Buffer.from('{}') }) }), /index digest differs/);
    await writeLockAtomic(path.join(temp, 'images.env'), 'NEW\n');
    assert.equal(await readFile(path.join(temp, 'images.env'), 'utf8'), 'NEW\n');
  } finally { await rm(temp, { recursive: true, force: true }); }
});

test('mocked resolution validates every one of the six index and child manifests', async () => {
  const { images, run } = mockedSix();
  const result = await resolveImages(images, { run });
  assert.equal(result.split('\n').filter(Boolean).length, 6);
});

test('mocked resolution rejects index, child, and child-config mismatches', async () => {
  const index = mockedSix();
  index.images[0].indexDigest = sha256('wrong');
  await assert.rejects(resolveImages(index.images, { run: index.run }), /index digest differs/);
  const child = mockedSix();
  const childReference = `${child.images[0].repository}@${child.images[0].children.amd64}`;
  child.responses.set(childReference, Buffer.from('{}'));
  await assert.rejects(resolveImages(child.images, { run: child.run }), /raw manifest size differs/);
  const config = mockedSix();
  const configReference = `${config.images[0].repository}@${config.images[0].children.amd64}`;
  const manifest = JSON.parse(config.responses.get(configReference));
  manifest.config.mediaType = 'application/octet-stream';
  const invalid = Buffer.from(JSON.stringify(manifest));
  config.responses.set(configReference, invalid);
  const indexDocument = JSON.parse(config.responses.get(config.images[0].tag));
  const descriptorInIndex = indexDocument.manifests[0];
  descriptorInIndex.digest = sha256(invalid);
  descriptorInIndex.size = invalid.length;
  const indexRaw = Buffer.from(JSON.stringify(indexDocument));
  config.responses.set(config.images[0].tag, indexRaw);
  config.images[0].indexDigest = sha256(indexRaw);
  config.images[0].children.amd64 = sha256(invalid);
  config.responses.set(`${config.images[0].repository}@${config.images[0].children.amd64}`, invalid);
  await assert.rejects(resolveImages(config.images, { run: config.run }), /invalid config descriptor/);
});
