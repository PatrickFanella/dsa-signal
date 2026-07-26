import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateG2EvidenceSchema, validateG2EvidenceV2, validateG2ExpectedV2, writeOrCheckSchema } from './g2-evidence-contract.mjs';
import { buildG2EvidenceFixture } from './g2-evidence-fixture.mjs';
import { PENDING, DISABLED, g2Prerequisites, g2Verdict, runG2, readStableArtifact } from './test-g2-encrypted-direct-chat.mjs';
import { createG2Artifact, createG2RunDirectory, destroyG2RunDirectory, g2FutureChildEnv } from './g2-run-lifecycle.mjs';

const complete = { G2_ACCOUNT_ONE: '@one:example', G2_ACCOUNT_TWO: '@two:example', G2_ACCOUNT_ONE_ENTITLED: 'authorized', G2_ACCOUNT_TWO_ENTITLED: 'authorized', G2_WIRE_CAPTURE_ACCESS: 'authorized', G2_POSTGRES_ACCESS: 'authorized', G2_LOG_ACCESS: 'authorized', G2_MEDIA_ACCESS: 'authorized' };
test('G2 missing prerequisites returns only exact pending verdict', async () => { assert.equal(g2Verdict({}), PENDING); assert.equal(await runG2({}), PENDING); });
test('G2 CLI is nonzero pending without prerequisites', () => { const child = spawnSync(process.execPath, ['scripts/test-g2-encrypted-direct-chat.mjs'], { encoding: 'utf8', env: {} }); assert.notEqual(child.status, 0); assert.equal(child.stdout, `${PENDING}\n`); });
test('G2 needs distinct entitled accounts and authorized collectors', () => { assert.equal(g2Prerequisites({ ...complete, G2_ACCOUNT_TWO: complete.G2_ACCOUNT_ONE }).accounts, false); assert.equal(g2Prerequisites({ ...complete, G2_LOG_ACCESS: 'yes' }).access, false); assert.equal(g2Verdict(complete), undefined); });

test('pure semantic validator validates a complete fixture without claiming trust', () => {
  const { expected, evidence } = buildG2EvidenceFixture();
  assert.equal(validateG2ExpectedV2(expected), true);
  assert.equal(validateG2EvidenceV2(evidence, expected), true);
  assert.equal(writeOrCheckSchema(true), true);
});
test('v2 evidence validator rejects the non-authoritative browser envelope with a valid expected argument', () => {
  const envelope = Object.freeze({ kind: 'non_authoritative_g2_browser_observations_v1', accepted: true });
  const { expected } = buildG2EvidenceFixture();
  assert.equal(validateG2ExpectedV2(expected), true);
  assert.equal(validateG2EvidenceV2(envelope, expected), false);
});
test('generated evidence schema is recursively closed and constrains every array', () => {
  const visit = (schema) => {
    if (!schema || typeof schema !== 'object') return;
    if (schema.type === 'object') {
      assert.equal(schema.additionalProperties, false);
      assert.ok(schema.properties && Object.keys(schema.properties).length > 0);
      assert.deepEqual([...schema.required].sort(), Object.keys(schema.properties).sort());
    }
    if (schema.type === 'array') assert.ok(Object.hasOwn(schema, 'items') || Object.hasOwn(schema, 'prefixItems'));
    for (const value of Object.values(schema)) {
      if (Array.isArray(value)) value.forEach(visit);
      else visit(value);
    }
  };
  visit(generateG2EvidenceSchema());
});
test('semantic validation rejects adversarial expected and evidence drift', () => {
  const { expected, evidence } = buildG2EvidenceFixture();
  const mutations = [
    x => { x.runNonceHash = '0'.repeat(64); }, x => { x.continuity.restart.slots[0].deviceRefHash = '0'.repeat(64); },
    x => { x.scanCells.pop(); }, x => { x.scanCells[0].markerHash = x.scanCells[0].canaryHash; }, x => { x.scanCells[0].controlMatches = 0; },
    x => { x.scanCells[12].corpusHash = '0'.repeat(64); }, x => { x.collection.capture.restartCorpusHash = '0'.repeat(64); },
    x => { x.collection.logs.collectors[0].endCursorHash = '0'.repeat(64); }, x => { x.provenance.runtimeImages[0].imageId = 'sha256:' + '0'.repeat(64); },
    x => { x.databases[1].clusterHash = x.databases[0].clusterHash; }, x => { x.databases[0].persistentWrites = 1; },
    x => { x.continuity.fresh.roomRefHash = '0'.repeat(64); }, x => { x.continuity.fresh.message.sender = 'second'; }, x => { x.continuity.fresh.message.received = false; }, x => { x.continuity.fresh.bootstrapComplete = false; }, x => { x.continuity.restart.observedSasUi = 1; }, x => { x.continuity.restart.newVerificationWireEvents = 1; }, x => { x.continuity.restart.priorA.decrypted = false; }, x => { x.media.noNetwork = false; }, x => { x.auxiliary[0].status = 'configured'; }, x => { x.conformance.status = 'failed'; },
  ];
  for (const mutate of mutations) { const candidate = structuredClone(evidence); mutate(candidate); assert.equal(validateG2EvidenceV2(candidate, expected), false); }
  const expectedMutations = [x => { x.accounts.secondHash = x.accounts.firstHash; }, x => { x.canaries.B = x.canaries.A; }, x => { x.captureCorpora.finalMembers.pop(); }, x => { x.scanAnchors['fresh:A:capture'].controlMatches = 0; }, x => { x.logCollection.collectors[0].containerId = '0'.repeat(64); }, x => { x.continuity.second.crossSigningMasterRefHash = x.continuity.first.crossSigningMasterRefHash; }, x => { x.provenance.builtImages[1].imageId = 'sha256:' + '0'.repeat(64); }, x => { x.databases[0].sourceContainerId = x.databases[1].sourceContainerId; }, x => { x.media.collectorContainerId = x.media.sourceContainerId; }, x => { x.provenance.lockedImages.NODE.platform = 'other'; }, x => { x.conformance.completedAt = '2026-07-25T11:00:01.000Z'; }, x => { x.auxiliary.push({ name: 'other', status: 'disabled', count: 0 }); }];
  for (const mutate of expectedMutations) { const candidate = structuredClone(expected); mutate(candidate); assert.equal(validateG2ExpectedV2(candidate), false); assert.equal(validateG2EvidenceV2(evidence, candidate), false); }
});
test('complete prerequisites remain hard-disabled before child or workspace artifacts', async () => { await assert.rejects(() => runG2(complete), new RegExp(DISABLED)); });
test('future private lifecycle is exclusive, cleaned, and strips hostile child environment', () => { const root = createG2RunDirectory(); const artifact = createG2Artifact(root, 'result.json'); assert.throws(() => createG2Artifact(root, 'result.json')); assert.equal(g2FutureChildEnv({ HOME:'bad', NODE_OPTIONS:'bad', npm_config_x:'bad', LANG:'C', SECRET:'bad' }).LANG, 'C'); assert.equal(g2FutureChildEnv({ HOME:'bad', NODE_OPTIONS:'bad' }).HOME, undefined); destroyG2RunDirectory(root); assert.throws(() => createG2Artifact(root, 'nope')); assert.ok(artifact.includes(root)); });
test('artifact reader is descriptor-bound and rejects symlinks', async () => { const root = await mkdtemp(join(tmpdir(), 'g2-artifact-')); const file = join(root, 'result.json'); await writeFile(file, '{"ok":true}'); assert.equal(await readStableArtifact(file), '{"ok":true}'); const link = join(root, 'link'); await symlink(file, link); await assert.rejects(() => readStableArtifact(link)); });
