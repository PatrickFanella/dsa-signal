import { createHash } from 'node:crypto';
import { G2_AUXILIARY, G2_CONTRACT, G2_LOG_SERVICES, expectedScanCells, canonicalCorpusHash } from './g2-evidence-contract.mjs';

const h = label => createHash('sha256').update(label).digest('hex');
const o = label => `sha256:${h(label)}`;

/** Complete deterministic authority/evidence pair for contract tests only. */
export function buildG2EvidenceFixture() {
  const canaries = { A: h('canary-A'), B: h('canary-B') };
  const freshMembers = [h('capture:fresh:one'), h('capture:fresh:two')].sort();
  const restartMembers = [h('capture:restart:one'), h('capture:restart:two')].sort();
  const finalMembers = [...freshMembers, ...restartMembers].sort();
  const captureCorpora = { freshMembers, restartMembers, finalMembers, freshCorpusHash: canonicalCorpusHash('fresh', freshMembers), restartCorpusHash: canonicalCorpusHash('restart', restartMembers), finalUnionCorpusHash: canonicalCorpusHash('final', finalMembers) };
  const scanAnchors = Object.fromEntries(expectedScanCells().map((key, index) => {
    const [phase, canary, surface] = key.split(':');
    const restart = phase === 'restart-final';
    const corpusHash = surface === 'capture' ? (restart ? captureCorpora.finalUnionCorpusHash : captureCorpora.freshCorpusHash) : h(`${phase}:${surface}:corpus`);
    return [key, { canaryHash: canaries[canary], markerHash: h(`control-marker:${key}`), scannerRunHash: h(`scanner-run:${key}`), corpusHash, inventoryHash: h(`${phase}:${surface}:inventory`), count: restart ? 100 + G2_CONTRACT.surfaces.indexOf(surface) : 10 + index, matches: 0, controlMatches: 1 }];
  }));
  // Restart A and B scan exactly the same final corpus/inventory while retaining distinct scanner/marker anchors.
  for (const surface of G2_CONTRACT.surfaces) {
    const a = scanAnchors[`restart-final:A:${surface}`]; const b = scanAnchors[`restart-final:B:${surface}`];
    b.corpusHash = a.corpusHash; b.inventoryHash = a.inventoryHash; b.count = a.count;
  }
  const logCorpus = h('full-project-log-corpus');
  scanAnchors['restart-final:A:logs'].corpusHash = logCorpus;
  scanAnchors['restart-final:B:logs'].corpusHash = logCorpus;
  const lockedImages = Object.fromEntries(['POSTGRES', 'SYNAPSE', 'MAS', 'CADDY', 'NODE', 'NGINX'].map(family => [family, { indexDigest: o(`${family}:index`), childManifestDigest: o(`${family}:child:amd64`), configDigest: o(`${family}:config`), platform: 'linux-amd64' }]));
  const serviceFamily = name => Object.entries(G2_CONTRACT.runtimeFamilies).find(([, names]) => names.includes(name))?.[0];
  const builtFamily = name => Object.entries(G2_CONTRACT.builtFamilies).find(([, entry]) => entry.services.includes(name))?.[0];
  const services = G2_LOG_SERVICES.map(name => ({ name, containerId: h(`container:${name}`), imageId: name === 'migrate' || name === 'api' ? o('built:backend') : serviceFamily(name) ? lockedImages[serviceFamily(name)].configDigest : o(`built:${name}`) }));
  const runtimeImages = Object.values(G2_CONTRACT.runtimeFamilies).flat().map(name => { const family = serviceFamily(name); const { platform, ...lock } = lockedImages[family]; const service = services.find(x => x.name === name); return { name, family, ...lock, imageId: lock.configDigest, containerId: service.containerId }; });
  const buildMarker = h('parent-build-marker');
  const builtImages = Object.values(G2_CONTRACT.builtFamilies).flatMap(entry => entry.services).map(name => { const family = builtFamily(name); const service = services.find(x => x.name === name); return { name, family, imageId: service.imageId, containerId: service.containerId, buildMarker, bases: G2_CONTRACT.builtFamilies[family].bases.map(base => { const { platform, ...lock } = lockedImages[base]; return { name: base, ...lock }; }) }; });
  const provenance = { sourceCommit: '0123456789abcdef0123456789abcdef01234567', archiveHash: h('source-archive'), renderedComposeHash: h('rendered-compose'), buildMarker, project: 'g2_project', hostArch: 'linux-amd64', lockedImages, services, runtimeImages, builtImages };
  const slots = [
    { name: 'first', accountHash: h('account:first'), deviceRefHash: h('device:first'), crossSigningMasterRefHash: h('cross-signing:first'), profileRefHash: h('profile:first') },
    { name: 'second', accountHash: h('account:second'), deviceRefHash: h('device:second'), crossSigningMasterRefHash: h('cross-signing:second'), profileRefHash: h('profile:second') },
  ];
  const logCollection = { corpusHash: logCorpus, collectors: G2_LOG_SERVICES.map(name => ({ name, containerId: services.find(x => x.name === name).containerId, startCursorHash: h(`cursor:start:${name}`), endCursorHash: h(`cursor:end:${name}`) })) };
  const databases = Object.entries(G2_CONTRACT.databases).map(([name, topology]) => {
    const anchor = scanAnchors[`restart-final:A:${name}`];
    return { name, sourceService: topology.sourceService, sourceContainerId: services.find(x => x.name === topology.sourceService).containerId, clusterHash: h(topology.cluster === 'control' ? 'cluster:control' : 'cluster:matrix'), databaseHash: h(`database:${name}`), networkHash: h(topology.network === 'control' ? 'network:control' : 'network:matrix'), project: provenance.project, scannerRunHash: anchor.scannerRunHash, corpusHash: anchor.corpusHash, inventoryHash: anchor.inventoryHash, inventoryCount: anchor.count, supportedTypes: name === 'masPostgres' ? [...G2_CONTRACT.builtInTypes, 'citext'] : [...G2_CONTRACT.builtInTypes] };
  });
  const mediaAnchor = scanAnchors['restart-final:A:media'];
  const media = { project: provenance.project, volume: G2_CONTRACT.media.volume, volumeIdentityHash: h('volume:synapse-data'), path: G2_CONTRACT.media.path, sourceService: 'synapse', sourceContainerId: services.find(x => x.name === 'synapse').containerId, collectorContainerId: h('collector:media:no-network'), scannerRunHash: mediaAnchor.scannerRunHash, corpusHash: mediaAnchor.corpusHash, inventoryHash: mediaAnchor.inventoryHash, inventoryCount: mediaAnchor.count };
  const auxiliary = G2_AUXILIARY.map((name, index) => ({ name, status: index % 2 ? 'not-configured' : 'disabled', count: 0 }));
  const conformance = { issuer: 'OpenID Foundation', plan: 'oidc-plan', suite: 'conformance-suite', status: 'passed', resultHash: h('conformance-result'), completedAt: '2026-07-23T10:00:00Z' };
  const expected = { runNonceHash: h('run-nonce'), runStartedAt: '2026-07-23T11:00:00Z', accounts: { firstHash: slots[0].accountHash, secondHash: slots[1].accountHash }, canaries, continuity: { first: slots[0], second: slots[1], roomRefHash: h('room') }, scanAnchors, captureCorpora, logCollection, provenance, databases, media, auxiliary, conformance };
  const msg = (sender, recipient, canary) => ({ sender, recipient, canary, canaryHash: canaries[canary], sent: true, decrypted: true, received: true });
  const evidence = {
    schemaVersion: 2, verdict: 'PASS_EXTERNAL_G2_ENCRYPTED_DIRECT_CHAT', runNonceHash: expected.runNonceHash, accounts: structuredClone(expected.accounts),
    continuity: { fresh: { slots: structuredClone(slots), roomRefHash: expected.continuity.roomRefHash, bothJoined: true, sendReady: true, bootstrapComplete: true, sasComplete: true, message: msg('first', 'second', 'A') }, restart: { slots: structuredClone(slots), roomRefHash: expected.continuity.roomRefHash, bothJoined: true, sendReady: true, priorA: msg('first', 'second', 'A'), observedSasUi: 0, newVerificationWireEvents: 0, message: msg('second', 'first', 'B') } },
    scanCells: expectedScanCells().map(key => { const [phase, canary, surface] = key.split(':'); return { phase, canary, surface, ...structuredClone(scanAnchors[key]) }; }),
    conformance: structuredClone(conformance), provenance: structuredClone(provenance),
    collection: { capture: { ...structuredClone(captureCorpora), fresh: { gapless: true, readyBeforeStart: true, missingBodies: 0, serviceWorkerGaps: 0, overflow: 0, dropped: 0 }, restart: { gapless: true, readyBeforeStart: true, missingBodies: 0, serviceWorkerGaps: 0, overflow: 0, dropped: 0 } }, logs: { corpusHash: logCollection.corpusHash, readyBeforeServiceStart: true, fullProjectLifetime: true, overflow: 0, drops: 0, rotation: 0, truncation: 0, missingBodies: 0, collectors: structuredClone(logCollection.collectors) } },
    databases: databases.map(db => ({ ...structuredClone(db), transactionRollback: true, persistentWrites: 0, extensionInstalled: false, discoveredSupportedTypes: structuredClone(db.supportedTypes), controlledTypes: structuredClone(db.supportedTypes) })),
    media: { ...structuredClone(media), readOnly: true, noNetwork: true }, auxiliary: structuredClone(auxiliary),
  };
  return { expected, evidence };
}
