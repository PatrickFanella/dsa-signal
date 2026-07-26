/** Pure G2 evidence semantics. Validation here establishes no trust. */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

export const G2_SCHEMA_VERSION = 2;
export const G2_PASS = 'PASS_EXTERNAL_G2_ENCRYPTED_DIRECT_CHAT';
export const G2_CONFORMANCE_FRESHNESS_MS = 24 * 60 * 60 * 1000;
export const G2_CONTRACT = Object.freeze({
  surfaces: ['capture', 'controlPostgres', 'synapsePostgres', 'masPostgres', 'logs', 'media'],
  phases: { fresh: ['A'], 'restart-final': ['A', 'B'] },
  services: ['control-db', 'matrix-db', 'migrate', 'api', 'web', 'synapse', 'synapse-data-init', 'mas', 'mas-ready', 'mas-migrate', 'gateway', 'gateway-ca-export'],
  runtimeFamilies: { POSTGRES: ['control-db', 'matrix-db'], SYNAPSE: ['synapse', 'synapse-data-init'], MAS: ['mas', 'mas-migrate'], CADDY: ['mas-ready', 'gateway', 'gateway-ca-export'] },
  builtFamilies: { BACKEND: { services: ['migrate', 'api'], bases: ['NODE'] }, WEB: { services: ['web'], bases: ['NODE', 'NGINX'] } },
  databases: { controlPostgres: { sourceService: 'control-db', cluster: 'control', network: 'control' }, synapsePostgres: { sourceService: 'matrix-db', cluster: 'matrix', network: 'matrix' }, masPostgres: { sourceService: 'matrix-db', cluster: 'matrix', network: 'matrix' } },
  media: { sourceService: 'synapse', volume: 'synapse-data', path: '/data/media_store' },
  auxiliary: ['push', 'metrics', 'traces', 'support', 'backups'],
  builtInTypes: ['text', 'varchar', 'json', 'jsonb', 'bytea'],
});
export const G2_SURFACES = G2_CONTRACT.surfaces;
export const G2_PHASES = Object.freeze(Object.keys(G2_CONTRACT.phases));
export const G2_CANARIES = Object.freeze(['A', 'B']);
export const G2_LOG_SERVICES = G2_CONTRACT.services;
export const G2_AUXILIARY = G2_CONTRACT.auxiliary;
export const expectedScanCells = () => G2_PHASES.flatMap((phase) => G2_CONTRACT.phases[phase].flatMap((canary) => G2_SURFACES.map((surface) => `${phase}:${canary}:${surface}`)));
export const canonicalCorpusHash = (label, members) => createHash('sha256').update(`g2-corpus-v2\0${label}\0${[...members].sort().join('\n')}`).digest('hex');

const H = /^[a-f0-9]{64}$/;
const O = /^sha256:[a-f0-9]{64}$/;
const TOKEN = /^[A-Za-z0-9._/-]+$/;
const NAME = /^[a-z0-9][a-z0-9_-]*$/;
const hash = (value) => typeof value === 'string' && H.test(value);
const oci = (value) => typeof value === 'string' && O.test(value);
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const unique = (values) => new Set(values).size === values.length;
const ordered = (values, names, predicate) => Array.isArray(values) && values.length === names.length && values.every((value, index) => value?.name === names[index] && predicate(value));
const runtimeFamily = (service) => Object.entries(G2_CONTRACT.runtimeFamilies).find(([, services]) => services.includes(service))?.[0];
const builtFamily = (service) => Object.entries(G2_CONTRACT.builtFamilies).find(([, entry]) => entry.services.includes(service))?.[0];
const lockNames = [...Object.keys(G2_CONTRACT.runtimeFamilies), 'NODE', 'NGINX'];
const runtimeServices = Object.values(G2_CONTRACT.runtimeFamilies).flat();
const builtServices = Object.values(G2_CONTRACT.builtFamilies).flatMap((entry) => entry.services);
const databaseNames = Object.keys(G2_CONTRACT.databases);

const validTime = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) && Number.isFinite(Date.parse(value));
const validMembers = (value) => Array.isArray(value) && value.length <= 4096 && value.every(hash) && unique(value) && equal(value, [...value].sort());
const validSlot = (value, name) => exact(value, ['name', 'accountHash', 'deviceRefHash', 'crossSigningMasterRefHash', 'profileRefHash']) && value.name === name && [value.accountHash, value.deviceRefHash, value.crossSigningMasterRefHash, value.profileRefHash].every(hash);
const validAnchor = (value) => exact(value, ['canaryHash', 'markerHash', 'scannerRunHash', 'corpusHash', 'inventoryHash', 'count', 'matches', 'controlMatches']) && [value.canaryHash, value.markerHash, value.scannerRunHash, value.corpusHash, value.inventoryHash].every(hash) && count(value.count) && value.matches === 0 && Number.isSafeInteger(value.controlMatches) && value.controlMatches > 0;

/** Validate the complete authority object before accepting any evidence. */
export function validateG2ExpectedV2(expected) {
  try {
    const root = ['runNonceHash', 'runStartedAt', 'accounts', 'canaries', 'continuity', 'scanAnchors', 'captureCorpora', 'logCollection', 'provenance', 'databases', 'media', 'auxiliary', 'conformance'];
    if (!exact(expected, root) || !hash(expected.runNonceHash) || !validTime(expected.runStartedAt)
      || !exact(expected.accounts, ['firstHash', 'secondHash']) || ![expected.accounts.firstHash, expected.accounts.secondHash].every(hash) || expected.accounts.firstHash === expected.accounts.secondHash
      || !exact(expected.canaries, ['A', 'B']) || ![expected.canaries.A, expected.canaries.B].every(hash) || expected.canaries.A === expected.canaries.B) return false;

    const continuity = expected.continuity;
    if (!exact(continuity, ['first', 'second', 'roomRefHash']) || !validSlot(continuity.first, 'first') || !validSlot(continuity.second, 'second') || !hash(continuity.roomRefHash)
      || continuity.first.accountHash !== expected.accounts.firstHash || continuity.second.accountHash !== expected.accounts.secondHash
      || !unique([continuity.first.deviceRefHash, continuity.second.deviceRefHash])
      || !unique([continuity.first.profileRefHash, continuity.second.profileRefHash])
      || !unique([continuity.first.crossSigningMasterRefHash, continuity.second.crossSigningMasterRefHash])) return false;

    const cellNames = expectedScanCells();
    if (!exact(expected.scanAnchors, cellNames) || !cellNames.every((name) => validAnchor(expected.scanAnchors[name]) && expected.scanAnchors[name].canaryHash === expected.canaries[name.split(':')[1]])) return false;
    const markers = cellNames.map((name) => expected.scanAnchors[name].markerHash);
    if (!unique(markers) || markers.some((marker) => marker === expected.canaries.A || marker === expected.canaries.B)) return false;
    for (const surface of G2_SURFACES) {
      const first = expected.scanAnchors[`restart-final:A:${surface}`];
      const second = expected.scanAnchors[`restart-final:B:${surface}`];
      if (first.corpusHash !== second.corpusHash || first.inventoryHash !== second.inventoryHash || first.count !== second.count) return false;
    }

    const capture = expected.captureCorpora;
    if (!exact(capture, ['freshMembers', 'restartMembers', 'finalMembers', 'freshCorpusHash', 'restartCorpusHash', 'finalUnionCorpusHash'])
      || ![capture.freshMembers, capture.restartMembers, capture.finalMembers].every(validMembers)
      || capture.freshMembers.some((member) => capture.restartMembers.includes(member))
      || !equal(capture.finalMembers, [...new Set([...capture.freshMembers, ...capture.restartMembers])].sort())
      || capture.freshCorpusHash !== canonicalCorpusHash('fresh', capture.freshMembers)
      || capture.restartCorpusHash !== canonicalCorpusHash('restart', capture.restartMembers)
      || capture.finalUnionCorpusHash !== canonicalCorpusHash('final', capture.finalMembers)
      || expected.scanAnchors['fresh:A:capture'].corpusHash !== capture.freshCorpusHash
      || G2_CANARIES.some((canary) => expected.scanAnchors[`restart-final:${canary}:capture`].corpusHash !== capture.finalUnionCorpusHash)) return false;

    const logs = expected.logCollection;
    if (!exact(logs, ['corpusHash', 'collectors']) || !hash(logs.corpusHash)
      || !ordered(logs.collectors, G2_LOG_SERVICES, (collector) => exact(collector, ['name', 'containerId', 'startCursorHash', 'endCursorHash']) && [collector.containerId, collector.startCursorHash, collector.endCursorHash].every(hash) && collector.startCursorHash !== collector.endCursorHash)
      || G2_CANARIES.some((canary) => expected.scanAnchors[`restart-final:${canary}:logs`].corpusHash !== logs.corpusHash)) return false;

    const provenance = expected.provenance;
    if (!exact(provenance, ['sourceCommit', 'archiveHash', 'renderedComposeHash', 'buildMarker', 'project', 'hostArch', 'lockedImages', 'services', 'runtimeImages', 'builtImages'])
      || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(provenance.sourceCommit) || ![provenance.archiveHash, provenance.renderedComposeHash, provenance.buildMarker].every(hash) || !NAME.test(provenance.project) || !TOKEN.test(provenance.hostArch)
      || !exact(provenance.lockedImages, lockNames)
      || !lockNames.every((name) => exact(provenance.lockedImages[name], ['indexDigest', 'childManifestDigest', 'configDigest', 'platform']) && [provenance.lockedImages[name].indexDigest, provenance.lockedImages[name].childManifestDigest, provenance.lockedImages[name].configDigest].every(oci) && provenance.lockedImages[name].platform === provenance.hostArch)
      || !ordered(provenance.services, G2_LOG_SERVICES, (service) => exact(service, ['name', 'containerId', 'imageId']) && hash(service.containerId) && oci(service.imageId))
      || !unique(provenance.services.map((service) => service.containerId))) return false;
    const service = (name) => provenance.services.find((entry) => entry.name === name);
    if (!ordered(provenance.runtimeImages, runtimeServices, (image) => {
      const lock = provenance.lockedImages[image.family];
      return exact(image, ['name', 'family', 'indexDigest', 'childManifestDigest', 'configDigest', 'imageId', 'containerId']) && image.family === runtimeFamily(image.name) && lock && [image.indexDigest, image.childManifestDigest, image.configDigest, image.imageId].every(oci) && image.indexDigest === lock.indexDigest && image.childManifestDigest === lock.childManifestDigest && image.configDigest === lock.configDigest && image.imageId === image.configDigest && image.imageId === service(image.name)?.imageId && image.containerId === service(image.name)?.containerId;
    }) || !ordered(provenance.builtImages, builtServices, (image) => {
      const family = G2_CONTRACT.builtFamilies[image.family];
      return exact(image, ['name', 'family', 'imageId', 'containerId', 'buildMarker', 'bases']) && image.family === builtFamily(image.name) && oci(image.imageId) && hash(image.containerId) && image.buildMarker === provenance.buildMarker && image.imageId === service(image.name)?.imageId && image.containerId === service(image.name)?.containerId && ordered(image.bases, family?.bases ?? [], (base) => {
        const lock = provenance.lockedImages[base.name];
        return exact(base, ['name', 'indexDigest', 'childManifestDigest', 'configDigest']) && lock && base.indexDigest === lock.indexDigest && base.childManifestDigest === lock.childManifestDigest && base.configDigest === lock.configDigest;
      });
    })) return false;
    const backend = provenance.builtImages.filter((image) => image.family === 'BACKEND');
    if (backend.length !== 2 || backend[0].imageId !== backend[1].imageId || backend[0].buildMarker !== backend[1].buildMarker || !logs.collectors.every((collector) => collector.containerId === service(collector.name)?.containerId)) return false;

    if (!ordered(expected.databases, databaseNames, (database) => exact(database, ['name', 'sourceService', 'sourceContainerId', 'clusterHash', 'databaseHash', 'networkHash', 'project', 'scannerRunHash', 'corpusHash', 'inventoryHash', 'inventoryCount', 'supportedTypes']) && database.sourceService === G2_CONTRACT.databases[database.name].sourceService && database.sourceContainerId === service(database.sourceService)?.containerId && [database.clusterHash, database.databaseHash, database.networkHash, database.scannerRunHash, database.corpusHash, database.inventoryHash].every(hash) && database.project === provenance.project && count(database.inventoryCount) && (equal(database.supportedTypes, G2_CONTRACT.builtInTypes) || equal(database.supportedTypes, [...G2_CONTRACT.builtInTypes, 'citext'])))) return false;
    const [control, synapse, mas] = expected.databases;
    if (control.clusterHash === synapse.clusterHash || control.networkHash === synapse.networkHash || control.databaseHash === synapse.databaseHash || control.databaseHash === mas.databaseHash || synapse.clusterHash !== mas.clusterHash || synapse.networkHash !== mas.networkHash || synapse.databaseHash === mas.databaseHash
      || !expected.databases.every((database) => {
        const anchor = expected.scanAnchors[`restart-final:A:${database.name}`];
        return database.scannerRunHash === anchor.scannerRunHash && database.corpusHash === anchor.corpusHash && database.inventoryHash === anchor.inventoryHash && database.inventoryCount === anchor.count;
      })) return false;

    const media = expected.media;
    const mediaAnchor = expected.scanAnchors['restart-final:A:media'];
    if (!exact(media, ['project', 'volume', 'volumeIdentityHash', 'path', 'sourceService', 'sourceContainerId', 'collectorContainerId', 'scannerRunHash', 'corpusHash', 'inventoryHash', 'inventoryCount']) || media.project !== provenance.project || media.volume !== G2_CONTRACT.media.volume || media.path !== G2_CONTRACT.media.path || media.sourceService !== G2_CONTRACT.media.sourceService || media.sourceContainerId !== service('synapse')?.containerId || ![media.volumeIdentityHash, media.collectorContainerId, media.scannerRunHash, media.corpusHash, media.inventoryHash].every(hash) || media.volumeIdentityHash === media.collectorContainerId || media.collectorContainerId === media.sourceContainerId || !count(media.inventoryCount) || media.scannerRunHash !== mediaAnchor.scannerRunHash || media.corpusHash !== mediaAnchor.corpusHash || media.inventoryHash !== mediaAnchor.inventoryHash || media.inventoryCount !== mediaAnchor.count) return false;
    if (!ordered(expected.auxiliary, G2_AUXILIARY, (entry) => exact(entry, ['name', 'status', 'count']) && ['disabled', 'not-configured'].includes(entry.status) && entry.count === 0)
      || !exact(expected.conformance, ['issuer', 'plan', 'suite', 'status', 'resultHash', 'completedAt']) || expected.conformance.issuer !== 'OpenID Foundation' || !TOKEN.test(expected.conformance.plan) || !TOKEN.test(expected.conformance.suite) || expected.conformance.status !== 'passed' || !hash(expected.conformance.resultHash) || !validTime(expected.conformance.completedAt) || Date.parse(expected.conformance.completedAt) > Date.parse(expected.runStartedAt) || Date.parse(expected.runStartedAt) - Date.parse(expected.conformance.completedAt) > G2_CONFORMANCE_FRESHNESS_MS) return false;
    return true;
  } catch {
    return false;
  }
}

const validMessage = (value, sender, recipient, canary, expected) => exact(value, ['sender', 'recipient', 'canary', 'canaryHash', 'sent', 'decrypted', 'received']) && value.sender === sender && value.recipient === recipient && value.canary === canary && value.canaryHash === expected.canaries[canary] && value.sent === true && value.decrypted === true && value.received === true;
const validCaptureRun = (value) => exact(value, ['gapless', 'readyBeforeStart', 'missingBodies', 'serviceWorkerGaps', 'overflow', 'dropped']) && value.gapless === true && value.readyBeforeStart === true && ['missingBodies', 'serviceWorkerGaps', 'overflow', 'dropped'].every((key) => value[key] === 0);

export function validateG2EvidenceV2(value, expected) {
  try {
    if (!validateG2ExpectedV2(expected)) return false;
    const root = ['schemaVersion', 'verdict', 'runNonceHash', 'accounts', 'continuity', 'scanCells', 'conformance', 'provenance', 'collection', 'databases', 'media', 'auxiliary'];
    if (!exact(value, root) || value.schemaVersion !== G2_SCHEMA_VERSION || value.verdict !== G2_PASS || value.runNonceHash !== expected.runNonceHash || !equal(value.accounts, expected.accounts) || !equal(value.conformance, expected.conformance) || !equal(value.provenance, expected.provenance) || !equal(value.auxiliary, expected.auxiliary)) return false;
    const { fresh, restart } = value.continuity ?? {};
    if (!exact(value.continuity, ['fresh', 'restart'])
      || !exact(fresh, ['slots', 'roomRefHash', 'bothJoined', 'sendReady', 'bootstrapComplete', 'sasComplete', 'message']) || !equal(fresh.slots, [expected.continuity.first, expected.continuity.second]) || fresh.roomRefHash !== expected.continuity.roomRefHash || ![fresh.bothJoined, fresh.sendReady, fresh.bootstrapComplete, fresh.sasComplete].every((item) => item === true) || !validMessage(fresh.message, 'first', 'second', 'A', expected)
      || !exact(restart, ['slots', 'roomRefHash', 'bothJoined', 'sendReady', 'priorA', 'observedSasUi', 'newVerificationWireEvents', 'message']) || !equal(restart.slots, [expected.continuity.first, expected.continuity.second]) || restart.roomRefHash !== expected.continuity.roomRefHash || restart.bothJoined !== true || restart.sendReady !== true || !validMessage(restart.priorA, 'first', 'second', 'A', expected) || restart.observedSasUi !== 0 || restart.newVerificationWireEvents !== 0 || !validMessage(restart.message, 'second', 'first', 'B', expected)) return false;
    if (!Array.isArray(value.scanCells) || value.scanCells.length !== expectedScanCells().length || !value.scanCells.every((cell, index) => {
      const name = expectedScanCells()[index];
      return exact(cell, ['phase', 'canary', 'surface', 'canaryHash', 'markerHash', 'scannerRunHash', 'corpusHash', 'inventoryHash', 'count', 'matches', 'controlMatches']) && `${cell.phase}:${cell.canary}:${cell.surface}` === name && equal({ canaryHash: cell.canaryHash, markerHash: cell.markerHash, scannerRunHash: cell.scannerRunHash, corpusHash: cell.corpusHash, inventoryHash: cell.inventoryHash, count: cell.count, matches: cell.matches, controlMatches: cell.controlMatches }, expected.scanAnchors[name]);
    })) return false;
    const capture = value.collection?.capture;
    const logs = value.collection?.logs;
    if (!exact(value.collection, ['capture', 'logs']) || !exact(capture, ['freshMembers', 'restartMembers', 'finalMembers', 'freshCorpusHash', 'restartCorpusHash', 'finalUnionCorpusHash', 'fresh', 'restart']) || !equal({ freshMembers: capture.freshMembers, restartMembers: capture.restartMembers, finalMembers: capture.finalMembers, freshCorpusHash: capture.freshCorpusHash, restartCorpusHash: capture.restartCorpusHash, finalUnionCorpusHash: capture.finalUnionCorpusHash }, expected.captureCorpora) || !validCaptureRun(capture.fresh) || !validCaptureRun(capture.restart) || !exact(logs, ['corpusHash', 'readyBeforeServiceStart', 'fullProjectLifetime', 'overflow', 'drops', 'rotation', 'truncation', 'missingBodies', 'collectors']) || logs.corpusHash !== expected.logCollection.corpusHash || logs.readyBeforeServiceStart !== true || logs.fullProjectLifetime !== true || !['overflow', 'drops', 'rotation', 'truncation', 'missingBodies'].every((key) => logs[key] === 0) || !equal(logs.collectors, expected.logCollection.collectors)) return false;
    if (!Array.isArray(value.databases) || value.databases.length !== expected.databases.length || !value.databases.every((database, index) => {
      const { transactionRollback, persistentWrites, extensionInstalled, discoveredSupportedTypes, controlledTypes, ...authority } = database;
      return equal(authority, expected.databases[index]) && transactionRollback === true && persistentWrites === 0 && extensionInstalled === false && equal(discoveredSupportedTypes, expected.databases[index].supportedTypes) && equal(controlledTypes, expected.databases[index].supportedTypes);
    })) return false;
    return exact(value.media, ['project', 'volume', 'volumeIdentityHash', 'path', 'sourceService', 'sourceContainerId', 'collectorContainerId', 'scannerRunHash', 'corpusHash', 'inventoryHash', 'inventoryCount', 'readOnly', 'noNetwork']) && equal({ ...value.media, readOnly: undefined, noNetwork: undefined }, { ...expected.media, readOnly: undefined, noNetwork: undefined }) && value.media.readOnly === true && value.media.noNetwork === true;
  } catch {
    return false;
  }
}

const closed = (required, properties) => ({ type: 'object', additionalProperties: false, required, properties });
const string = (pattern) => ({ type: 'string', pattern });
const Hs = string(H.source);
const Os = string(O.source);
const integer = (minimum = 0) => ({ type: 'integer', minimum });
const tuple = (items) => ({ type: 'array', minItems: items.length, maxItems: items.length, prefixItems: items, items: false });
const namedTuple = (names, schema) => tuple(names.map((name) => ({ ...schema(name), properties: { ...schema(name).properties, name: { const: name } } })));

/** Generated closed structural schema; semantic cross-field equality is checked above. */
export function generateG2EvidenceSchema() {
  const slot = (name) => closed(['name', 'accountHash', 'deviceRefHash', 'crossSigningMasterRefHash', 'profileRefHash'], { name: { const: name }, accountHash: Hs, deviceRefHash: Hs, crossSigningMasterRefHash: Hs, profileRefHash: Hs });
  const message = (sender, recipient, canary) => closed(['sender', 'recipient', 'canary', 'canaryHash', 'sent', 'decrypted', 'received'], { sender: { const: sender }, recipient: { const: recipient }, canary: { const: canary }, canaryHash: Hs, sent: { const: true }, decrypted: { const: true }, received: { const: true } });
  const scan = (key) => { const [phase, canary, surface] = key.split(':'); return closed(['phase', 'canary', 'surface', 'canaryHash', 'markerHash', 'scannerRunHash', 'corpusHash', 'inventoryHash', 'count', 'matches', 'controlMatches'], { phase: { const: phase }, canary: { const: canary }, surface: { const: surface }, canaryHash: Hs, markerHash: Hs, scannerRunHash: Hs, corpusHash: Hs, inventoryHash: Hs, count: integer(), matches: { const: 0 }, controlMatches: integer(1) }); };
  const captureRun = closed(['gapless', 'readyBeforeStart', 'missingBodies', 'serviceWorkerGaps', 'overflow', 'dropped'], { gapless: { const: true }, readyBeforeStart: { const: true }, missingBodies: { const: 0 }, serviceWorkerGaps: { const: 0 }, overflow: { const: 0 }, dropped: { const: 0 } });
  const collector = (name) => closed(['name', 'containerId', 'startCursorHash', 'endCursorHash'], { name: { const: name }, containerId: Hs, startCursorHash: Hs, endCursorHash: Hs });
  const service = (name) => closed(['name', 'containerId', 'imageId'], { name: { const: name }, containerId: Hs, imageId: Os });
  const lock = closed(['indexDigest', 'childManifestDigest', 'configDigest', 'platform'], { indexDigest: Os, childManifestDigest: Os, configDigest: Os, platform: string(TOKEN.source) });
  const runtime = (name) => closed(['name', 'family', 'indexDigest', 'childManifestDigest', 'configDigest', 'imageId', 'containerId'], { name: { const: name }, family: { const: runtimeFamily(name) }, indexDigest: Os, childManifestDigest: Os, configDigest: Os, imageId: Os, containerId: Hs });
  const built = (name) => { const family = builtFamily(name); return closed(['name', 'family', 'imageId', 'containerId', 'buildMarker', 'bases'], { name: { const: name }, family: { const: family }, imageId: Os, containerId: Hs, buildMarker: Hs, bases: tuple(G2_CONTRACT.builtFamilies[family].bases.map((base) => closed(['name', 'indexDigest', 'childManifestDigest', 'configDigest'], { name: { const: base }, indexDigest: Os, childManifestDigest: Os, configDigest: Os }))) }); };
  const types = { oneOf: [tuple(G2_CONTRACT.builtInTypes.map((type) => ({ const: type }))), tuple([...G2_CONTRACT.builtInTypes, 'citext'].map((type) => ({ const: type })))] };
  const database = (name) => closed(['name', 'sourceService', 'sourceContainerId', 'clusterHash', 'databaseHash', 'networkHash', 'project', 'scannerRunHash', 'corpusHash', 'inventoryHash', 'inventoryCount', 'supportedTypes', 'transactionRollback', 'persistentWrites', 'extensionInstalled', 'discoveredSupportedTypes', 'controlledTypes'], { name: { const: name }, sourceService: { const: G2_CONTRACT.databases[name].sourceService }, sourceContainerId: Hs, clusterHash: Hs, databaseHash: Hs, networkHash: Hs, project: string(NAME.source), scannerRunHash: Hs, corpusHash: Hs, inventoryHash: Hs, inventoryCount: integer(), supportedTypes: types, transactionRollback: { const: true }, persistentWrites: { const: 0 }, extensionInstalled: { const: false }, discoveredSupportedTypes: types, controlledTypes: types });
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $comment: 'Generated by scripts/g2-evidence-contract.mjs; do not edit.',
    ...closed(['schemaVersion', 'verdict', 'runNonceHash', 'accounts', 'continuity', 'scanCells', 'conformance', 'provenance', 'collection', 'databases', 'media', 'auxiliary'], {
      schemaVersion: { const: G2_SCHEMA_VERSION }, verdict: { const: G2_PASS }, runNonceHash: Hs,
      accounts: closed(['firstHash', 'secondHash'], { firstHash: Hs, secondHash: Hs }),
      continuity: closed(['fresh', 'restart'], { fresh: closed(['slots', 'roomRefHash', 'bothJoined', 'sendReady', 'bootstrapComplete', 'sasComplete', 'message'], { slots: tuple([slot('first'), slot('second')]), roomRefHash: Hs, bothJoined: { const: true }, sendReady: { const: true }, bootstrapComplete: { const: true }, sasComplete: { const: true }, message: message('first', 'second', 'A') }), restart: closed(['slots', 'roomRefHash', 'bothJoined', 'sendReady', 'priorA', 'observedSasUi', 'newVerificationWireEvents', 'message'], { slots: tuple([slot('first'), slot('second')]), roomRefHash: Hs, bothJoined: { const: true }, sendReady: { const: true }, priorA: message('first', 'second', 'A'), observedSasUi: { const: 0 }, newVerificationWireEvents: { const: 0 }, message: message('second', 'first', 'B') }) }),
      scanCells: tuple(expectedScanCells().map(scan)),
      conformance: closed(['issuer', 'plan', 'suite', 'status', 'resultHash', 'completedAt'], { issuer: { const: 'OpenID Foundation' }, plan: string(TOKEN.source), suite: string(TOKEN.source), status: { const: 'passed' }, resultHash: Hs, completedAt: { type: 'string', format: 'date-time' } }),
      provenance: closed(['sourceCommit', 'archiveHash', 'renderedComposeHash', 'buildMarker', 'project', 'hostArch', 'lockedImages', 'services', 'runtimeImages', 'builtImages'], { sourceCommit: string('^(?:[a-f0-9]{40}|[a-f0-9]{64})$'), archiveHash: Hs, renderedComposeHash: Hs, buildMarker: Hs, project: string(NAME.source), hostArch: string(TOKEN.source), lockedImages: closed(lockNames, Object.fromEntries(lockNames.map((name) => [name, lock]))), services: tuple(G2_LOG_SERVICES.map(service)), runtimeImages: tuple(runtimeServices.map(runtime)), builtImages: tuple(builtServices.map(built)) }),
      collection: closed(['capture', 'logs'], { capture: closed(['freshMembers', 'restartMembers', 'finalMembers', 'freshCorpusHash', 'restartCorpusHash', 'finalUnionCorpusHash', 'fresh', 'restart'], { freshMembers: { type: 'array', maxItems: 4096, items: Hs }, restartMembers: { type: 'array', maxItems: 4096, items: Hs }, finalMembers: { type: 'array', maxItems: 4096, items: Hs }, freshCorpusHash: Hs, restartCorpusHash: Hs, finalUnionCorpusHash: Hs, fresh: captureRun, restart: captureRun }), logs: closed(['corpusHash', 'readyBeforeServiceStart', 'fullProjectLifetime', 'overflow', 'drops', 'rotation', 'truncation', 'missingBodies', 'collectors'], { corpusHash: Hs, readyBeforeServiceStart: { const: true }, fullProjectLifetime: { const: true }, overflow: { const: 0 }, drops: { const: 0 }, rotation: { const: 0 }, truncation: { const: 0 }, missingBodies: { const: 0 }, collectors: tuple(G2_LOG_SERVICES.map(collector)) }) }),
      databases: tuple(databaseNames.map(database)),
      media: closed(['project', 'volume', 'volumeIdentityHash', 'path', 'sourceService', 'sourceContainerId', 'collectorContainerId', 'scannerRunHash', 'corpusHash', 'inventoryHash', 'inventoryCount', 'readOnly', 'noNetwork'], { project: string(NAME.source), volume: { const: G2_CONTRACT.media.volume }, volumeIdentityHash: Hs, path: { const: G2_CONTRACT.media.path }, sourceService: { const: G2_CONTRACT.media.sourceService }, sourceContainerId: Hs, collectorContainerId: Hs, scannerRunHash: Hs, corpusHash: Hs, inventoryHash: Hs, inventoryCount: integer(), readOnly: { const: true }, noNetwork: { const: true } }),
      auxiliary: tuple(G2_AUXILIARY.map((name) => closed(['name', 'status', 'count'], { name: { const: name }, status: { enum: ['disabled', 'not-configured'] }, count: { const: 0 } }))),
    }),
  };
}

export const schemaPath = resolve('web/e2e/g2-encrypted-direct-chat.evidence.schema.json');
export function writeOrCheckSchema(check = false) {
  const rendered = `${JSON.stringify(generateG2EvidenceSchema(), null, 2)}\n`;
  if (check) return readFileSync(schemaPath, 'utf8') === rendered;
  writeFileSync(schemaPath, rendered);
  return true;
}
if (process.argv[1]?.endsWith('g2-evidence-contract.mjs') && !writeOrCheckSchema(process.argv.includes('--check'))) process.exitCode = 1;
