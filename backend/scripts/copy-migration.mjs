import { copyFile, mkdir } from 'node:fs/promises';
import { URL } from 'node:url';

const destination = new URL('../dist/migrations/', import.meta.url);
await mkdir(destination, { recursive: true });
for (const name of ['0002_identity_control_plane.sql', '0003_entitlement_session_binding.sql', '0004_mas_upstream_oidc.sql', '0005_access_revocation_foundation.sql', '0006_access_revocation_enforcement.sql', '0007_access_revocation_source_set_guard.sql', '0008_access_revocation_local_enforcement_fix.sql', '0009_access_revocation_reconciliation_fix.sql', '0010_access_revocation_worker.sql']) {
  await copyFile(new URL(`../../migrations/${name}`, import.meta.url), new URL(name, destination));
}
const catalogDestination = new URL('../dist/migrations/catalog/', import.meta.url);
await mkdir(catalogDestination, { recursive: true });
for (const name of ['0003-pre.json', '0004-post.json', '0005-post.json', '0006-post.json', '0007-post.json', '0008-post.json', '0009-post.json', '0010-post.json']) {
  await copyFile(new URL(`../../migrations/catalog/${name}`, import.meta.url), new URL(name, catalogDestination));
}
