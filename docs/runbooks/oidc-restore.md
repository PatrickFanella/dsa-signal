# OIDC isolated restore

## Non-destructive OIDC activation

Use activation only during a fully blocked outage; it neither purges data nor
uses a trusted clock. Candidate descriptor files must be owner-only `0600`; the
external chain directory must be owner-only `0700`. It is migration-owner-only,
with all traffic blocked, and requires an independent mandatory update of the
shared `OIDC_RESTORE_FLOOR_HEAD` to the returned head before deployment.

```sh
npm --prefix backend run activate:oidc -- --candidate-state /secure/candidate-oidc-state.json --candidate-cookie-keys /secure/candidate-cookie-keys.json --candidate-signing-jwks /secure/candidate-signing-jwks.json --candidate-mas-client-secret /secure/candidate-mas-client-secret --expected-previous-floor "$FLOOR" --expected-next-sequence "$SEQUENCE" --expected-head "$OIDC_RESTORE_FLOOR_HEAD"
```

Keep traffic/writers blocked while the lock drains writers, through independent
head publication and uniform candidate deployment. Shared adapter/index IDs are
immutable with their exact material; shared signing `kid`s retain their exact
public keys. Historical OIDC symmetric material is purpose-bound: adapter/index
bytes may overlap only at the same ID, cookie bytes only cookies, and client-secret
bytes only the client secret. Epoch/key removal requires
the normal 930-second drain and purge first. Before publish old head/config is
usable; published record + old head causes startup mismatch and requires
cutover; new head + wrong material fails startup. Rollback is another validated
activation only while no new material output permits it. v3 restore advances
the floor; v3 activation preserves it, so its expected floor is unchanged while
its required head and sequence advance. At the 1024-record cap do not append;
keep traffic blocked until the ledger is migrated. Legacy v2 signs a
`kid` code-unit-sorted signing-key view; v3 signs exact configured key order.

1. Block all traffic and stop every writer. Obtain the encrypted database backup
   and separately escrowed adapter AES/index, cookie, signing, envelope, subject,
   entitlement-binding, challenge, session, JTI, idempotency, and request-
   fingerprint keys; do not place keys in logs or restore scripts.
2. Restore into an isolated database under the migration-owner role. Before any
   purge, use backup-era escrowed keys to authenticate/decrypt representative
   OIDC, mapping, and policy envelopes and run the permitted plaintext-canary
   scan. Failure stops the restore; never open runtime traffic.
3. With traffic still blocked, run the migration-owner-only executable (all state
   and key files must be owner-only `0600`; the floor directory must be `0700`):
   ```sh
   mise exec node@24 -- npm --prefix backend run build
   mise exec node@24 -- npm --prefix backend run restore:oidc -- --fresh-state /secure/fresh-oidc-state.json --fresh-cookie-keys /secure/fresh-cookie-keys.json --fresh-signing-jwks /secure/fresh-signing-jwks.json --fresh-mas-client-secret /secure/fresh-mas-client-secret --expected-previous-floor 0 --expected-next-sequence 1 --expected-head "$OIDC_RESTORE_FLOOR_HEAD" --trusted-restore-time 2026-01-01T00:00:00Z
   ```
   The expected floor and sequence are mandatory replay protection: after a
   failure after floor creation, inspect the immutable record and rerun with the
   record's prior sequence/floor only; do not choose a new sequence. The command
   prints only its new sequence/head, minimum issued-at time, and aggregate purge counts. Update independently managed `OIDC_RESTORE_FLOOR_HEAD` to that exact returned head before API or refresh startup; do not store this anchor in database backup/PITR. From trusted restore time compute `minimumIssuedAt` as the first whole UTC
   second strictly after both that clock and the prior record's floor. Append
   the next contiguous 20-digit-
   sequence immutable record to the owner-only, non-symlink
   `OIDC_RESTORE_FLOOR_DIR` outside backup/PITR scope using the contract's
   O_EXCL/fsync procedure; filename and JSON sequence must match, and startup
   rejects any gap or non-increasing floor. In
   FK-safe order purge `oidc.interaction_csrf`,
   `oidc.authorization_contexts`, and `oidc.provider_artifacts`; then
   `control_plane.idempotency_key_aliases`, `idempotency_results`,
   `jti_key_aliases`, `jti_uses`, `proof_challenges`, `login_states`,
   `entitlements`, `identity_sessions`, and `active_policy`. Retain 90-day audit rows, DID
   mappings, policy snapshots, and their envelopes with every key they still
   reference. Delete sessions rather than assigning a late `revoked_at`.
   Record only timestamp, backup ID, operator ID, and pass/fail in an external
   restricted operational audit system; add no free-form database event.
4. Install a new 22-character artifact epoch and fresh adapter/index/cookie,
   MAS client secret, and RS256 signing keys. Coordinate the confidential-secret
   cutover with MAS while traffic remains blocked. Publish a fresh-only JWKS excluding every backup-era
   `kid`; restart/evict MAS's JWKS cache as documented, prove positive validation
   with the new key and negative rejection of each old `kid`, then destroy every
   backup-era private signing key while traffic remains blocked.
   Backup-era OIDC adapter/index/cookie keys exist only in the isolated
   verification environment and are destroyed after catalog/preflight proves no
   surviving OIDC reference. Mapping, policy-envelope, subject, and every other
   key still referenced by retained rows remains escrowed and configured.
5. Bootstrap a newly root-signed compact policy whose `issuedAt` is at or after
   `minimumIssuedAt` and not after the refresh decision clock, and whose exact
   provenance verifies against live Foundation authority. Policy refresh reads
   floor directory through the same safe descriptor rules, verifies contiguous
   sequence, selects the highest record, and rejects an older bootstrap. Retain
   every floor record permanently outside database backup and PITR scope; every
   later startup/refresh reselects the latest floor. No
   rollbackable database high-water mark is used. If Foundation or the signer
   is unavailable, keep traffic blocked.
   Validate versioned catalog,
   exact ACLs, retained-key references, envelope decryption, and plaintext
   canaries again before reopening traffic.

Pre-restore interactions, codes, grants, CSRF tokens, cookies, sessions, and
entitlements never continue. Continuation requires an external replay ledger;
this deployment does not provide one. Exercise this runbook in tests before code
consume, logout, entitlement regeneration, and policy revocation, including
rejection of every pre-restore signed policy below the restore floor.

Persistent owner-only `.staging` is intentional: interrupted candidates remain
ignored; only an operator's own candidate is removed and staging is synced. A
concurrent winner is accepted only when byte-identical. The restore record is
published inside the exclusive database transaction before purge and verification.
If its `COMMIT` reply is ambiguous, treat the restore outcome as indeterminate;
retry with identical inputs, which recovers the exact published record.
