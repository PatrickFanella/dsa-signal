# Control-plane retention

## OIDC activation chain

Non-destructive activation retains all referenced OIDC keys for both current
and candidate material. Do not remove an epoch or adapter/index key until a
930-second writer drain and retention purge remove every reference. Alert and
migrate before the external 1024-record ledger cap.

Run both database-owned cleanup functions at least hourly from a scheduler that holds only the retention-role connection string. OIDC cleanup must run first so retained authorization contexts cannot delay control-plane expiry. The API container must never receive this credential.

```bash
psql "$CONTROL_PLANE_RETENTION_DATABASE_URL" \
  --no-psqlrc --set=ON_ERROR_STOP=1 \
  --command="BEGIN; SELECT oidc.cleanup_expired(clock_timestamp()); SELECT control_plane.cleanup_expired(clock_timestamp() - interval '90 days'); COMMIT;" \
  >/dev/null
```

The functions, not the scheduler, enforce row deadlines and the 90-day audit minimum. They acquire the shared OIDC maintenance fence (`8004`) before validation or deletion, so retention is structurally blocked by restore/activation rather than relying on scheduler convention. Alert on any failed invocation and on a last-success age greater than two hours. Do not log the connection string, query result, row identifiers, or database error detail outside restricted operator logs. A failed run is safe to retry; do not compensate with direct table deletion or grants to the retention role.

## HMAC write-key rotation (v1)

v1 supports **only outage/quiescence activation**. Rolling mixed active epochs, online activation, staged dual-write, and any claim of historical alias backfill are prohibited.

1. Stop every writer and API instance, block traffic, and drain at least the maximum JTI retention (930 seconds) and idempotency retention (60 seconds).
2. With only the runtime environment available (including `DATABASE_URL`, `CONTROL_PLANE_RUNTIME_ROLE`, and every runtime key-ring variable; never migration-owner or retention credentials), run the retained-key preflight before changing active IDs:

   ```bash
   pnpm --filter '*api' check:retained-keys
   ```

   Its only successful output is `retained-key preflight ok`. It is read-only; treat any other outcome as failure.
3. Keep all old keys in their rings, change the active IDs in one consistent configuration, and run the same preflight again while writers remain stopped. Verify that no live row references a key absent from that configuration.
4. On either failure, abort or revert the configuration while traffic remains blocked; do not write traffic using the failed configuration. Deploy every instance with the same validated new active IDs, then restart and restore traffic.

Old keys remain retained until all references have expired. Rollback is permitted only while traffic remains blocked and every restarted instance uses one consistent previously validated configuration; never roll back into a mixed active epoch or after writing new-epoch rows. There is no online or rolling activation.
