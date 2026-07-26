# Revoke member access

## Purpose and scope

This runbook describes the **current local** Task 10 revocation reconciler and the evidence required before a future production member revocation can be claimed. The production contract requires an authenticated publisher; the local drill uses owner-seeded immutable source evidence because no producer exists yet. A valid published source suspends the affected control-plane mapping, revokes its active entitlement, control sessions, authorization contexts, and related provider artifacts, and appends reason-coded evidence. It does not currently remove a Matrix member, end a MAS session, rotate room keys, or erase data from a device.

Use only these source-kind/reason mappings. Do not substitute a similar reason or infer a source from a policy omission or ordinary key revocation.

| Source kind | Reason |
| --- | --- |
| `entitlement_expiry` | `entitlement_expired` |
| `signed_policy_revocation` | `policy_revoked` |
| `authenticated_issuer_revocation` | `issuer_revoked` |
| `authenticated_key_compromise` | `issuer_key_compromise` |
| `authenticated_lost_device` | `lost_device` |

`policy_revoked` requires an explicit signed policy-revocation source; `issuer_revoked` requires an authenticated issuer-revocation source; and `issuer_key_compromise` requires authenticated compromise evidence. `active` is not a revocation reason.

## Authority boundary and current status

Source producers authenticate and publish immutable causes. The local materializer applies the mapping suspension transaction. The separate claimant protocol may claim and record reconciler work, but it has no source-creation, direct table-mutation, OIDC/runtime, retention, or operator-retry authority. External MAS administration, room moderation, managed-room registry ownership, and crypto enforcement must remain separately scoped; do not combine their credentials with an API or claimant credential.

The local schema barrier/materializer and claimant protocol exist. There is no production source producer, managed-room registry, MAS/room/crypto adapter, worker entrypoint/Compose service, or Task-10 external G2. Therefore production initiation, production completion, and private beta are unavailable. **Do not issue ad hoc `INSERT` or `UPDATE` statements to create, alter, or replay a source.**

The only local success verdict is:

```text
PASS_LOCAL_TASK10_SCHEMA_RECONCILER_PENDING_ROOM_CRYPTO_G2
```

It proves local schema/materializer/reconciler behavior only. Master Task 10 Steps 1, 2, and 4 remain open. Task 9 G2 cannot satisfy the Task-10 revocation G2.

## Local drill

From the repository root, run exactly:

```bash
pnpm exec vitest run tests/security/revocation.test.ts && make verify
```

Expected outcome: the security drill reports all five source-kind/reason cases, each with reason-coded local audit, suspended mapping, revoked local entitlement/session/context/artifact, a prerequisite-blocked downstream operation, and coupled successful-before/denied-after session authentication. Record the checked-in verdict above only after the entire compound command, including `make verify`, succeeds. Partial output or any failure is not a verdict; the root test itself does not emit it. It must not be interpreted as a complete OIDC authorization flow, MAS shutdown, Matrix removal/ban, room-key rotation, or a decryption result.

On any failure, keep the environment non-production, retain the failing test and restricted logs, and escalate to the Task 10 owner. Do not repair rows, delete evidence, or convert a failed local drill into a production procedure.

## Read-only observation

Before inspection, independently verify the approved deployment/environment, database name, endpoint, and operator identity against the change record. Use the read-only credential only. Do not put a connection string in shell history, logs, tickets, or command output.

Start a read-only transaction and set both timeouts before any query. From the approved operator terminal (where the connection is already configured), use this transaction shape:

```sql
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '5s';
SELECT current_database(), current_user, inet_server_addr(), inet_server_port();
-- Inspect aggregate state and counts only; use restricted correlation output.
ROLLBACK;
```

Compare that identity output with the approved environment before proceeding. Inspect aggregate operation/step states, blocked codes, attempt counts, and audit presence; expose only the minimum approved, truncated or pseudonymous correlation identifiers in restricted operator records. Never output credentials, tokens, Matrix IDs, room IDs, plaintext, key material, raw external errors, or free-form reasons. Preserve the append-only source, operation, attempt, and audit evidence.

Step states are `pending`, `leased`, `retry_wait`, `succeeded`, and `blocked`. Blocked prerequisites honestly report unavailable capabilities, including `missing_mas_binding`, `missing_managed_room_registry`, and `missing_crypto_enforcement`; aggregate blocking for these prerequisites is `missing_external_prerequisites`. A blocked executable step produces `external_step_blocked`. Automatic exhaustion produces `retry_exhausted`.

The database issues a fixed 30-second lease. Worker external I/O is limited to 20 seconds, so it must return before lease expiry. Only due `pending` or `retry_wait` work, or an expired `leased` row, is eligible. There are at most 8 automatic attempts; retry backoff is database-derived and capped: `min(300 seconds, 2^(attempt_count-1) seconds)`. The eighth retryable result is blocked as `retry_exhausted`, not retried a ninth time. A late, stale, or wrong-owner/token/generation result makes no mutation.

## Break-glass retry (migration-owner only)

There is no dedicated operator role. This is migration-owner-only break-glass work, not a routine operator action. It applies only to a blocked, non-prerequisite step after the external dependency and escalation owner have confirmed it is safe to retry. The claimant role must never receive claimant table access, source authority, or retry authority.

1. Perform the following read-only inspection in a separate transaction. Substitute only the approved internal operation UUID for `:operation_id`; do not record the operation UUID or any external identifier in output. It deliberately selects the latest `result` by `created_at DESC, id DESC`, exactly as migration `0010` does, and then requires that result to be blocked and to match the current step generation. It returns only the CAS inputs:

   ```sql
   BEGIN READ ONLY;
   SET LOCAL statement_timeout = '10s';
   SET LOCAL lock_timeout = '5s';
   SELECT
     s.id AS step_id,
     latest.id AS latest_blocked_result_attempt_id,
     s.lease_generation AS expected_lease_generation
   FROM control_plane.membership_access_steps AS s
   JOIN control_plane.membership_access_operations AS o ON o.id = s.operation_id
   CROSS JOIN LATERAL (
     SELECT a.id, a.outcome, a.lease_generation
     FROM control_plane.membership_access_step_attempts AS a
     WHERE a.step_id = s.id
       AND a.event_kind = 'result'
     ORDER BY a.created_at DESC, a.id DESC
     LIMIT 1
   ) AS latest
   WHERE s.operation_id = :'operation_id'::uuid
     AND o.state = 'blocked'
     AND s.state = 'blocked'
     AND s.step_kind NOT LIKE '%_prerequisite'
     AND latest.outcome = 'blocked'
     AND latest.lease_generation = s.lease_generation;
   ROLLBACK;
   ```

   Confirm the approved operation/environment identity separately. Zero or multiple rows means abort and escalate; do not choose a row, modify the query, or start the mutation transaction. In the restricted record, retain only the exact returned step identifier, latest blocked result attempt identifier, and expected lease generation.
2. Open a new migration-owner mutation transaction; do not reuse the inspection connection. Set local timeouts before the call:

   ```sql
   BEGIN;
   SET LOCAL statement_timeout = '10s';
   SET LOCAL lock_timeout = '5s';
   SELECT control_plane.retry_membership_access_step(
     :'step_id'::uuid,
     :'latest_blocked_result_attempt_id'::uuid,
     :'expected_lease_generation'::bigint
   ) AS retried;
   ```

3. Commit **only** when `retried` is exactly `true`. If it is `false`, errors, or any observed value differs from the inspected CAS inputs, issue `ROLLBACK`, preserve the evidence, and escalate; do not retry the call with changed values. On true, `COMMIT`; the database appends an `operator_retry`, advances the generation, resets the automatic attempt count, and schedules the step immediately.

Never directly repair or delete revocation tables, attempts, audits, sources, operations, or steps. There is no unsuspend/rollback promise in this runbook.

## Alerts, escalation, and cleanup

Alert immediately for a failed local drill, identity mismatch, source-authentication failure, blocked prerequisite, `external_step_blocked`, `retry_exhausted`, lease expiry/stale result, unexpected identifier exposure, or any request to use production initiation. Escalate to the Task 10 owner, migration owner, and the responsible future MAS/room/crypto authority as applicable. Stop private beta: it remains stopped until the external G2 below passes.

Cleanup is limited to ending read-only or failed mutation transactions with `ROLLBACK`, removing only ephemeral local test resources created by the test harness, and retaining restricted evidence according to policy. Do not delete append-only evidence or promise restoration of access.

## Irreversible boundary and future external G2

Real removal/ban and room-key rotation can block future authorization and key access only after they actually occur. They cannot erase plaintext or keys that were previously downloaded or decrypted. Local tests never cross this boundary.

Only a future Task-10-specific, two-account external drill can pass revocation G2. It must use real MAS session/grant shutdown, Matrix removal/ban, room-key rotation, post-removal ciphertext, retained historical plaintext, and evidence. Before claiming success, retain a restricted checklist showing:

- approved environment, two distinct test accounts, and exact time ordering;
- authenticated source and local suspension/audit evidence;
- real MAS session and grant shutdown evidence;
- real Matrix membership removal or ban evidence for every authoritative target;
- room-key rotation after removal and a post-removal ciphertext observation;
- proof the removed account cannot obtain future authorization or decrypt the post-removal material under the defined protocol; and
- proof that previously retained/downloaded historical plaintext remains possible, plus scrubbed evidence references and operator approvals.

No command or adapter is supplied here because none exists in this repository.
