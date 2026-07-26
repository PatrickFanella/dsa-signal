-- Task 5: immutable binding of an idempotency result to the identity session.
-- No foreign key: an idempotency retry deliberately outlives the session row.
-- Deployment must quiesce retries for at least the one-minute idempotency window.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM control_plane.idempotency_results WHERE expires_at > clock_timestamp()) THEN
    RAISE EXCEPTION 'cannot bind live idempotency results; quiesce retries for at least 60 seconds';
  END IF;
END $$;
DELETE FROM control_plane.idempotency_results WHERE expires_at <= clock_timestamp();
ALTER TABLE control_plane.idempotency_results
  ADD COLUMN binding_key_id text NOT NULL,
  ADD COLUMN binding_fingerprint bytea NOT NULL,
  ADD CONSTRAINT idempotency_results_binding_key_format CHECK(binding_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  ADD CONSTRAINT idempotency_results_binding_fingerprint_length CHECK(octet_length(binding_fingerprint)=32);
CREATE INDEX idempotency_binding_expiry_idx ON control_plane.idempotency_results(binding_key_id,binding_fingerprint,expires_at);
ALTER TABLE control_plane.policy_snapshots DROP CONSTRAINT policy_snapshots_version_key;
CREATE INDEX policy_snapshots_fresh_until_idx ON control_plane.policy_snapshots(fresh_until);
CREATE OR REPLACE FUNCTION control_plane.active_policy_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog, control_plane AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM control_plane.policy_snapshots WHERE id=NEW.snapshot_id AND verified_at<=NEW.activated_at AND fresh_until>NEW.activated_at) THEN RAISE EXCEPTION 'active policy must be verified and fresh at activation'; END IF; IF TG_OP='UPDATE' AND NOT EXISTS (SELECT 1 FROM control_plane.policy_snapshots incoming JOIN control_plane.policy_snapshots prior ON prior.id=OLD.snapshot_id WHERE incoming.id=NEW.snapshot_id AND incoming.signed_at>prior.signed_at) THEN RAISE EXCEPTION 'active policy signed_at must increase'; END IF; RETURN NEW; END $$;
