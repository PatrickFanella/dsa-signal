-- Task 6 final catalog.  This migration is outage-only: old writers must be
-- stopped and the complete entitlement lifetime (930 seconds) drained first.
LOCK TABLE control_plane.entitlements IN ACCESS EXCLUSIVE MODE;
DELETE FROM control_plane.entitlements WHERE expires_at <= clock_timestamp();
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM control_plane.entitlements) THEN
    RAISE EXCEPTION 'cannot migrate live entitlements; stop writers and drain 930 seconds';
  END IF;
END $$;

ALTER TABLE control_plane.entitlements
  DROP CONSTRAINT entitlements_mapping_jkt_kind_key,
  ADD COLUMN oidc_epoch char(22) NOT NULL,
  ADD COLUMN session_binding_key_id text NOT NULL,
  ADD COLUMN session_binding_fingerprint bytea NOT NULL,
  ADD COLUMN generation bigint NOT NULL,
  ADD CONSTRAINT entitlements_oidc_epoch_format CHECK (oidc_epoch ~ '^[A-Za-z0-9_-]{21}[AQgw]$'),
  ADD CONSTRAINT entitlements_session_binding_key_format CHECK (session_binding_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'),
  ADD CONSTRAINT entitlements_session_binding_fingerprint_length CHECK (octet_length(session_binding_fingerprint)=32),
  ADD CONSTRAINT entitlements_generation_positive CHECK (generation>0 AND generation<=9223372036854775807),
  ADD CONSTRAINT entitlements_session_binding_entitlement_key UNIQUE (session_binding_key_id,session_binding_fingerprint,entitlement);

CREATE SCHEMA oidc;
REVOKE ALL ON SCHEMA oidc FROM PUBLIC;

CREATE TABLE oidc.provider_artifacts (
 id uuid NOT NULL PRIMARY KEY, epoch char(22) NOT NULL CHECK(epoch ~ '^[A-Za-z0-9_-]{21}[AQgw]$'),
 model text NOT NULL CHECK(model IN ('AuthorizationCode','AccessToken','Session','Grant','Interaction')),
 artifact_key_id text NOT NULL CHECK(artifact_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), artifact_fingerprint bytea NOT NULL CHECK(octet_length(artifact_fingerprint)=32),
 session_uid_key_id text CHECK(session_uid_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), session_uid_fingerprint bytea CHECK(octet_length(session_uid_fingerprint)=32),
 grant_key_id text CHECK(grant_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), grant_fingerprint bytea CHECK(octet_length(grant_fingerprint)=32),
 cipher_key_id text NOT NULL CHECK(cipher_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), nonce bytea NOT NULL CHECK(octet_length(nonce)=12), ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 16 AND 32784),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz, revoked_at timestamptz, retained_until timestamptz NOT NULL,
 UNIQUE(epoch,model,artifact_key_id,artifact_fingerprint), UNIQUE(cipher_key_id,nonce),
 CHECK(expires_at>created_at AND retained_until=expires_at+interval '30 seconds'),
 CHECK((model='AuthorizationCode' AND expires_at=created_at+interval '60 seconds') OR (model IN ('AccessToken','Interaction') AND expires_at<=created_at+interval '300 seconds') OR (model IN ('Grant','Session') AND expires_at<=created_at+interval '900 seconds')),
 CHECK((session_uid_key_id IS NULL)=(session_uid_fingerprint IS NULL)), CHECK((grant_key_id IS NULL)=(grant_fingerprint IS NULL)),
 CHECK((model='Session')=(session_uid_key_id IS NOT NULL)), CHECK((model IN ('Grant','AuthorizationCode','AccessToken'))=(grant_key_id IS NOT NULL)),
 CHECK(consumed_at IS NULL OR consumed_at BETWEEN created_at AND retained_until), CHECK(revoked_at IS NULL OR revoked_at BETWEEN created_at AND retained_until)
);
CREATE UNIQUE INDEX provider_artifacts_session_uid ON oidc.provider_artifacts(epoch,session_uid_key_id,session_uid_fingerprint) WHERE model='Session';
CREATE INDEX provider_artifacts_grant ON oidc.provider_artifacts(epoch,grant_key_id,grant_fingerprint);
CREATE INDEX provider_artifacts_expiry ON oidc.provider_artifacts(expires_at);
CREATE INDEX provider_artifacts_retained ON oidc.provider_artifacts(retained_until);

CREATE TABLE oidc.authorization_contexts (
 id uuid NOT NULL PRIMARY KEY, epoch char(22) NOT NULL CHECK(epoch ~ '^[A-Za-z0-9_-]{21}[AQgw]$'),
 client_key_id text NOT NULL CHECK(client_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), client_fingerprint bytea NOT NULL CHECK(octet_length(client_fingerprint)=32),
 grant_key_id text NOT NULL CHECK(grant_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), grant_fingerprint bytea NOT NULL CHECK(octet_length(grant_fingerprint)=32),
 interaction_chain_key_id text NOT NULL CHECK(interaction_chain_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), interaction_chain_fingerprint bytea NOT NULL CHECK(octet_length(interaction_chain_fingerprint)=32),
 interaction_uid_key_id text NOT NULL CHECK(interaction_uid_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), interaction_uid_fingerprint bytea NOT NULL CHECK(octet_length(interaction_uid_fingerprint)=32),
 provider_session_uid_key_id text CHECK(provider_session_uid_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), provider_session_uid_fingerprint bytea CHECK(octet_length(provider_session_uid_fingerprint)=32),
 control_session_key_id text NOT NULL CHECK(control_session_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), control_session_fingerprint bytea NOT NULL CHECK(octet_length(control_session_fingerprint)=32),
 authorization_code_key_id text CHECK(authorization_code_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), authorization_code_fingerprint bytea CHECK(octet_length(authorization_code_fingerprint)=32),
 mapping_id uuid NOT NULL, entitlement_id uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0 AND generation<=9223372036854775807), jkt char(43) NOT NULL CHECK(jkt ~ '^[A-Za-z0-9_-]{43}$'), policy_snapshot_id uuid NOT NULL, policy_version text NOT NULL CHECK(policy_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, grant_expires_at timestamptz NOT NULL, retained_until timestamptz NOT NULL, revoked_at timestamptz,
 UNIQUE(epoch,grant_key_id,grant_fingerprint), UNIQUE(epoch,interaction_chain_key_id,interaction_chain_fingerprint,interaction_uid_key_id,interaction_uid_fingerprint),
 CHECK((provider_session_uid_key_id IS NULL)=(provider_session_uid_fingerprint IS NULL)), CHECK((authorization_code_key_id IS NULL)=(authorization_code_fingerprint IS NULL)),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '300 seconds' AND grant_expires_at=created_at+interval '900 seconds' AND retained_until=grant_expires_at+interval '30 seconds'), CHECK(revoked_at IS NULL OR revoked_at BETWEEN created_at AND retained_until)
);
CREATE UNIQUE INDEX authorization_context_code ON oidc.authorization_contexts(epoch,authorization_code_key_id,authorization_code_fingerprint) WHERE authorization_code_key_id IS NOT NULL;
CREATE INDEX authorization_context_control ON oidc.authorization_contexts(epoch,control_session_key_id,control_session_fingerprint);
CREATE INDEX authorization_context_expiry ON oidc.authorization_contexts(expires_at); CREATE INDEX authorization_context_retained ON oidc.authorization_contexts(retained_until);

CREATE TABLE oidc.interaction_csrf (
 id uuid NOT NULL PRIMARY KEY, epoch char(22) NOT NULL CHECK(epoch ~ '^[A-Za-z0-9_-]{21}[AQgw]$'),
 csrf_key_id text NOT NULL CHECK(csrf_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), csrf_fingerprint bytea NOT NULL CHECK(octet_length(csrf_fingerprint)=32),
 client_key_id text NOT NULL CHECK(client_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), client_fingerprint bytea NOT NULL CHECK(octet_length(client_fingerprint)=32),
 interaction_chain_key_id text NOT NULL CHECK(interaction_chain_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), interaction_chain_fingerprint bytea NOT NULL CHECK(octet_length(interaction_chain_fingerprint)=32),
 interaction_uid_key_id text NOT NULL CHECK(interaction_uid_key_id ~ '^[a-z][a-z0-9_-]{0,31}$'), interaction_uid_fingerprint bytea NOT NULL CHECK(octet_length(interaction_uid_fingerprint)=32),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz, retained_until timestamptz NOT NULL,
 UNIQUE(epoch,csrf_key_id,csrf_fingerprint), UNIQUE(epoch,interaction_uid_key_id,interaction_uid_fingerprint),
 CHECK(expires_at=created_at+interval '300 seconds' AND retained_until=expires_at+interval '30 seconds'), CHECK(consumed_at IS NULL OR consumed_at BETWEEN created_at AND retained_until)
);
CREATE INDEX interaction_csrf_expiry ON oidc.interaction_csrf(expires_at); CREATE INDEX interaction_csrf_retained ON oidc.interaction_csrf(retained_until);

CREATE FUNCTION oidc.cleanup_expired(p_now timestamptz) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,oidc AS $$
DECLARE v_now timestamptz := clock_timestamp(); removed bigint := 0; affected bigint;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(8004);
 IF p_now IS NULL OR NOT isfinite(p_now) OR p_now>v_now THEN RAISE EXCEPTION 'invalid cleanup cutoff'; END IF;
 DELETE FROM oidc.interaction_csrf WHERE retained_until<=p_now; GET DIAGNOSTICS affected=ROW_COUNT; removed:=removed+affected;
 DELETE FROM oidc.authorization_contexts WHERE retained_until<=p_now; GET DIAGNOSTICS affected=ROW_COUNT; removed:=removed+affected;
 DELETE FROM oidc.provider_artifacts WHERE retained_until<=p_now; GET DIAGNOSTICS affected=ROW_COUNT; removed:=removed+affected;
 RETURN removed;
END $$;

REVOKE ALL ON SCHEMA control_plane,oidc FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA control_plane,oidc FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA control_plane,oidc FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA control_plane,oidc FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_plane REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_plane REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_plane REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA control_plane REVOKE ALL ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA oidc REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA oidc REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA oidc REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA oidc REVOKE ALL ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON TYPES FROM PUBLIC;
