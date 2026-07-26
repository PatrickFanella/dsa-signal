-- Phase 2 corrective migration.  Keep the local decision entirely in the
-- database so callers cannot observe a partially-applied suspension.
CREATE OR REPLACE FUNCTION control_plane.enforce_published_source_target(p_source uuid,p_mapping uuid) RETURNS TABLE(operation_id uuid,transition_revision bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control_plane,oidc AS $$
DECLARE s membership_access_sources%ROWTYPE; st membership_access_states%ROWTYPE; o uuid; rev bigint; now_at timestamptz; request_id uuid; mas uuid; registry uuid; crypto uuid; BEGIN
 PERFORM pg_advisory_xact_lock_shared(8004); PERFORM membership_access_source_set_fence(false);
 SELECT * INTO s FROM membership_access_sources WHERE id=p_source AND publication_state='published' FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM membership_access_source_targets WHERE source_id=p_source AND mapping_id=p_mapping) THEN RAISE EXCEPTION 'source target is not published'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('dsa-signal-membership-access:v1:'||p_mapping::text,0));
 SELECT * INTO st FROM membership_access_states WHERE mapping_id=p_mapping FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'mapping access state is missing'; END IF;
 -- Branch one: an exact replay is observational only and writes nothing.
 SELECT r.operation_id INTO o FROM membership_access_requests r WHERE r.source_id=p_source AND r.mapping_id=p_mapping;
 IF FOUND THEN RETURN QUERY SELECT o,(SELECT x.transition_revision FROM membership_access_operations x WHERE x.id=o); RETURN; END IF;
 now_at:=clock_timestamp();
 -- Branch two: a later cause joins the still-open suspension at its revision.
 IF st.barrier_state='suspended' AND st.current_operation_id IS NOT NULL AND EXISTS(SELECT 1 FROM membership_access_operations WHERE id=st.current_operation_id AND state<>'completed') THEN
  o:=st.current_operation_id;
  INSERT INTO membership_access_requests(id,source_id,mapping_id,operation_id,created_at) VALUES(gen_random_uuid(),p_source,p_mapping,o,now_at) RETURNING id INTO request_id;
  INSERT INTO membership_access_request_operation_links(request_id,operation_id,link_kind,created_at) VALUES(request_id,o,'reconciliation',now_at);
  RETURN QUERY SELECT o,st.revision; RETURN;
 END IF;
 -- Branch three: only an active state or a completed prior operation starts N+1.
 rev:=st.revision+1; o:=gen_random_uuid();
 INSERT INTO membership_access_operations(id,mapping_id,transition_revision,state,first_effective_at,local_enforced_at,blocked_code) VALUES(o,p_mapping,rev,'blocked',s.source_effective_at,now_at,'missing_external_prerequisites');
 INSERT INTO membership_access_requests(id,source_id,mapping_id,operation_id,created_at) VALUES(gen_random_uuid(),p_source,p_mapping,o,now_at) RETURNING id INTO request_id;
 INSERT INTO membership_access_request_operation_links(request_id,operation_id,link_kind,created_at) VALUES(request_id,o,'initial',now_at);
 INSERT INTO membership_access_mas_targets(id,operation_id,mapping_id,transition_revision,kind) VALUES(gen_random_uuid(),o,p_mapping,rev,'missing') RETURNING id INTO mas;
 INSERT INTO membership_access_registry_snapshots(id,operation_id,mapping_id,transition_revision,kind,expected_room_count) VALUES(gen_random_uuid(),o,p_mapping,rev,'missing',0) RETURNING id INTO registry;
 INSERT INTO membership_access_crypto_capabilities(id,operation_id,mapping_id,transition_revision,kind) VALUES(gen_random_uuid(),o,p_mapping,rev,'missing') RETURNING id INTO crypto;
 INSERT INTO membership_access_steps(id,operation_id,mapping_id,transition_revision,step_kind,state,mas_target_id,error_code) VALUES(gen_random_uuid(),o,p_mapping,rev,'mas_prerequisite','blocked',mas,'missing_mas_binding');
 INSERT INTO membership_access_steps(id,operation_id,mapping_id,transition_revision,step_kind,state,registry_snapshot_id,error_code) VALUES(gen_random_uuid(),o,p_mapping,rev,'registry_prerequisite','blocked',registry,'missing_managed_room_registry');
 INSERT INTO membership_access_steps(id,operation_id,mapping_id,transition_revision,step_kind,state,crypto_capability_id,error_code) VALUES(gen_random_uuid(),o,p_mapping,rev,'crypto_prerequisite','blocked',crypto,'missing_crypto_enforcement');
 UPDATE membership_access_states SET barrier_state='suspended',revision=rev,current_operation_id=o,changed_at=now_at,cause_request_id=request_id WHERE mapping_id=p_mapping;
 UPDATE entitlements SET status='revoked',revoked_at=now_at,reason='revoked',generation=CASE WHEN generation=9223372036854775807 THEN generation ELSE generation+1 END WHERE mapping_id=p_mapping AND status='active';
 UPDATE identity_sessions SET revoked_at=now_at WHERE mapping_id=p_mapping AND revoked_at IS NULL;
 -- Contexts may deliberately outlive a local session; revoke by mapping first.
 UPDATE authorization_contexts SET revoked_at=now_at WHERE mapping_id=p_mapping AND revoked_at IS NULL;
 -- Artifacts are the union of grant and provider Session identities, including
 -- a Session with no remaining control-plane session row.
 UPDATE provider_artifacts a SET revoked_at=now_at WHERE a.revoked_at IS NULL AND EXISTS(SELECT 1 FROM authorization_contexts c WHERE c.mapping_id=p_mapping AND ((a.grant_key_id,a.grant_fingerprint)=(c.grant_key_id,c.grant_fingerprint) OR (a.model='Session' AND (a.session_uid_key_id,a.session_uid_fingerprint)=(c.provider_session_uid_key_id,c.provider_session_uid_fingerprint))));
 INSERT INTO security_audit_events(id,event_type,mapping_id,outcome,reason,occurred_at,source_id,operation_id) VALUES(gen_random_uuid(),'membership_access_local_enforced',p_mapping,'success',s.reason,now_at,p_source,o);
 RETURN QUERY SELECT o,rev;
END $$;
