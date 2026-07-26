-- Phase 2 corrective migration: every entitlement write participates in the
-- finite global source-set fence before it observes published tombstones.
CREATE OR REPLACE FUNCTION control_plane.entitlement_source_set_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control_plane AS $$
DECLARE m uuid:=COALESCE(NEW.mapping_id,OLD.mapping_id); e uuid:=COALESCE(NEW.id,OLD.id); BEGIN
 PERFORM membership_access_source_set_fence(false);
 IF TG_OP<>'DELETE' AND EXISTS (SELECT 1 FROM membership_access_sources s WHERE s.publication_state='published' AND NOT EXISTS (SELECT 1 FROM membership_access_source_targets t WHERE t.source_id=s.id AND t.mapping_id=m) AND (s.mapping_id=m OR EXISTS (SELECT 1 FROM membership_access_source_selector_aliases sa WHERE sa.source_id=s.id AND EXISTS (SELECT 1 FROM entitlement_evidence_aliases ea WHERE ea.entitlement_id=e AND ea.evidence_kind=sa.selector_kind AND ea.fingerprint_key_id=sa.fingerprint_key_id AND ea.fingerprint=sa.fingerprint)))) THEN RAISE EXCEPTION 'entitlement matches a published revocation source'; END IF;
 RETURN COALESCE(NEW,OLD); END $$;
