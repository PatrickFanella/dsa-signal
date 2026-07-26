-- Correct direct-source fanout after the entitlement has already been revoked.
CREATE OR REPLACE FUNCTION control_plane.source_fanout_valid(p_source uuid) RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,control_plane AS $$
 WITH source AS (SELECT * FROM membership_access_sources WHERE id=p_source), expected AS (
  SELECT s.mapping_id FROM source s WHERE s.source_kind IN ('entitlement_expiry','authenticated_lost_device')
  UNION
  SELECT DISTINCT e.mapping_id FROM source s JOIN entitlements e ON e.status='active' AND s.source_kind NOT IN ('entitlement_expiry','authenticated_lost_device')
   AND NOT EXISTS (SELECT 1 FROM membership_access_source_selector_aliases a WHERE a.source_id=s.id AND NOT EXISTS (SELECT 1 FROM entitlement_evidence_aliases ea WHERE ea.entitlement_id=e.id AND ea.evidence_kind=a.selector_kind AND ea.fingerprint_key_id=a.fingerprint_key_id AND ea.fingerprint=a.fingerprint))
 ), chunk_facts AS (
  SELECT c.chunk_no,c.target_count,c.chunk_digest,count(t.mapping_id)::integer actual_count,sha256(convert_to(COALESCE(string_agg(t.mapping_id::text,',' ORDER BY t.mapping_id),''),'UTF8')) actual_digest FROM membership_access_source_chunks c LEFT JOIN membership_access_source_targets t ON t.source_id=c.source_id AND t.chunk_no=c.chunk_no WHERE c.source_id=p_source GROUP BY c.chunk_no,c.target_count,c.chunk_digest
 ), summary AS (
  SELECT count(*)::integer chunk_count,COALESCE(sum(actual_count),0)::integer target_count,sha256(decode(COALESCE(string_agg(encode(chunk_digest,'hex'),'' ORDER BY chunk_no),''),'hex')) cursor_digest,bool_and(target_count=actual_count AND chunk_digest=actual_digest) chunks_valid,COALESCE(min(chunk_no),0) min_chunk,COALESCE(max(chunk_no),-1) max_chunk FROM chunk_facts
 ) SELECT COALESCE((SELECT revocation_aliases_valid(NULL,s.id) AND s.chunk_count=q.chunk_count AND q.min_chunk=0 AND q.max_chunk=q.chunk_count-1 AND q.target_count=(SELECT count(*) FROM expected) AND q.chunks_valid IS NOT FALSE AND s.cursor_digest=q.cursor_digest AND NOT EXISTS((SELECT mapping_id FROM expected EXCEPT SELECT mapping_id FROM membership_access_source_targets WHERE source_id=p_source) UNION ALL (SELECT mapping_id FROM membership_access_source_targets WHERE source_id=p_source EXCEPT SELECT mapping_id FROM expected)) FROM source s CROSS JOIN summary q),true) $$;
