/** Runtime order: global source set, mapping access, then canonical session. */
export type LockClient = Readonly<{ query(sql: string, values?: readonly unknown[]): Promise<{ rows: readonly Record<string, unknown>[]; rowCount?: number | null }> }>;

export async function lockSourceSet(client: LockClient): Promise<void> {
  await client.query('SELECT control_plane.membership_access_source_set_fence(false)');
}

export async function lockMappingAccess(client: LockClient, mappingId: string): Promise<boolean> {
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('dsa-signal-membership-access:v1:' || $1::text,0))", [mappingId]);
  const state = await client.query('SELECT barrier_state FROM control_plane.membership_access_states WHERE mapping_id=$1 FOR UPDATE', [mappingId]);
  return state.rows[0]?.barrier_state === 'active';
}

export async function lockSession(client: LockClient, bindingKeyId: string, bindingFingerprint: Uint8Array): Promise<void> {
  void bindingKeyId;
  await client.query("SELECT pg_advisory_xact_lock(('x' || encode($1::bytea, 'hex'))::bit(64)::bigint)", [Buffer.from(bindingFingerprint.subarray(0, 8))]);
}
