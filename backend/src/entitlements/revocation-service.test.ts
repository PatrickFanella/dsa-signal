import { describe, expect, it } from 'vitest';
import { createRevocationMaterializer, RevocationMaterializationError } from './revocation-service.js';

describe('published-source materializer', () => {
  it('uses UUID keyset pages and one committed function call per target', async () => {
    const calls: string[] = [];
    const pages = [['00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002'], []];
    const pool = { connect: async () => ({
      query: async (sql: string, values?: readonly unknown[]) => {
        calls.push(sql);
        if (sql.startsWith('SELECT mapping_id')) return { rows: (pages.shift() ?? []).map(mapping_id => ({ mapping_id })), rowCount: 0 };
        if (sql === 'SELECT * FROM control_plane.enforce_published_source_target($1,$2)') expect(values).toHaveLength(2);
        return { rows: [], rowCount: 1 };
      }, release: () => undefined,
    }) };
    await expect(createRevocationMaterializer(pool as never).materializePublishedSource('00000000-0000-0000-0000-000000000000')).resolves.toBe(2);
    expect(calls.filter(call => call === 'SELECT * FROM control_plane.enforce_published_source_target($1,$2)')).toHaveLength(2);
    expect(calls.filter(call => call === 'COMMIT')).toHaveLength(2);
    expect(calls.find(call => call.startsWith('SELECT mapping_id'))).toContain('ORDER BY mapping_id LIMIT $3');
  });

  it('does not expose database failures', async () => {
    const pool = { connect: async () => { throw new Error('relation membership_access_source_targets does not exist'); } };
    await expect(createRevocationMaterializer(pool as never).materializePublishedSource('not-an-id')).rejects.toBeInstanceOf(RevocationMaterializationError);
  });
});
