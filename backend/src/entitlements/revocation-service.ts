import type { Pool } from 'pg';

export type RevocationMaterializer = Readonly<{
  /** Materializes each immutable published target in its own committed transaction. */
  materializePublishedSource(sourceId: string): Promise<number>;
}>;

/** Deliberately coarse boundary: publication IDs and database state are not an API. */
export class RevocationMaterializationError extends Error {
  constructor() { super('revocation materialization unavailable'); this.name = 'RevocationMaterializationError'; }
}

const PAGE_SIZE = 100;

/**
 * Internal database-only reconciler.  It intentionally has neither HTTP
 * dependencies nor executor credentials: 0006 can only establish the local
 * barrier and blocked prerequisite shape.
 */
export function createRevocationMaterializer(pool: Pick<Pool, 'connect'>): RevocationMaterializer {
  return {
    async materializePublishedSource(sourceId: string): Promise<number> {
      try {
        let after: string | undefined;
        let count = 0;
        for (;;) {
          const reader = await pool.connect();
          let targets: readonly string[];
          try {
            const result = await reader.query<{ mapping_id: string }>('SELECT mapping_id FROM control_plane.membership_access_source_targets WHERE source_id=$1 AND ($2::uuid IS NULL OR mapping_id>$2::uuid) ORDER BY mapping_id LIMIT $3', [sourceId, after ?? null, PAGE_SIZE]);
            targets = result.rows.map((row) => row.mapping_id);
          } finally { reader.release(); }
          if (!targets.length) return count;
          for (const mappingId of targets) {
            const client = await pool.connect();
            try {
              await client.query('BEGIN');
              // Exactly one production function call owns one target transaction.
              await client.query('SELECT * FROM control_plane.enforce_published_source_target($1,$2)', [sourceId, mappingId]);
              await client.query('COMMIT');
              count++;
            } catch {
              try { await client.query('ROLLBACK'); } catch { /* preserve the coarse boundary */ }
              throw new RevocationMaterializationError();
            } finally { client.release(); }
            after = mappingId;
          }
        }
      } catch (error) {
        if (error instanceof RevocationMaterializationError) throw error;
        throw new RevocationMaterializationError();
      }
    },
  };
}
