import { Pool } from 'pg';
import { getMigrationConfig } from './config.js';
import { applyControlPlaneMigration } from './db.js';

const config = getMigrationConfig();
const pool = new Pool({ connectionString: config.MIGRATION_DATABASE_URL });

try {
  await applyControlPlaneMigration(pool, config.CONTROL_PLANE_RUNTIME_ROLE, config.CONTROL_PLANE_RETENTION_ROLE, undefined, config.CONTROL_PLANE_REVOCATION_ROLE, config.REVOCATION_EVIDENCE_KEY_IDS);
} finally {
  await pool.end();
}
