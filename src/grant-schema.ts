import type { DatabaseSync } from 'node:sqlite';

// SQLite's original inline UNIQUE(pairing_id) must be rebuilt to retain old
// grants while allowing one explicitly approved successor. Never drop history.
export function ensureRenewableGrants(db: DatabaseSync): void {
  const migrated = () => db.prepare('PRAGMA table_info(grants)').all().some(row => row.name === 'superseded_at');
  if (migrated()) return;
  db.exec('PRAGMA foreign_keys = OFF');
  try {
    db.exec('BEGIN IMMEDIATE');
    try {
      // Another process may have completed migration while we waited for the lock.
      if (!migrated()) {
        db.exec(`
          CREATE TABLE grants_successors (
            grant_id TEXT PRIMARY KEY, pairing_id TEXT NOT NULL REFERENCES pairings(pairing_id),
            principal TEXT NOT NULL, signed_grant TEXT NOT NULL, created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL, version INTEGER NOT NULL,
            revoked_at INTEGER, signed_revocation TEXT,
            wallet_id TEXT NOT NULL DEFAULT 'wallet_demo',
            action TEXT NOT NULL DEFAULT 'demo.orders.read',
            connection_id TEXT NOT NULL DEFAULT 'connection_local_demo',
            resource TEXT NOT NULL DEFAULT 'demo:store/orders',
            max_calls INTEGER NOT NULL DEFAULT 1000,
            max_amount_minor INTEGER NOT NULL DEFAULT 0,
            superseded_at INTEGER
          );
          INSERT INTO grants_successors
            SELECT grant_id, pairing_id, principal, signed_grant, created_at, expires_at,
              version, revoked_at, signed_revocation, wallet_id, action, connection_id,
              resource, max_calls, max_amount_minor, NULL FROM grants;
          DROP TABLE grants;
          ALTER TABLE grants_successors RENAME TO grants;
          CREATE UNIQUE INDEX grants_current_pairing ON grants(pairing_id) WHERE superseded_at IS NULL;
        `);
        if (db.prepare('PRAGMA foreign_key_check').all().length !== 0) {
          throw new Error('Grant migration failed integrity verification.');
        }
      }
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
  } finally { db.exec('PRAGMA foreign_keys = ON'); }
}
