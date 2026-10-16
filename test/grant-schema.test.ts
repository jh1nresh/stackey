import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { ensureRenewableGrants } from '../src/grant-schema.js';

function legacyDatabase() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    PRAGMA foreign_keys=ON;
    CREATE TABLE pairings (pairing_id TEXT PRIMARY KEY);
    CREATE TABLE grants (
      grant_id TEXT PRIMARY KEY, pairing_id TEXT NOT NULL UNIQUE REFERENCES pairings(pairing_id),
      principal TEXT NOT NULL, signed_grant TEXT NOT NULL, created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL, version INTEGER NOT NULL, revoked_at INTEGER, signed_revocation TEXT,
      wallet_id TEXT NOT NULL DEFAULT 'wallet_demo', action TEXT NOT NULL DEFAULT 'demo.orders.read',
      connection_id TEXT NOT NULL DEFAULT 'connection_local_demo', resource TEXT NOT NULL DEFAULT 'demo:store/orders',
      max_calls INTEGER NOT NULL DEFAULT 1000, max_amount_minor INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE sessions (session_id TEXT PRIMARY KEY, grant_id TEXT REFERENCES grants(grant_id));
    CREATE TABLE operations (operation_id TEXT PRIMARY KEY, grant_id TEXT REFERENCES grants(grant_id), result_json TEXT);
    CREATE TABLE provider_operations (operation_id TEXT PRIMARY KEY, grant_id TEXT REFERENCES grants(grant_id), result_json TEXT);
    INSERT INTO pairings VALUES ('pair-a'), ('pair-b');
    INSERT INTO grants VALUES ('grant-a','pair-a','agent-a','signed-a',10,100,1,NULL,NULL,'wallet_demo','credential.get','conn-a','resource-a',1,0);
    INSERT INTO grants VALUES ('grant-b','pair-b','agent-b','signed-b',11,101,2,12,'revocation-b','wallet_demo','demo.orders.read','connection_local_demo','demo:store/orders',1000,0);
    INSERT INTO sessions VALUES ('session-a','grant-a');
    INSERT INTO operations VALUES ('op-b','grant-b','{"rows":[]}');
    INSERT INTO provider_operations VALUES ('op-a','grant-a','{"issued":true}');
  `);
  return db;
}

test('grant migration preserves legacy grants, signatures, sessions and operation history with foreign keys enabled', () => {
  const db = legacyDatabase();
  try {
    const before = db.prepare('SELECT * FROM grants ORDER BY grant_id').all();
    const children = ['sessions', 'operations', 'provider_operations'].map(table => db.prepare(`SELECT * FROM ${table}`).all());
    ensureRenewableGrants(db);
    assert.deepEqual(db.prepare('SELECT * FROM grants ORDER BY grant_id').all().map(row => ({ ...row })), before.map(row => ({ ...row, superseded_at: null })));
    assert.deepEqual(['sessions', 'operations', 'provider_operations'].map(table => db.prepare(`SELECT * FROM ${table}`).all()), children);
    assert.equal(db.prepare('PRAGMA foreign_keys').get()!.foreign_keys, 1);
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
    const insert = db.prepare(`INSERT INTO grants(grant_id,pairing_id,principal,signed_grant,created_at,expires_at,version)
      VALUES ('grant-next','pair-a','agent-a','signed-next',20,200,1)`);
    assert.throws(() => insert.run()); // two current grants cannot exist
    db.prepare('UPDATE grants SET superseded_at=20,revoked_at=20 WHERE grant_id=?').run('grant-a');
    insert.run();
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM grants').get()!.n, 3);
    assert.throws(() => db.prepare('DELETE FROM grants WHERE grant_id=?').run('grant-a'));
    ensureRenewableGrants(db); // reopening does not rewrite history or reset the active grant
    assert.equal(db.prepare('SELECT grant_id FROM grants WHERE pairing_id=? AND superseded_at IS NULL').get('pair-a')!.grant_id, 'grant-next');
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
  } finally { db.close(); }
});

test('grant migration rolls back on broken references and restores foreign-key enforcement', () => {
  const db = legacyDatabase();
  try {
    db.exec("PRAGMA foreign_keys=OFF; INSERT INTO sessions VALUES ('broken','missing'); PRAGMA foreign_keys=ON;");
    assert.throws(() => ensureRenewableGrants(db), /integrity/);
    assert.equal(db.prepare('PRAGMA foreign_keys').get()!.foreign_keys, 1);
    assert.equal(db.prepare('PRAGMA table_info(grants)').all().some(row => row.name === 'superseded_at'), false);
    assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name='grants_successors'").get(), undefined);
    assert.equal(db.prepare('SELECT signed_grant FROM grants WHERE grant_id=?').get('grant-a')!.signed_grant, 'signed-a');
    db.prepare('DELETE FROM sessions WHERE session_id=?').run('broken');
    ensureRenewableGrants(db);
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
  } finally { db.close(); }
});
