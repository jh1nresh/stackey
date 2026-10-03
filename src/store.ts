import { existsSync, lstatSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { AppError, invalid } from './contracts.js';
import { privateDirectory } from './identity.js';

export interface Pairing {
  pairing_id: string;
  principal: string;
  public_jwk: string;
  display_name: string;
  created_at: number;
  status: 'approval_required';
}

export class Store {
  readonly db: DatabaseSync;
  constructor(dir: string) {
    const path = join(privateDirectory(dir), 'pairings.sqlite');
    if (!existsSync(path)) writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
        (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) {
      invalid('unsafe_database', 'Pairing database must be a private regular file.');
    }
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS invitations (
        id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL, consumed_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS pairings (
        pairing_id TEXT PRIMARY KEY, principal TEXT NOT NULL, public_jwk TEXT NOT NULL,
        display_name TEXT NOT NULL, created_at INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status = 'approval_required'),
        invitation_id TEXT NOT NULL UNIQUE REFERENCES invitations(id),
        proof_jti TEXT NOT NULL UNIQUE
      );
      CREATE TABLE IF NOT EXISTS grants (
        grant_id TEXT PRIMARY KEY, pairing_id TEXT NOT NULL UNIQUE REFERENCES pairings(pairing_id),
        principal TEXT NOT NULL, signed_grant TEXT NOT NULL, created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, version INTEGER NOT NULL,
        revoked_at INTEGER, signed_revocation TEXT
      );
      CREATE TABLE IF NOT EXISTS challenges (
        nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, consumed_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS request_proofs (jti TEXT PRIMARY KEY, accepted_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(grant_id),
        principal TEXT NOT NULL, expires_at INTEGER NOT NULL, version INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS demo_orders (
        id TEXT PRIMARY KEY, created_at TEXT NOT NULL, currency TEXT NOT NULL,
        amount_minor INTEGER NOT NULL, payment_status TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS operations (
        operation_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(grant_id),
        principal TEXT NOT NULL, input_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
        result_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS events (
        sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL, subject TEXT NOT NULL, object_id TEXT NOT NULL, created_at INTEGER NOT NULL
      );
    `);
    if (!this.db.prepare('PRAGMA table_info(grants)').all().some(row => row.name === 'wallet_id')) {
      this.db.exec("ALTER TABLE grants ADD COLUMN wallet_id TEXT NOT NULL DEFAULT 'wallet_demo'");
    }
  }

  transaction<T>(work: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = work(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }

  getEndpoint(): string {
    const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get('endpoint');
    if (!row) invalid('node_not_started', 'Start the Node before issuing invitations.');
    return row.value as string;
  }

  setEndpoint(value: string): void {
    this.db.prepare('INSERT INTO settings VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run('endpoint', value);
  }

  addInvite(id: string, tokenHash: string, expiresAt: number): void {
    this.db.prepare('INSERT INTO invitations(id, token_hash, expires_at) VALUES (?, ?, ?)')
      .run(id, tokenHash, expiresAt);
  }

  consumeInvite(
    id: string, tokenHash: string, proof: { jti: string; issuedAt: number; expiresAt: number },
    pairing: Pairing, clock: () => number,
  ): number {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      // A transaction may wait for another writer. Recheck time only after the
      // lock is held, not at headers or before asynchronous proof verification.
      const now = clock();
      const invite = this.db.prepare('SELECT * FROM invitations WHERE id = ?').get(id);
      if (!invite || invite.token_hash !== tokenHash || (invite.expires_at as number) <= now) {
        throw new AppError('invalid_invitation', 'Invitation is invalid or expired.', 403, 3, 'permission_denied');
      }
      if (invite.consumed_at !== null) {
        throw new AppError('invitation_used', 'Invitation has already been used.', 409, 3, 'permission_denied');
      }
      if (proof.issuedAt > now || proof.expiresAt <= now || now - proof.issuedAt > 30) {
        throw new AppError('invalid_proof', 'Pairing proof expired before acceptance.', 403, 3, 'permission_denied');
      }
      if (this.db.prepare('SELECT 1 FROM pairings WHERE proof_jti = ?').get(proof.jti)) {
        throw new AppError('proof_replayed', 'Pairing proof has already been used.', 409, 3, 'permission_denied');
      }
      this.db.prepare('INSERT INTO pairings VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(pairing.pairing_id, pairing.principal, pairing.public_jwk, pairing.display_name,
          now, pairing.status, id, proof.jti);
      this.db.prepare('UPDATE invitations SET consumed_at = ? WHERE id = ?').run(now, id);
      this.db.exec('COMMIT');
      return now;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  listPairings(after?: string): { pairings: Pairing[]; next_cursor: string | null } {
    let timestamp = -1;
    let pairingId = '';
    if (after !== undefined) {
      const cursor = this.db.prepare('SELECT created_at, pairing_id FROM pairings WHERE pairing_id = ?').get(after);
      if (!cursor) invalid('invalid_cursor', 'Pairing cursor was not found in this Node.');
      timestamp = cursor.created_at as number;
      pairingId = cursor.pairing_id as string;
    }
    const rows = this.db.prepare(`
      SELECT pairing_id, principal, public_jwk, display_name, created_at, status
      FROM pairings WHERE (created_at, pairing_id) > (?, ?)
      ORDER BY created_at, pairing_id LIMIT 201
    `).all(timestamp, pairingId) as unknown as Pairing[];
    const pairings = rows.slice(0, 200);
    return { pairings, next_cursor: rows.length > 200 ? pairings[199]!.pairing_id : null };
  }

  close(): void { this.db.close(); }
}
