import { randomBytes, randomUUID } from 'node:crypto';
import { AppError, textField } from './contracts.js';
import { integer } from './providers.js';
import type { Store } from './store.js';
import { websiteOrigin } from './website-login.js';

export const WEBSITE_SESSION_TTL_DEFAULT = 1800;
export const WEBSITE_SESSION_TTL_MIN = 60;
export const WEBSITE_SESSION_TTL_MAX = 1800;
export const AUDIT_RESULTS = [
  'authenticated', 'human_required', 'failed', 'refused', 'revoked', 'issued',
  'budget_exceeded', 'grant_expired', 'grant_revoked', 'permission_denied', 'agent_not_paired', 'node_locked',
  'paired', 'approved', 'replaced', 'locked', 'unlocked',
] as const;
export type AuditResult = typeof AUDIT_RESULTS[number];
const AUDIT_CHECK = "('authenticated','human_required','failed','refused','revoked','issued','budget_exceeded','grant_expired','grant_revoked','permission_denied','agent_not_paired','node_locked','paired','approved','replaced','locked','unlocked')";
export interface AuditEntry {
  credential_id: string;
  agent_id: string;
  origin: string;
  started_at: number;
  result: AuditResult;
  session_handle_id?: string;
  reason?: string;
}

export function ensureWebsiteLoginTables(store: Store): void {
  store.db.exec(`
    CREATE TABLE IF NOT EXISTS credential_origins (
      credential_id TEXT NOT NULL,
      origin TEXT NOT NULL,
      PRIMARY KEY (credential_id, origin)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      credential_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      origin TEXT NOT NULL,
      started_at INTEGER NOT NULL,
      result TEXT NOT NULL CHECK(result IN ${AUDIT_CHECK}),
      session_handle_id TEXT,
      reason TEXT
    );
    CREATE TABLE IF NOT EXISTS connection_credentials (
      connection_id TEXT PRIMARY KEY,
      credential_id TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS website_sessions (
      handle_id TEXT PRIMARY KEY,
      credential_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      origin TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked_at INTEGER
    );
    CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
  `);
  const sql = String(store.db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_log'").get()?.sql ?? '');
  const columns = store.db.prepare('PRAGMA table_info(audit_log)').all().map(row => String(row.name));
  if (sql.includes("'budget_exceeded'") && columns.includes('reason')) return;
  store.db.exec(`
    DROP TRIGGER IF EXISTS audit_log_no_update;
    DROP TRIGGER IF EXISTS audit_log_no_delete;
    CREATE TABLE audit_log_new (
      id TEXT PRIMARY KEY,
      credential_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      origin TEXT NOT NULL,
      started_at INTEGER NOT NULL,
      result TEXT NOT NULL CHECK(result IN ${AUDIT_CHECK}),
      session_handle_id TEXT,
      reason TEXT
    );
    INSERT INTO audit_log_new (id, credential_id, agent_id, origin, started_at, result, session_handle_id, reason)
      SELECT id, credential_id, agent_id, origin, started_at, result, session_handle_id,
        ${columns.includes('reason') ? 'reason' : 'NULL'} FROM audit_log;
    DROP TABLE audit_log;
    ALTER TABLE audit_log_new RENAME TO audit_log;
    CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
  `);
}

export function websiteSessionTtl(store: Store, override?: unknown): number {
  if (override !== undefined) return integer(override, WEBSITE_SESSION_TTL_MIN, WEBSITE_SESSION_TTL_MAX);
  const row = store.db.prepare("SELECT value FROM settings WHERE key='website_session_ttl'").get();
  if (!row) return WEBSITE_SESSION_TTL_DEFAULT;
  return integer(Number(row.value), WEBSITE_SESSION_TTL_MIN, WEBSITE_SESSION_TTL_MAX);
}

export function setWebsiteSessionTtl(store: Store, seconds: number): void {
  const ttl = integer(seconds, WEBSITE_SESSION_TTL_MIN, WEBSITE_SESSION_TTL_MAX);
  store.db.prepare("INSERT INTO settings VALUES ('website_session_ttl', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run(String(ttl));
}

export function addCredentialOrigin(store: Store, credentialId: string, origin: string): void {
  const id = textField(credentialId, 64);
  const allowed = websiteOrigin(origin);
  store.db.prepare('INSERT OR IGNORE INTO credential_origins(credential_id, origin) VALUES (?, ?)').run(id, allowed);
}

export function credentialOrigins(store: Store, credentialId: string): string[] {
  return store.db.prepare('SELECT origin FROM credential_origins WHERE credential_id=? ORDER BY origin')
    .all(credentialId).map(row => String(row.origin));
}

export function originAllowed(store: Store, credentialId: string, origin: string): boolean {
  return !!store.db.prepare('SELECT 1 FROM credential_origins WHERE credential_id=? AND origin=?')
    .get(credentialId, origin);
}

export function linkConnectionCredential(store: Store, connectionId: string, credentialId: string): void {
  store.db.prepare('INSERT INTO connection_credentials(connection_id, credential_id) VALUES (?, ?) ON CONFLICT(connection_id) DO UPDATE SET credential_id=excluded.credential_id')
    .run(textField(connectionId, 64), textField(credentialId, 64));
}

export function credentialForConnection(store: Store, connectionId: string | null | undefined): string {
  if (!connectionId) return '-';
  const row = store.db.prepare('SELECT credential_id FROM connection_credentials WHERE connection_id=?').get(connectionId);
  return row ? String(row.credential_id) : '-';
}

export function insertAudit(store: Store, entry: AuditEntry): void {
  if (!AUDIT_RESULTS.includes(entry.result)) throw new AppError('invalid_parameters', 'Invalid audit result.');
  store.db.prepare('INSERT INTO audit_log(id, credential_id, agent_id, origin, started_at, result, session_handle_id, reason) VALUES (?,?,?,?,?,?,?,?)')
    .run(randomUUID(), entry.credential_id, entry.agent_id, entry.origin, entry.started_at, entry.result,
      entry.session_handle_id ?? null, entry.reason ?? entry.result);
}

export function writeAudit(store: Store, entry: AuditEntry): void {
  const row: AuditEntry = {
    credential_id: entry.credential_id || '-',
    agent_id: entry.agent_id || '-',
    origin: entry.origin || '-',
    started_at: entry.started_at,
    result: entry.result,
    reason: entry.reason ?? entry.result,
    ...(entry.session_handle_id ? { session_handle_id: entry.session_handle_id } : {}),
  };
  if (store.writing) store.queuedAudit.push(row);
  else insertAudit(store, row);
}

export function recordAudit(store: Store, input: {
  result: AuditResult; agent_id: string; credential_id?: string; origin?: string;
  reason?: string; started_at?: number; session_handle_id?: string;
}): void {
  writeAudit(store, {
    credential_id: input.credential_id ?? '-',
    agent_id: input.agent_id,
    origin: input.origin ?? '-',
    started_at: input.started_at ?? Math.floor(Date.now() / 1000),
    result: input.result,
    reason: input.reason ?? input.result,
    ...(input.session_handle_id ? { session_handle_id: input.session_handle_id } : {}),
  });
}

export function flushQueuedAudit(store: Store): void {
  const pending = store.queuedAudit;
  store.queuedAudit = [];
  for (const entry of pending) insertAudit(store, entry);
}

export function listAudit(store: Store, after?: string): { entries: Record<string, unknown>[]; next_cursor: string | null } {
  let startedAt = -1; let id = '';
  if (after !== undefined) {
    const cursor = store.db.prepare('SELECT started_at, id FROM audit_log WHERE id=?').get(textField(after, 36));
    if (!cursor) throw new AppError('invalid_cursor', 'Audit cursor was not found.');
    startedAt = cursor.started_at as number; id = String(cursor.id);
  }
  const rows = store.db.prepare(`
    SELECT id, credential_id, agent_id, origin, started_at, result, reason, session_handle_id
    FROM audit_log WHERE (started_at, id) > (?, ?) ORDER BY started_at, id LIMIT 201
  `).all(startedAt, id) as Record<string, unknown>[];
  const entries = rows.slice(0, 200);
  return { entries, next_cursor: rows.length > 200 ? String(entries[199]!.id) : null };
}

export function createWebsiteSession(store: Store, input: {
  credential_id: string; agent_id: string; origin: string; now: number; ttl: number;
}): { handle_id: string; expires_at: number } {
  const ttl = integer(input.ttl, WEBSITE_SESSION_TTL_MIN, WEBSITE_SESSION_TTL_MAX);
  const handle_id = randomBytes(32).toString('base64url');
  const expires_at = input.now + ttl;
  store.db.prepare('INSERT INTO website_sessions(handle_id, credential_id, agent_id, origin, expires_at, revoked_at) VALUES (?,?,?,?,?,NULL)')
    .run(handle_id, input.credential_id, input.agent_id, input.origin, expires_at);
  return { handle_id, expires_at };
}

export function revokeWebsiteSessions(store: Store, credentialId: string, now: number): number {
  return Number(store.db.prepare('UPDATE website_sessions SET revoked_at=? WHERE credential_id=? AND revoked_at IS NULL')
    .run(now, credentialId).changes);
}

export function websiteSession(store: Store, handleId: string) {
  return store.db.prepare('SELECT * FROM website_sessions WHERE handle_id=?').get(handleId) as
    | { handle_id: string; credential_id: string; agent_id: string; origin: string; expires_at: number; revoked_at: number | null }
    | undefined;
}

export function requireWebsiteSession(store: Store, handleId: string, now: number) {
  const row = websiteSession(store, handleId);
  if (!row || row.revoked_at !== null || row.expires_at <= now) {
    throw new AppError('invalid_session', 'Session is expired or no longer authorized.', 403, 3, 'permission_denied');
  }
  return row;
}
