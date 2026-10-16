import { randomBytes, randomUUID } from 'node:crypto';
import { AppError, textField } from './contracts.js';
import { integer } from './providers.js';
import type { Store } from './store.js';
import { websiteOrigin } from './website-login.js';

export const WEBSITE_SESSION_TTL_DEFAULT = 1800;
export const WEBSITE_SESSION_TTL_MIN = 60;
export const WEBSITE_SESSION_TTL_MAX = 1800;
export const AUDIT_RESULTS = ['authenticated', 'human_required', 'failed', 'refused', 'revoked'] as const;
export type AuditResult = typeof AUDIT_RESULTS[number];

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
      result TEXT NOT NULL CHECK(result IN ('authenticated','human_required','failed','refused','revoked')),
      session_handle_id TEXT
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

export function writeAudit(store: Store, entry: {
  credential_id: string; agent_id: string; origin: string; started_at: number;
  result: AuditResult; session_handle_id?: string;
}): void {
  if (!AUDIT_RESULTS.includes(entry.result)) throw new AppError('invalid_parameters', 'Invalid audit result.');
  store.db.prepare('INSERT INTO audit_log(id, credential_id, agent_id, origin, started_at, result, session_handle_id) VALUES (?,?,?,?,?,?,?)')
    .run(randomUUID(), entry.credential_id, entry.agent_id, entry.origin, entry.started_at, entry.result, entry.session_handle_id ?? null);
}

export function listAudit(store: Store, after?: string): { entries: Record<string, unknown>[]; next_cursor: string | null } {
  let startedAt = -1; let id = '';
  if (after !== undefined) {
    const cursor = store.db.prepare('SELECT started_at, id FROM audit_log WHERE id=?').get(textField(after, 36));
    if (!cursor) throw new AppError('invalid_cursor', 'Audit cursor was not found.');
    startedAt = cursor.started_at as number; id = String(cursor.id);
  }
  const rows = store.db.prepare(`
    SELECT id, credential_id, agent_id, origin, started_at, result, session_handle_id
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
