import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { AppError } from '../src/contracts.js';
import { Store } from '../src/store.js';
import {
  addCredentialOrigin,
  createWebsiteSession,
  credentialOrigins,
  listAudit,
  originAllowed,
  requireWebsiteSession,
  revokeWebsiteSessions,
  setWebsiteSessionTtl,
  websiteSession,
  websiteSessionTtl,
  writeAudit,
  WEBSITE_SESSION_TTL_DEFAULT,
} from '../src/website-sessions.js';

function store() {
  const dir = mkdtempSync(join(tmpdir(), 'stackey-sessions-'));
  const value = new Store(dir);
  return { dir, value, close() { value.close(); rmSync(dir, { recursive: true }); } };
}

test('credential_origins is an exact https://host allowlist with no wildcards', () => {
  const f = store();
  try {
    const id = 'credential_' + randomUUID();
    addCredentialOrigin(f.value, id, 'https://dashboard.example.test');
    assert.deepEqual(credentialOrigins(f.value, id), ['https://dashboard.example.test']);
    assert.equal(originAllowed(f.value, id, 'https://dashboard.example.test'), true);
    assert.equal(originAllowed(f.value, id, 'https://other.example.test'), false);
    assert.equal(originAllowed(f.value, id, 'https://dashboard.example.test.evil.test'), false);
    for (const origin of ['https://*.example.test', 'https://example*.test', 'https://%.example.test', '*',
      'https://dashboard.example.test.', 'https://dashboard.example.test..', 'https://example.com..']) {
      assert.throws(() => addCredentialOrigin(f.value, id, origin), error => error instanceof AppError && error.code === 'invalid_origin');
    }
    assert.equal(originAllowed(f.value, id, 'https://dashboard.example.test'), true);
  } finally { f.close(); }
});

test('audit_log is append-only, has no secret column, and listAudit pages by cursor', () => {
  const f = store();
  try {
    const credential = 'credential_' + randomUUID();
    writeAudit(f.value, { credential_id: credential, agent_id: 'agent_a', origin: 'https://dashboard.example.test', started_at: 100, result: 'authenticated', session_handle_id: 'h1' });
    writeAudit(f.value, { credential_id: credential, agent_id: 'agent_a', origin: 'https://dashboard.example.test', started_at: 101, result: 'revoked' });
    writeAudit(f.value, { credential_id: credential, agent_id: 'agent_a', origin: 'https://dashboard.example.test', started_at: 102, result: 'issued' });
    const columns = f.value.db.prepare('PRAGMA table_info(audit_log)').all().map(row => String(row.name));
    assert.deepEqual(columns.sort(), ['agent_id', 'credential_id', 'id', 'origin', 'reason', 'result', 'session_handle_id', 'started_at']);
    assert.throws(() => f.value.db.prepare("UPDATE audit_log SET result='failed'").run());
    assert.throws(() => f.value.db.prepare('DELETE FROM audit_log').run());
    const first = listAudit(f.value);
    assert.equal(first.entries.length, 3);
    assert.equal(first.next_cursor, null);
    assert.equal(first.entries[0]!.result, 'authenticated');
    const rest = listAudit(f.value, String(first.entries[0]!.id));
    assert.equal(rest.entries.length, 2);
    assert.equal(rest.entries[0]!.result, 'revoked');
    assert.equal(rest.entries[1]!.result, 'issued');
    assert.equal(JSON.stringify(first).includes('password'), false);
  } finally { f.close(); }
});

test('website sessions use an opaque handle, default 30 min TTL, and revoke immediately', () => {
  const f = store();
  try {
    assert.equal(websiteSessionTtl(f.value), WEBSITE_SESSION_TTL_DEFAULT);
    setWebsiteSessionTtl(f.value, 120);
    assert.equal(websiteSessionTtl(f.value), 120);
    const credential = 'credential_' + randomUUID();
    const session = createWebsiteSession(f.value, {
      credential_id: credential, agent_id: 'agent_a', origin: 'https://dashboard.example.test', now: 1_000, ttl: 120,
    });
    assert.match(session.handle_id, /^[A-Za-z0-9_-]{32,64}$/);
    assert.equal(session.expires_at, 1_120);
    requireWebsiteSession(f.value, session.handle_id, 1_000);
    assert.equal(revokeWebsiteSessions(f.value, credential, 1_050), 1);
    const row = websiteSession(f.value, session.handle_id)!;
    assert.equal(row.revoked_at, 1_050);
    assert.throws(() => requireWebsiteSession(f.value, session.handle_id, 1_051),
      error => error instanceof AppError && error.code === 'invalid_session');
    assert.throws(() => requireWebsiteSession(f.value, session.handle_id, 2_000),
      error => error instanceof AppError && error.code === 'invalid_session');
  } finally { f.close(); }
});
