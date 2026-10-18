import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { takeCredential } from '../src/agent-client.js';
import { connect } from '../src/client.js';
import {
  AppError, EXIT_BUDGET, EXIT_DENIED, EXIT_GRANT_EXPIRED, EXIT_GRANT_REVOKED, EXIT_LOCKED,
  exitCodeFor, publicError,
} from '../src/contracts.js';
import { CREDENTIAL_GET_ACTION } from '../src/credential-get.js';
import { loadIdentity } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { issueInvitation } from '../src/pairing.js';
import { grantLifecycle, listedGrantStatus } from '../src/policy.js';
import { isSqliteExperimentalWarning, nodeMeetsRequirement } from '../src/runtime-guard.js';
import { Store } from '../src/store.js';
import { initializeVault } from '../src/vault.js';
import { vaultRequest } from '../src/vault-client.js';
import { unlockVault } from '../src/vault-session.js';
import { ensureWebsiteLoginTables, writeAudit } from '../src/website-sessions.js';

const cli = resolve('dist/src/cli.js');
const SECRET = 'fixture-audit-policy-DO-NOT-LEAK';
const ORIGIN = 'https://dashboard.example.test';

async function cliResult(...args: string[]) {
  const child = spawn(process.execPath, [cli, ...args], { env: process.env });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const [code] = await once(child, 'close');
  return { code, stdout, stderr, body: stdout.trim() ? JSON.parse(stdout) : undefined };
}

function results(store: Store, result: string) {
  return store.db.prepare('SELECT * FROM audit_log WHERE result=? ORDER BY started_at, id').all(result) as Record<string, unknown>[];
}

async function runtime(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), 'stackey-audit-policy-'));
  const dir = join(root, 'vault'); const nodeDir = join(root, 'node'); const recovery = join(root, 'seed.json');
  await initializeVault(dir, recovery);
  const identity = await loadIdentity(nodeDir, 'node', true);
  const node = await startNode(nodeDir, 0);
  const store = new Store(nodeDir);
  const vault = await unlockVault(dir, recovery, nodeDir);
  t.after(async () => { await node.close(); await vault.close(); store.close(); rmSync(root, { recursive: true }); });
  const owner = { _node_dir: resolve(nodeDir) };
  await vaultRequest(dir, 'node.bind', owner);
  const imported = await vaultRequest(dir, 'credential.import', { wallet_id: 'wallet_demo', name: 'API', kind: 'api_key', value: SECRET });
  const connected = await vaultRequest(dir, 'connection.add', { wallet_id: 'wallet_demo', name: 'Handoff', provider: 'credential',
    config: { origin: ORIGIN, credential_id: imported.id } });
  const agent = join(root, 'agent');
  const invitation = await issueInvitation(store, identity, 300);
  const pairing = (await connect(invitation, agent, 'Audit Agent')).data as any;
  return { root, dir, node, store, agent, owner, imported, connected, pairing, identity, vault, recovery };
}

async function approve(f: Awaited<ReturnType<typeof runtime>>, extra: Record<string, unknown> = {}) {
  return vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: CREDENTIAL_GET_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0, ...extra });
}

test('exitCodeFor keeps 3 for vault lock only and splits grant denials', () => {
  assert.equal(exitCodeFor('node_locked'), EXIT_LOCKED);
  assert.equal(exitCodeFor('permission_denied'), EXIT_DENIED);
  assert.equal(exitCodeFor('grant_expired'), EXIT_GRANT_EXPIRED);
  assert.equal(exitCodeFor('grant_revoked'), EXIT_GRANT_REVOKED);
  assert.equal(exitCodeFor('budget_exceeded'), EXIT_BUDGET);
  assert.equal(exitCodeFor('unknown_code', EXIT_LOCKED), EXIT_DENIED);
  assert.equal(publicError(new AppError('node_locked', 'locked', 403, 3, 'node_locked')).exitCode, EXIT_LOCKED);
  assert.equal(publicError(new AppError('budget_exceeded', 'spent', 403, 3, 'permission_denied')).exitCode, EXIT_BUDGET);
  assert.equal(publicError(new AppError('grant_expired', 'late', 403, 3, 'grant_expired')).exitCode, EXIT_GRANT_EXPIRED);
  assert.equal(publicError(new AppError('grant_revoked', 'stopped', 403, 3, 'grant_revoked')).exitCode, EXIT_GRANT_REVOKED);
  assert.equal(publicError(new AppError('permission_denied', 'no', 403, 3, 'permission_denied')).exitCode, EXIT_DENIED);
});

test('grantLifecycle distinguishes spent, replaced, expired and owner-revoked', () => {
  const base = { max_calls: 1, expires_at: 200, revoked_at: null as number | null, superseded_at: null as number | null };
  assert.equal(grantLifecycle(base, 100, 0), 'active');
  assert.equal(grantLifecycle(base, 100, 1), 'spent');
  assert.equal(grantLifecycle({ ...base, expires_at: 50 }, 100, 0), 'expired');
  assert.equal(grantLifecycle({ ...base, revoked_at: 90 }, 100, 1), 'revoked');
  assert.equal(grantLifecycle({ ...base, revoked_at: 90, superseded_at: 90 }, 100, 1), 'replaced');
});

test('runtime guard requires Node 22.18 and recognizes the SQLite experimental warning', () => {
  assert.equal(nodeMeetsRequirement('22.18.0'), true);
  assert.equal(nodeMeetsRequirement('22.17.9'), false);
  assert.equal(nodeMeetsRequirement('20.19.0'), false);
  assert.equal(nodeMeetsRequirement('23.0.0'), true);
  assert.equal(isSqliteExperimentalWarning({ name: 'ExperimentalWarning', message: 'SQLite is an experimental feature and might change at any time' }), true);
  assert.equal(isSqliteExperimentalWarning({ name: 'ExperimentalWarning', message: 'Other experiment' }), false);
});

test('CLI help does not print the SQLite experimental warning', async () => {
  const child = spawn(process.execPath, [cli, '--help'], { env: process.env });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const [code] = await once(child, 'close');
  assert.equal(code, 0);
  assert.equal(/ExperimentalWarning|SQLite is an experimental feature/i.test(stderr), false);
  assert.match(stdout, /Exit codes:/);
  assert.match(stdout, /3 {2}vault locked/);
  assert.match(stdout, /8 {2}grant budget exceeded/);
});

test('node grants reports spent, replaced, expired and revoked separately, and audit records denials plus owner changes', async t => {
  const f = await runtime(t);
  const ownerFlags = ['--vault-dir', f.dir, '--data-dir', f.store.directory];
  const approveArgs = ['node', 'approve', f.pairing.pairing_id, '--principal', f.pairing.principal,
    '--action', CREDENTIAL_GET_ACTION, '--connection', String(f.connected.id), '--wallet', 'wallet_demo', ...ownerFlags];

  assert.ok(results(f.store, 'unlocked').length >= 1);
  assert.equal(results(f.store, 'paired')[0]!.agent_id, f.pairing.principal);

  const unpaired = await cliResult('credential', 'get', '--state-dir', join(f.root, 'missing-agent'), '--data-dir', f.store.directory);
  assert.equal(unpaired.body.error.code, 'agent_not_paired');
  assert.equal(unpaired.code, EXIT_DENIED);
  assert.ok(results(f.store, 'agent_not_paired').length >= 1);

  const denied = await cliResult('credential', 'get', '--state-dir', f.agent);
  assert.equal(denied.body.error.code, 'permission_denied');
  assert.equal(denied.code, EXIT_DENIED);
  assert.ok(results(f.store, 'permission_denied').some(row => row.agent_id === f.pairing.principal));

  const first = await cliResult(...approveArgs);
  assert.equal(first.code, 0);
  assert.equal(results(f.store, 'approved').length, 1);
  assert.equal(results(f.store, 'approved')[0]!.credential_id, f.imported.id);
  assert.equal(results(f.store, 'approved')[0]!.reason, 'approve');

  assert.deepEqual((await cliResult('credential', 'get', '--state-dir', f.agent)).body, { value: SECRET });
  const spentList = await cliResult('node', 'grants', '--data-dir', f.store.directory);
  assert.equal(spentList.body.data.grants[0].status, 'spent');
  assert.equal(listedGrantStatus(f.store, f.store.db.prepare('SELECT * FROM grants WHERE grant_id=?').get(first.body.data.grant_id) as any), 'spent');

  const budget = await cliResult('credential', 'get', '--state-dir', f.agent);
  assert.equal(budget.body.error.code, 'budget_exceeded');
  assert.equal(budget.code, EXIT_BUDGET);
  assert.equal(results(f.store, 'budget_exceeded')[0]!.credential_id, f.imported.id);
  assert.equal(results(f.store, 'budget_exceeded')[0]!.agent_id, f.pairing.principal);

  const replaced = await cliResult(...approveArgs, '--replace-grant', first.body.data.grant_id);
  assert.equal(replaced.code, 0);
  const listed = await cliResult('node', 'grants', '--data-dir', f.store.directory);
  const byId = Object.fromEntries(listed.body.data.grants.map((row: { grant_id: string; status: string }) => [row.grant_id, row.status]));
  assert.equal(byId[first.body.data.grant_id], 'replaced');
  assert.equal(byId[replaced.body.data.grant_id], 'active');
  assert.equal(results(f.store, 'replaced')[0]!.reason, 'replace');
  assert.equal(results(f.store, 'replaced')[0]!.credential_id, f.imported.id);

  f.store.db.prepare('UPDATE grants SET expires_at=0 WHERE grant_id=?').run(replaced.body.data.grant_id);
  const expiredList = await cliResult('node', 'grants', '--data-dir', f.store.directory);
  const expiredRow = expiredList.body.data.grants.find((row: { grant_id: string }) => row.grant_id === replaced.body.data.grant_id);
  assert.equal(expiredRow.status, 'expired');
  const expired = await cliResult('credential', 'get', '--state-dir', f.agent);
  assert.equal(expired.body.error.code, 'grant_expired');
  assert.equal(expired.code, EXIT_GRANT_EXPIRED);
  assert.ok(results(f.store, 'grant_expired').length >= 1);

  const fresh = await cliResult(...approveArgs, '--replace-grant', replaced.body.data.grant_id);
  assert.equal(fresh.code, 0);
  assert.equal((await cliResult('node', 'revoke', fresh.body.data.grant_id, ...ownerFlags)).code, 0);
  const revokedList = await cliResult('node', 'grants', '--data-dir', f.store.directory);
  assert.equal(revokedList.body.data.grants.find((row: { grant_id: string }) => row.grant_id === fresh.body.data.grant_id).status, 'revoked');
  const revoked = await cliResult('credential', 'get', '--state-dir', f.agent);
  assert.equal(revoked.body.error.code, 'grant_revoked');
  assert.equal(revoked.code, EXIT_GRANT_REVOKED);
  assert.ok(results(f.store, 'revoked').some(row => row.reason === 'revoke' && row.agent_id === f.pairing.principal));

  await f.vault.close();
  const locked = await cliResult('credential', 'get', '--state-dir', f.agent);
  assert.equal(locked.body.error.code, 'node_locked');
  assert.equal(locked.code, EXIT_LOCKED);
  assert.ok(results(f.store, 'locked').length >= 1);
  assert.ok(results(f.store, 'node_locked').length >= 1);

  const audit = await cliResult('audit', '--data-dir', f.store.directory);
  assert.equal(audit.code, 0);
  const kinds = new Set(audit.body.data.entries.map((row: { result: string }) => row.result));
  for (const kind of ['paired', 'approved', 'replaced', 'revoked', 'unlocked', 'locked',
    'permission_denied', 'budget_exceeded', 'grant_expired', 'grant_revoked', 'agent_not_paired', 'node_locked', 'issued']) {
    assert.equal(kinds.has(kind), true, kind);
  }
  for (const row of audit.body.data.entries) {
    assert.equal(Object.hasOwn(row, 'reason'), true);
    assert.equal(Object.hasOwn(row, 'agent_id'), true);
    assert.equal(Object.hasOwn(row, 'credential_id'), true);
    assert.equal(Object.hasOwn(row, 'started_at'), true);
    assert.equal(JSON.stringify(row).includes(SECRET), false);
  }
});

test('audit_log migration adds reason and new result values without dropping history', () => {
  const dir = mkdtempSync(join(tmpdir(), 'stackey-audit-migrate-'));
  const store = new Store(dir);
  try {
    store.db.exec(`
      DROP TRIGGER IF EXISTS audit_log_no_update;
      DROP TRIGGER IF EXISTS audit_log_no_delete;
      DROP TABLE audit_log;
      CREATE TABLE audit_log (
        id TEXT PRIMARY KEY, credential_id TEXT NOT NULL, agent_id TEXT NOT NULL, origin TEXT NOT NULL,
        started_at INTEGER NOT NULL, result TEXT NOT NULL CHECK(result IN ('authenticated','human_required','failed','refused','revoked','issued')),
        session_handle_id TEXT
      );
    `);
    store.db.prepare('INSERT INTO audit_log VALUES (?,?,?,?,?,?,?)')
      .run('id-legacy', 'credential_legacy', 'agent_a', 'https://dashboard.example.test', 10, 'issued', null);
    ensureWebsiteLoginTables(store);
    const columns = store.db.prepare('PRAGMA table_info(audit_log)').all().map(row => String(row.name));
    assert.equal(columns.includes('reason'), true);
    const preserved = store.db.prepare('SELECT result, reason, credential_id FROM audit_log WHERE id=?').get('id-legacy') as Record<string, unknown>;
    assert.equal(preserved.result, 'issued');
    assert.equal(preserved.reason, null);
    assert.equal(preserved.credential_id, 'credential_legacy');
    writeAudit(store, {
      credential_id: '-', agent_id: 'agent_a', origin: '-', started_at: 11, result: 'budget_exceeded', reason: 'budget_exceeded',
    });
    assert.throws(() => store.db.prepare("UPDATE audit_log SET result='failed'").run());
  } finally { store.close(); rmSync(dir, { recursive: true }); }
});

test('spent grant fetch still never writes the secret into audit rows', async t => {
  const f = await runtime(t);
  await approve(f);
  await takeCredential(f.agent);
  await assert.rejects(takeCredential(f.agent), error => error instanceof AppError && error.code === 'budget_exceeded' && error.exitCode === EXIT_BUDGET);
  const dump = JSON.stringify(f.store.db.prepare('SELECT * FROM audit_log').all());
  assert.equal(dump.includes(SECRET), false);
});
