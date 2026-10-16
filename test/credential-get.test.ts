import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { capabilities, operation, runOrders, takeCredential } from '../src/agent-client.js';
import { connect } from '../src/client.js';
import { AppError } from '../src/contracts.js';
import { CREDENTIAL_GET_ACTION } from '../src/credential-get.js';
import { secretForms } from '../src/redact.js';
import { loadIdentity } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { issueInvitation } from '../src/pairing.js';
import { drainProviderOperations } from '../src/provider-operations.js';
import { Store } from '../src/store.js';
import { initializeVault } from '../src/vault.js';
import { vaultRequest } from '../src/vault-client.js';
import { unlockVault } from '../src/vault-session.js';
import { originAllowed } from '../src/website-sessions.js';

const cli = resolve('dist/src/cli.js');
const SECRET = 'fixture-credential-get-DO-NOT-LEAK';
const ORIGIN = 'https://dashboard.example.test';
const denied = (code?: string) => (error: unknown) => error instanceof AppError && error.exitCode === 3 && (!code || error.code === code);

function captureProcessIo() {
  const chunks: string[] = [];
  const hook = (stream: NodeJS.WriteStream) => {
    const original = stream.write.bind(stream);
    (stream as { write: (chunk: unknown, ...rest: unknown[]) => boolean }).write = (chunk, ...rest) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk));
      return original(chunk as string | Uint8Array, ...rest as []);
    };
    return () => { stream.write = original; };
  };
  const restore = [hook(process.stdout), hook(process.stderr)];
  return { text: () => chunks.join(''), restore: () => { for (const undo of restore) undo(); } };
}

function walkFiles(root: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(root)) {
    const path = join(root, name);
    const stat = statSync(path);
    if (stat.isDirectory()) out.push(...walkFiles(path));
    else if (stat.isFile()) out.push(path);
  }
  return out;
}

function assertSecretAbsent(secret: string, ...parts: unknown[]) {
  const needles = secretForms(secret);
  for (const part of parts) {
    const text = Buffer.isBuffer(part) ? part.toString('latin1') : typeof part === 'string' ? part : JSON.stringify(part);
    for (const needle of needles) {
      assert.equal(text.includes(needle), false);
    }
  }
}

function traces(store: Store, extra: unknown[] = []) {
  return [
    store.db.prepare('SELECT * FROM provider_operations').all(),
    store.db.prepare('SELECT * FROM events').all(),
    store.db.prepare('SELECT grant_id, pairing_id, principal, action, connection_id, max_calls, signed_grant FROM grants').all(),
    store.db.prepare('SELECT * FROM audit_log').all(),
    store.db.prepare('SELECT * FROM credential_origins').all(),
    ...extra,
  ];
}

async function runtime(t: TestContext, secret = SECRET) {
  const root = mkdtempSync(join(tmpdir(), 'stackey-credget-'));
  const dir = join(root, 'vault'); const nodeDir = join(root, 'node'); const recovery = join(root, 'seed.json');
  await initializeVault(dir, recovery);
  const identity = await loadIdentity(nodeDir, 'node', true);
  const node = await startNode(nodeDir, 0);
  const store = new Store(nodeDir);
  const vault = await unlockVault(dir, recovery, nodeDir);
  t.after(async () => { await node.close(); await vault.close(); store.close(); rmSync(root, { recursive: true }); });
  const owner = { _node_dir: resolve(nodeDir) };
  await vaultRequest(dir, 'node.bind', owner);
  const imported = await vaultRequest(dir, 'credential.import', { wallet_id: 'wallet_demo', name: 'API', kind: 'api_key', value: secret });
  const connected = await vaultRequest(dir, 'connection.add', { wallet_id: 'wallet_demo', name: 'Handoff', provider: 'credential',
    config: { origin: ORIGIN, credential_id: imported.id } });
  const agent = join(root, 'agent');
  const invitation = await issueInvitation(store, identity, 300);
  const pairing = (await connect(invitation, agent, 'Get Agent')).data as any;
  return { root, dir, node, store, agent, owner, imported, connected, pairing, identity };
}

async function approve(f: Awaited<ReturnType<typeof runtime>>, ttl = 300) {
  return vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: CREDENTIAL_GET_ACTION, ttl, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
}

test('without approval a paired agent cannot fetch a credential', async t => {
  const f = await runtime(t);
  await assert.rejects(runOrders(f.agent, CREDENTIAL_GET_ACTION, {}), denied('permission_denied'));
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM provider_operations').get()!.n, 0);
  assertSecretAbsent(SECRET, traces(f.store));
});

test('approved single-use credential.get returns the secret once, persists issued, then refuses replay and revoke', async t => {
  const f = await runtime(t);
  await assert.rejects(vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: CREDENTIAL_GET_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 5, max_amount_minor: 0 }), error => error instanceof AppError && error.code === 'invalid_limit');
  await assert.rejects(vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: CREDENTIAL_GET_ACTION, ttl: 900, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 }), error => error instanceof AppError && error.code === 'invalid_ttl');

  const grant = await approve(f);
  assert.equal(grant.max_calls, 1);
  assert.equal(grant.actions[0], CREDENTIAL_GET_ACTION);
  const caps = await capabilities(f.agent);
  assert.equal((caps.data as any).capabilities[0].action, CREDENTIAL_GET_ACTION);
  assert.equal((caps.data as any).capabilities[0].credentials_exported, true);
  assert.equal((caps.data as any).max_calls, 1);

  const id = randomUUID();
  const pending = await runOrders(f.agent, CREDENTIAL_GET_ACTION, {}, id);
  assert.equal(pending.status, 'operation_pending');
  await drainProviderOperations(f.node.nodeId);
  const completed = await operation(f.agent, id);
  assert.equal(completed.status, 'ok');
  assert.deepEqual((completed.data as any).result, { value: SECRET });
  const row = f.store.db.prepare('SELECT state, result_json FROM provider_operations WHERE operation_id=?').get(id);
  assert.equal(row!.state, 'completed');
  assert.deepEqual(JSON.parse(String(row!.result_json)), { issued: true });
  const audit = f.store.db.prepare('SELECT * FROM audit_log').all() as Record<string, unknown>[];
  assert.equal(audit.length, 1);
  assert.equal(audit[0]!.result, 'issued');
  assert.equal(audit[0]!.origin, ORIGIN);
  assert.equal(audit[0]!.credential_id, f.imported.id);
  assert.equal(audit[0]!.agent_id, f.pairing.principal);
  assert.equal('value' in audit[0]! || 'secret' in audit[0]! || 'password' in audit[0]!, false);

  const replay = await runOrders(f.agent, CREDENTIAL_GET_ACTION, {}, id);
  assert.equal((replay.data as any).replayed, true);
  assert.deepEqual((replay.data as any).result, { issued: true });
  await assert.rejects(takeCredential(f.agent, id), denied('already_issued'));
  await assert.rejects(runOrders(f.agent, CREDENTIAL_GET_ACTION, {}), denied('budget_exceeded'));

  await vaultRequest(f.dir, 'grant.revoke', { ...f.owner, grant_id: grant.grant_id });
  await assert.rejects(runOrders(f.agent, CREDENTIAL_GET_ACTION, {}, id), denied('grant_revoked'));
  assertSecretAbsent(SECRET, traces(f.store, [grant, pending, replay, caps, row]), JSON.stringify(audit));
});

test('allowlist mismatch fails closed, writes refused, and does not consume the grant', async t => {
  const f = await runtime(t);
  await approve(f);
  assert.equal(originAllowed(f.store, String(f.imported.id), ORIGIN), true);
  f.store.db.prepare('DELETE FROM credential_origins WHERE credential_id=?').run(String(f.imported.id));
  const id = randomUUID();
  await runOrders(f.agent, CREDENTIAL_GET_ACTION, {}, id);
  await drainProviderOperations(f.node.nodeId);
  await assert.rejects(operation(f.agent, id), denied('origin_not_allowed'));
  const row = f.store.db.prepare('SELECT state, result_json FROM provider_operations WHERE operation_id=?').get(id);
  assert.equal(row!.state, 'failed');
  assert.deepEqual(JSON.parse(String(row!.result_json)), { error: { code: 'origin_not_allowed' } });
  const audit = f.store.db.prepare('SELECT * FROM audit_log').all() as Record<string, unknown>[];
  assert.equal(audit[0]!.result, 'refused');
  await vaultRequest(f.dir, 'credential.origin.add', { ...f.owner, credential_id: f.imported.id, origin: ORIGIN });
  const retry = randomUUID();
  await runOrders(f.agent, CREDENTIAL_GET_ACTION, {}, retry);
  await drainProviderOperations(f.node.nodeId);
  const completed = await operation(f.agent, retry);
  assert.deepEqual((completed.data as any).result, { value: SECRET });
  await assert.rejects(vaultRequest(f.dir, 'credential.origin.add', { ...f.owner, credential_id: f.imported.id, origin: 'https://*.example.test' }),
    error => error instanceof AppError && error.code === 'invalid_origin');
  assertSecretAbsent(SECRET, traces(f.store, [row]));
});

test('a second paired agent cannot fetch with someone else\'s grant', async t => {
  const f = await runtime(t);
  await approve(f);
  const other = join(f.root, 'agent-b');
  const invitation = await issueInvitation(f.store, f.identity, 300);
  await connect(invitation, other, 'Other Agent');
  await assert.rejects(runOrders(other, CREDENTIAL_GET_ACTION, {}), denied('permission_denied'));
  const handed = await takeCredential(f.agent);
  assert.deepEqual(handed, { value: SECRET });
  assertSecretAbsent(SECRET, traces(f.store));
});

test('stackey credential get prints only {value} and never writes the secret to logs, errors, or sqlite', async t => {
  const canary = `CANARY-get-${randomUUID()}`;
  const f = await runtime(t, canary);
  await approve(f);
  const logs = captureProcessIo();
  try {
    const child = spawn(process.execPath, [cli, 'credential', 'get', '--state-dir', f.agent], { env: process.env });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const [code] = await once(child, 'exit');
    assert.equal(code, 0);
    const body = JSON.parse(stdout);
    assert.deepEqual(body, { value: canary });
    assert.equal(Object.keys(body).join(','), 'value');
    assert.equal(stdout.trim().split('\n').length, 1);
    const row = f.store.db.prepare('SELECT result_json FROM provider_operations').get();
    const files = walkFiles(f.root).map(path => readFileSync(path));
    assertSecretAbsent(canary, traces(f.store), logs.text(), stderr, row, ...files);
  } finally { logs.restore(); }
});

test('canary secret in a failed get never appears in the error envelope or audit row', async t => {
  const canary = `CANARY-get-${randomUUID()}`;
  const f = await runtime(t, canary);
  await approve(f);
  f.store.db.prepare('DELETE FROM credential_origins WHERE credential_id=?').run(String(f.imported.id));
  const logs = captureProcessIo();
  try {
    const id = randomUUID();
    await runOrders(f.agent, CREDENTIAL_GET_ACTION, {}, id);
    await drainProviderOperations(f.node.nodeId);
    await assert.rejects(operation(f.agent, id), error => error instanceof AppError && error.code === 'origin_not_allowed' && !JSON.stringify(error).includes(canary));
    const audit = f.store.db.prepare('SELECT * FROM audit_log').all();
    const row = f.store.db.prepare('SELECT result_json FROM provider_operations WHERE operation_id=?').get(id);
    assertSecretAbsent(canary, traces(f.store, [audit, row]), logs.text());
  } finally { logs.restore(); }
});
