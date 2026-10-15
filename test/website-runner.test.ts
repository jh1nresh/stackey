import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { operation, runOrders } from '../src/agent-client.js';
import { connect } from '../src/client.js';
import { AppError } from '../src/contracts.js';
import { loadIdentity } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { issueInvitation } from '../src/pairing.js';
import { seconds } from '../src/policy.js';
import { drainProviderOperations } from '../src/provider-operations.js';
import { secretForms } from '../src/redact.js';
import { Store } from '../src/store.js';
import { initializeVault } from '../src/vault.js';
import { vaultRequest } from '../src/vault-client.js';
import { unlockVault } from '../src/vault-session.js';
import { executeWebsiteLogin, refuseWebsiteLogin, WEBSITE_LOGIN_ACTION } from '../src/website-login.js';
import { createPlaywrightExecutor, websiteRunnerFromEnv } from '../src/website-runner.js';
import { FIXTURE_HOSTS, FIXTURE_ORIGIN, fixtureAdapter, installFixtureRoutes } from './website-fixture.js';

const USER = 'founder@example.test';
const denied = (code?: string) => (error: unknown) => error instanceof AppError && error.exitCode === 3 && (!code || error.code === code);

function runner(path: string, lookup?: (host: string) => Promise<string[]>) {
  return createPlaywrightExecutor({
    adapters: [fixtureAdapter(path)],
    allowPrivateHosts: FIXTURE_HOSTS,
    ignoreHTTPSErrors: true,
    headed: false,
    humanWaitMs: 0,
    ...(lookup ? { lookup } : {}),
    preparePage: page => installFixtureRoutes(page, secretFor(path)),
  });
}

function secretFor(path: string) {
  return path.includes('echo') ? `CANARY-pw-${path}` : 'fixture-website-password-DO-NOT-LEAK';
}

function connection(origin = FIXTURE_ORIGIN) {
  return { id: 'connection_' + randomUUID(), wallet_id: 'wallet_demo', provider: 'website' as const,
    name: 'Fixture', config: { origin, username: USER, credential_id: 'credential_' + randomUUID() } };
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
    for (const needle of needles) assert.equal(text.includes(needle), false);
  }
}

async function runtime(t: TestContext, path: string, password?: string) {
  const secret = password ?? secretFor(path);
  const root = mkdtempSync(join(tmpdir(), 'stackey-runner-'));
  const dir = join(root, 'vault'); const nodeDir = join(root, 'node'); const recovery = join(root, 'seed.json');
  await initializeVault(dir, recovery);
  const identity = await loadIdentity(nodeDir, 'node', true);
  const node = await startNode(nodeDir, 0);
  const store = new Store(nodeDir);
  const vault = await unlockVault(dir, recovery, nodeDir, 900, seconds, undefined, runner(path));
  t.after(async () => { await node.close(); await vault.close(); store.close(); rmSync(root, { recursive: true }); });
  const owner = { _node_dir: resolve(nodeDir) };
  await vaultRequest(dir, 'node.bind', owner);
  const imported = await vaultRequest(dir, 'credential.import', { wallet_id: 'wallet_demo', name: 'Dashboard', kind: 'website_login', value: secret });
  const connected = await vaultRequest(dir, 'connection.add', { wallet_id: 'wallet_demo', name: 'Example', provider: 'website',
    config: { origin: FIXTURE_ORIGIN, username: USER, credential_id: imported.id } });
  const agent = join(root, 'agent');
  const invitation = await issueInvitation(store, identity, 300);
  const pairing = (await connect(invitation, agent, 'Website Agent')).data as { pairing_id: string; principal: string };
  return { root, dir, node, store, agent, owner, imported, connected, pairing, secret };
}

test('websiteRunnerFromEnv stays refuse unless explicitly enabled on macOS', () => {
  const previous = process.env.STACKEY_WEBSITE_RUNNER;
  const linux = process.env.STACKEY_WEBSITE_RUNNER_ALLOW_LINUX;
  try {
    delete process.env.STACKEY_WEBSITE_RUNNER;
    delete process.env.STACKEY_WEBSITE_RUNNER_ALLOW_LINUX;
    assert.equal(websiteRunnerFromEnv(), refuseWebsiteLogin);
    process.env.STACKEY_WEBSITE_RUNNER = '1';
    if (process.platform !== 'darwin') assert.equal(websiteRunnerFromEnv(), refuseWebsiteLogin);
  } finally {
    if (previous === undefined) delete process.env.STACKEY_WEBSITE_RUNNER;
    else process.env.STACKEY_WEBSITE_RUNNER = previous;
    if (linux === undefined) delete process.env.STACKEY_WEBSITE_RUNNER_ALLOW_LINUX;
    else process.env.STACKEY_WEBSITE_RUNNER_ALLOW_LINUX = linux;
  }
});

test('Playwright runner refuses DNS rebinding and unknown origins before fill', async () => {
  const rebound = createPlaywrightExecutor({ lookup: async () => ['127.0.0.1'] });
  await assert.rejects(rebound({ origin: 'https://github.com', username: USER, password: 'x' }), denied('origin_not_allowed'));
  await assert.rejects(createPlaywrightExecutor()({ origin: 'https://evil.example.test', username: USER, password: 'x' }), denied('origin_not_allowed'));
});

test('fixture login fills through the runner, stores a jar, and never returns the password', { timeout: 60_000 }, async () => {
  const secret = 'fixture-website-password-DO-NOT-LEAK';
  const outcome = await executeWebsiteLogin(connection(), secret, {}, () => {}, runner('/login'));
  assert.equal(outcome.result.outcome, 'authenticated');
  assert.equal(outcome.result.origin, FIXTURE_ORIGIN);
  assert.ok(outcome.jar);
  const cookies = JSON.parse(outcome.jar!) as { name: string; value: string }[];
  assert.equal(cookies.some(cookie => cookie.name === 'session' && cookie.value === 'ok'), true);
  assert.equal(JSON.stringify(outcome.result).includes(secret), false);
  assert.equal(JSON.stringify(outcome.result).includes('cookie'), false);
});

test('redirect off origin refuses without authenticating and writes a refused audit row', { timeout: 60_000 }, async t => {
  const f = await runtime(t, '/login-redirect');
  await vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
  const id = randomUUID();
  await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
  await drainProviderOperations(f.node.nodeId);
  await assert.rejects(operation(f.agent, id), denied('origin_not_allowed'));
  const row = f.store.db.prepare('SELECT state, result_json FROM provider_operations WHERE operation_id=?').get(id);
  assert.equal(row!.state, 'failed');
  assert.deepEqual(JSON.parse(String(row!.result_json)), { error: { code: 'origin_not_allowed' } });
  const audit = f.store.db.prepare('SELECT result, origin FROM audit_log').all();
  assert.deepEqual(audit.map(entry => entry.result), ['refused']);
  assertSecretAbsent(f.secret, audit, row, f.store.db.prepare('SELECT * FROM website_sessions').all());
});

test('2FA page pauses as human_required and does not bypass the challenge', { timeout: 60_000 }, async t => {
  const f = await runtime(t, '/login-mfa');
  await vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
  const id = randomUUID();
  await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
  await drainProviderOperations(f.node.nodeId);
  const waiting = await operation(f.agent, id);
  assert.equal(waiting.status, 'ok');
  assert.deepEqual((waiting.data as { result: unknown }).result, {
    source: 'website_login', origin: FIXTURE_ORIGIN, outcome: 'human_required', reason: 'email_otp',
  });
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM website_sessions').get()!.n, 0);
  assert.equal(f.store.db.prepare("SELECT result FROM audit_log").get()!.result, 'human_required');
});

test('canary password echoed by the fixture never reaches the agent, DB, logs, or audit', { timeout: 60_000 }, async t => {
  const canary = `CANARY-pw-${randomUUID()}`;
  const f = await runtime(t, '/login-echo', canary);
  await vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
  const id = randomUUID();
  await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
  await drainProviderOperations(f.node.nodeId);
  const result = await operation(f.agent, id);
  assert.equal(result.status, 'result_unknown');
  assert.deepEqual((result.data as { result: { error: { code: string } } }).result.error, { code: 'executor_failed' });
  const files = walkFiles(f.root).map(path => readFileSync(path));
  const audit = f.store.db.prepare('SELECT * FROM audit_log').all();
  assertSecretAbsent(canary, result, audit, files);
});
