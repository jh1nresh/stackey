import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { capabilities, operation, runOrders } from '../src/agent-client.js';
import { connect } from '../src/client.js';
import { AppError } from '../src/contracts.js';
import { loadIdentity } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { issueInvitation } from '../src/pairing.js';
import { seconds } from '../src/policy.js';
import { drainProviderOperations } from '../src/provider-operations.js';
import { Store } from '../src/store.js';
import { initializeVault } from '../src/vault.js';
import { vaultRequest } from '../src/vault-client.js';
import { unlockVault } from '../src/vault-session.js';
import {
  executeWebsiteLogin,
  refuseWebsiteLogin,
  WEBSITE_LOGIN_ACTION,
  websiteOrigin,
  websiteUsername,
  type WebsiteLoginExecutor,
  type WebsiteLoginInput,
  type WebsiteLoginOutcome,
} from '../src/website-login.js';

const SECRET = 'fixture-website-password-DO-NOT-LEAK';
const USER = 'owner@example.test';
const ORIGIN = 'https://dashboard.example.test';
const denied = (code?: string) => (error: unknown) => error instanceof AppError && error.exitCode === 3 && (!code || error.code === code);
const leak = (value: unknown) => JSON.stringify(value).includes(SECRET);

function mockLogin(calls: number[], human?: 'email_otp' | 'passkey' | 'captcha' | 'device_confirmation', received: { password: boolean } = { password: false }): WebsiteLoginExecutor {
  return async (input: WebsiteLoginInput) => {
    calls.push(1);
    received.password = input.password === SECRET && input.username === USER && input.origin === ORIGIN;
    if (human) return { state: 'human_required', reason: human };
    return { state: 'completed' };
  };
}

test('website origin and username fail closed on open redirects, local targets and control characters', () => {
  assert.equal(websiteOrigin(ORIGIN), ORIGIN);
  assert.equal(websiteUsername(USER), USER);
  for (const origin of ['http://dashboard.example.test', 'https://127.0.0.1', 'https://localhost',
    'https://localhost.', 'https://foo.localhost.',
    'https://evil.test/login', 'https://user:pass@evil.test', 'https://dashboard.example.test:444',
    'https://192.168.0.1', 'https://dashboard.example.test/?next=https://evil.test']) {
    assert.throws(() => websiteOrigin(origin));
  }
  assert.throws(() => websiteUsername(' owner@example.test'));
  assert.throws(() => websiteUsername('owner\nadmin'));
});

test('default executor refuses without networking and never returns the password', async () => {
  let fetches = 0;
  const original = globalThis.fetch;
  globalThis.fetch = (async (...args: Parameters<typeof fetch>) => { fetches++; return original(...args); }) as typeof fetch;
  try {
    await assert.rejects(refuseWebsiteLogin({ origin: ORIGIN, username: USER, password: SECRET }), denied('executor_unavailable'));
    const connection = { id: 'connection_' + randomUUID(), wallet_id: 'wallet_demo', provider: 'website' as const,
      name: 'Site', config: { origin: ORIGIN, username: USER, credential_id: 'credential_' + randomUUID() } };
    await assert.rejects(executeWebsiteLogin(connection, SECRET, {}, () => {}, refuseWebsiteLogin), denied('executor_unavailable'));
    assert.equal(fetches, 0);
  } finally { globalThis.fetch = original; }
});

test('executor output is rebuilt from a whitelist; extra cookie or password fields never reach the agent', async () => {
  const connection = { id: 'connection_' + randomUUID(), wallet_id: 'wallet_demo', provider: 'website' as const,
    name: 'Site', config: { origin: ORIGIN, username: USER, credential_id: 'credential_' + randomUUID() } };
  const leaky: WebsiteLoginExecutor = async () => ({ state: 'completed', cookie: 'sid=stolen', html: '<input value="redacted">' } as any);
  const completed = await executeWebsiteLogin(connection, SECRET, {}, () => {}, leaky);
  assert.deepEqual(completed, { state: 'completed', result: { source: 'website_login', origin: ORIGIN, outcome: 'authenticated' } });
  assert.equal(leak(completed), false);
  const extra: WebsiteLoginExecutor = async () => ({ state: 'completed', password: SECRET } as any);
  const ignored = await executeWebsiteLogin(connection, SECRET, {}, () => {}, extra);
  assert.deepEqual(ignored.result, { source: 'website_login', origin: ORIGIN, outcome: 'authenticated' });
  assert.equal(leak(ignored), false);
  const reasonLeak: WebsiteLoginExecutor = async () => ({ state: 'human_required', reason: SECRET } as any);
  await assert.rejects(executeWebsiteLogin(connection, SECRET, {}, () => {}, reasonLeak), error => error instanceof AppError && error.code === 'secret_leak_blocked' && !leak(error));
  await assert.rejects(executeWebsiteLogin(connection, SECRET, { url: ORIGIN }, () => {}, leaky), error => error instanceof AppError && error.code === 'invalid_parameters');
});

function fixtureConnection() {
  return { id: 'connection_' + randomUUID(), wallet_id: 'wallet_demo', provider: 'website' as const,
    name: 'Site', config: { origin: ORIGIN, username: USER, credential_id: 'credential_' + randomUUID() } };
}

test('executor result getters are snapshotted once; later reads and throwing getters cannot leak', async () => {
  const connection = fixtureConnection();
  let reads = 0;
  const flipping: WebsiteLoginExecutor = async () => ({
    state: 'human_required',
    get reason() { reads += 1; return reads === 1 ? 'email_otp' : SECRET; },
  }) as WebsiteLoginOutcome;
  const first = await executeWebsiteLogin(connection, SECRET, {}, () => {}, flipping);
  assert.deepEqual(first, { state: 'completed', result: { source: 'website_login', origin: ORIGIN, outcome: 'human_required', reason: 'email_otp' } });
  assert.equal(reads, 1);
  assert.equal(leak(first), false);

  const throwing: WebsiteLoginExecutor = async () => ({
    state: 'human_required',
    get reason() { throw new AppError('login_failed', `could not type ${SECRET}`, 400, 2, 'failed'); },
  }) as unknown as WebsiteLoginOutcome;
  await assert.rejects(executeWebsiteLogin(connection, SECRET, {}, () => {}, throwing),
    error => error instanceof AppError && error.code === 'executor_failed' && !leak(error) && !String(error.message).includes(SECRET));
});

test('non-Error executor throws and post-executor check failures stay distinct', async () => {
  const connection = fixtureConnection();
  const nonError: WebsiteLoginExecutor = async () => { throw SECRET; };
  await assert.rejects(executeWebsiteLogin(connection, SECRET, {}, () => {}, nonError),
    error => error instanceof AppError && error.code === 'executor_failed' && !leak(error) && !String(error.message).includes(SECRET));
  let checks = 0;
  await assert.rejects(executeWebsiteLogin(connection, SECRET, {}, () => {
    checks += 1;
    if (checks > 1) throw new AppError('grant_revoked', 'Owner revoked this grant.', 403, 3, 'grant_revoked');
  }, async () => ({ state: 'completed' })), error => error instanceof AppError && error.code === 'grant_revoked');
  assert.equal(checks, 2);
});

test('executor AppError that includes the password is replaced with executor_failed', async () => {
  const connection = { id: 'connection_' + randomUUID(), wallet_id: 'wallet_demo', provider: 'website' as const,
    name: 'Site', config: { origin: ORIGIN, username: USER, credential_id: 'credential_' + randomUUID() } };
  const noisy: WebsiteLoginExecutor = async () => { throw new AppError('login_failed', `could not type ${SECRET}`, 400, 2, 'failed'); };
  await assert.rejects(executeWebsiteLogin(connection, SECRET, {}, () => {}, noisy),
    error => error instanceof AppError && error.code === 'executor_failed' && !leak(error) && !String(error.message).includes(SECRET));
  const spoofed: WebsiteLoginExecutor = async () => {
    throw new AppError('executor_unavailable', `Website login failed for ${SECRET}`, 403, 3, 'permission_denied');
  };
  await assert.rejects(executeWebsiteLogin(connection, SECRET, {}, () => {}, spoofed),
    error => error instanceof AppError && error.code === 'executor_failed' && !leak(error) && !String(error.message).includes(SECRET));
});

async function runtime(t: TestContext, executor: WebsiteLoginExecutor = refuseWebsiteLogin) {
  const root = mkdtempSync(join(tmpdir(), 'stackey-website-'));
  const dir = join(root, 'vault'); const nodeDir = join(root, 'node'); const recovery = join(root, 'seed.json');
  await initializeVault(dir, recovery);
  const identity = await loadIdentity(nodeDir, 'node', true);
  const node = await startNode(nodeDir, 0);
  const store = new Store(nodeDir);
  const vault = await unlockVault(dir, recovery, nodeDir, 900, seconds, undefined, executor);
  t.after(async () => { await node.close(); await vault.close(); store.close(); rmSync(root, { recursive: true }); });
  const owner = { _node_dir: resolve(nodeDir) };
  await vaultRequest(dir, 'node.bind', owner);
  const imported = await vaultRequest(dir, 'credential.import', { wallet_id: 'wallet_demo', name: 'Dashboard', kind: 'website_login', value: SECRET });
  const connected = await vaultRequest(dir, 'connection.add', { wallet_id: 'wallet_demo', name: 'Example', provider: 'website',
    config: { origin: ORIGIN, username: USER, credential_id: imported.id } });
  const agent = join(root, 'agent');
  const invitation = await issueInvitation(store, identity, 300);
  const pairing = (await connect(invitation, agent, 'Website Agent')).data as any;
  return { dir, node, store, agent, owner, imported, connected, pairing, identity };
}

function traces(store: Store, extra: unknown[] = []) {
  return [
    store.db.prepare('SELECT * FROM provider_operations').all(),
    store.db.prepare('SELECT * FROM events').all(),
    store.db.prepare('SELECT grant_id, pairing_id, principal, action, connection_id, max_calls, signed_grant FROM grants').all(),
    ...extra,
  ];
}

test('without approval a paired agent cannot start a website login', async t => {
  const f = await runtime(t, mockLogin([]));
  await assert.rejects(runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}), denied('permission_denied'));
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM provider_operations').get()!.n, 0);
  assert.equal(leak(traces(f.store)), false);
});

test('approved single-use login runs in the daemon mock, then revoke and reuse are denied', async t => {
  const calls: number[] = [];
  const received = { password: false };
  const f = await runtime(t, mockLogin(calls, undefined, received));
  const listed = await vaultRequest(f.dir, 'credential.list', { wallet_id: 'wallet_demo' });
  const connections = await vaultRequest(f.dir, 'connection.list', { wallet_id: 'wallet_demo' });
  assert.equal(listed.credentials[0].kind, 'website_login');
  assert.equal(listed.credentials[0].value, undefined);
  assert.equal(connections.connections[0].config, undefined);
  assert.ok(!JSON.stringify(listed).includes(SECRET));
  assert.ok(!JSON.stringify(connections).includes(SECRET));
  assert.ok(!JSON.stringify(connections).includes(USER));

  await assert.rejects(vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 5, max_amount_minor: 0 }), error => error instanceof AppError && error.code === 'invalid_limit');

  const grant = await vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
  assert.equal(grant.max_calls, 1);
  assert.equal(grant.actions[0], WEBSITE_LOGIN_ACTION);

  const caps = await capabilities(f.agent);
  assert.equal((caps.data as any).capabilities[0].action, WEBSITE_LOGIN_ACTION);
  assert.equal((caps.data as any).max_calls, 1);
  assert.equal(leak(caps), false);

  const id = randomUUID();
  const pending = await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
  assert.equal(pending.status, 'operation_pending');
  await drainProviderOperations(f.node.nodeId);
  const completed = await operation(f.agent, id);
  assert.equal(completed.status, 'ok');
  assert.deepEqual((completed.data as any).result, { source: 'website_login', origin: ORIGIN, outcome: 'authenticated' });
  assert.equal(received.password, true);
  assert.equal(calls.length, 1);
  assert.equal(leak(completed), false);

  const replay = await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
  assert.equal((replay.data as any).replayed, true);
  assert.equal(calls.length, 1);
  await assert.rejects(runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}), denied('budget_exceeded'));
  assert.equal(calls.length, 1);

  await vaultRequest(f.dir, 'grant.revoke', { ...f.owner, grant_id: grant.grant_id });
  await assert.rejects(runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id), denied('grant_revoked'));
  assert.equal(leak(traces(f.store, [listed, connections, grant, pending, completed, replay, caps])), false);
});

test('human_required outcomes stay sanitized and a leaking executor error never reaches the agent or audit log', async t => {
  const humanCalls: number[] = [];
  const human = await runtime(t, mockLogin(humanCalls, 'email_otp'));
  await vaultRequest(human.dir, 'grant.approve', { ...human.owner, pairing_id: human.pairing.pairing_id,
    principal: human.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: human.connected.id, max_calls: 1, max_amount_minor: 0 });
  const humanId = randomUUID();
  await runOrders(human.agent, WEBSITE_LOGIN_ACTION, {}, humanId);
  await drainProviderOperations(human.node.nodeId);
  const waiting = await operation(human.agent, humanId);
  assert.deepEqual((waiting.data as any).result, { source: 'website_login', origin: ORIGIN, outcome: 'human_required', reason: 'email_otp' });
  assert.equal(leak(waiting), false);

  const noisy: WebsiteLoginExecutor = async () => { throw new Error(`typed ${SECRET} into the page`); };
  const fail = await runtime(t, noisy);
  await vaultRequest(fail.dir, 'grant.approve', { ...fail.owner, pairing_id: fail.pairing.pairing_id,
    principal: fail.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: fail.connected.id, max_calls: 1, max_amount_minor: 0 });
  const failId = randomUUID();
  await runOrders(fail.agent, WEBSITE_LOGIN_ACTION, {}, failId);
  await drainProviderOperations(fail.node.nodeId);
  const unknown = await operation(fail.agent, failId);
  assert.equal(unknown.status, 'result_unknown');
  assert.equal((unknown.data as any).result.error.code, 'executor_failed');
  assert.equal(leak(unknown), false);
  assert.equal(leak(traces(fail.store, [unknown])), false);

  const appError: WebsiteLoginExecutor = async () => { throw new AppError('login_failed', `could not type ${SECRET}`, 400, 2, 'failed'); };
  const leaky = await runtime(t, appError);
  await vaultRequest(leaky.dir, 'grant.approve', { ...leaky.owner, pairing_id: leaky.pairing.pairing_id,
    principal: leaky.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: leaky.connected.id, max_calls: 1, max_amount_minor: 0 });
  const leakId = randomUUID();
  await runOrders(leaky.agent, WEBSITE_LOGIN_ACTION, {}, leakId);
  await drainProviderOperations(leaky.node.nodeId);
  const sanitized = await operation(leaky.agent, leakId);
  assert.equal(sanitized.status, 'result_unknown');
  assert.equal((sanitized.data as any).result.error.code, 'executor_failed');
  assert.ok(!(sanitized.data as any).result.error.message.includes(SECRET));
  assert.equal(leak(sanitized), false);
  assert.equal(leak(traces(leaky.store, [sanitized])), false);
});

test('result getters cannot leak the password into results or audit rows and still consume the grant', async t => {
  let reads = 0;
  const flipping: WebsiteLoginExecutor = async () => ({
    state: 'human_required',
    get reason() { reads += 1; return reads === 1 ? 'email_otp' : SECRET; },
  }) as WebsiteLoginOutcome;
  const flip = await runtime(t, flipping);
  await vaultRequest(flip.dir, 'grant.approve', { ...flip.owner, pairing_id: flip.pairing.pairing_id,
    principal: flip.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: flip.connected.id, max_calls: 1, max_amount_minor: 0 });
  const flipId = randomUUID();
  await runOrders(flip.agent, WEBSITE_LOGIN_ACTION, {}, flipId);
  await drainProviderOperations(flip.node.nodeId);
  const flipped = await operation(flip.agent, flipId);
  assert.equal(flipped.status, 'ok');
  assert.deepEqual((flipped.data as any).result, { source: 'website_login', origin: ORIGIN, outcome: 'human_required', reason: 'email_otp' });
  assert.equal(leak(flipped), false);
  assert.equal(leak(traces(flip.store, [flipped])), false);
  await assert.rejects(runOrders(flip.agent, WEBSITE_LOGIN_ACTION, {}), denied('budget_exceeded'));

  const throwing: WebsiteLoginExecutor = async () => ({
    state: 'human_required',
    get reason() { throw new AppError('login_failed', `could not type ${SECRET}`, 400, 2, 'failed'); },
  }) as unknown as WebsiteLoginOutcome;
  const boom = await runtime(t, throwing);
  await vaultRequest(boom.dir, 'grant.approve', { ...boom.owner, pairing_id: boom.pairing.pairing_id,
    principal: boom.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: boom.connected.id, max_calls: 1, max_amount_minor: 0 });
  const boomId = randomUUID();
  await runOrders(boom.agent, WEBSITE_LOGIN_ACTION, {}, boomId);
  await drainProviderOperations(boom.node.nodeId);
  const failed = await operation(boom.agent, boomId);
  assert.equal(failed.status, 'result_unknown');
  assert.equal((failed.data as any).result.error.code, 'executor_failed');
  assert.ok(!(failed.data as any).result.error.message.includes(SECRET));
  assert.equal(leak(failed), false);
  assert.equal(leak(traces(boom.store, [failed])), false);
  await assert.rejects(runOrders(boom.agent, WEBSITE_LOGIN_ACTION, {}), denied('budget_exceeded'));
});

test('injected executor_unavailable AppError is sanitized and still consumes the single-use grant', async t => {
  const spoofed: WebsiteLoginExecutor = async () => {
    throw new AppError('executor_unavailable', `Website login failed for ${SECRET}`, 403, 3, 'permission_denied');
  };
  const f = await runtime(t, spoofed);
  await vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
  const id = randomUUID();
  await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
  await drainProviderOperations(f.node.nodeId);
  const result = await operation(f.agent, id);
  assert.equal(result.status, 'result_unknown');
  assert.equal((result.data as any).result.error.code, 'executor_failed');
  assert.ok(!(result.data as any).result.error.message.includes(SECRET));
  assert.equal(leak(result), false);
  assert.equal(leak(traces(f.store, [result])), false);
  await assert.rejects(runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}), denied('budget_exceeded'));
});

test('production default executor refuses with permission_denied and does not consume the single-use grant', async t => {
  const f = await runtime(t);
  await vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
  const id = randomUUID();
  await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
  await drainProviderOperations(f.node.nodeId);
  await assert.rejects(operation(f.agent, id), denied('executor_unavailable'));
  const again = randomUUID();
  await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, again);
  await drainProviderOperations(f.node.nodeId);
  await assert.rejects(operation(f.agent, again), denied('executor_unavailable'));
  assert.equal(leak(traces(f.store)), false);
});
