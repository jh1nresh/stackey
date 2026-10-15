import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { capabilities, operation, runOrders } from '../src/agent-client.js';
import { connect } from '../src/client.js';
import { AppError } from '../src/contracts.js';
import { secretForms } from '../src/redact.js';
import { loadIdentity } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { issueInvitation } from '../src/pairing.js';
import { seconds } from '../src/policy.js';
import { drainProviderOperations } from '../src/provider-operations.js';
import { Store } from '../src/store.js';
import { initializeVault, openVault, recovery } from '../src/vault.js';
import { vaultRequest } from '../src/vault-client.js';
import { unlockVault } from '../src/vault-session.js';
import {
  credentialOrigins,
  originAllowed,
  requireWebsiteSession,
  websiteSession,
  WEBSITE_SESSION_TTL_DEFAULT,
} from '../src/website-sessions.js';
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

const cli = resolve('dist/src/cli.js');
const SECRET = 'fixture-website-password-DO-NOT-LEAK';
const USER = 'owner@example.test';
const ORIGIN = 'https://dashboard.example.test';
const denied = (code?: string) => (error: unknown) => error instanceof AppError && error.exitCode === 3 && (!code || error.code === code);
const leak = (value: unknown) => JSON.stringify(value).includes(SECRET);

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
    'https://localhost.', 'https://foo.localhost.', 'https://[::1]', 'https://[::ffff:127.0.0.1]',
    'https://[0:0:0:0:0:0:0:1]', 'https://127.1', 'https://127.0.1', 'https://0x7f000001',
    'https://2130706433', 'https://Dashboard.Example.TEST', 'https://bücher.example',
    'https://evil.test/login', 'https://user:pass@evil.test', 'https://dashboard.example.test:444',
    'https://192.168.0.1', 'https://dashboard.example.test/?next=https://evil.test',
    'https://dashboard.example.test.', 'https://dashboard.example.test..', 'https://example.com..',
    'https://*.example.test', 'https://example*.test', 'https://%.example.test']) {
    assert.throws(() => websiteOrigin(origin), error => error instanceof AppError && error.code === 'invalid_origin');
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

async function runtime(t: TestContext, executor: WebsiteLoginExecutor = refuseWebsiteLogin, password = SECRET) {
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
  const imported = await vaultRequest(dir, 'credential.import', { wallet_id: 'wallet_demo', name: 'Dashboard', kind: 'website_login', value: password });
  const connected = await vaultRequest(dir, 'connection.add', { wallet_id: 'wallet_demo', name: 'Example', provider: 'website',
    config: { origin: ORIGIN, username: USER, credential_id: imported.id } });
  const agent = join(root, 'agent');
  const invitation = await issueInvitation(store, identity, 300);
  const pairing = (await connect(invitation, agent, 'Website Agent')).data as any;
  return { root, dir, node, store, agent, owner, imported, connected, pairing, identity };
}

function traces(store: Store, extra: unknown[] = []) {
  return [
    store.db.prepare('SELECT * FROM provider_operations').all(),
    store.db.prepare('SELECT * FROM events').all(),
    store.db.prepare('SELECT grant_id, pairing_id, principal, action, connection_id, max_calls, signed_grant FROM grants').all(),
    store.db.prepare('SELECT * FROM audit_log').all(),
    store.db.prepare('SELECT * FROM website_sessions').all(),
    store.db.prepare('SELECT * FROM credential_origins').all(),
    ...extra,
  ];
}

function assertAuthenticated(result: Record<string, unknown>) {
  assert.equal(result.source, 'website_login');
  assert.equal(result.origin, ORIGIN);
  assert.equal(result.outcome, 'authenticated');
  assert.equal(typeof result.session_handle, 'string');
  assert.match(String(result.session_handle), /^[A-Za-z0-9_-]{32,64}$/);
  assert.equal(typeof result.expires_at, 'number');
  assert.equal(result.cookie, undefined);
  assert.equal(Object.keys(result).sort().join(','), 'expires_at,origin,outcome,session_handle,source');
  return result as { session_handle: string; expires_at: number };
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
  const loginResult = assertAuthenticated((completed.data as any).result);
  assert.equal(received.password, true);
  const sessionRow = websiteSession(f.store, loginResult.session_handle);
  assert.ok(sessionRow);
  assert.equal(sessionRow!.revoked_at, null);
  assert.equal(sessionRow!.expires_at, loginResult.expires_at);
  assert.equal(loginResult.expires_at - seconds() <= WEBSITE_SESSION_TTL_DEFAULT, true);
  const audit = f.store.db.prepare('SELECT * FROM audit_log').all() as Record<string, unknown>[];
  assert.equal(audit.length, 1);
  assert.equal(audit[0]!.result, 'authenticated');
  assert.equal(audit[0]!.origin, ORIGIN);
  assert.equal(audit[0]!.credential_id, f.imported.id);
  assert.equal(audit[0]!.agent_id, f.pairing.principal);
  assert.equal(audit[0]!.session_handle_id, loginResult.session_handle);
  assert.equal('password' in audit[0]! || 'secret' in audit[0]! || 'value' in audit[0]!, false);
  assert.deepEqual(credentialOrigins(f.store, String(f.imported.id)), [ORIGIN]);
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
  assert.deepEqual((unknown.data as any).result.error, { code: 'executor_failed' });
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
  assert.deepEqual((sanitized.data as any).result.error, { code: 'executor_failed' });
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
  assert.deepEqual((failed.data as any).result.error, { code: 'executor_failed' });
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
  assert.deepEqual((result.data as any).result.error, { code: 'executor_failed' });
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
  const refused = f.store.db.prepare('SELECT result FROM audit_log').all();
  assert.deepEqual(refused.map(row => row.result), ['refused', 'refused']);
  assert.equal(leak(traces(f.store)), false);
});

async function approvedLogin(t: TestContext, executor: WebsiteLoginExecutor, password: string) {
  const f = await runtime(t, executor, password);
  await vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
  const id = randomUUID();
  const logs = captureProcessIo();
  try {
    await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
    await drainProviderOperations(f.node.nodeId);
    const result = await operation(f.agent, id);
    const row = f.store.db.prepare('SELECT result_json FROM provider_operations WHERE operation_id=?').get(id);
    const files = walkFiles(f.root).map(path => readFileSync(path));
    assertSecretAbsent(password, result, traces(f.store, [result]), logs.text(), row, ...files);
    return { f, id, result, row };
  } finally { logs.restore(); }
}

test('canary password from a throwing executor appears in zero DB rows, API responses, and logs', async t => {
  const canary = `CANARY-pw-${randomUUID()}`;
  const noisy: WebsiteLoginExecutor = async () => { throw new AppError('login_failed', `could not type ${canary}`, 400, 2, 'failed'); };
  const ran = await approvedLogin(t, noisy, canary);
  assert.equal(ran.result.status, 'result_unknown');
  assert.deepEqual((ran.result.data as any).result.error, { code: 'executor_failed' });
  assert.equal(JSON.parse(String(ran.row!.result_json)).error.message, undefined);
});

test('canary password echoed by a mock site never reaches the agent, DB, or logs', async t => {
  const canary = `CANARY-pw-${randomUUID()}`;
  const echo: WebsiteLoginExecutor = async () => ({ state: 'completed', html: `<p>invalid password ${canary}</p>`, error: canary } as any);
  const ran = await approvedLogin(t, echo, canary);
  assert.equal(ran.result.status, 'ok');
  assertAuthenticated((ran.result.data as any).result);
});

test('allowlist mismatch fails closed, writes a refused audit row, and does not consume the grant', async t => {
  const f = await runtime(t, mockLogin([]));
  await vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
  assert.equal(originAllowed(f.store, String(f.imported.id), ORIGIN), true);
  f.store.db.prepare('DELETE FROM credential_origins WHERE credential_id=?').run(String(f.imported.id));
  assert.equal(originAllowed(f.store, String(f.imported.id), ORIGIN), false);
  const id = randomUUID();
  await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
  await drainProviderOperations(f.node.nodeId);
  await assert.rejects(operation(f.agent, id), denied('origin_not_allowed'));
  const row = f.store.db.prepare('SELECT state, result_json FROM provider_operations WHERE operation_id=?').get(id);
  assert.equal(row!.state, 'failed');
  assert.deepEqual(JSON.parse(String(row!.result_json)), { error: { code: 'origin_not_allowed' } });
  const audit = f.store.db.prepare('SELECT * FROM audit_log').all() as Record<string, unknown>[];
  assert.equal(audit.length, 1);
  assert.equal(audit[0]!.result, 'refused');
  assert.equal(audit[0]!.origin, ORIGIN);
  assert.equal(audit[0]!.session_handle_id, null);
  await vaultRequest(f.dir, 'credential.origin.add', { ...f.owner, credential_id: f.imported.id, origin: ORIGIN });
  const retry = randomUUID();
  await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, retry);
  await drainProviderOperations(f.node.nodeId);
  const completed = await operation(f.agent, retry);
  assert.equal(completed.status, 'ok');
  assertAuthenticated((completed.data as any).result);
  await assert.rejects(vaultRequest(f.dir, 'credential.origin.add', { ...f.owner, credential_id: f.imported.id, origin: 'https://*.example.test' }),
    error => error instanceof AppError && error.code === 'invalid_origin');
});

test('credential revoke deletes ciphertext, wipes jars, invalidates sessions and grants immediately, and writes an audit row', async t => {
  const f = await runtime(t, mockLogin([]));
  const grant = await vaultRequest(f.dir, 'grant.approve', { ...f.owner, pairing_id: f.pairing.pairing_id,
    principal: f.pairing.principal, action: WEBSITE_LOGIN_ACTION, ttl: 300, wallet_id: 'wallet_demo',
    connection_id: f.connected.id, max_calls: 1, max_amount_minor: 0 });
  const id = randomUUID();
  await runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}, id);
  await drainProviderOperations(f.node.nodeId);
  const completed = await operation(f.agent, id);
  const handle = assertAuthenticated((completed.data as any).result).session_handle;
  requireWebsiteSession(f.store, handle, seconds());
  await assert.rejects(vaultRequest(f.dir, 'credential.remove', { credential_id: f.imported.id }),
    error => error instanceof AppError && error.code === 'invalid_kind');
  const child = spawn(process.execPath, [cli, 'credential', 'revoke', String(f.imported.id), '--vault-dir', f.dir, '--data-dir', f.store.directory]);
  let stdout = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  const [code] = await once(child, 'exit');
  assert.equal(code, 0);
  const revoked = JSON.parse(stdout).data;
  assert.equal(revoked.revoked, true);
  assert.equal(revoked.ciphertext_deleted, true);
  assert.equal(revoked.revoked_sessions, 1);
  assert.equal(revoked.invalidated_grants, 1);
  const sessionRow = websiteSession(f.store, handle)!;
  assert.ok(sessionRow.revoked_at);
  assert.throws(() => requireWebsiteSession(f.store, handle, seconds()),
    error => error instanceof AppError && error.code === 'invalid_session');
  const listed = await vaultRequest(f.dir, 'credential.list', { wallet_id: 'wallet_demo' });
  assert.equal(listed.credentials.length, 0);
  const disk = await openVault(f.dir, await recovery(join(f.root, 'seed.json')));
  try {
    assert.equal(disk.data.credentials.length, 0);
    assert.equal(disk.data.session_jars.length, 0);
  } finally { disk.close(); }
  const grantRow = f.store.db.prepare('SELECT version, revoked_at FROM grants WHERE grant_id=?').get(grant.grant_id)!;
  assert.ok(grantRow.revoked_at);
  assert.ok((grantRow.version as number) >= 2);
  const audit = f.store.db.prepare("SELECT * FROM audit_log WHERE result='revoked'").get() as Record<string, unknown>;
  assert.equal(audit.credential_id, f.imported.id);
  assert.equal(audit.origin, '-');
  assert.equal('password' in audit || 'secret' in audit, false);
  await assert.rejects(runOrders(f.agent, WEBSITE_LOGIN_ACTION, {}), denied('grant_revoked'));
  const cliAudit = spawnSync(process.execPath, [cli, 'audit', '--data-dir', f.store.directory], { encoding: 'utf8' });
  assert.equal(cliAudit.status, 0);
  const body = JSON.parse(cliAudit.stdout);
  assert.equal(body.data.entries.length, 2);
  assert.deepEqual(body.data.entries.map((row: { result: string }) => row.result).sort(), ['authenticated', 'revoked']);
  assert.equal(JSON.stringify(body).includes(SECRET), false);
});


