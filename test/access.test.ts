import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { test, type TestContext } from 'node:test';
import { decodeJwt, importJWK, SignJWT } from 'jose';
import { agentAction } from '../src/access.js';
import { agentContext, bootstrapProof, challenge, liveStatus, operation,
  resourceRequest, runOrders, session, verifiedResponse, type AgentContext } from '../src/agent-client.js';
import { connect } from '../src/client.js';
import { AppError, digest } from '../src/contracts.js';
import { createIdentity, loadIdentity } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { ACTION, initializeDemo, readOrders } from '../src/orders.js';
import { issueInvitation } from '../src/pairing.js';
import { approvePairing, grantForPairing, initializeOwner, revokeGrant } from '../src/policy.js';
import { Store } from '../src/store.js';

const cli = resolve('dist/src/cli.js');
function local(...args: string[]) {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  assert.equal(result.error, undefined);
  return { code: result.status, stdout: result.stdout, body: JSON.parse(result.stdout) as any };
}
async function remote(...args: string[]) {
  const process = spawn(globalThis.process.execPath, [cli, ...args]);
  let stdout = ''; let stderr = '';
  process.stdout.on('data', chunk => { stdout += chunk; });
  process.stderr.on('data', chunk => { stderr += chunk; });
  const [code] = await once(process, 'exit');
  assert.ok(stdout.trim(), stderr);
  return { code, stdout, body: JSON.parse(stdout) as any };
}
async function fixture(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), 'stackey-access-test-'));
  const nodeDir = join(root, 'node'); const ownerDir = join(root, 'owner');
  const identity = await loadIdentity(nodeDir, 'node', true);
  const owner = await loadIdentity(ownerDir, 'owner', true);
  const store = new Store(nodeDir);
  await initializeOwner(store, owner); initializeDemo(store);
  const node = await startNode(nodeDir, 0);
  t.after(async () => { await node.close(); store.close(); rmSync(root, { recursive: true }); });
  const pair = async (name: string) => {
    const dir = join(root, name);
    await connect(await issueInvitation(store, identity, 300), dir, name);
    const context = await agentContext(dir);
    return { dir, context };
  };
  const first = await pair('agent1');
  const approve = (context = first.context, ttl = 900) => approvePairing(store, identity, owner,
    context.pairingId, context.identity.id, ACTION, ttl);
  return { root, nodeDir, ownerDir, identity, owner, store, node, pair, approve, ...first };
}

const denied = (code?: string) => (error: unknown) => error instanceof AppError && error.exitCode === 3 && (!code || error.code === code);
async function proof(context: AgentContext, nonce: string, token: string, method: string, path: string, body = '', extra: object = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ nonce, jti: randomUUID(), iat: now, exp: now + 30,
    htm: method, htu: context.origin + path, ath: digest(token), stackey_body_hash: digest(body), ...extra })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: context.identity.publicJwk })
    .sign(await importJWK(context.identity.privateJwk, 'ES256'));
}
async function request(context: AgentContext, token: string, signed: string, path = '/v1/capabilities', method = 'GET', body?: string) {
  const response = await fetch(context.origin + path, { method,
    headers: { authorization: 'DPoP ' + token, dpop: signed, 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body }) });
  return verifiedResponse(context, response, digest(signed));
}

// Actual owner commands and actual agent subprocesses; no provider credentials or accounts.
test('owner CLI approval, agent CLI read, live status, durable operation and revocation form a complete local workflow', async t => {
  const f = await fixture(t);
  assert.equal((await liveStatus(f.dir)).status, 'approval_required');
  const before = await remote('run', ACTION, '--from', '2026-09-26', '--to', '2026-10-02', '--state-dir', f.dir);
  assert.equal(before.code, 3);
  const approved = local('node', 'approve', f.context.pairingId, '--principal', f.context.identity.id,
    '--action', ACTION, '--data-dir', f.nodeDir, '--owner-dir', f.ownerDir);
  assert.equal(approved.code, 0);
  const grantId = approved.body.data.grant_id;
  assert.equal((await liveStatus(f.dir)).status, 'active');
  const caps = await remote('capabilities', '--state-dir', f.dir);
  assert.equal(caps.code, 0);
  assert.equal(caps.body.data.capabilities[0].action, ACTION);
  const result = await remote('run', ACTION, '--from', '2026-09-26', '--to', '2026-10-02', '--state-dir', f.dir);
  assert.equal(result.code, 0);
  const data = result.body.data.result;
  assert.equal(data.source, 'local_synthetic');
  assert.equal(data.rows.length, 21); assert.equal(data.complete, true);
  assert.equal(data.next_cursor, null); assert.equal(data.timezone, 'UTC'); assert.equal(data.amount_unit, 'minor');
  const sum = (currency: string) => data.rows.filter((row: any) => row.currency === currency && row.payment_status === 'paid')
    .reduce((total: number, row: any) => total + row.amount_minor, 0);
  assert.equal(sum('USD'), 9100); assert.equal(sum('TWD'), 231000);
  assert.equal(data.rows.filter((row: any) => row.payment_status === 'payment_failed').length, 7);
  const resumed = await remote('operation', result.body.data.operation_id, '--state-dir', f.dir);
  assert.equal(resumed.code, 0); assert.deepEqual(resumed.body.data.result, data);
  const events = local('node', 'events', '--data-dir', f.nodeDir);
  assert.deepEqual(events.body.data.events.map((row: any) => row.kind), ['grant_approved', 'operation_completed']);
  const listed = local('node', 'grants', '--data-dir', f.nodeDir);
  assert.equal(listed.body.data.grants[0].status, 'active');
  const existingToken = await session(f.context);
  assert.equal(local('node', 'revoke', grantId, '--owner-dir', f.ownerDir, '--data-dir', f.nodeDir).code, 0);
  assert.equal((await liveStatus(f.dir)).status, 'grant_revoked');
  await assert.rejects(resourceRequest(f.context, existingToken, 'GET', '/v1/capabilities'), denied('grant_revoked'));
  const after = await remote('run', ACTION, '--from', '2026-09-26', '--to', '2026-10-02', '--state-dir', f.dir);
  assert.equal(after.code, 3); assert.equal(after.body.status, 'grant_revoked');
  const eventsAfter = local('node', 'events', '--data-dir', f.nodeDir);
  assert.equal(eventsAfter.body.data.events.at(-1).kind, 'grant_revoked');
  for (const output of [approved.stdout, caps.stdout, result.stdout, resumed.stdout, events.stdout, listed.stdout]) {
    assert.ok(!output.includes(f.owner.privateJwk.d!));
    assert.ok(!output.includes(f.identity.privateJwk.d!));
    assert.ok(!output.includes(f.context.identity.privateJwk.d!));
    assert.ok(!output.includes('access_token')); assert.ok(!output.includes('signed_grant'));
  }
});

test('approval requires the pinned owner and full matching fingerprint and never accepts another action', async t => {
  const f = await fixture(t);
  const another = await createIdentity('EdDSA');
  await assert.rejects(approvePairing(f.store, f.identity, another, f.context.pairingId, f.context.identity.id, ACTION, 900), denied('owner_mismatch'));
  await assert.rejects(approvePairing(f.store, f.identity, f.owner, f.context.pairingId, 'wrong-fingerprint', ACTION, 900), denied('principal_mismatch'));
  await assert.rejects(approvePairing(f.store, f.identity, f.owner, f.context.pairingId, f.context.identity.id, 'supabase.orders.delete', 900), denied('action_not_available'));
  await assert.rejects(f.approve(f.context, 901));
  assert.equal(grantForPairing(f.store, f.context.pairingId), undefined);
  await assert.rejects(initializeOwner(f.store, another), denied('owner_mismatch'));
  await f.approve();
  await assert.rejects(f.approve(), error => error instanceof AppError && error.code === 'already_approved');
  const publicManagement = await fetch(f.node.endpoint + '/admin/approve', { method: 'POST' });
  assert.equal(publicManagement.status, 404); await publicManagement.arrayBuffer();
});

test('two agent keys share one connection but cannot use each others session, pairing or operation; revocation is isolated', async t => {
  const f = await fixture(t); const second = await f.pair('agent2');
  const firstGrant = await f.approve(); await f.approve(second.context);
  const firstToken = await session(f.context);
  await assert.rejects(resourceRequest(f.context, firstToken, 'GET', '/v1/capabilities', '', second.context.identity), denied('invalid_session_proof'));
  const nonce = await challenge(second.context);
  const signed = await bootstrapProof(second.context, nonce, 'GET', '/v1/pairings/' + f.context.pairingId, '');
  const response = await fetch(f.node.endpoint + '/v1/pairings/' + f.context.pairingId, { headers: { 'x-stackey-proof': signed } });
  await assert.rejects(verifiedResponse(second.context, response, digest(signed)), denied('permission_denied'));
  const first = await runOrders(f.dir, ACTION, { from: '2026-09-26', to: '2026-10-02' });
  await assert.rejects(operation(second.dir, (first.data as any).operation_id), denied('permission_denied'));
  await revokeGrant(f.store, f.identity, f.owner, firstGrant.grant_id);
  assert.equal((await runOrders(second.dir, ACTION, { from: '2026-09-26', to: '2026-09-26' })).status, 'ok');
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS count FROM demo_orders').get()!.count, 21);
});

test('DPoP proof replay is refused durably, while a valid session survives restart with a fresh proof', async t => {
  const f = await fixture(t); await f.approve();
  const token = await session(f.context);
  const signed = await proof(f.context, await challenge(f.context), token, 'GET', '/v1/capabilities');
  assert.equal((await request(f.context, token, signed)).status, 'ok');
  await assert.rejects(request(f.context, token, signed), denied('proof_replayed'));
  const port = Number(new URL(f.node.endpoint).port);
  await f.node.close();
  const restarted = await startNode(f.nodeDir, port); t.after(() => restarted.close());
  await assert.rejects(request(f.context, token, signed), denied('proof_replayed'));
  assert.equal((await resourceRequest(f.context, token, 'GET', '/v1/capabilities')).status, 'ok');
});

test('sessions are bounded by grant expiry and bearer tokens alone never authorize a resource', async t => {
  const f = await fixture(t); const grant = await f.approve(f.context, 60);
  const token = await session(f.context);
  const claims = decodeJwt(token);
  assert.ok(claims.exp! <= grant.expires_at);
  assert.ok(claims.exp! - claims.iat! <= 60);
  const response = await fetch(f.node.endpoint + '/v1/capabilities', { headers: { authorization: 'Bearer ' + token } });
  assert.equal(response.status, 403); await response.arrayBuffer();
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS count FROM operations').get()!.count, 0);
});

test('DPoP rejects URI, method, token hash, nonce, future/stale timestamps and wrong token audience', async t => {
  const f = await fixture(t); await f.approve(); const token = await session(f.context);
  const now = Math.floor(Date.now() / 1000);
  for (const extra of [
    { htu: f.node.endpoint + '/v1/operations' }, { htm: 'POST' }, { ath: digest('another-token') },
    { nonce: 'unknown' }, { iat: now + 60, exp: now + 90 }, { iat: now - 31, exp: now + 1 },
  ]) {
    const signed = await proof(f.context, await challenge(f.context), token, 'GET', '/v1/capabilities', '', extra);
    await assert.rejects(request(f.context, token, signed), denied());
  }
  const wrongToken = await new SignJWT({ ...decodeJwt(token) as Record<string, unknown>, aud: 'other-node' })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'at+jwt' }).sign(await importJWK(f.identity.privateJwk, 'EdDSA'));
  await assert.rejects(request(f.context, wrongToken, await proof(f.context, await challenge(f.context), wrongToken, 'GET', '/v1/capabilities')), denied('invalid_session_proof'));
});

test('proof binds the exact body and the API rejects extra parameters, arbitrary actions and invalid dates', async t => {
  const f = await fixture(t); await f.approve(); const token = await session(f.context);
  const body = JSON.stringify({ operation_id: randomUUID(), action: ACTION, params: { from: '2026-09-26', to: '2026-10-02' } });
  const signed = await proof(f.context, await challenge(f.context), token, 'POST', '/v1/operations', body);
  await assert.rejects(request(f.context, token, signed, '/v1/operations', 'POST', body.replace('2026-10-02', '2026-10-01')), denied('invalid_session_proof'));
  for (const params of [
    { from: '2026-02-30', to: '2026-03-01' }, { from: '2026-10-02', to: '2026-09-26' },
    { from: '2026-01-01', to: '2026-12-31' }, { from: '2026-09-26', to: '2026-10-02', sql: 'SELECT *' },
  ]) {
    await assert.rejects(resourceRequest(f.context, token, 'POST', '/v1/operations', JSON.stringify({ operation_id: randomUUID(), action: ACTION, params })));
  }
  await assert.rejects(resourceRequest(f.context, token, 'POST', '/v1/operations', JSON.stringify({ operation_id: randomUUID(), action: 'demo.orders.delete', params: {} })), denied('action_not_allowed'));
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS count FROM operations').get()!.count, 0);
});

test('same operation ID returns its stored result; changed input conflicts and UTC bounds are inclusive', async t => {
  const f = await fixture(t); await f.approve(); const id = randomUUID();
  const params = { from: '2026-09-26', to: '2026-09-26' };
  const first = await runOrders(f.dir, ACTION, params, id);
  assert.equal((first.data as any).result.rows.length, 3);
  const again = await runOrders(f.dir, ACTION, params, id);
  assert.equal((again.data as any).replayed, true); assert.deepEqual((again.data as any).result, (first.data as any).result);
  await assert.rejects(runOrders(f.dir, ACTION, { ...params, to: '2026-09-27' }, id), error => error instanceof AppError && error.code === 'operation_conflict');
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS count FROM operations').get()!.count, 1);
  assert.equal(f.store.db.prepare("SELECT COUNT(*) AS count FROM events WHERE kind = 'operation_completed'").get()!.count, 1);
});

test('order pagination reports completeness and exposes every row including tied timestamps', async t => {
  const f = await fixture(t);
  for (let index = 0; index < 205; index++) f.store.db.prepare('INSERT INTO demo_orders VALUES (?, ?, ?, ?, ?)')
    .run(`extra-${String(index).padStart(3, '0')}`, '2026-09-26T12:00:00.000Z', 'USD', index, 'paid');
  await f.approve();
  const ids: string[] = []; let cursor: string | undefined;
  do {
    const result = await runOrders(f.dir, ACTION, { from: '2026-09-26', to: '2026-09-26', ...(cursor === undefined ? {} : { cursor }) });
    const data = (result.data as any).result;
    assert.equal(data.complete, data.next_cursor === null);
    ids.push(...data.rows.map((row: any) => row.id)); cursor = data.next_cursor ?? undefined;
  } while (cursor);
  assert.equal(ids.length, 208); assert.equal(new Set(ids).size, 208);
  assert.throws(() => readOrders(f.store, { from: '2026-09-27', to: '2026-09-27', cursor: ids[0]! }));
});

test('expired policy refuses new sessions and async verification cannot cross the acceptance time boundary', async t => {
  const f = await fixture(t); const grant = await f.approve(f.context, 60);
  const body = JSON.stringify({ pairing_id: f.context.pairingId });
  const nonce = await challenge(f.context);
  const signed = await bootstrapProof(f.context, nonce, 'POST', '/v1/sessions', body);
  let checks = 0;
  await assert.rejects(agentAction(f.store, f.identity, f.node.endpoint, {
    method: 'POST', path: '/v1/sessions', rawBody: body, proof: signed,
  }, () => ++checks === 1 ? grant.expires_at - 60 : grant.expires_at + 1), denied());
  assert.equal(f.store.db.prepare('SELECT consumed_at FROM challenges WHERE nonce = ?').get(nonce)!.consumed_at, null);
  // Move only the durable policy expiry back; a valid old signature must not make modified policy usable.
  f.store.db.prepare('UPDATE grants SET expires_at = ? WHERE grant_id = ?').run(Math.floor(Date.now() / 1000) - 1, grant.grant_id);
  await assert.rejects(session(f.context), denied('grant_expired'));
});

test('altered or incorrectly signed owner grants are refused before operations', async t => {
  const f = await fixture(t); const grant = await f.approve();
  const row = grantForPairing(f.store, f.context.pairingId)!;
  const changed = await new SignJWT({ ...decodeJwt(row.signed_grant) as Record<string, unknown>, resource: 'demo:other/orders' })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'stackey-grant+jwt' }).sign(await importJWK(f.owner.privateJwk, 'EdDSA'));
  f.store.db.prepare('UPDATE grants SET signed_grant = ? WHERE grant_id = ?').run(changed, grant.grant_id);
  await assert.rejects(session(f.context), denied('invalid_grant'));
  const stranger = await createIdentity('EdDSA');
  const wrong = await new SignJWT(decodeJwt(row.signed_grant)).setProtectedHeader({ alg: 'EdDSA', typ: 'stackey-grant+jwt' })
    .sign(await importJWK(stranger.privateJwk, 'EdDSA'));
  f.store.db.prepare('UPDATE grants SET signed_grant = ? WHERE grant_id = ?').run(wrong, grant.grant_id);
  await assert.rejects(session(f.context), denied('invalid_grant'));
});

test('schema is discoverable without state and existing pairing receipts remain readable', async t => {
  const result = local('run', ACTION, '--schema');
  assert.equal(result.code, 0); assert.equal(result.body.data.source, 'local_synthetic');
  const f = await fixture(t); await f.approve();
  const localReceipt = local('status', '--state-dir', f.dir);
  assert.equal(localReceipt.body.data.source, 'local_pairing_receipt');
  assert.equal((await remote('status', '--live', '--state-dir', f.dir)).body.status, 'active');
  assert.ok(JSON.parse(readFileSync(join(f.dir, 'pairing.json'), 'utf8')).node_public_jwk);
});

test('rate-limit receipts remain bound to challenge and resource requests and report rate_limited', async t => {
  const f = await fixture(t); await f.approve();
  const token = await session(f.context); // challenge + session = 2 agent requests
  const nonce = await challenge(f.context); // 3; keep a valid nonce for a later resource request
  for (let index = 0; index < 117; index++) await challenge(f.context); // 120 total
  const challengesBefore = f.store.db.prepare('SELECT COUNT(*) AS count FROM challenges').get()!.count;
  await assert.rejects(challenge(f.context), error => error instanceof AppError &&
    error.code === 'rate_limited' && error.status === 'rate_limited' && error.httpStatus === 429 && error.exitCode === 4);
  const signed = await proof(f.context, nonce, token, 'GET', '/v1/capabilities');
  await assert.rejects(request(f.context, token, signed), error => error instanceof AppError &&
    error.code === 'rate_limited' && error.status === 'rate_limited' && error.httpStatus === 429 && error.exitCode === 4);
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS count FROM challenges').get()!.count, challengesBefore);
  assert.equal(f.store.db.prepare('SELECT consumed_at FROM challenges WHERE nonce = ?').get(nonce)!.consumed_at, null);
});
