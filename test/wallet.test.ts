import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { connect } from '../src/client.js';
import { liveStatus, runOrders } from '../src/agent-client.js';
import { AppError } from '../src/contracts.js';
import { loadIdentity } from '../src/identity.js';
import { ACTION, initializeDemo } from '../src/orders.js';
import { initializeOwner } from '../src/policy.js';
import { Store } from '../src/store.js';
import { startWallet } from '../src/wallet.js';

async function fixture(t: TestContext, seed = true) {
  const root = mkdtempSync(join(tmpdir(), 'stackey-wallet-test-'));
  const dir = join(root, 'node'); const ownerDir = join(root, 'owner');
  const identity = await loadIdentity(dir, 'node', true);
  const owner = await loadIdentity(ownerDir, 'owner', true);
  const store = new Store(dir);
  await initializeOwner(store, owner);
  if (seed) initializeDemo(store);
  let now = Math.floor(Date.now() / 1000);
  const wallet = await startWallet(dir, ownerDir, 0, 0, () => now);
  const token = new URL(wallet.launchUrl).hash.slice(1);
  const api = async (path: string, data?: unknown, headers: Record<string, string> = {}) => {
    const response = await fetch(wallet.endpoint + path, { method: data === undefined ? 'GET' : 'POST',
      headers: { authorization: 'Bearer ' + token, origin: wallet.endpoint, 'content-type': 'application/json', ...headers },
      ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
    return { status: response.status, body: await response.json() as any };
  };
  const pair = async (name = 'Test Agent') => {
    const invite = await api('/api/invitations', {});
    const agentDir = join(root, 'agent-' + store.listPairings().pairings.length);
    const result = await connect(invite.body.data.invitation, agentDir, name);
    return { agentDir, pairing: result.data as { pairing_id: string; principal: string } };
  };
  t.after(async () => { await wallet.close(); store.close(); rmSync(root, { recursive: true }); });
  return { dir, ownerDir, root, identity, owner, store, wallet, token, api, pair, advance: (seconds: number) => { now += seconds; } };
}

test('wallet invitation, independent agent acceptance, explicit approval, read and revoke persist through restart', async t => {
  const f = await fixture(t);
  const { agentDir, pairing } = await f.pair('<img src=x onerror=alert(1)>');
  const pending = await f.api('/api/state');
  assert.equal(pending.body.data.pairings[0].status, 'approval_required');
  assert.equal(pending.body.data.pending_count, 1);
  assert.equal(pending.body.data.pairings[0].display_name, '<img src=x onerror=alert(1)>');
  assert.equal((await liveStatus(agentDir)).status, 'approval_required');
  const grant = await f.api('/api/approve', { ...pairing, action: ACTION, ttl: 300, confirmed: true });
  assert.equal(grant.status, 200);
  assert.equal((await f.api('/api/state')).body.data.pending_count, 0);
  assert.equal((await liveStatus(agentDir)).status, 'active');
  const orders = await runOrders(agentDir, ACTION, { from: '2026-09-26', to: '2026-10-02' });
  assert.equal((orders.data as any).result.rows.length, 21);
  assert.equal((await f.api('/api/state')).body.data.pairings[0].status, 'active');
  assert.equal((await f.api('/api/revoke', { grant_id: grant.body.data.grant_id, confirmed: true })).status, 200);
  assert.equal((await liveStatus(agentDir)).status, 'grant_revoked');
  await assert.rejects(runOrders(agentDir, ACTION, { from: '2026-09-26', to: '2026-10-02' }), error => error instanceof AppError && error.exitCode === 3);
  assert.equal((await f.api('/api/state')).body.data.pairings[0].status, 'revoked');
  await f.wallet.close();
  const next = await startWallet(f.dir, f.ownerDir, 0, Number(new URL(f.wallet.nodeEndpoint).port));
  t.after(() => next.close());
  const oldToken = await fetch(next.endpoint + '/api/state', { headers: { authorization: 'Bearer ' + f.token } });
  assert.equal(oldToken.status, 401); await oldToken.arrayBuffer();
  assert.equal((await liveStatus(agentDir)).status, 'grant_revoked');
});

test('management requires launch capability, exact host and same-origin browser requests', async t => {
  const f = await fixture(t);
  for (const headers of [
    { authorization: '' }, { authorization: 'Bearer invalid' },
    { origin: 'https://attacker.example' }, { origin: 'null' },
    { 'sec-fetch-site': 'cross-site' }, { 'sec-fetch-site': 'same-site' },
  ]) {
    const result = await f.api('/api/invitations', {}, headers);
    assert.ok([401, 403].includes(result.status), JSON.stringify({ headers, status: result.status }));
  }
  // Native fetch normalizes Host; use an actual raw HTTP request for rebinding.
  const wrongHost = await new Promise<number>((resolve, reject) => {
    const request = httpRequest(f.wallet.endpoint + '/api/invitations', { method: 'POST', headers: {
      host: 'attacker.example', authorization: 'Bearer ' + f.token,
      origin: f.wallet.endpoint, 'content-type': 'application/json',
    } }, response => { response.resume(); response.on('end', () => resolve(response.statusCode!)); });
    request.on('error', reject); request.end('{}');
  });
  assert.equal(wrongHost, 403);
  const noOrigin = await fetch(f.wallet.endpoint + '/api/invitations', { method: 'POST',
    headers: { authorization: 'Bearer ' + f.token, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(noOrigin.status, 403); await noOrigin.arrayBuffer();
  const preflight = await fetch(f.wallet.endpoint + '/api/invitations', { method: 'OPTIONS', headers: { origin: 'https://attacker.example' } });
  assert.equal(preflight.status, 403); assert.equal(preflight.headers.get('access-control-allow-origin'), null); await preflight.arrayBuffer();
  assert.equal(f.store.db.prepare('SELECT count(*) AS n FROM invitations').get()!.n, 0);
  assert.equal((await f.api('/api/invitations', {})).status, 200);
  for (const path of ['/api/state', '/api/invitations', '/api/approve', '/api/revoke']) {
    const response = await fetch(f.wallet.nodeEndpoint + path, { method: 'POST' });
    assert.equal(response.status, 404); await response.arrayBuffer();
  }
});

test('confirmation, principal, action and TTL cannot be bypassed; no automatic grants', async t => {
  const f = await fixture(t);
  const { pairing } = await f.pair();
  const valid = { ...pairing, action: ACTION, ttl: 300, confirmed: true };
  for (const change of [{ confirmed: false }, { principal: 'other-agent' }, { action: 'payments.send' }, { ttl: 901 }, { ttl: 0 }, { pairing_id: 'missing' }]) {
    assert.notEqual((await f.api('/api/approve', { ...valid, ...change })).status, 200);
  }
  assert.equal(f.store.db.prepare('SELECT count(*) AS n FROM grants').get()!.n, 0);
  const granted = await f.api('/api/approve', valid);
  assert.equal(granted.status, 200);
  assert.notEqual((await f.api('/api/approve', valid)).status, 200);
  assert.notEqual((await f.api('/api/revoke', { grant_id: granted.body.data.grant_id, confirmed: false })).status, 200);
  f.advance(301);
  assert.equal((await f.api('/api/state')).body.data.pairings[0].status, 'expired');
});

test('uninitialized resource remains visible but cannot be granted', async t => {
  const f = await fixture(t, false);
  const { pairing } = await f.pair();
  assert.equal((await f.api('/api/state')).body.data.demo_ready, false);
  assert.equal((await f.api('/api/approve', { ...pairing, action: ACTION, ttl: 300, confirmed: true })).body.error.code, 'connection_unavailable');
});

test('management session expires, including requests stalled during body upload', async t => {
  const f = await fixture(t);
  const result = new Promise<number>((resolve, reject) => {
    const request = httpRequest(f.wallet.endpoint + '/api/invitations', { method: 'POST', headers: {
      authorization: 'Bearer ' + f.token, origin: f.wallet.endpoint, 'content-type': 'application/json', 'content-length': 2,
    } }, response => { response.resume(); response.on('end', () => resolve(response.statusCode!)); });
    request.on('error', reject); request.write('{');
    setTimeout(() => { f.advance(3601); request.end('}'); }, 30);
  });
  assert.equal(await result, 401);
  assert.equal((await f.api('/api/state')).status, 401);
  assert.equal(f.store.db.prepare('SELECT count(*) AS n FROM invitations').get()!.n, 0);
});

test('static assets are inert without authentication and never contain keys or launch capability', async t => {
  const f = await fixture(t);
  for (const path of ['/', '/wallet.js', '/wallet.css', '/api/state']) {
    const response = await fetch(f.wallet.endpoint + path);
    const text = await response.text();
    assert.equal(response.status, path === '/api/state' ? 401 : 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
    assert.match(response.headers.get('content-security-policy')!, /frame-ancestors 'none'/);
    for (const secret of [f.token, f.owner.privateJwk.d!, f.identity.privateJwk.d!]) assert.ok(!text.includes(secret));
  }
  const state = JSON.stringify((await f.api('/api/state')).body);
  assert.ok(!state.includes('privateJwk')); assert.ok(!state.includes('signed_grant'));
  assert.equal((await f.api('/identity.json')).status, 404);
});

test('management rejects malformed, oversized bodies and bounds invitation issuance', async t => {
  const f = await fixture(t);
  const malformed = await fetch(f.wallet.endpoint + '/api/invitations', { method: 'POST', headers: {
    authorization: 'Bearer ' + f.token, origin: f.wallet.endpoint, 'content-type': 'application/json' }, body: '{bad' });
  assert.equal(malformed.status, 400); await malformed.arrayBuffer();
  assert.equal((await f.api('/api/invitations', {}, { 'content-type': 'text/plain' })).status, 415);
  assert.equal((await f.api('/api/invitations', { padding: 'a'.repeat(17000) })).status, 413);
  assert.equal((await f.api('/api/invitations', [])).status, 400);
  for (let n = 0; n < 30; n++) await f.api('/api/invitations', {});
  assert.equal((await f.api('/api/invitations', {})).status, 429);
});

test('pairing pagination retains the 201st entry and its effective grant state', async t => {
  const f = await fixture(t);
  const { pairing } = await f.pair();
  const original = f.store.db.prepare('SELECT * FROM pairings WHERE pairing_id = ?').get(pairing.pairing_id)!;
  for (let index = 0; index < 200; index++) {
    const id = 'page-' + index;
    f.store.addInvite(id, id, 9999999999);
    f.store.db.prepare('INSERT INTO pairings VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, original.principal!, original.public_jwk!, id, original.created_at!, 'approval_required', id, id);
  }
  const first = await f.api('/api/state');
  assert.equal(first.body.data.pairings.length, 200);
  assert.equal(first.body.data.pending_count, 201);
  const second = await f.api('/api/state?after=' + first.body.data.next_cursor);
  assert.equal(second.body.data.pairings.length, 1);
  assert.equal(second.body.data.next_cursor, null);
  assert.equal(new Set([...first.body.data.pairings, ...second.body.data.pairings].map(row => row.pairing_id)).size, 201);
  assert.equal((await f.api('/api/state?after=missing')).status, 400);
});

test('wallet CLI starts both listeners and closes them on SIGTERM', async t => {
  const f = await fixture(t);
  await f.wallet.close();
  const child = spawn(process.execPath, [resolve('dist/src/cli.js'), 'wallet', 'start', '--data-dir', f.dir, '--owner-dir', f.ownerDir, '--port', '0', '--node-port', '0']);
  const exited = once(child, 'exit');
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); await exited; });
  const started = await new Promise<any>((resolve, reject) => {
    let buffer = ''; let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk; });
    const timeout = setTimeout(() => reject(new Error('Wallet startup timeout: ' + stderr)), 5000);
    child.once('exit', () => { clearTimeout(timeout); reject(new Error('Wallet exited: ' + stderr)); });
    child.stdout.on('data', chunk => { buffer += chunk; if (buffer.includes('\n')) { clearTimeout(timeout); resolve(JSON.parse(buffer.split('\n')[0]!)); } });
  });
  assert.equal(started.status, 'ok');
  const page = await fetch(started.data.wallet_url); assert.equal(page.status, 200); await page.arrayBuffer();
  child.kill('SIGTERM'); assert.equal((await exited)[0], 0);
  await assert.rejects(fetch(new URL(started.data.wallet_url).origin));
  await assert.rejects(fetch(started.data.endpoint));
});
