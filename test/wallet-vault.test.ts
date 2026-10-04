import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { loadIdentity } from '../src/identity.js';
import { initializeVault } from '../src/vault.js';
import { unlockVault } from '../src/vault-session.js';
import { vaultRequest } from '../src/vault-client.js';
import { startWallet } from '../src/wallet.js';
import { connect } from '../src/client.js';
import { runOrders } from '../src/agent-client.js';
import { Store } from '../src/store.js';
import { ACTION } from '../src/orders.js';

async function fixture(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), 'stackey-wallet-vault-'));
  const vaultDir = join(root, 'vault'), nodeDir = join(root, 'node'), recovery = join(root, 'recovery.json');
  await initializeVault(vaultDir, recovery); await loadIdentity(nodeDir, 'node', true);
  const store = new Store(nodeDir);
  const vault = await unlockVault(vaultDir, recovery, nodeDir, 3600);
  await vaultRequest(vaultDir, 'node.bind', { _node_dir: resolve(nodeDir) });
  await vaultRequest(vaultDir, 'demo.init', { _node_dir: resolve(nodeDir) });
  await vaultRequest(vaultDir, 'connection.add', { wallet_id: 'wallet_demo', name: 'Demo', provider: 'demo', config: {} });
  const credential = await vaultRequest(vaultDir, 'credential.import', { wallet_id: 'wallet_demo', name: '<img src=x> demo@example.test', kind: 'password', value: 'fixture-secret-DO-NOT-LEAK' });
  const wallet = await startWallet(nodeDir, { vaultDir }, 0, 0);
  const headers = { authorization: 'Bearer ' + new URL(wallet.launchUrl).hash.slice(1), origin: wallet.endpoint, 'content-type': 'application/json' };
  const api = async (path: string, data?: unknown, overrides = {}) => {
    const response = await fetch(wallet.endpoint + path, { method: data === undefined ? 'GET' : 'POST', headers: { ...headers, ...overrides }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
    return { status: response.status, headers: response.headers, body: await response.json() as any };
  };
  t.after(async () => { await wallet.close(); await vault.close(); store.close(); rmSync(root, { recursive: true }); });
  return { root, vaultDir, nodeDir, vault, store, credential, wallet, api };
}

test('owner inventory withholds secrets; reveal requires authenticated same-origin explicit action and stays off agent listener', async t => {
  const f = await fixture(t);
  const inventory = await f.api('/api/credentials');
  assert.equal(inventory.status, 200); assert.equal(inventory.body.data.credentials[0].wallet_name, 'Demo Wallet');
  assert.equal(inventory.body.data.credentials[0].value, undefined);
  assert.ok(!JSON.stringify(inventory.body).includes('fixture-secret'));
  assert.ok(!JSON.stringify((await f.api('/api/state')).body).includes('fixture-secret'));
  assert.ok(!readFileSync(join(f.vaultDir, 'vault.json'), 'utf8').includes('fixture-secret'));
  const data = { credential_id: f.credential.id, confirmed: true };
  for (const overrides of [{ authorization: '' }, { authorization: 'Bearer wrong' }, { origin: 'https://evil.example' }, { 'sec-fetch-site': 'cross-site' }]) {
    const response = await f.api('/api/credentials/reveal', data, overrides);
    assert.ok([401, 403].includes(response.status)); assert.ok(!JSON.stringify(response.body).includes('fixture-secret'));
  }
  assert.equal((await f.api('/api/credentials/reveal', { ...data, confirmed: false })).status, 400);
  assert.equal((await f.api('/api/credentials/reveal')).status, 404);
  assert.notEqual((await f.api('/api/credentials/reveal', { ...data, credential_id: 'missing' })).status, 200);
  const reveal = await f.api('/api/credentials/reveal', data);
  assert.equal(reveal.status, 200); assert.equal(reveal.body.data.value, 'fixture-secret-DO-NOT-LEAK');
  assert.equal(reveal.headers.get('cache-control'), 'no-store');
  for (const path of ['/api/credentials', '/api/credentials/reveal', '/owner']) {
    const response = await fetch(f.wallet.nodeEndpoint + path, { method: 'POST', body: JSON.stringify(data) });
    assert.equal(response.status, 404); assert.ok(!(await response.text()).includes('fixture-secret'));
  }
  await assert.rejects(vaultRequest(f.vaultDir, 'credential.reveal', { ...data, vault_id: 'another-vault' }));
  await f.vault.close();
  assert.notEqual((await f.api('/api/credentials/reveal', data)).status, 200);
  assert.notEqual((await f.api('/api/credentials')).status, 200);
});

test('displayed agent permissions track verified grants, revocation, tampering and vault locking', async t => {
  const f = await fixture(t);
  const invite = await f.api('/api/invitations', {});
  const agentDir = join(f.root, 'agent');
  const pairing = (await connect(invite.body.data.invitation, agentDir, 'Demo operator')).data as any;
  let state = (await f.api('/api/state')).body.data;
  assert.equal(state.vault_status, 'unlocked'); assert.deepEqual(state.pairings[0].actions, []);
  const grant = await f.api('/api/approve', { ...pairing, action: ACTION, ttl: 300, confirmed: true });
  assert.equal(grant.status, 200);
  state = (await f.api('/api/state')).body.data;
  assert.deepEqual(state.pairings[0].actions, [ACTION]); assert.equal(state.pairings[0].credential_access, false);
  assert.equal(state.pairings[0].delegation_allowed, false);
  assert.equal((await runOrders(agentDir, ACTION, { from: '2026-09-26', to: '2026-10-02' })).status, 'ok');
  const original = f.store.db.prepare('SELECT signed_grant FROM grants WHERE grant_id = ?').get(grant.body.data.grant_id)!.signed_grant;
  f.store.db.prepare('UPDATE grants SET signed_grant = ? WHERE grant_id = ?').run('invalid', grant.body.data.grant_id);
  state = (await f.api('/api/state')).body.data;
  assert.equal(state.pairings[0].status, 'invalid'); assert.deepEqual(state.pairings[0].actions, []);
  f.store.db.prepare('UPDATE grants SET signed_grant = ? WHERE grant_id = ?').run(original!, grant.body.data.grant_id);
  assert.equal((await f.api('/api/revoke', { grant_id: grant.body.data.grant_id, confirmed: true })).status, 200);
  state = (await f.api('/api/state')).body.data;
  assert.equal(state.pairings[0].status, 'revoked'); assert.deepEqual(state.pairings[0].actions, []);
  const nextInvite = await f.api('/api/invitations', {});
  const nextPairing = (await connect(nextInvite.body.data.invitation, join(f.root, 'agent2'), 'Second operator')).data as any;
  await f.api('/api/approve', { ...nextPairing, action: ACTION, ttl: 300, confirmed: true });
  await f.vault.close();
  state = (await f.api('/api/state')).body.data;
  assert.equal(state.vault_status, 'locked');
  assert.ok(state.pairings.every((p: any) => p.actions.length === 0));
  assert.ok(state.pairings.some((p: any) => p.status === 'locked'));
});

test('wallet shows an existing provider grant without inventing demo-order access or exporting its credential', async t => {
  const f = await fixture(t);
  const credential = await vaultRequest(f.vaultDir, 'credential.import', { wallet_id: 'wallet_demo', name: 'Stripe fixture', kind: 'api_key', value: 'sk_test_fake_wallet_fixture' });
  const connection = await vaultRequest(f.vaultDir, 'connection.add', { wallet_id: 'wallet_demo', name: 'Test payments', provider: 'stripe', config: { mode: 'payments', credential_id: credential.id } });
  const invitation = (await f.api('/api/invitations', {})).body.data.invitation;
  const pair = await connect(invitation, join(f.root, 'provider-agent'), 'Provider Agent');
  const pairing = pair.data as { pairing_id: string; principal: string };
  await vaultRequest(f.vaultDir, 'grant.approve', { _node_dir: resolve(f.nodeDir), pairing_id: pairing.pairing_id, principal: pairing.principal, action: 'stripe.payments.read', ttl: 300, wallet_id: 'wallet_demo', connection_id: connection.id, max_calls: 1, max_amount_minor: 0 });
  const state = (await f.api('/api/state')).body.data;
  const agent = state.pairings.find((p: any) => p.pairing_id === pairing.pairing_id);
  assert.equal(agent.status, 'active');
  assert.deepEqual(agent.actions, ['stripe.payments.read']);
  assert.equal(agent.resource, `connection:${connection.id}/stripe.payments.read`);
  assert.equal(agent.credential_access, false);
  assert.ok(!JSON.stringify(state).includes('sk_test_fake_wallet_fixture'));
});

test('credential inventory paginates across wallets and rejects foreign cursors', async t => {
  const f = await fixture(t);
  const other = await vaultRequest(f.vaultDir, 'wallet.create', { name: 'Second wallet' });
  for (let n = 0; n < 100; n++) await vaultRequest(f.vaultDir, 'credential.import', { wallet_id: other.id, name: 'Key ' + n, kind: 'api_key', value: 'fixture-key' });
  const first = (await f.api('/api/credentials')).body.data;
  assert.equal(first.total, 101); assert.equal(first.credentials.length, 100);
  const second = (await f.api('/api/credentials?after=' + first.next_cursor)).body.data;
  assert.equal(second.credentials.length, 1); assert.equal(second.credentials[0].wallet_name, 'Second wallet');
  assert.equal(second.next_cursor, null);
  assert.equal((await f.api('/api/credentials?after=missing')).status, 400);
});
