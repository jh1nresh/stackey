import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test, type TestContext } from 'node:test';
import { randomUUID } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { startWalletSetup } from '../src/wallet-setup.js';
import { initializeVault, openVault, recovery } from '../src/vault.js';

async function fixture(t: TestContext) {
  const parent = mkdtempSync(join(tmpdir(), 'stackey-setup-test-')), root = join(parent, 'new');
  let now = Math.floor(Date.now() / 1000);
  const server = await startWalletSetup(root, 0, () => now);
  t.after(async () => { await server.close(); rmSync(parent, { recursive: true }); });
  const headers = { authorization: 'Bearer ' + new URL(server.launchUrl).hash.slice(1), origin: server.endpoint, 'content-type': 'application/json' };
  const api = async (path: string, data?: unknown, overrides = {}) => {
    const response = await fetch(server.endpoint + path, { method: data === undefined ? 'GET' : 'POST', headers: { ...headers, ...overrides }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
    return { status: response.status, headers: response.headers, body: await response.json() as any };
  };
  return { parent, root, server, api, advance: (seconds: number) => { now += seconds; } };
}

test('new wallet requires explicit phrase reveal and matching backup words; inventory and assets never expose the phrase', async t => {
  const f = await fixture(t);
  assert.equal((await f.api('/api/state')).body.data.stage, 'welcome');
  assert.notEqual((await f.api('/api/create', { confirmed: false })).status, 200);
  assert.equal((await f.api('/api/create', { confirmed: true })).status, 200);
  const state = (await f.api('/api/state')).body.data;
  assert.equal(new Set(state.positions).size, 3); assert.equal(state.words, undefined);
  assert.equal((await f.api('/api/phrase', { draft_id: state.draft_id, confirmed: false })).status, 400);
  const reveal = await f.api('/api/phrase', { draft_id: state.draft_id, confirmed: true });
  assert.equal(reveal.status, 200); assert.equal(reveal.body.data.words.length, 24);
  assert.equal(reveal.headers.get('cache-control'), 'no-store');
  const words: string[] = reveal.body.data.words;
  for (const path of ['/', '/setup.js', '/setup.css', '/api/state']) {
    const response = await fetch(f.server.endpoint + path);
    assert.ok(!(await response.text()).includes(words.join(' ')));
  }
  assert.equal((await f.api('/api/confirm', { draft_id: state.draft_id, answers: ['wrong','wrong','wrong'], confirmed: true })).body.error.code, 'words_mismatch');
  const answers = state.positions.map((n: number) => words[n]);
  const responses = await Promise.all([1, 2].map(() => f.api('/api/confirm', { draft_id: state.draft_id, answers, confirmed: true })));
  assert.equal(responses.filter(r => r.status === 200).length, 1);
  assert.equal((await f.api('/api/state')).body.data.stage, 'complete');
  assert.notEqual((await f.api('/api/phrase', { draft_id: state.draft_id, confirmed: true })).status, 200);
  const backup = (await f.api('/api/backup', {})).body.data.backup;
  assert.ok(!backup.includes(words.join(' ')));
  assert.equal(statSync(join(f.root, 'wallet/recovery.json')).mode & 0o777, 0o600);
  assert.equal(statSync(join(f.root, 'wallet/vault/vault.json')).mode & 0o777, 0o600);
  assert.equal(await recovery(join(f.root, 'wallet/recovery.json')), words.join(' '));
  const opened = await f.api('/api/open', {}); assert.equal(opened.status, 200);
  const url = new URL(opened.body.data.wallet_url);
  const walletResponse = await fetch(url.origin + '/api/state', { headers: { authorization: 'Bearer ' + url.hash.slice(1) } });
  assert.equal(walletResponse.status, 200);
  assert.equal((await walletResponse.json() as any).data.pairings.length, 0);
});

test('restore requires correct mnemonic and authenticated encrypted backup, preserves originals, and copies no grants', async t => {
  const f = await fixture(t);
  const source = join(f.parent, 'original'), recoveryFile = join(f.parent, 'recovery.json');
  await initializeVault(source, recoveryFile);
  const mnemonic = await recovery(recoveryFile);
  const opened = await openVault(source, mnemonic);
  opened.data.credentials.push({ id: 'credential_' + randomUUID(), wallet_id: 'wallet_demo', name: 'Fixture account', kind: 'password', value: 'fixture-secret-unchanged' });
  opened.save(opened.data); opened.close();
  const backup = readFileSync(join(source, 'vault.json'), 'utf8');
  for (const input of [
    { mnemonic, backup, confirmed: false },
    { mnemonic: 'wrong '.repeat(24).trim(), backup, confirmed: true },
    { mnemonic, backup: '{}', confirmed: true },
    { mnemonic, backup: JSON.stringify({ ...JSON.parse(backup), version: 900 }), confirmed: true },
  ]) {
    const result = await f.api('/api/restore', input);
    assert.notEqual(result.status, 200); assert.ok(!JSON.stringify(result.body).includes(mnemonic));
    assert.deepEqual(readdirSync(f.root), []);
  }
  const result = await f.api('/api/restore', { mnemonic, backup, confirmed: true });
  assert.equal(result.status, 200); assert.equal(result.body.data.grants_restored, false);
  assert.notEqual(result.body.data.vault_id, JSON.parse(backup).vault_id);
  const restored = await openVault(join(f.root, 'wallet/vault'), mnemonic);
  assert.equal(restored.data.credentials[0]?.value, 'fixture-secret-unchanged'); restored.close();
  assert.equal(readFileSync(join(source, 'vault.json'), 'utf8'), backup);
  assert.notEqual((await f.api('/api/restore', { mnemonic, backup, confirmed: true })).status, 200);
  await assert.rejects(startWalletSetup(source), /new setup directory/);
});

test('bootstrap rejects unauthenticated and cross-origin calls; expired/cancelled drafts remove their recovery material', async t => {
  const f = await fixture(t);
  for (const headers of [{ authorization: '' }, { authorization: 'Bearer invalid' }, { origin: 'https://evil.example' }, { 'sec-fetch-site': 'cross-site' }]) {
    assert.ok([401, 403].includes((await f.api('/api/create', { confirmed: true }, headers)).status));
  }
  const hostStatus = await new Promise<number>((accept, reject) => {
    const req = httpRequest(f.server.endpoint + '/api/state', { headers: { host: 'evil.example' } }, response => {
      response.resume(); response.on('end', () => accept(response.statusCode!));
    }); req.on('error', reject); req.end();
  });
  assert.equal(hostStatus, 403);
  const started = (await f.api('/api/create', { confirmed: true })).body.data;
  assert.notEqual((await f.api('/api/phrase', { draft_id: 'different', confirmed: true })).status, 200);
  await f.api('/api/cancel', {}); assert.deepEqual(readdirSync(f.root), []);
  assert.notEqual((await f.api('/api/phrase', { draft_id: started.draft_id, confirmed: true })).status, 200);
  await f.api('/api/create', { confirmed: true }); f.advance(601);
  assert.equal((await f.api('/api/state')).body.data.stage, 'welcome'); assert.deepEqual(readdirSync(f.root), []);
  await f.api('/api/create', { confirmed: true });
  await f.server.close(); assert.deepEqual(readdirSync(f.root), []);
});

test('setup lifetime and existing destination protection fail closed', async t => {
  const f = await fixture(t); f.advance(1801);
  assert.equal((await f.api('/api/create', { confirmed: true })).status, 401);
  assert.deepEqual(readdirSync(f.root), []);
  const occupied = join(f.parent, 'occupied'); writeFileSync(occupied, 'keep me');
  await assert.rejects(startWalletSetup(occupied)); assert.equal(readFileSync(occupied, 'utf8'), 'keep me');
});

test('slow uploads cannot outlive bootstrap authority and do not create a wallet', async t => {
  const f = await fixture(t);
  const payload = JSON.stringify({ confirmed: true });
  const status = await new Promise<number>((accept, reject) => {
    const req = httpRequest(f.server.endpoint + '/api/create', { method: 'POST', headers: {
      authorization: 'Bearer ' + new URL(f.server.launchUrl).hash.slice(1), origin: f.server.endpoint,
      'content-type': 'application/json', 'content-length': Buffer.byteLength(payload),
    } }, response => { response.resume(); response.on('end', () => accept(response.statusCode!)); });
    req.on('error', reject); req.write(payload.slice(0, 1));
    setTimeout(() => { f.advance(1801); req.end(payload.slice(1)); }, 20);
  });
  assert.equal(status, 401); assert.deepEqual(readdirSync(f.root), []);
});
