import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { request } from 'node:http';
import { test } from 'node:test';
import { endpoint, record } from '../src/contracts.js';
import { publicAddress, nodeFetch } from '../src/transport.js';
import { loadIdentity } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { Store } from '../src/store.js';
import { issueInvitation, parseInvitation, makePairingProof } from '../src/pairing.js';
import { connect } from '../src/client.js';
import { orderReport, renderReport } from '../src/order-report.js';
import { initializeDemo, ACTION } from '../src/orders.js';
import { initializeOwner, approvePairing, revokeGrant } from '../src/policy.js';

function hostFetch(url: string, options: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Response> {
  return new Promise((resolve, reject) => {
    const req = request(url, options, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('end', () => resolve(new Response(Buffer.concat(chunks), { status: res.statusCode ?? 500 })));
      res.on('error', reject);
    });
    req.on('error', reject); req.end(options.body);
  });
}

test('remote transport accepts canonical HTTPS and rejects private/reserved endpoints', async () => {
  assert.equal(endpoint('https://agent.stackey.dev'), 'https://agent.stackey.dev');
  for (const value of ['http://agent.stackey.dev', 'https://127.0.0.1', 'https://[::1]', 'https://agent.local', 'https://agent.stackey.dev/path', 'https://agent.stackey.dev/']) assert.throws(() => endpoint(value));
  for (const ip of ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '100.64.0.1', '169.254.169.254', '198.18.0.1', '192.0.2.1', '203.0.113.1', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '2001:db8::1', '2002:7f00:1::']) assert.equal(publicAddress(ip), false, ip);
  assert.equal(publicAddress('1.1.1.1'), true);
  assert.equal(publicAddress('2606:4700:4700::1111'), true);
  await assert.rejects(nodeFetch('https://127.0.0.1.nip.io/v1/challenges'), /public addresses/);
});

test('remote origin is signed, Host-bound, package-gated and keeps existing local agents working', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-cloud-test-'));
  const nodeDir = join(root, 'node');
  const identity = await loadIdentity(nodeDir, 'node', true);
  const node = await startNode(nodeDir, 0);
  const store = new Store(nodeDir);
  t.after(async () => { await node.close(); store.close(); rmSync(root, { recursive: true }); });
  const localInvite = await issueInvitation(store, identity, 300);
  node.setPublicEndpoint('https://agent.stackey.dev');
  assert.equal((await connect(localInvite, join(root, 'local-agent'), 'Local agent')).status, 'approval_required');
  const encoded = await issueInvitation(store, identity, 300);
  const invite = await parseInvitation(encoded);
  assert.equal(invite.endpoint, 'https://agent.stackey.dev');
  const agent = await loadIdentity(join(root, 'cloud-agent'), 'agent', true);
  const proof = await makePairingProof(invite, agent, 'Cloud agent');
  const headers = { host: 'agent.stackey.dev', authorization: 'Bearer ' + encoded };
  const denied = await hostFetch(node.localEndpoint + '/v1/agent-package', { headers: { host: headers.host } });
  assert.equal(denied.status, 403);
  const downloaded = await hostFetch(node.localEndpoint + '/v1/agent-package', { headers });
  assert.equal(downloaded.status, 200); assert.ok((await downloaded.arrayBuffer()).byteLength > 1000);
  const body = JSON.stringify({ invitation: invite.token, proof: proof.proof });
  const mismatch = await fetch(node.localEndpoint + '/v1/pairings', { method: 'POST', headers: { 'content-type': 'application/json' }, body });
  assert.equal(mismatch.status, 403);
  const accepted = await hostFetch(node.localEndpoint + '/v1/pairings', { method: 'POST', headers: { host: headers.host, 'content-type': 'application/json' }, body });
  assert.equal(accepted.status, 201);
  assert.equal((await hostFetch(node.localEndpoint + '/v1/agent-package', { headers })).status, 403);
  for (const path of ['/api/state', '/api/credentials', '/api/remote', '/', '/owner', '/vault']) assert.equal((await hostFetch(node.localEndpoint + path, { headers })).status, 404);
  assert.equal((await hostFetch(node.localEndpoint + '/v1/challenges', { headers: { host: 'attacker.stackey.dev', 'x-forwarded-host': headers.host } })).status, 403);
  const entries = execFileSync('tar', ['-tzf', 'dist/agent-package.tgz'], { encoding: 'utf8' });
  assert.ok(entries.includes('src/cloud-agent.js'));
  assert.ok(!/src\/(?:cli|vault|wallet|vault-session)\.js|identity\.json|recovery\.json|\.sqlite|\.stackey/.test(entries));
  assert.ok(!/src\/(?:access|provider-operations|providers|mpp-payment)\.js/.test(entries));
  execFileSync('tar', ['-xzf', 'dist/agent-package.tgz', '-C', root]);
  const portable = JSON.parse(execFileSync(process.execPath, [join(root, 'stackey-agent/src/cloud-agent.js'), 'status', '--state-dir', join(root, 'portable-agent')], { encoding: 'utf8' }));
  assert.equal(portable.status, 'unpaired');
});

test('report uses approved reads, separates currencies, finds pattern and is blocked immediately after revocation', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-report-test-'));
  const nodeDir = join(root, 'node'), agentDir = join(root, 'agent');
  const identity = await loadIdentity(nodeDir, 'node', true);
  const owner = await loadIdentity(join(root, 'owner'), 'owner', true);
  const node = await startNode(nodeDir, 0), store = new Store(nodeDir);
  t.after(async () => { await node.close(); store.close(); rmSync(root, { recursive: true }); });
  await initializeOwner(store, owner); initializeDemo(store);
  const paired = await connect(await issueInvitation(store, identity, 300), agentDir, 'Report agent');
  const params = { from: '2026-09-26', to: '2026-10-02' };
  await assert.rejects(orderReport(agentDir, params));
  const grant = await approvePairing(store, identity, owner, String(record(paired.data).pairing_id), String(record(paired.data).principal), ACTION, 900);
  const report = await orderReport(agentDir, params);
  assert.match(report, /7\/21 \(33.3%\)/);
  assert.match(report, /Highest USD revenue: 2026-10-02 — USD 16.00/);
  assert.match(report, /Highest TWD revenue: 2026-10-02 — TWD 360.00/);
  assert.match(report, /Recurring pattern: one USD 12.00/);
  assert.match(report, /Revenue includes paid orders only/);
  await revokeGrant(store, identity, owner, grant.grant_id);
  await assert.rejects(orderReport(agentDir, params), (error: any) => error.code === 'grant_revoked');
  assert.throws(() => renderReport({ source: 'local_synthetic', complete: false, rows: [] }), /complete/);
});
