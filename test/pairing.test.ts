import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { importJWK, SignJWT } from 'jose';
import { connect, localStatus } from '../src/client.js';
import { AppError, digest, record, PROOF_TYPE, RECEIPT_TYPE } from '../src/contracts.js';
import { createIdentity, loadIdentity, privateDirectory, publicKey } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { acceptPairing, issueInvitation, makePairingProof, parseInvitation } from '../src/pairing.js';
import { Store } from '../src/store.js';

const cli = resolve('dist/src/cli.js');
const command = (...args: string[]) => {
  const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  assert.equal(result.error, undefined);
  return { ...result, json: JSON.parse(result.stdout.trim()) as Record<string, any> };
};

function sandbox(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), 'stackey-pairing-test-'));
  t.after(() => rmSync(root, { recursive: true }));
  return { root, nodeDir: join(root, 'node'), agentDir: join(root, 'agent') };
}

async function fixture(t: TestContext, clock?: () => number) {
  const paths = sandbox(t);
  const nodeIdentity = await loadIdentity(paths.nodeDir, 'node', true);
  const node = await startNode(paths.nodeDir, 0, clock);
  const store = new Store(paths.nodeDir);
  t.after(async () => { await node.close(); store.close(); });
  const encoded = await issueInvitation(store, nodeIdentity, 300);
  const invitation = await parseInvitation(encoded);
  const agent = await createIdentity('ES256');
  const request = await makePairingProof(invitation, agent, 'Test Agent');
  const post = (body: unknown) => fetch(node.endpoint + '/v1/pairings', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return { ...paths, node, nodeIdentity, store, encoded, invitation, agent, request, post };
}

test('real CLI submits a pending request, persists its identity and never grants service access', async t => {
  const f = await fixture(t);
  const child = spawn(process.execPath, [cli, 'connect', f.encoded, '--state-dir', f.agentDir, '--name', 'Codex local', '--json']);
  let stdout = ''; let stderr = '';
  child.stdout.on('data', data => { stdout += data; });
  child.stderr.on('data', data => { stderr += data; });
  const [exitCode] = await once(child, 'exit');
  assert.equal(exitCode, 0, stderr);
  const result = JSON.parse(stdout);
  assert.equal(result.status, 'approval_required');
  assert.deepEqual(result.data.granted_actions, []);
  const pairings = f.store.listPairings().pairings;
  assert.equal(pairings.length, 1);
  assert.equal(pairings[0]?.pairing_id, result.data.pairing_id);
  assert.equal(pairings[0]?.principal, result.data.principal);
  assert.equal(pairings[0]?.display_name, 'Codex local');
  assert.equal(pairings[0]?.status, 'approval_required');
  const privateIdentity = JSON.parse(readFileSync(join(f.agentDir, 'identity.json'), 'utf8'));
  assert.equal(privateIdentity.id, result.data.principal);
  assert.ok(privateIdentity.privateJwk.d);
  assert.ok(!stdout.includes(privateIdentity.privateJwk.d));
  assert.ok(!stdout.includes(f.invitation.token));
  assert.ok(!stdout.includes('access_token'));
  assert.equal(statSync(join(f.agentDir, 'identity.json')).mode & 0o777, 0o600);
  assert.equal(statSync(join(f.agentDir, 'pairing.json')).mode & 0o777, 0o600);
  const status = command('status', '--state-dir', f.agentDir, '--json');
  assert.equal(status.status, 0);
  assert.equal(status.json.status, 'approval_required');
  assert.equal(status.json.data.source, 'local_pairing_receipt');
  assert.deepEqual(status.json.data.granted_actions, []);
});

test('one invitation can create only one pending pairing under simultaneous requests', async t => {
  const f = await fixture(t);
  const body = { invitation: f.invitation.token, proof: f.request.proof };
  const responses = await Promise.all([f.post(body), f.post(body)]);
  assert.deepEqual(responses.map(r => r.status).sort(), [201, 409]);
  await Promise.all(responses.map(r => r.arrayBuffer()));
  assert.equal(f.store.listPairings().pairings.length, 1);
});

test('invitation consumption and pending identity survive Node restart', async t => {
  const f = await fixture(t);
  const body = { invitation: f.invitation.token, proof: f.request.proof };
  const first = await f.post(body);
  assert.equal(first.status, 201); await first.arrayBuffer();
  const port = Number(new URL(f.node.endpoint).port);
  await f.node.close();
  const restarted = await startNode(f.nodeDir, port);
  t.after(() => restarted.close());
  const replay = await f.post(body);
  assert.equal(replay.status, 409);
  assert.equal(record(record(await replay.json()).error).code, 'invitation_used');
  assert.equal(f.store.listPairings().pairings.length, 1);
});

test('invalid signature does not consume the invitation', async t => {
  const f = await fixture(t);
  const attacker = await createIdentity('ES256');
  const forged = await new SignJWT({ purpose: 'pairing-request' })
    .setProtectedHeader({ alg: 'ES256', typ: PROOF_TYPE, jwk: f.agent.publicJwk })
    .setIssuer(f.agent.id).setAudience(f.nodeIdentity.id).setJti('forged')
    .setIssuedAt().setExpirationTime('30s').sign(await importJWK(attacker.privateJwk, 'ES256'));
  const denied = await f.post({ invitation: f.invitation.token, proof: forged });
  assert.equal(denied.status, 403);
  assert.equal(record(record(await denied.json()).error).code, 'invalid_proof');
  assert.equal(f.store.listPairings().pairings.length, 0);
  const valid = await f.post({ invitation: f.invitation.token, proof: f.request.proof });
  assert.equal(valid.status, 201); await valid.arrayBuffer();
});

test('proof binding rejects another invitation, audience, endpoint and stale timestamp', async t => {
  const f = await fixture(t);
  const another = await issueInvitation(f.store, f.nodeIdentity, 300);
  const anotherToken = (await parseInvitation(another)).token;
  const mismatch = await f.post({ invitation: anotherToken, proof: f.request.proof });
  assert.equal(mismatch.status, 403); await mismatch.arrayBuffer();
  const now = Math.floor(Date.now() / 1000);
  for (const change of [
    { aud: 'different-node' },
    { uri: f.node.endpoint + '/v1/operations' },
    { iat: now - 60, exp: now + 30 },
    { iat: now + 60, exp: now + 90 },
  ]) {
    const claims = {
      purpose: 'pairing-request', invitation_hash: digest(f.invitation.token),
      invitation_id: f.invitation.invitationId, display_name: 'Test Agent',
      method: 'POST', uri: f.node.endpoint + '/v1/pairings',
      iss: f.agent.id, aud: f.nodeIdentity.id, iat: now, exp: now + 30,
      jti: 'binding-test', ...change,
    };
    const proof = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', typ: PROOF_TYPE, jwk: f.agent.publicJwk })
      .sign(await importJWK(f.agent.privateJwk, 'ES256'));
    const response = await f.post({ invitation: f.invitation.token, proof });
    assert.equal(response.status, 403); await response.arrayBuffer();
  }
  assert.equal(f.store.listPairings().pairings.length, 0);
});

test('expired invitations are refused by CLI and Node', async t => {
  const current = Math.floor(Date.now() / 1000);
  let now = current;
  const f = await fixture(t, () => now);
  now = current + 301;
  await assert.rejects(parseInvitation(f.encoded, now), error => error instanceof AppError && error.code === 'invalid_invitation');
  const response = await f.post({ invitation: f.invitation.token, proof: f.request.proof });
  assert.equal(response.status, 403);
  assert.equal(record(record(await response.json()).error).code, 'invalid_invitation');
  assert.equal(f.store.listPairings().pairings.length, 0);
});

test('expiry is checked when the complete HTTP body arrives, not when headers arrive', async t => {
  const current = Math.floor(Date.now() / 1000);
  let now = current;
  const f = await fixture(t, () => now);
  const body = JSON.stringify({ invitation: f.invitation.token, proof: f.request.proof });
  const result = new Promise<{ status: number; body: any }>((resolve, reject) => {
    const request = httpRequest(f.node.endpoint + '/v1/pairings', {
      method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
    }, response => {
      let output = '';
      response.on('data', chunk => { output += chunk; });
      response.on('end', () => resolve({ status: response.statusCode!, body: JSON.parse(output) }));
    });
    request.on('error', reject);
    request.write(body.slice(0, -1));
    // Allow headers and the partial body to be handled while still valid.
    setTimeout(() => { now = current + 301; request.end(body.slice(-1)); }, 30);
  });
  assert.equal((await result).status, 403);
  assert.equal(f.store.listPairings().pairings.length, 0);
});

test('proof expiry is rechecked inside acceptance after asynchronous verification', async t => {
  const f = await fixture(t);
  const now = Math.floor(Date.now() / 1000);
  let checks = 0;
  await assert.rejects(acceptPairing(f.store, f.nodeIdentity, f.node.endpoint, {
    invitation: f.invitation.token, proof: f.request.proof,
  }, () => ++checks === 1 ? now : now + 31), error => error instanceof AppError && error.code === 'invalid_proof');
  assert.equal(f.store.listPairings().pairings.length, 0);
  const valid = await f.post({ invitation: f.invitation.token, proof: f.request.proof });
  assert.equal(valid.status, 201); await valid.arrayBuffer();
});

test('invitation expiry is rechecked inside the consumption transaction', async t => {
  const f = await fixture(t);
  const now = Math.floor(Date.now() / 1000);
  let checks = 0;
  await assert.rejects(acceptPairing(f.store, f.nodeIdentity, f.node.endpoint, {
    invitation: f.invitation.token, proof: f.request.proof,
  }, () => ++checks === 1 ? now : now + 301), error => error instanceof AppError && error.code === 'invalid_invitation');
  assert.equal(f.store.listPairings().pairings.length, 0);
});

test('proof replay with a different valid invitation is rejected durably', async t => {
  const f = await fixture(t);
  const first = await f.post({ invitation: f.invitation.token, proof: f.request.proof });
  assert.equal(first.status, 201); await first.arrayBuffer();
  const encoded = await issueInvitation(f.store, f.nodeIdentity, 300);
  const invitation = await parseInvitation(encoded);
  const now = Math.floor(Date.now() / 1000);
  const proof = await new SignJWT({
    purpose: 'pairing-request', invitation_hash: digest(invitation.token),
    invitation_id: invitation.invitationId, display_name: 'Test Agent',
    method: 'POST', uri: f.node.endpoint + '/v1/pairings',
  }).setProtectedHeader({ alg: 'ES256', typ: PROOF_TYPE, jwk: f.agent.publicJwk })
    .setIssuer(f.agent.id).setAudience(f.nodeIdentity.id).setJti(f.request.jti)
    .setIssuedAt(now).setExpirationTime(now + 30).sign(await importJWK(f.agent.privateJwk, 'ES256'));
  const response = await f.post({ invitation: invitation.token, proof });
  assert.equal(response.status, 409);
  assert.equal(record(record(await response.json()).error).code, 'proof_replayed');
  assert.equal(f.store.listPairings().pairings.length, 1);
});

test('tampered invitation endpoints, public keys and non-loopback URLs are refused before networking', async t => {
  const f = await fixture(t);
  const untrusted = await createIdentity('EdDSA');
  for (const patch of [
    { endpoint: 'http://127.0.0.1:12345' }, { endpoint: 'https://example.com' },
    { endpoint: 'http://localhost:12345' }, { endpoint: f.node.endpoint + '/path' },
    { endpoint: f.node.endpoint + '?redirect=yes' }, { node: untrusted.publicJwk },
  ]) {
    const raw = { endpoint: f.invitation.endpoint, node: f.invitation.node, token: f.invitation.token, ...patch };
    const encoded = 'stackey-invite-v1.' + Buffer.from(JSON.stringify(raw)).toString('base64url');
    await assert.rejects(connect(encoded, f.agentDir, 'Agent'));
    assert.ok(!existsSync(join(f.agentDir, 'identity.json')));
  }
});

test('private key material in a public proof header is rejected', async t => {
  const f = await fixture(t);
  assert.throws(() => publicKey(f.agent.privateJwk, 'ES256'));
  const proof = await new SignJWT({ purpose: 'pairing-request' })
    .setProtectedHeader({ alg: 'ES256', typ: PROOF_TYPE, jwk: f.agent.privateJwk })
    .setIssuedAt().setExpirationTime('30s').sign(await importJWK(f.agent.privateJwk, 'ES256'));
  const response = await f.post({ invitation: f.invitation.token, proof });
  const result = await response.json();
  assert.equal(response.status, 403);
  assert.ok(!JSON.stringify(result).includes(f.agent.privateJwk.d!));
  assert.equal(f.store.listPairings().pairings.length, 0);
});

test('malformed requests, browser requests, service and management routes never create access', async t => {
  const f = await fixture(t);
  const invalid = await fetch(f.node.endpoint + '/v1/pairings', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad json',
  });
  assert.equal(invalid.status, 400); await invalid.arrayBuffer();
  const browser = await fetch(f.node.endpoint + '/v1/pairings', {
    method: 'POST', headers: { origin: 'https://attacker.example', 'content-type': 'application/json' },
    body: JSON.stringify({ invitation: f.invitation.token, proof: f.request.proof }),
  });
  assert.equal(browser.status, 403); await browser.arrayBuffer();
  for (const path of ['/v1/grants', '/admin/unlock', '/admin/approve']) {
    const response = await fetch(f.node.endpoint + path, { method: 'POST' });
    assert.equal(response.status, 404); await response.arrayBuffer();
  }
  assert.equal(f.store.listPairings().pairings.length, 0);
});

test('body size and request rate are bounded', async t => {
  const f = await fixture(t);
  const oversized = await fetch(f.node.endpoint + '/v1/pairings', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ padding: 'a'.repeat(17_000) }),
  });
  assert.equal(oversized.status, 413); await oversized.arrayBuffer();
  let limited = false;
  for (let i = 0; i < 30; i++) {
    const response = await f.post({});
    limited ||= response.status === 429;
    await response.arrayBuffer();
  }
  assert.ok(limited);
  assert.equal(f.store.listPairings().pairings.length, 0);
});

test('Node-signed receipt is pinned; another signing key cannot confirm a pairing', async t => {
  const f = await fixture(t);
  const port = Number(new URL(f.node.endpoint).port);
  await f.node.close();
  const attacker = await createIdentity('EdDSA');
  const fake = createServer((_req, response) => {
    void (async () => {
      const receipt = await new SignJWT({ purpose: 'pairing-receipt', status: 'approval_required' })
        .setProtectedHeader({ alg: 'EdDSA', typ: RECEIPT_TYPE })
        .setIssuer(f.nodeIdentity.id).setAudience('agent').setIssuedAt().setExpirationTime('30s')
        .sign(await importJWK(attacker.privateJwk, 'EdDSA'));
      response.writeHead(201, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 'approval_required', data: { receipt } }));
    })();
  });
  await new Promise<void>(resolve => fake.listen(port, '127.0.0.1', resolve));
  t.after(() => new Promise<void>(resolve => { fake.close(() => resolve()); fake.closeIdleConnections(); }));
  await assert.rejects(connect(f.encoded, f.agentDir, 'Agent'), error => error instanceof AppError && error.code === 'invalid_node_receipt');
  assert.ok(!existsSync(join(f.agentDir, 'pairing.json')));
});

test('CLI rejects redirects and never follows an untrusted response location', async t => {
  const f = await fixture(t);
  const port = Number(new URL(f.node.endpoint).port);
  await f.node.close();
  let destinationRequests = 0;
  const destination = createServer((_req, res) => { destinationRequests++; res.end('{}'); });
  await new Promise<void>(resolve => destination.listen(0, '127.0.0.1', resolve));
  const destAddress = destination.address();
  assert.ok(destAddress && typeof destAddress !== 'string');
  const fake = createServer((_req, res) => {
    res.writeHead(307, { location: `http://127.0.0.1:${destAddress.port}/capture` }); res.end();
  });
  await new Promise<void>(resolve => fake.listen(port, '127.0.0.1', resolve));
  t.after(async () => {
    await Promise.all([fake, destination].map(server => new Promise<void>(resolve => {
      server.close(() => resolve()); server.closeIdleConnections();
    })));
  });
  await assert.rejects(connect(f.encoded, f.agentDir, 'Agent'), error => error instanceof AppError && error.status === 'result_unknown');
  assert.equal(destinationRequests, 0);
});

test('private state is reused without overwriting keys, and unsafe directories or symlinks are refused', async t => {
  const paths = sandbox(t);
  const first = await loadIdentity(paths.agentDir, 'agent', true);
  const second = await loadIdentity(paths.agentDir, 'agent', true);
  assert.deepEqual(second, first);
  const unsafe = join(paths.root, 'unsafe'); privateDirectory(unsafe); chmodSync(unsafe, 0o755);
  await assert.rejects(loadIdentity(unsafe, 'agent', true), error => error instanceof AppError && error.code === 'unsafe_state_directory');
  const linked = join(paths.root, 'linked'); symlinkSync(paths.agentDir, linked);
  await assert.rejects(loadIdentity(linked, 'agent', true));
  assert.equal((await localStatus(paths.agentDir)).status, 'unpaired');
});

test('CLI init, start, file-based invitation and local owner list form a reproducible workflow', async t => {
  const paths = sandbox(t);
  assert.equal(command('node', 'init', '--data-dir', paths.nodeDir).status, 0);
  assert.equal(command('node', 'init', '--data-dir', paths.nodeDir).json.error.code, 'already_initialized');
  const child: ChildProcessWithoutNullStreams = spawn(process.execPath, [cli, 'node', 'start', '--data-dir', paths.nodeDir, '--port', '0']);
  let stderr = ''; child.stderr.on('data', chunk => { stderr += chunk; });
  const exited = once(child, 'exit');
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); await exited; });
  const started = await new Promise<Record<string, any>>((resolve, reject) => {
    let buffer = '';
    const timeout = setTimeout(() => reject(new Error('Node did not start: ' + stderr)), 5000);
    child.once('exit', () => { clearTimeout(timeout); reject(new Error('Node exited early: ' + stderr)); });
    child.stdout.on('data', data => {
      buffer += data;
      if (buffer.includes('\n')) { clearTimeout(timeout); resolve(JSON.parse(buffer.split('\n')[0]!)); }
    });
  });
  assert.equal(started.status, 'ok');
  const file = join(paths.root, 'invitation.json');
  const invite = command('node', 'invite', '--data-dir', paths.nodeDir, '--out', file);
  assert.equal(invite.status, 0);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.ok(!invite.stdout.includes('stackey-invite-v1'));
  assert.equal(command('node', 'invite', '--data-dir', paths.nodeDir, '--out', file).json.error.code, 'output_exists');
  const connected = spawn(process.execPath, [cli, 'connect', '--invite-file', file, '--state-dir', paths.agentDir]);
  let stdout = ''; connected.stdout.on('data', chunk => { stdout += chunk; });
  const [code] = await once(connected, 'exit');
  assert.equal(code, 0);
  const pairing = JSON.parse(stdout);
  assert.equal(pairing.status, 'approval_required');
  const listed = command('node', 'pairings', '--data-dir', paths.nodeDir);
  assert.equal(listed.json.data.pairings[0].pairing_id, pairing.data.pairing_id);
  assert.equal(command('connect', '--invite-file', file, '--state-dir', paths.agentDir).json.error.code, 'already_paired');
  const invalid = command('connect', '--unknown-secret-option', 'secret-marker-value');
  assert.equal(invalid.status, 2);
  assert.ok(!invalid.stdout.includes('secret-marker-value'));
});


test('owner CLI paginates every pending request including more than 200 with tied timestamps', async t => {
  const f = await fixture(t);
  const now = Math.floor(Date.now() / 1000);
  for (let index = 0; index < 201; index++) {
    const encoded = await issueInvitation(f.store, f.nodeIdentity, 300, now);
    const invite = await parseInvitation(encoded, now);
    const proof = await makePairingProof(invite, f.agent, `Pairing ${index}`, now);
    await acceptPairing(f.store, f.nodeIdentity, f.node.endpoint,
      { invitation: invite.token, proof: proof.proof }, () => now);
  }
  const first = command('node', 'pairings', '--data-dir', f.nodeDir);
  assert.equal(first.status, 0);
  assert.equal(first.json.data.pairings.length, 200);
  assert.equal(typeof first.json.data.next_cursor, 'string');
  const second = command('node', 'pairings', '--data-dir', f.nodeDir,
    '--after', first.json.data.next_cursor);
  assert.equal(second.status, 0);
  assert.equal(second.json.data.pairings.length, 1);
  assert.equal(second.json.data.next_cursor, null);
  const all = [...first.json.data.pairings, ...second.json.data.pairings];
  assert.equal(new Set(all.map(row => row.pairing_id)).size, 201);
  assert.deepEqual(new Set(all.map(row => row.display_name)),
    new Set(Array.from({ length: 201 }, (_, index) => `Pairing ${index}`)));
  const invalid = command('node', 'pairings', '--data-dir', f.nodeDir, '--after', 'unknown');
  assert.equal(invalid.status, 2);
  assert.equal(invalid.json.error.code, 'invalid_cursor');
});
