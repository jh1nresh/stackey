import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { AppError } from '../src/contracts.js';
import { writePrivateJson } from '../src/identity.js';
import {
  PAIR_CODE_RE, createAccessRequest, listPendingAccessRequests, redeemPairingCode,
  resolveAccessRequest, savePairingCode, selectTargetFromStore, stopSimpleRuntime,
} from '../src/simple-wallet.js';
import { Store } from '../src/store.js';
import { recovery } from '../src/vault.js';

const cli = resolve('dist/src/cli.js');
const SECRET = 'fixture-wallet-simple-DO-NOT-LEAK';

async function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close();
        reject(new Error('no port'));
        return;
      }
      const port = address.port;
      server.close(error => error ? reject(error) : resolvePort(port));
    });
  });
}

async function cliResult(...args: string[]) {
  const child = spawn(process.execPath, [cli, ...args], { env: process.env });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const [code] = await once(child, 'close');
  let body: { status?: string; data?: Record<string, unknown>; error?: { code: string }; value?: string } | undefined;
  try { body = JSON.parse(stdout); } catch { body = undefined; }
  return { code, stdout, stderr, body };
}

async function workspace(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), 'stackey-simple-'));
  const vaultDir = join(root, 'vault');
  const dataDir = join(root, 'node');
  const agentDir = join(root, 'agent');
  const port = await freePort();
  const dirs = ['--vault-dir', vaultDir, '--data-dir', dataDir, '--port', String(port)];
  t.after(() => {
    stopSimpleRuntime(dataDir);
    rmSync(root, { recursive: true, force: true });
  });
  return { root, vaultDir, dataDir, agentDir, port, dirs };
}

test('pairing codes are single-use and never mint an invitation after expiry', () => {
  const dir = mkdtempSync(join(tmpdir(), 'stackey-pair-code-'));
  const store = new Store(dir);
  try {
    const issued = savePairingCode(store, 'stackey-invite-v1.fixture', 60, 1_000);
    assert.match(issued.code, PAIR_CODE_RE);
    assert.equal(redeemPairingCode(store, issued.code.toLowerCase(), 1_010), 'stackey-invite-v1.fixture');
    assert.throws(() => redeemPairingCode(store, issued.code, 1_011), (error: unknown) =>
      error instanceof AppError && error.code === 'pairing_code_invalid' && error.exitCode === 5);
    const expired = savePairingCode(store, 'stackey-invite-v1.expired', 60, 2_000);
    assert.throws(() => redeemPairingCode(store, expired.code, 2_061), (error: unknown) =>
      error instanceof AppError && error.code === 'pairing_code_invalid');
    assert.throws(() => redeemPairingCode(store, '!!!!!!', 2_000), (error: unknown) =>
      error instanceof AppError && error.code === 'pairing_code_invalid');
  } finally { store.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('access requests queue one pending row per agent and resolve without grant IDs', () => {
  const dir = mkdtempSync(join(tmpdir(), 'stackey-access-'));
  const store = new Store(dir);
  try {
    assert.throws(() => selectTargetFromStore(store, '00000000-0000-0000-0000-000000000000'), (error: unknown) =>
      error instanceof AppError && error.code === 'no_credential' && error.exitCode === 2);
    store.db.prepare('INSERT INTO invitations(id, token_hash, expires_at) VALUES (?,?,?)')
      .run('invite-a', 'hash-a', 9_999);
    store.db.prepare('INSERT INTO pairings(pairing_id, principal, public_jwk, display_name, created_at, status, invitation_id, proof_jti) VALUES (?,?,?,?,?,?,?,?)')
      .run('11111111-1111-1111-1111-111111111111', 'agent-a', '{}', 'Codex', 1, 'approval_required', 'invite-a', 'proof-a');
    const first = createAccessRequest(store, '11111111-1111-1111-1111-111111111111', 'agent-a', {
      connection_id: 'connection_demo', credential_id: 'credential_demo', credential_name: 'GITHUB_TOKEN',
    }, 50, 300);
    const again = createAccessRequest(store, '11111111-1111-1111-1111-111111111111', 'agent-a', {
      connection_id: 'connection_demo', credential_id: 'credential_demo', credential_name: 'GITHUB_TOKEN',
    }, 51, 300);
    assert.equal(again.request_id, first.request_id);
    assert.equal(listPendingAccessRequests(store, 52).length, 1);
    const resolved = resolveAccessRequest(store, first.request_id, 'approved', 53);
    assert.equal(resolved.decision, 'approved');
    assert.equal(listPendingAccessRequests(store, 54).length, 0);
  } finally { store.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('stackey init add connect approve status is a one-terminal wallet flow', async t => {
  const f = await workspace(t);
  const started = await cliResult('init', '--json', ...f.dirs);
  assert.equal(started.code, 0, started.stderr + started.stdout);
  assert.equal(started.body?.data?.unlocked, true);
  assert.equal(started.body?.data?.created_vault, true);
  assert.match(String(started.body?.data?.backup_nudge ?? ''), /not backed up/i);
  const mnemonic = await recovery(join(f.root, 'recovery.json'));
  assert.equal(started.stdout.includes(mnemonic), false);

  const secretFile = join(f.root, 'secret.json');
  writePrivateJson(secretFile, { value: SECRET });
  const added = await cliResult('add', 'GITHUB_TOKEN', '--secret-file', secretFile, '--json', ...f.dirs);
  assert.equal(added.code, 0, added.stderr + added.stdout);
  assert.equal(added.body?.data?.name, 'GITHUB_TOKEN');
  assert.equal(JSON.stringify(added.body).includes(SECRET), false);

  const owner = await cliResult('connect', '--json', ...f.dirs);
  assert.equal(owner.code, 0, owner.stderr + owner.stdout);
  const code = String(owner.body?.data?.code ?? '');
  assert.match(code, PAIR_CODE_RE);
  assert.match(String(owner.body?.data?.snippet), new RegExp(`stackey connect ${code}`));
  assert.equal(String(owner.body?.data?.snippet).length < 40, true);
  assert.equal(Object.hasOwn(owner.body?.data ?? {}, 'principal'), false);
  assert.equal(Object.hasOwn(owner.body?.data ?? {}, 'pairing_id'), false);

  const human = await cliResult('connect', ...f.dirs);
  assert.equal(human.code, 0);
  assert.match(human.stdout, /stackey connect [A-HJ-NP-Z2-9]{6}/);
  assert.equal(/pairing_id|principal/i.test(human.stdout), false);

  const paired = await cliResult('connect', code, '--state-dir', f.agentDir, '--name', 'Codex', '--json', ...f.dirs);
  assert.equal(paired.code, 0, paired.stderr + paired.stdout);
  assert.equal(paired.body?.status, 'approval_required');
  assert.deepEqual(paired.body?.data?.granted_actions, []);

  const reused = await cliResult('connect', code, '--state-dir', join(f.root, 'agent-2'), '--json', ...f.dirs);
  assert.equal(reused.body?.error?.code, 'pairing_code_invalid');
  assert.equal(reused.code, 5);

  const getting = cliResult('credential', 'get', '--state-dir', f.agentDir, ...f.dirs);
  let pending = false;
  for (let i = 0; i < 40; i++) {
    const status = await cliResult('status', '--json', ...f.dirs);
    const requests = status.body?.data?.pending_requests as Array<{ agent?: string; credential?: string }> | undefined;
    if (requests?.some(row => row.credential === 'GITHUB_TOKEN')) { pending = true; break; }
    await delay(250);
  }
  assert.equal(pending, true, 'owner status never showed the pending request');
  const approved = await cliResult('approve', '--yes', '--json', ...f.dirs);
  assert.equal(approved.code, 0, approved.stderr + approved.stdout);
  assert.equal(approved.body?.data?.decision, 'approved');
  assert.equal(Object.hasOwn(approved.body?.data ?? {}, 'grant_id'), false);

  const fetched = await getting;
  assert.equal(fetched.code, 0, fetched.stderr + fetched.stdout);
  assert.deepEqual(fetched.body, { value: SECRET });

  const status = await cliResult('status', '--json', ...f.dirs);
  assert.equal(status.code, 0, status.stderr + status.stdout);
  const credentials = status.body?.data?.credentials as Array<{ name: string }> | undefined;
  assert.equal(credentials?.some(row => row.name === 'GITHUB_TOKEN'), true);
  const agents = status.body?.data?.agents as Array<{ name: string }> | undefined;
  assert.equal(agents?.some(row => row.name === 'Codex'), true);
  assert.match(String(status.body?.data?.backup_nudge ?? ''), /not backed up/i);

  const humanStatus = await cliResult('status', ...f.dirs);
  assert.match(humanStatus.stdout, /GITHUB_TOKEN/);
  assert.match(humanStatus.stdout, /Codex/);
  assert.match(humanStatus.stdout, /not backed up/);

  const audit = await cliResult('audit', '--json', ...f.dirs);
  assert.equal(JSON.stringify(audit.body).includes(SECRET), false);
  assert.equal(humanStatus.stdout.includes(SECRET), false);
  assert.equal(owner.stdout.includes(SECRET), false);
});
