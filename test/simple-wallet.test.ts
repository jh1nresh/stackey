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
import { ACCESS_WAIT_MS } from '../src/agent-client.js';
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
    const timedOut = createAccessRequest(store, '11111111-1111-1111-1111-111111111111', 'agent-a', {
      connection_id: 'connection_demo', credential_id: 'credential_demo', credential_name: 'GITHUB_TOKEN',
    }, 200, 2);
    assert.equal(listPendingAccessRequests(store, 201).some(row => row.request_id === timedOut.request_id), true);
    assert.equal(listPendingAccessRequests(store, 203).some(row => row.request_id === timedOut.request_id), false);
    assert.equal(listPendingAccessRequests(store, 203).length, 0);
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

  const paired = await cliResult('connect', code, '--state-dir', f.agentDir, '--json', ...f.dirs);
  assert.equal(paired.code, 0, paired.stderr + paired.stdout);
  assert.equal(paired.body?.status, 'approval_required');
  assert.equal(paired.body?.data?.display_name, `agent-${code}`);
  assert.deepEqual(paired.body?.data?.granted_actions, []);

  const reused = await cliResult('connect', code, '--state-dir', join(f.root, 'agent-2'), '--json', ...f.dirs);
  assert.equal(reused.body?.error?.code, 'pairing_code_invalid');
  assert.equal(reused.code, 5);

  const denied = await cliResult('credential', 'get', '--no-wait', '--state-dir', f.agentDir, ...f.dirs);
  assert.equal(denied.code, 5, denied.stderr + denied.stdout);
  assert.equal(denied.body?.error?.code, 'permission_denied');

  const denialStatus = await cliResult('status', '--json', ...f.dirs);
  const denials = denialStatus.body?.data?.recent_denials as Array<{ reason?: string; at?: string }> | undefined;
  assert.equal(denials?.some(row => row.reason === 'permission denied'), true, JSON.stringify(denials));
  assert.equal(denials?.every(row => typeof row.at === 'string' && !/^\d{10}$/.test(row.at)), true);

  const getting = cliResult('credential', 'get', '--state-dir', f.agentDir, ...f.dirs);
  let pending = false;
  for (let i = 0; i < 40; i++) {
    const status = await cliResult('status', '--json', ...f.dirs);
    const requests = status.body?.data?.pending_requests as Array<{ agent?: string; credential?: string }> | undefined;
    if (requests?.some(row => row.credential === 'GITHUB_TOKEN' && row.agent === `agent-${code}`)) { pending = true; break; }
    await delay(250);
  }
  assert.equal(pending, true, 'owner status never showed the pending request');
  const prompt = await cliResult('approve', ...f.dirs);
  assert.match(prompt.stdout, new RegExp(`agent-${code} wants GITHUB_TOKEN once`));
  assert.equal(/Agent Agent|Agent Codex/.test(prompt.stdout), false);
  const approved = await cliResult('approve', '--yes', '--json', ...f.dirs);
  assert.equal(approved.code, 0, approved.stderr + approved.stdout);
  assert.equal(approved.body?.data?.decision, 'approved');
  assert.equal(Object.hasOwn(approved.body?.data ?? {}, 'grant_id'), false);

  const fetched = await getting;
  assert.equal(fetched.code, 0, fetched.stderr + fetched.stdout);
  assert.deepEqual(fetched.body, { value: SECRET });
  assert.match(fetched.stderr, /owner approval is required; requesting new approval/);

  const status = await cliResult('status', '--json', ...f.dirs);
  assert.equal(status.code, 0, status.stderr + status.stdout);
  const credentials = status.body?.data?.credentials as Array<{ name: string }> | undefined;
  assert.equal(credentials?.some(row => row.name === 'GITHUB_TOKEN'), true);
  const agents = status.body?.data?.agents as Array<{ name: string }> | undefined;
  assert.equal(agents?.some(row => row.name === `agent-${code}`), true);
  assert.match(String(status.body?.data?.backup_nudge ?? ''), /not backed up/i);

  const humanStatus = await cliResult('status', ...f.dirs);
  assert.match(humanStatus.stdout, /GITHUB_TOKEN/);
  assert.match(humanStatus.stdout, new RegExp(`agent-${code}`));
  assert.match(humanStatus.stdout, /not backed up/);
  assert.match(humanStatus.stdout, /permission denied/);
  assert.equal(/\(\d{10,}\)/.test(humanStatus.stdout), false);

  const spentWait = cliResult('credential', 'get', '--state-dir', f.agentDir, ...f.dirs);
  let spentPending = false;
  for (let i = 0; i < 40; i++) {
    const live = await cliResult('status', '--json', ...f.dirs);
    const requests = live.body?.data?.pending_requests as Array<{ credential?: string }> | undefined;
    if (requests?.some(row => row.credential === 'GITHUB_TOKEN')) { spentPending = true; break; }
    await delay(250);
  }
  assert.equal(spentPending, true, 'spent get never queued a new approval request');
  const reapproved = await cliResult('approve', '--yes', '--json', ...f.dirs);
  assert.equal(reapproved.code, 0, reapproved.stderr + reapproved.stdout);
  const spentFetched = await spentWait;
  assert.equal(spentFetched.code, 0, spentFetched.stderr + spentFetched.stdout);
  assert.deepEqual(spentFetched.body, { value: SECRET });
  assert.match(spentFetched.stderr, /previous grant was spent; requesting new approval/);

  const locked = await cliResult('vault', 'lock', '--vault-dir', f.vaultDir);
  assert.equal(locked.code, 0, locked.stderr + locked.stdout);
  const lockedStatus = await cliResult('status', ...f.dirs);
  assert.match(lockedStatus.stdout, /Vault locked — run `stackey` to unlock/);
  assert.equal(/Credentials/.test(lockedStatus.stdout), false);

  const audit = await cliResult('audit', '--json', ...f.dirs);
  assert.equal(JSON.stringify(audit.body).includes(SECRET), false);
  assert.equal(humanStatus.stdout.includes(SECRET), false);
  assert.equal(owner.stdout.includes(SECRET), false);
});

test('waiting credential get for 120s+ does not rate-limit the agent or live status', { timeout: 210_000 }, async t => {
  const f = await workspace(t);
  assert.equal((await cliResult('init', '--json', ...f.dirs)).code, 0);
  const secretFile = join(f.root, 'secret.json');
  writePrivateJson(secretFile, { value: SECRET });
  assert.equal((await cliResult('add', 'GITHUB_TOKEN', '--secret-file', secretFile, '--json', ...f.dirs)).code, 0);
  const owner = await cliResult('connect', '--json', ...f.dirs);
  const code = String(owner.body?.data?.code ?? '');
  assert.match(code, PAIR_CODE_RE);
  assert.equal((await cliResult('connect', code, '--state-dir', f.agentDir, '--json', ...f.dirs)).code, 0);

  const started = Date.now();
  let getElapsed = 0;
  const getting = cliResult('credential', 'get', '--state-dir', f.agentDir, ...f.dirs).then(result => {
    getElapsed = Date.now() - started;
    return result;
  });
  const liveCodes: Array<{ at: number; code: unknown; error: string | undefined }> = [];
  while (Date.now() - started < ACCESS_WAIT_MS + 5_000) {
    const live = await cliResult('status', '--live', '--state-dir', f.agentDir, ...f.dirs);
    liveCodes.push({ at: Date.now() - started, code: live.code, error: live.body?.error?.code });
    assert.notEqual(live.body?.error?.code, 'rate_limited', live.stdout + live.stderr);
    assert.notEqual(live.code, 4, live.stdout + live.stderr);
    await delay(10_000);
  }
  const fetched = await getting;
  assert.ok(getElapsed >= 115_000, `credential get returned after ${getElapsed}ms`);
  assert.notEqual(fetched.body?.error?.code, 'rate_limited', fetched.stdout + fetched.stderr);
  assert.notEqual(fetched.code, 4, fetched.stdout + fetched.stderr);
  assert.equal(fetched.code, 5, fetched.stdout + fetched.stderr);
  assert.equal(fetched.body?.error?.code, 'permission_denied');
  assert.equal(liveCodes.length > 10, true, JSON.stringify(liveCodes));
  assert.equal(liveCodes.every(row => row.error !== 'rate_limited' && row.code !== 4), true);

  const lateStatus = await cliResult('status', '--json', ...f.dirs);
  const pending = lateStatus.body?.data?.pending_requests as Array<{ credential?: string }> | undefined;
  assert.equal((pending ?? []).length, 0, 'timed-out requests must drop off pending');
});
