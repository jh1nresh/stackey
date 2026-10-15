import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { NOT_BACKED_UP_NUDGE, backupStatePath, defaultRecoveryPath, readBackupState } from '../src/backup-state.js';
import { loadIdentity } from '../src/identity.js';
import { recovery } from '../src/vault.js';

const cli = resolve('dist/src/cli.js');
function local(...args: string[]) {
  const child = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  return { code: child.status, stdout: child.stdout, stderr: child.stderr, body: JSON.parse(child.stdout) as {
    status: string; data: Record<string, unknown>; error?: { code: string };
  } };
}

test('stackey setup creates a vault without printing the recovery phrase and persists a not-backed-up nudge', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-setup-'));
  t.after(() => rmSync(root, { recursive: true }));
  const vaultDir = join(root, 'vault');
  const result = local('setup', '--vault-dir', vaultDir);
  assert.equal(result.code, 0);
  const recoveryFile = defaultRecoveryPath(vaultDir);
  assert.equal(result.body.data.recovery_file, recoveryFile);
  assert.equal(result.body.data.status, 'locked');
  assert.equal(result.body.data.backup_status, 'not_backed_up');
  assert.equal(result.body.data.backed_up, false);
  assert.equal(result.body.data.backup_nudge, NOT_BACKED_UP_NUDGE);
  assert.equal(typeof result.body.data.next_step, 'string');
  assert.ok(existsSync(join(vaultDir, 'vault.json')));
  assert.equal(lstatSync(recoveryFile).mode & 0o777, 0o600);
  const mnemonic = await recovery(recoveryFile);
  assert.equal(mnemonic.split(' ').length, 24);
  assert.ok(validateMnemonic(mnemonic, wordlist));
  assert.equal(result.stdout.includes(mnemonic), false);
  assert.equal(result.stderr.includes(mnemonic), false);
  const sidecar = readFileSync(backupStatePath(vaultDir), 'utf8');
  assert.equal(sidecar.includes(mnemonic), false);
  const state = readBackupState(vaultDir);
  assert.equal(state?.backed_up, false);
  assert.equal(state?.plaintext_recovery, true);
  assert.equal(state?.recovery_file, recoveryFile);

  const status = local('vault', 'status', '--vault-dir', vaultDir);
  assert.equal(status.code, 0);
  assert.equal(status.body.data.status, 'locked');
  assert.equal(status.body.data.backup_status, 'not_backed_up');
  assert.equal(status.body.data.backup_nudge, NOT_BACKED_UP_NUDGE);
  assert.equal(status.stdout.includes(mnemonic), false);

  const pairing = local('status', '--state-dir', join(root, 'agent'), '--vault-dir', vaultDir);
  assert.equal(pairing.code, 0);
  assert.equal(pairing.body.data.backup_status, 'not_backed_up');
  assert.equal(pairing.body.data.backup_nudge, NOT_BACKED_UP_NUDGE);

  const again = local('setup', '--vault-dir', vaultDir);
  assert.equal(again.code, 2);
  assert.equal(again.body.error?.code, 'output_exists');
});

test('vault init also records the not-backed-up nudge; missing sidecar still nudges', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-init-nudge-'));
  t.after(() => rmSync(root, { recursive: true }));
  const vaultDir = join(root, 'vault');
  const recoveryFile = join(root, 'recovery.json');
  const result = local('vault', 'init', '--vault-dir', vaultDir, '--recovery-out', recoveryFile);
  assert.equal(result.code, 0);
  assert.equal(result.body.data.backup_status, 'not_backed_up');
  assert.equal(result.body.data.backup_nudge, NOT_BACKED_UP_NUDGE);
  const mnemonic = await recovery(recoveryFile);
  assert.equal(result.stdout.includes(mnemonic), false);

  unlinkSync(backupStatePath(vaultDir));
  const status = local('vault', 'status', '--vault-dir', vaultDir);
  assert.equal(status.body.data.backup_status, 'not_backed_up');
  assert.equal(status.body.data.backup_nudge, NOT_BACKED_UP_NUDGE);
});

test('unlocked vault status keeps the not-backed-up nudge and never prints the phrase', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-setup-unlock-'));
  t.after(() => rmSync(root, { recursive: true }));
  const vaultDir = join(root, 'vault');
  const nodeDir = join(root, 'node');
  const created = local('setup', '--vault-dir', vaultDir);
  assert.equal(created.code, 0);
  const recoveryFile = String(created.body.data.recovery_file);
  const mnemonic = await recovery(recoveryFile);
  await loadIdentity(nodeDir, 'node', true);
  const child = spawn(process.execPath, [cli, 'vault', 'unlock', '--vault-dir', vaultDir, '--recovery-file', recoveryFile, '--data-dir', nodeDir]);
  t.after(() => { if (child.exitCode === null) child.kill('SIGTERM'); });
  let stdout = '';
  await new Promise<void>((resolve, reject) => {
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.includes('\n')) resolve(); });
    child.once('error', reject);
    child.once('exit', code => { if (!stdout) reject(new Error('Unlock exited ' + code)); });
  });
  const unlocked = JSON.parse(stdout.trim()) as { data: Record<string, unknown> };
  assert.equal(unlocked.data.status, 'unlocked');
  assert.equal(unlocked.data.backup_status, 'not_backed_up');
  assert.equal(unlocked.data.backup_nudge, NOT_BACKED_UP_NUDGE);
  assert.equal(stdout.includes(mnemonic), false);
  const status = local('vault', 'status', '--vault-dir', vaultDir);
  assert.equal(status.body.data.status, 'unlocked');
  assert.equal(status.body.data.backup_status, 'not_backed_up');
  assert.equal(status.body.data.backup_nudge, NOT_BACKED_UP_NUDGE);
  assert.equal(status.stdout.includes(mnemonic), false);
  const exit = once(child, 'exit');
  assert.equal(local('vault', 'lock', '--vault-dir', vaultDir).code, 0);
  await exit;
});
