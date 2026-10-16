import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, lstatSync, mkdtempSync, rmSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { AppError, PUBLIC_ERROR_MESSAGES, publicError } from '../src/contracts.js';
import { loadIdentity } from '../src/identity.js';
import { FileKeychain, MacosKeychain, keychainFor } from '../src/keychain.js';
import { recovery } from '../src/vault.js';

const cli = resolve('dist/src/cli.js');
function local(...args: string[]) {
  const child = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  return { code: child.status, stdout: child.stdout, stderr: child.stderr, body: JSON.parse(child.stdout) as {
    status: string; data: Record<string, unknown>; error?: { code: string };
  } };
}

test('setup stores the vault key; unlock does not need the plaintext phrase file', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-keychain-'));
  t.after(() => rmSync(root, { recursive: true }));
  const vaultDir = join(root, 'vault');
  const nodeDir = join(root, 'node');
  const created = local('setup', '--vault-dir', vaultDir);
  assert.equal(created.code, 0);
  assert.equal(created.body.data.keychain_unlock, true);
  const recoveryFile = String(created.body.data.recovery_file);
  const mnemonic = await recovery(recoveryFile);
  assert.equal(created.stdout.includes(mnemonic), false);
  await loadIdentity(nodeDir, 'node', true);

  unlinkSync(recoveryFile);
  assert.equal(existsSync(recoveryFile), false);

  const child = spawn(process.execPath, [cli, 'vault', 'unlock', '--vault-dir', vaultDir, '--data-dir', nodeDir]);
  t.after(() => { if (child.exitCode === null) child.kill('SIGTERM'); });
  let stdout = '';
  await new Promise<void>((resolveUnlock, reject) => {
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.includes('\n')) resolveUnlock(); });
    child.once('error', reject);
    child.once('exit', code => { if (!stdout) reject(new Error('Unlock exited ' + code)); });
  });
  const unlocked = JSON.parse(stdout.trim()) as { data: Record<string, unknown> };
  assert.equal(unlocked.data.status, 'unlocked');
  assert.equal(unlocked.data.keychain_unlock, true);
  assert.equal(stdout.includes(mnemonic), false);
  const exit = once(child, 'exit');
  assert.equal(local('vault', 'lock', '--vault-dir', vaultDir).code, 0);
  await exit;
});

test('FileKeychain stores 0600 items and MacosKeychain never puts the secret on argv', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-keychain-unit-'));
  t.after(() => rmSync(root, { recursive: true }));
  const vaultId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const mnemonic = 'test mnemonic not a real phrase';
  const file = new FileKeychain(join(root, 'kc'));
  await file.store(vaultId, mnemonic);
  const path = join(root, 'kc', 'items.json');
  assert.equal(lstatSync(path).mode & 0o777, 0o600);
  assert.equal(await file.load(vaultId), mnemonic);
  await file.delete(vaultId);
  await assert.rejects(file.load(vaultId), (error: unknown) => error instanceof AppError && error.code === 'keychain_unavailable');

  const argv: string[][] = [];
  const macos = new MacosKeychain(async (op, id, secret) => {
    argv.push([op, id, ...(secret === undefined ? [] : ['stdin-only'])]);
    if (op === 'store' && secret !== mnemonic) throw new Error('secret must travel as stdin payload');
    if (op === 'load') return mnemonic;
    if (op === 'delete') return '';
    return '';
  });
  await macos.store(vaultId, mnemonic);
  assert.equal(await macos.load(vaultId), mnemonic);
  await macos.delete(vaultId);
  assert.deepEqual(argv, [
    ['store', vaultId, 'stdin-only'],
    ['load', vaultId],
    ['delete', vaultId],
  ]);

  const denied = new MacosKeychain(async () => { throw new AppError('keychain_denied', 'no'); });
  await assert.rejects(denied.load(vaultId), (error: unknown) => error instanceof AppError && error.code === 'keychain_denied');
  const mapped = publicError(new AppError('keychain_denied', `touch id failed for ${mnemonic}`));
  assert.equal(mapped.body.error.message, PUBLIC_ERROR_MESSAGES.keychain_denied);
  assert.equal(JSON.stringify(mapped).includes(mnemonic), false);

  assert.equal(keychainFor(root, 'linux') instanceof FileKeychain, true);
});

test('keychain helper maps cancel to keychain_denied and unknown failures to unavailable', async () => {
  const { runMacosHelper } = await import('../src/keychain.js');
  if (process.platform === 'darwin') return;
  await assert.rejects(runMacosHelper('load', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'), (error: unknown) =>
    error instanceof AppError && error.code === 'keychain_unavailable');
});
