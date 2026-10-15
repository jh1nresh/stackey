import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { AppError, PUBLIC_ERROR_MESSAGES, publicError } from '../src/contracts.js';
import { writePrivateJson } from '../src/identity.js';
import { backupToIcloud, restoreFromIcloud } from '../src/icloud-backup.js';
import { openVault, recovery } from '../src/vault.js';

const cli = resolve('dist/src/cli.js');
function local(env: NodeJS.ProcessEnv, ...args: string[]) {
  const child = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
  return { code: child.status, stdout: child.stdout, stderr: child.stderr, body: JSON.parse(child.stdout) as {
    status: string; data: Record<string, unknown>; error?: { code: string };
  } };
}

test('icloud backup encrypts phrase and vault with scrypt; restore opens the same secrets', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-icloud-'));
  t.after(() => rmSync(root, { recursive: true }));
  const vaultDir = join(root, 'vault');
  const icloud = join(root, 'icloud');
  const env = { STACKEY_ICLOUD_DIR: icloud, STACKEY_SCRYPT_N: '4096' };
  Object.assign(process.env, env);
  const created = local(env, 'setup', '--vault-dir', vaultDir);
  assert.equal(created.code, 0);
  const recoveryFile = String(created.body.data.recovery_file);
  const mnemonic = await recovery(recoveryFile);
  const opened = await openVault(vaultDir, mnemonic);
  opened.data.credentials.push({
    id: 'credential_' + randomUUID(), wallet_id: 'wallet_demo', name: 'API', kind: 'api_key', value: 'fixture-icloud-secret',
  });
  opened.save(opened.data);
  opened.close();

  const passwordFile = join(root, 'password.json');
  const password = 'test-backup-password';
  writePrivateJson(passwordFile, { password });
  const backup = local(env, 'backup', '--icloud', '--vault-dir', vaultDir, '--password-file', passwordFile);
  assert.equal(backup.code, 0);
  assert.equal(backup.body.data.icloud, true);
  assert.equal(backup.body.data.encrypted, true);
  assert.equal(backup.body.data.kdf, 'scrypt');
  assert.equal(backup.body.data.icloud_backup, true);
  assert.equal(backup.stdout.includes(mnemonic), false);
  assert.equal(backup.stdout.includes(password), false);
  const backupFile = String(backup.body.data.backup_file);
  assert.equal(existsSync(backupFile), true);
  const raw = readFileSync(backupFile, 'utf8');
  assert.equal(raw.includes(mnemonic), false);
  assert.equal(raw.includes(password), false);
  assert.equal(raw.includes('fixture-icloud-secret'), false);
  assert.equal(JSON.parse(raw).kdf, 'scrypt');

  const restoredDir = join(root, 'restored');
  const restored = local(env, 'restore', '--vault-dir', restoredDir, '--password-file', passwordFile, '--backup-file', backupFile);
  assert.equal(restored.code, 0);
  assert.equal(restored.body.data.icloud, true);
  assert.equal(restored.body.data.keychain_unlock, true);
  assert.equal(restored.stdout.includes(mnemonic), false);
  const recovered = await openVault(restoredDir, mnemonic);
  assert.equal(recovered.data.credentials[0]?.value, 'fixture-icloud-secret');
  recovered.close();

  const wrongPassword = join(root, 'wrong.json');
  writePrivateJson(wrongPassword, { password: 'wrong-password-value' });
  const failed = local(env, 'restore', '--vault-dir', join(root, 'failed'), '--password-file', wrongPassword, '--backup-file', backupFile);
  assert.equal(failed.code, 2);
  assert.equal(failed.body.error?.code, 'invalid_backup_password');
  assert.equal(failed.stdout.includes(password), false);
  assert.equal(existsSync(join(root, 'failed', 'vault.json')), false);

  const missing = local(env, 'backup', '--icloud', '--vault-dir', vaultDir);
  assert.equal(missing.body.error?.code, 'backup_password_required');

  const mapped = publicError(new AppError('invalid_backup_password', password));
  assert.equal(mapped.body.error.message, PUBLIC_ERROR_MESSAGES.invalid_backup_password);
  assert.equal(JSON.stringify(mapped).includes(password), false);
});

test('in-process icloud backup round-trip and reject a short password', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-icloud-unit-'));
  t.after(() => rmSync(root, { recursive: true }));
  process.env.STACKEY_SCRYPT_N = '4096';
  process.env.STACKEY_ICLOUD_DIR = join(root, 'icloud');
  const vaultDir = join(root, 'vault');
  const created = local({ STACKEY_ICLOUD_DIR: process.env.STACKEY_ICLOUD_DIR, STACKEY_SCRYPT_N: '4096' }, 'setup', '--vault-dir', vaultDir);
  assert.equal(created.code, 0);
  const result = await backupToIcloud(vaultDir, 'unit-test-password-ok');
  const target = join(root, 'from-api');
  const restored = await restoreFromIcloud(target, 'unit-test-password-ok', String(result.backup_file));
  assert.equal(restored.icloud, true);
  await assert.rejects(restoreFromIcloud(join(root, 'bad'), 'short', String(result.backup_file)), (error: unknown) =>
    error instanceof AppError && (error.code === 'invalid_backup_password' || error.code === 'invalid_format'));
});
