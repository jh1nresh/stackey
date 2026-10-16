import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { NOT_BACKED_UP_NUDGE, backupStatusFields, readBackupState } from '../src/backup-state.js';
import { pickConfirmPositions, runPhraseBackup, secureDelete } from '../src/backup-phrase.js';
import { AppError, PUBLIC_ERROR_MESSAGES, publicError } from '../src/contracts.js';
import { writePrivateJson } from '../src/identity.js';
import { recovery } from '../src/vault.js';

const cli = resolve('dist/src/cli.js');
function local(...args: string[]) {
  const child = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
  return { code: child.status, stdout: child.stdout, stderr: child.stderr, body: JSON.parse(child.stdout) as {
    status: string; data: Record<string, unknown>; error?: { code: string };
  } };
}

async function waitFor(check: () => boolean, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  while (!check()) {
    if (Date.now() - start > timeoutMs) throw new Error('timeout');
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}

function pickSequence(values: number[]) {
  let index = 0;
  return () => {
    const value = values[index];
    if (value === undefined) throw new Error('pick exhausted');
    index += 1;
    return value;
  };
}

test('pickConfirmPositions returns three distinct 1-based indexes', () => {
  const positions = pickConfirmPositions(24, 3, pickSequence([0, 0, 5, 11]));
  assert.deepEqual(positions, [1, 6, 12]);
});

test('phrase is hidden until Enter; three matching words clear the nudge and can wipe the plaintext file', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-backup-'));
  t.after(() => rmSync(root, { recursive: true }));
  const vaultDir = join(root, 'vault');
  const created = local('setup', '--vault-dir', vaultDir);
  assert.equal(created.code, 0);
  const recoveryFile = String(created.body.data.recovery_file);
  const mnemonic = await recovery(recoveryFile);
  const words = mnemonic.split(' ');
  const humanChunks: string[] = [];
  const human = new PassThrough();
  human.on('data', chunk => { humanChunks.push(chunk.toString()); });
  const input = new PassThrough();
  const running = runPhraseBackup(vaultDir, { input, human, pick: pickSequence([0, 5, 11]) });
  await waitFor(() => humanChunks.join('').includes('Press Enter to show the 24 words.'));
  const before = humanChunks.join('');
  assert.equal(before.includes(`1. ${words[0]}`), false);
  assert.equal(before.includes(`24. ${words[23]}`), false);
  input.write('\n');
  await waitFor(() => humanChunks.join('').includes('Confirm word 1:'));
  const revealed = humanChunks.join('');
  assert.equal(revealed.includes(`1. ${words[0]}`), true);
  assert.equal(revealed.includes(`24. ${words[23]}`), true);
  input.write(words[0] + '\n');
  await waitFor(() => humanChunks.join('').includes('Confirm word 6:'));
  input.write(words[5] + '\n');
  await waitFor(() => humanChunks.join('').includes('Confirm word 12:'));
  input.write(words[11] + '\n');
  await waitFor(() => humanChunks.join('').includes('Delete the plaintext recovery file'));
  input.write('y\n');
  const result = await running;
  assert.equal(result.backed_up, true);
  assert.equal(result.backup_status, 'backed_up');
  assert.equal(result.backup_nudge, undefined);
  assert.equal(result.deleted_plaintext, true);
  assert.equal(result.plaintext_recovery, false);
  assert.equal(JSON.stringify(result).includes(mnemonic), false);
  assert.equal(existsSync(recoveryFile), false);
  const status = local('vault', 'status', '--vault-dir', vaultDir);
  assert.equal(status.body.data.backup_status, 'backed_up');
  assert.equal(status.body.data.backup_nudge, undefined);
  assert.equal(status.body.data.plaintext_recovery, false);
  assert.equal(status.stdout.includes(mnemonic), false);
});

test('wrong confirmation word leaves the not-backed-up nudge and the plaintext file', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-backup-fail-'));
  t.after(() => rmSync(root, { recursive: true }));
  const vaultDir = join(root, 'vault');
  const created = local('setup', '--vault-dir', vaultDir);
  const recoveryFile = String(created.body.data.recovery_file);
  const mnemonic = await recovery(recoveryFile);
  const humanChunks: string[] = [];
  const human = new PassThrough();
  human.on('data', chunk => { humanChunks.push(chunk.toString()); });
  const input = new PassThrough();
  const running = runPhraseBackup(vaultDir, { input, human, pick: pickSequence([1, 2, 3]) });
  await waitFor(() => humanChunks.join('').includes('Press Enter to show the 24 words.'));
  input.write('\n');
  await waitFor(() => humanChunks.join('').includes('Confirm word 2:'));
  input.write('wrong\n');
  await assert.rejects(running, (error: unknown) => error instanceof AppError && error.code === 'backup_confirm_failed');
  assert.equal(existsSync(recoveryFile), true);
  assert.equal(readBackupState(vaultDir)?.backed_up, false);
  assert.equal(backupStatusFields(vaultDir).backup_nudge, NOT_BACKED_UP_NUDGE);
  const mapped = publicError(new AppError('backup_confirm_failed', mnemonic));
  assert.equal(mapped.body.error.message, PUBLIC_ERROR_MESSAGES.backup_confirm_failed);
  assert.equal(JSON.stringify(mapped).includes(mnemonic), false);
});

test('CLI backup reveals only after Enter, confirms words from stderr prompts, and JSON never contains the phrase', async t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-backup-cli-'));
  t.after(() => rmSync(root, { recursive: true }));
  const vaultDir = join(root, 'vault');
  const created = local('setup', '--vault-dir', vaultDir);
  const recoveryFile = String(created.body.data.recovery_file);
  const mnemonic = await recovery(recoveryFile);
  const words = mnemonic.split(' ');
  const child = spawn(process.execPath, [cli, 'backup', '--vault-dir', vaultDir], { stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null) child.kill('SIGTERM'); });
  let stderr = '';
  let stdout = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdout.on('data', chunk => { stdout += chunk; });
  await waitFor(() => stderr.includes('Press Enter to show the 24 words.'));
  assert.equal(stderr.includes(`1. ${words[0]}`), false);
  assert.equal(stdout.includes(mnemonic), false);
  child.stdin.write('\n');
  await waitFor(() => /Confirm word (\d+):/.test(stderr) && stderr.includes(`1. ${words[0]}`));
  for (let i = 0; i < 3; i++) {
    await waitFor(() => (stderr.match(/Confirm word (\d+):/g) ?? []).length >= i + 1);
    const matches = [...stderr.matchAll(/Confirm word (\d+):/g)];
    const position = Number(matches[i]![1]);
    child.stdin.write(words[position - 1] + '\n');
  }
  await waitFor(() => stderr.includes('Delete the plaintext recovery file'));
  child.stdin.write('n\n');
  const [code] = await new Promise<[number | null]>((resolveExit) => child.once('exit', code => resolveExit([code])));
  assert.equal(code, 0);
  const body = JSON.parse(stdout) as { data: Record<string, unknown> };
  assert.equal(body.data.backed_up, true);
  assert.equal(body.data.backup_status, 'backed_up');
  assert.equal(body.data.deleted_plaintext, false);
  assert.equal(existsSync(recoveryFile), true);
  assert.equal(stdout.includes(mnemonic), false);
});

test('secureDelete overwrites a private file before unlinking', t => {
  const root = mkdtempSync(join(tmpdir(), 'stackey-secure-delete-'));
  t.after(() => rmSync(root, { recursive: true }));
  const path = join(root, 'secret.json');
  writePrivateJson(path, { mnemonic: 'secret-canary-value' });
  secureDelete(path);
  assert.equal(existsSync(path), false);
});
