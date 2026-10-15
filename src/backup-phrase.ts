import { randomBytes, randomInt } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, openSync, unlinkSync, writeFileSync } from 'node:fs';
import { createInterface, type Interface } from 'node:readline/promises';
import { AppError } from './contracts.js';
import { resolveUnlockMnemonic } from './vault-session.js';
import { readBackupState, updateBackupState, withBackupStatus } from './backup-state.js';

export function pickConfirmPositions(total = 24, count = 3, pick: (max: number) => number = randomInt): number[] {
  if (count > total) throw new AppError('invalid_parameters', 'Unexpected vault parameters.');
  const positions = new Set<number>();
  while (positions.size < count) positions.add(pick(total) + 1);
  return [...positions].sort((a, b) => a - b);
}

export function secureDelete(path: string): void {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
      (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) {
    throw new AppError('unsafe_state_file', 'State file must be a private regular file.');
  }
  const fd = openSync(path, 'r+');
  try {
    const size = Math.max(stat.size, 64);
    writeFileSync(fd, randomBytes(size));
    fsyncSync(fd);
  } finally { closeSync(fd); }
  unlinkSync(path);
}

export interface PhraseBackupIo {
  input: NodeJS.ReadableStream;
  human: NodeJS.WritableStream;
  pick?: (max: number) => number;
}

export async function confirmRecoveryPhrase(mnemonic: string, io: PhraseBackupIo, rl: Interface): Promise<number[]> {
  const words = mnemonic.split(' ');
  if (words.length !== 24) throw new AppError('invalid_vault', 'Vault format, recovery material or integrity check failed.');
  io.human.write('This is your Stackey recovery phrase. Anyone with it can open this vault.\n');
  io.human.write('It will be shown only after you press Enter.\n');
  await rl.question('Press Enter to show the 24 words.\n');
  words.forEach((word, index) => { io.human.write(`${index + 1}. ${word}\n`); });
  io.human.write('Write these words down offline. Confirm three random words next.\n');
  const positions = pickConfirmPositions(24, 3, io.pick);
  for (const position of positions) {
    const answer = (await rl.question(`Confirm word ${position}:\n`)).trim().toLowerCase();
    const expected = words[position - 1]!;
    if (answer !== expected) {
      throw new AppError('backup_confirm_failed', 'Recovery confirmation did not match. The not-backed-up nudge was not cleared.');
    }
  }
  io.human.write('Recovery phrase confirmed.\n');
  return positions;
}

export async function runPhraseBackup(vaultDir: string, io: PhraseBackupIo, recoveryFile?: string): Promise<Record<string, unknown>> {
  const mnemonic = await resolveUnlockMnemonic(vaultDir, recoveryFile);
  const rl = createInterface({ input: io.input, output: io.human, terminal: false });
  try {
    await confirmRecoveryPhrase(mnemonic, io, rl);
    updateBackupState(vaultDir, { backed_up: true });
    const state = readBackupState(vaultDir);
    let deleted_plaintext = false;
    const target = state?.plaintext_recovery ? state.recovery_file : undefined;
    if (target && existsSync(target)) {
      const answer = (await rl.question(`Delete the plaintext recovery file at ${target}? [y/N]\n`)).trim().toLowerCase();
      if (answer === 'y' || answer === 'yes') {
        secureDelete(target);
        updateBackupState(vaultDir, { plaintext_recovery: false });
        deleted_plaintext = true;
        io.human.write('Plaintext recovery file securely deleted.\n');
      }
    }
    return withBackupStatus(vaultDir, {
      backed_up: true,
      deleted_plaintext,
      next_step: deleted_plaintext
        ? 'Unlock with Keychain or Touch ID. Keep the paper backup offline.'
        : 'Keep the paper backup offline. You can delete the plaintext recovery file later.',
    });
  } finally {
    rl.close();
  }
}
