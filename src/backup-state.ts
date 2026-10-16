import { existsSync, lstatSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { AppError, record, textField } from './contracts.js';
import { privateDirectory, readPrivateJson, replacePrivateJson, writePrivateJson } from './identity.js';

export const NOT_BACKED_UP_NUDGE = 'This vault is not backed up. Run stackey backup to write down your recovery phrase.';
export const BACKUP_STATE_FORMAT = 'stackey-backup-state';

export interface BackupState {
  format: typeof BACKUP_STATE_FORMAT;
  version: 1;
  vault_id: string;
  recovery_file: string;
  backed_up: boolean;
  plaintext_recovery: boolean;
  keychain_unlock: boolean;
  icloud_backup: boolean;
}

export interface BackupStatusFields {
  backup_status: 'not_backed_up' | 'backed_up';
  backed_up: boolean;
  plaintext_recovery: boolean;
  keychain_unlock: boolean;
  icloud_backup: boolean;
  backup_nudge?: string;
}

export function backupStatePath(dir: string): string {
  return join(resolve(dir), 'backup-state.json');
}

export function defaultRecoveryPath(vaultDir: string): string {
  return join(resolve(vaultDir), '..', 'recovery.json');
}

export function writeBackupState(dir: string, state: BackupState): void {
  privateDirectory(dir);
  writePrivateJson(backupStatePath(dir), state);
}

export function createBackupState(dir: string, vaultId: string, recoveryFile: string): BackupState {
  const state: BackupState = {
    format: BACKUP_STATE_FORMAT,
    version: 1,
    vault_id: vaultId,
    recovery_file: resolve(recoveryFile),
    backed_up: false,
    plaintext_recovery: true,
    keychain_unlock: false,
    icloud_backup: false,
  };
  writeBackupState(dir, state);
  return state;
}

export function readBackupState(dir: string): BackupState | undefined {
  const path = backupStatePath(dir);
  if (!existsSync(path)) return undefined;
  const raw = record(readPrivateJson(path));
  if (raw.format !== BACKUP_STATE_FORMAT || raw.version !== 1) {
    throw new AppError('invalid_state', 'Backup state file is invalid.');
  }
  const vault_id = textField(raw.vault_id, 36);
  if (!/^[0-9a-f-]{36}$/.test(vault_id)) throw new AppError('invalid_state', 'Backup state file is invalid.');
  const recovery_file = textField(raw.recovery_file, 4096);
  if (typeof raw.backed_up !== 'boolean' || typeof raw.plaintext_recovery !== 'boolean') {
    throw new AppError('invalid_state', 'Backup state file is invalid.');
  }
  const keychain_unlock = raw.keychain_unlock === undefined ? false : raw.keychain_unlock === true;
  if (raw.keychain_unlock !== undefined && typeof raw.keychain_unlock !== 'boolean') {
    throw new AppError('invalid_state', 'Backup state file is invalid.');
  }
  const icloud_backup = raw.icloud_backup === undefined ? false : raw.icloud_backup === true;
  if (raw.icloud_backup !== undefined && typeof raw.icloud_backup !== 'boolean') {
    throw new AppError('invalid_state', 'Backup state file is invalid.');
  }
  return {
    format: BACKUP_STATE_FORMAT,
    version: 1,
    vault_id,
    recovery_file,
    backed_up: raw.backed_up,
    plaintext_recovery: raw.plaintext_recovery,
    keychain_unlock,
    icloud_backup,
  };
}

export function updateBackupState(dir: string, patch: Partial<Pick<BackupState, 'backed_up' | 'plaintext_recovery' | 'keychain_unlock' | 'icloud_backup' | 'recovery_file'>>): BackupState {
  const current = readBackupState(dir);
  if (!current) throw new AppError('invalid_state', 'Backup state file is invalid.');
  const next: BackupState = { ...current, ...patch };
  replacePrivateJson(backupStatePath(dir), next);
  return next;
}

export function vaultExists(dir: string): boolean {
  const path = join(resolve(dir), 'vault.json');
  if (!existsSync(path)) return false;
  try {
    const stat = lstatSync(path);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch { return false; }
}

export function backupStatusFields(dir: string): BackupStatusFields | Record<string, never> {
  if (!vaultExists(dir)) return {};
  let state: BackupState | undefined;
  try { state = readBackupState(dir); } catch { state = undefined; }
  if (state?.backed_up) {
    return {
      backup_status: 'backed_up',
      backed_up: true,
      plaintext_recovery: state.plaintext_recovery,
      keychain_unlock: state.keychain_unlock,
      icloud_backup: state.icloud_backup,
    };
  }
  return {
    backup_status: 'not_backed_up',
    backed_up: false,
    plaintext_recovery: state?.plaintext_recovery ?? true,
    keychain_unlock: state?.keychain_unlock ?? false,
    icloud_backup: state?.icloud_backup ?? false,
    backup_nudge: NOT_BACKED_UP_NUDGE,
  };
}

export function withBackupStatus<T extends Record<string, unknown>>(dir: string, data: T): T & Partial<BackupStatusFields> {
  return { ...data, ...backupStatusFields(dir) };
}
