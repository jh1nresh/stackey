import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createBackupState, updateBackupState, withBackupStatus } from './backup-state.js';
import { AppError, record, textField } from './contracts.js';
import { privateDirectory, readPrivateJson } from './identity.js';
import { storeVaultKey } from './keychain.js';
import { backupVault, restoreVault } from './vault.js';
import { resolveUnlockMnemonic } from './vault-session.js';
import { secureDelete } from './backup-phrase.js';

const ICLOUD_FORMAT = 'stackey-icloud-backup';
const ALLOWED_N = new Set([4096, 8192, 16384, 32768, 65536, 131072]);

export function scryptParams(): { N: number; r: number; p: number; keylen: number } {
  const N = Number(process.env.STACKEY_SCRYPT_N ?? 32768);
  if (!ALLOWED_N.has(N)) throw new AppError('invalid_parameters', 'Unexpected vault parameters.');
  return { N, r: 8, p: 1, keylen: 32 };
}

export function icloudDirectory(): string {
  if (process.env.STACKEY_ICLOUD_DIR) return resolve(process.env.STACKEY_ICLOUD_DIR);
  if (process.platform === 'darwin') {
    const dir = join(homedir(), 'Library/Mobile Documents/com~apple~CloudDocs');
    if (!existsSync(dir)) throw new AppError('icloud_unavailable', 'iCloud Drive is not available. Set STACKEY_ICLOUD_DIR or run this on macOS with iCloud Drive.');
    return dir;
  }
  throw new AppError('icloud_unavailable', 'iCloud Drive is not available. Set STACKEY_ICLOUD_DIR or run this on macOS with iCloud Drive.');
}

export function icloudBackupPath(vaultId: string, directory = icloudDirectory()): string {
  return join(directory, 'Stackey', `vault-${textField(vaultId, 36)}.json`);
}

function requirePassword(password: string): string {
  if (password.length < 8 || password.length > 256) throw new AppError('invalid_backup_password', 'iCloud backup password was rejected.');
  return password;
}

export function readBackupPassword(passwordFile: string): string {
  return requirePassword(textField(record(readPrivateJson(resolve(passwordFile))).password, 256));
}

function derive(password: string, salt: Buffer, N: number, r: number, p: number, keylen: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, { N, r, p, maxmem: 256 * 1024 * 1024 }, (error, key) => {
      if (error || !key) reject(error ?? new AppError('invalid_backup_password', 'iCloud backup password was rejected.'));
      else resolve(key);
    });
  });
}

function seal(key: Buffer, plain: Buffer, aad: unknown) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify(aad)));
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  return { iv: iv.toString('base64url'), ciphertext: encrypted.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') };
}

function unseal(key: Buffer, value: { iv: string; ciphertext: string; tag: string }, aad: unknown) {
  const decode = (text: string, size?: number) => {
    const buf = Buffer.from(text, 'base64url');
    if (buf.toString('base64url') !== text || (size !== undefined && buf.length !== size)) {
      throw new AppError('invalid_backup_password', 'iCloud backup password was rejected.');
    }
    return buf;
  };
  const cipher = createDecipheriv('aes-256-gcm', key, decode(value.iv, 12));
  cipher.setAAD(Buffer.from(JSON.stringify(aad)));
  cipher.setAuthTag(decode(value.tag, 16));
  return Buffer.concat([cipher.update(decode(value.ciphertext)), cipher.final()]);
}

function writeIcloudFile(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  try {
    writeFileSync(path, JSON.stringify(value) + '\n', { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new AppError('output_exists', 'Output already exists; choose a new filename.');
    throw error;
  }
}

export async function backupToIcloud(vaultDir: string, password: string, directory = icloudDirectory()): Promise<Record<string, unknown>> {
  requirePassword(password);
  const mnemonic = await resolveUnlockMnemonic(vaultDir);
  const scratch = join(privateDirectory(join(tmpdir(), 'stackey-icloud-' + randomBytes(8).toString('hex'))), 'vault.json');
  try {
    const copied = backupVault(vaultDir, scratch);
    const params = scryptParams();
    const salt = randomBytes(32);
    const key = await derive(password, salt, params.N, params.r, params.p, params.keylen);
    try {
      const aad = {
        format: ICLOUD_FORMAT, version: 1, kdf: 'scrypt', ...params,
        salt: salt.toString('base64url'), vault_id: copied.vault_id, purpose: 'icloud-backup',
      };
      const plain = Buffer.from(JSON.stringify({ mnemonic, vault: JSON.parse(readFileSync(scratch, 'utf8')) }));
      const wrapped = seal(key, plain, aad);
      plain.fill(0);
      const target = icloudBackupPath(copied.vault_id, directory);
      writeIcloudFile(target, { ...aad, wrapped });
      try { updateBackupState(vaultDir, { icloud_backup: true }); } catch { /* sidecar is best-effort */ }
      return withBackupStatus(vaultDir, {
        backup_file: target,
        vault_id: copied.vault_id,
        encrypted: true,
        kdf: 'scrypt',
        icloud: true,
      });
    } finally { key.fill(0); }
  } finally {
    if (existsSync(scratch)) secureDelete(scratch);
  }
}

function parseIcloudBackup(raw: unknown) {
  const value = record(raw);
  if (value.format !== ICLOUD_FORMAT || value.version !== 1 || value.kdf !== 'scrypt' || value.purpose !== 'icloud-backup') {
    throw new AppError('invalid_vault', 'Vault format, recovery material or integrity check failed.');
  }
  const N = Number(value.N); const r = Number(value.r); const p = Number(value.p); const keylen = Number(value.keylen);
  if (!ALLOWED_N.has(N) || r !== 8 || p !== 1 || keylen !== 32) {
    throw new AppError('invalid_vault', 'Vault format, recovery material or integrity check failed.');
  }
  const salt = textField(value.salt, 64);
  const vault_id = textField(value.vault_id, 36);
  const wrapped = record(value.wrapped);
  return {
    N, r, p, keylen, salt, vault_id,
    wrapped: { iv: textField(wrapped.iv, 32), ciphertext: textField(wrapped.ciphertext, 8_000_000), tag: textField(wrapped.tag, 32) },
    aad: { format: ICLOUD_FORMAT, version: 1, kdf: 'scrypt', N, r, p, keylen, salt, vault_id, purpose: 'icloud-backup' },
  };
}

export function findIcloudBackup(directory = icloudDirectory(), vaultId?: string): string {
  if (vaultId) {
    const path = icloudBackupPath(vaultId, directory);
    if (!existsSync(path)) throw new AppError('icloud_unavailable', 'iCloud Drive is not available. Set STACKEY_ICLOUD_DIR or run this on macOS with iCloud Drive.');
    return path;
  }
  const folder = join(directory, 'Stackey');
  if (!existsSync(folder)) throw new AppError('icloud_unavailable', 'iCloud Drive is not available. Set STACKEY_ICLOUD_DIR or run this on macOS with iCloud Drive.');
  const files = readdirSync(folder).filter(name => /^vault-[0-9a-f-]{36}\.json$/.test(name)).sort();
  if (files.length !== 1) throw new AppError('icloud_unavailable', 'iCloud Drive is not available. Set STACKEY_ICLOUD_DIR or run this on macOS with iCloud Drive.');
  return join(folder, files[0]!);
}

export async function restoreFromIcloud(vaultDir: string, password: string, backupFile: string): Promise<Record<string, unknown>> {
  requirePassword(password);
  const parsed = parseIcloudBackup(JSON.parse(readFileSync(resolve(backupFile), 'utf8')));
  const key = await derive(password, Buffer.from(parsed.salt, 'base64url'), parsed.N, parsed.r, parsed.p, parsed.keylen);
  let plain: Buffer | undefined;
  try {
    try { plain = unseal(key, parsed.wrapped, parsed.aad); }
    catch { throw new AppError('invalid_backup_password', 'iCloud backup password was rejected.'); }
    const payload = record(JSON.parse(plain.toString('utf8')));
    const mnemonic = textField(payload.mnemonic, 512);
    const scratchDir = privateDirectory(join(tmpdir(), 'stackey-icloud-restore-' + randomBytes(8).toString('hex')));
    const scratch = join(scratchDir, 'backup.json');
    writeFileSync(scratch, JSON.stringify(payload.vault) + '\n', { mode: 0o600, flag: 'wx' });
    try {
      const restored = await restoreVault(vaultDir, scratch, mnemonic);
      createBackupState(vaultDir, restored.vault_id, join(resolve(vaultDir), '..', 'recovery.json'));
      updateBackupState(vaultDir, { backed_up: true, plaintext_recovery: false, icloud_backup: true });
      const stored = await storeVaultKey(vaultDir, restored.vault_id, mnemonic);
      if (stored) updateBackupState(vaultDir, { keychain_unlock: true });
      return withBackupStatus(vaultDir, { ...restored, icloud: true, keychain_unlock: stored });
    } finally {
      if (existsSync(scratch)) secureDelete(scratch);
    }
  } finally {
    key.fill(0);
    plain?.fill(0);
  }
}
