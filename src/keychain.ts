import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError, record, textField } from './contracts.js';
import { privateDirectory, readPrivateJson, replacePrivateJson, writePrivateJson } from './identity.js';

export const KEYCHAIN_SERVICE = 'app.stackey.vault';

export interface Keychain {
  store(vaultId: string, secret: string): Promise<void>;
  load(vaultId: string): Promise<string>;
  delete(vaultId: string): Promise<void>;
}

function account(vaultId: string): string {
  const id = textField(vaultId, 36);
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new AppError('invalid_vault', 'Vault format, recovery material or integrity check failed.');
  return id;
}

export class FileKeychain implements Keychain {
  constructor(private readonly dir: string) {}
  private path(): string {
    return join(privateDirectory(this.dir), 'items.json');
  }
  private read(): Record<string, string> {
    const path = this.path();
    if (!existsSync(path)) return {};
    const raw = record(readPrivateJson(path));
    if (raw.format !== 'stackey-file-keychain' || raw.version !== 1 || !raw.items || typeof raw.items !== 'object' || Array.isArray(raw.items)) {
      throw new AppError('invalid_state', 'Keychain state file is invalid.');
    }
    const items: Record<string, string> = {};
    for (const [key, value] of Object.entries(raw.items as Record<string, unknown>)) {
      items[account(key)] = textField(value, 512);
    }
    return items;
  }
  private write(items: Record<string, string>): void {
    const path = this.path();
    const value = { format: 'stackey-file-keychain', version: 1, items };
    if (existsSync(path)) replacePrivateJson(path, value);
    else writePrivateJson(path, value);
  }
  async store(vaultId: string, secret: string): Promise<void> {
    const items = this.read();
    items[account(vaultId)] = textField(secret, 512);
    this.write(items);
  }
  async load(vaultId: string): Promise<string> {
    const secret = this.read()[account(vaultId)];
    if (!secret) throw new AppError('keychain_unavailable', 'Keychain unlock is unavailable. Use --recovery-file or run stackey setup on this device.');
    return secret;
  }
  async delete(vaultId: string): Promise<void> {
    const items = this.read();
    delete items[account(vaultId)];
    this.write(items);
  }
}

export type KeychainHelper = (op: 'store' | 'load' | 'delete', vaultId: string, secret?: string) => Promise<string>;

export class MacosKeychain implements Keychain {
  constructor(private readonly helper: KeychainHelper = runMacosHelper) {}
  async store(vaultId: string, secret: string): Promise<void> {
    await this.helper('store', account(vaultId), textField(secret, 512));
  }
  async load(vaultId: string): Promise<string> {
    const secret = await this.helper('load', account(vaultId));
    return textField(secret, 512);
  }
  async delete(vaultId: string): Promise<void> {
    await this.helper('delete', account(vaultId));
  }
}

function helperBinary(): string {
  return process.env.STACKEY_KEYCHAIN_HELPER ?? join(homedir(), '.stackey', 'keychain-helper');
}

function helperSource(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(process.cwd(), 'scripts', 'stackey-keychain.swift'),
    join(here, '..', '..', 'scripts', 'stackey-keychain.swift'),
    join(here, '..', '../scripts', 'stackey-keychain.swift'),
  ];
  return candidates.find(path => existsSync(path)) ?? candidates[0]!;
}

function spawnOnce(command: string, args: string[], stdin?: string): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => resolve({ code: code ?? 1, stdout, stderr }));
    if (stdin !== undefined) child.stdin.end(stdin);
    else child.stdin.end();
  });
}

async function ensureHelper(): Promise<string> {
  const binary = helperBinary();
  if (existsSync(binary)) return binary;
  const source = helperSource();
  if (!existsSync(source)) throw new AppError('keychain_unavailable', 'Keychain unlock is unavailable. Use --recovery-file or run stackey setup on this device.');
  mkdirSync(dirname(binary), { recursive: true, mode: 0o700 });
  const compiled = join(tmpdir(), 'stackey-keychain-' + process.pid);
  const result = await spawnOnce('swiftc', ['-O', '-o', compiled, source]);
  if (result.code !== 0) throw new AppError('keychain_unavailable', 'Keychain unlock is unavailable. Use --recovery-file or run stackey setup on this device.');
  try {
    const { renameSync } = await import('node:fs');
    renameSync(compiled, binary);
    chmodSync(binary, 0o700);
  } catch {
    return compiled;
  }
  return binary;
}

export async function runMacosHelper(op: 'store' | 'load' | 'delete', vaultId: string, secret?: string): Promise<string> {
  if (process.platform !== 'darwin') {
    throw new AppError('keychain_unavailable', 'Keychain unlock is unavailable. Use --recovery-file or run stackey setup on this device.');
  }
  const binary = await ensureHelper();
  const result = await spawnOnce(binary, [op, vaultId], op === 'store' ? secret : undefined);
  if (result.code !== 0) {
    if (/\bdenied\b/.test(result.stderr)) {
      throw new AppError('keychain_denied', 'Keychain or Touch ID did not authorize this unlock.');
    }
    throw new AppError('keychain_unavailable', 'Keychain unlock is unavailable. Use --recovery-file or run stackey setup on this device.');
  }
  return result.stdout;
}

export function keychainFor(vaultDir: string, platform = process.platform): Keychain {
  const override = process.env.STACKEY_KEYCHAIN_DIR;
  if (override) return new FileKeychain(resolve(override));
  if (platform === 'darwin') return new MacosKeychain();
  return new FileKeychain(join(resolve(vaultDir), 'keychain'));
}

export async function storeVaultKey(vaultDir: string, vaultId: string, mnemonic: string, store: Keychain = keychainFor(vaultDir)): Promise<boolean> {
  try {
    await store.store(vaultId, mnemonic);
    return true;
  } catch {
    return false;
  }
}

export async function loadVaultKey(vaultDir: string, vaultId: string, store: Keychain = keychainFor(vaultDir)): Promise<string> {
  return store.load(vaultId);
}
