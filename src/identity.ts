import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { AppError, invalid, record, textField } from './contracts.js';

export interface Identity {
  id: string;
  publicJwk: JWK;
  privateJwk: JWK;
}

export function privateDirectory(path: string): string {
  const dir = resolve(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    invalid('unsafe_state_directory', 'Use a private directory owned by this process user.');
  }
  if (stat.uid !== process.getuid?.()) {
    invalid('unsafe_state_directory', 'State directory must belong to this process user.');
  }
  return dir;
}

export function readPrivateJson(path: string): unknown {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
      (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.() || stat.size > 32_768) {
    invalid('unsafe_state_file', 'State file must be a private regular file.');
  }
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch { invalid('invalid_state', 'Unable to read local state.'); }
}

export function writePrivateJson(path: string, value: unknown): void {
  // Exclusive create: never replace another identity, invitation or receipt.
  writeFileSync(path, JSON.stringify(value) + '\n', { mode: 0o600, flag: 'wx' });
}

export function publicKey(value: unknown, algorithm: 'EdDSA' | 'ES256'): JWK {
  const key = record(value);
  if (algorithm === 'EdDSA') {
    if (Object.keys(key).sort().join(',') !== 'crv,kty,x' ||
        key.kty !== 'OKP' || key.crv !== 'Ed25519' ||
        !/^[A-Za-z0-9_-]{43}$/.test(textField(key.x, 43))) {
      invalid('invalid_public_key', 'Expected a public Ed25519 key.');
    }
    return { kty: 'OKP', crv: 'Ed25519', x: key.x as string };
  }
  if (Object.keys(key).sort().join(',') !== 'crv,kty,x,y' ||
      key.kty !== 'EC' || key.crv !== 'P-256' ||
      !/^[A-Za-z0-9_-]{43}$/.test(textField(key.x, 43)) ||
      !/^[A-Za-z0-9_-]{43}$/.test(textField(key.y, 43))) {
    invalid('invalid_public_key', 'Expected a public P-256 key.');
  }
  return { kty: 'EC', crv: 'P-256', x: key.x as string, y: key.y as string };
}

export async function createIdentity(algorithm: 'EdDSA' | 'ES256'): Promise<Identity> {
  const { publicKey: pub, privateKey: priv } = await generateKeyPair(algorithm, { extractable: true });
  const publicJwk = publicKey(await exportJWK(pub), algorithm);
  return { id: await calculateJwkThumbprint(publicJwk), publicJwk, privateJwk: await exportJWK(priv) };
}

export async function loadIdentity(dir: string, kind: 'node' | 'agent', create = false): Promise<Identity> {
  const safeDir = privateDirectory(dir);
  const path = join(safeDir, 'identity.json');
  const algorithm = kind === 'node' ? 'EdDSA' : 'ES256';
  if (!existsSync(path)) {
    if (!create) throw new AppError('node_not_initialized', 'Initialize the Node first.');
    const identity = await createIdentity(algorithm);
    writePrivateJson(path, identity);
    return identity;
  }
  const stored = record(readPrivateJson(path));
  const publicJwk = publicKey(stored.publicJwk, algorithm);
  const privateJwk = record(stored.privateJwk) as JWK;
  const id = await calculateJwkThumbprint(publicJwk);
  if (stored.id !== id || typeof privateJwk.d !== 'string') {
    invalid('invalid_identity', 'Local identity does not match its public fingerprint.');
  }
  // Ensure the imported private key matches the saved public coordinates.
  if (privateJwk.kty !== publicJwk.kty || privateJwk.crv !== publicJwk.crv ||
      privateJwk.x !== publicJwk.x || privateJwk.y !== publicJwk.y) {
    invalid('invalid_identity', 'Local identity contains inconsistent key material.');
  }
  await importJWK(privateJwk, algorithm);
  return { id, publicJwk, privateJwk };
}
