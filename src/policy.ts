import { randomUUID } from 'node:crypto';
import { calculateJwkThumbprint, importJWK, jwtVerify, SignJWT } from 'jose';
import { AppError, record, textField } from './contracts.js';
import { publicKey, type Identity } from './identity.js';
import { ACTION, CONNECTION, requireDemo, RESOURCE, WALLET } from './orders.js';
import { integer, providerAction, resourceFor } from './providers.js';
import type { Store } from './store.js';

export interface Grant {
  grant_id: string; pairing_id: string; principal: string; signed_grant: string;
  created_at: number; expires_at: number; version: number; revoked_at: number | null; wallet_id: string; action: string; connection_id: string; resource: string; max_calls: number; max_amount_minor: number;
}
export const seconds = () => Math.floor(Date.now() / 1000);
export function denied(code: string, message: string): never {
  throw new AppError(code, message, 403, 3, code === 'grant_revoked' || code === 'grant_expired' ? code : 'permission_denied');
}
export function event(store: Store, kind: string, subject: string, object: string, now: number): void {
  store.db.prepare('INSERT INTO events(event_id, kind, subject, object_id, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(randomUUID(), kind, subject, object, now);
}

export async function initializeOwner(store: Store, owner: Identity): Promise<void> {
  // The bootstrap channel is the existing private local Node directory, never HTTP.
  await importJWK(owner.privateJwk, 'EdDSA');
  store.transaction(() => {
    const existing = store.db.prepare('SELECT value FROM settings WHERE key = ?').get('owner_public_jwk');
    if (existing && existing.value !== JSON.stringify(owner.publicJwk)) denied('owner_mismatch', 'This Node already has a different owner.');
    store.db.prepare('INSERT OR IGNORE INTO settings VALUES (?, ?)').run('owner_public_jwk', JSON.stringify(owner.publicJwk));
  });
}

async function ownerKey(store: Store) {
  const row = store.db.prepare('SELECT value FROM settings WHERE key = ?').get('owner_public_jwk');
  if (!row) denied('owner_not_initialized', 'Initialize the local owner first.');
  const key = publicKey(JSON.parse(row.value as string), 'EdDSA');
  return { key, id: await calculateJwkThumbprint(key) };
}

export async function approvePairing(store: Store, node: Identity, owner: Identity,
  pairingId: string, principal: string, action: string, ttl: number, clock = seconds, walletId = WALLET, scope?: { connection_id: string; max_calls: number; max_amount_minor: number }, guard?: (store: Store) => void) {
  if (action !== ACTION && (!providerAction(action) || !scope)) denied('action_not_available', 'Select a supported action and connection.');
  const connectionId = scope?.connection_id ?? CONNECTION;
  const resource = scope ? resourceFor(action, connectionId) : RESOURCE;
  const websiteLogin = action === 'website.session.login';
  const maxCalls = websiteLogin ? integer(scope!.max_calls, 1, 1) : scope ? integer(scope.max_calls, 1, 100) : 1000;
  const maxAmount = websiteLogin ? integer(scope!.max_amount_minor, 0, 0) : scope ? integer(scope.max_amount_minor, 0, 10000) : 0;
  if (action === 'stripe.mpp.pay' && maxAmount < 50) throw new AppError('invalid_budget', 'MPP requires a positive USD minor-unit budget.');
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > 900) throw new AppError('invalid_ttl', 'Grant lifetime must be 60–900 seconds.');
  if (!/^(wallet_demo|wallet_[0-9a-f-]{36})$/.test(walletId)) throw new AppError('invalid_wallet', 'Invalid wallet ID.');
  if (action === ACTION) requireDemo(store);
  const pinned = await ownerKey(store);
  if (owner.id !== pinned.id) denied('owner_mismatch', 'Owner signer does not match this Node.');
  const pairing = store.db.prepare('SELECT principal FROM pairings WHERE pairing_id = ?').get(pairingId);
  if (!pairing || pairing.principal !== principal) denied('principal_mismatch', 'Pairing and full principal fingerprint must match.');
  const now = clock(); const grantId = randomUUID();
  const signed = await new SignJWT({ grant_id: grantId, pairing_id: pairingId, subject: principal,
    wallet_id: walletId, connection_id: connectionId, resource, actions: [action],
    ...(scope ? { max_calls: maxCalls, max_amount_minor: maxAmount, currency: 'usd' } : {}),
    policy_version: 1, delegation_allowed: false })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'stackey-grant+jwt' }).setIssuer(owner.id)
    .setAudience(node.id).setSubject(principal).setIssuedAt(now).setExpirationTime(now + ttl)
    .sign(await importJWK(owner.privateJwk, 'EdDSA'));
  const checked = await jwtVerify(signed, await importJWK(pinned.key, 'EdDSA'), {
    algorithms: ['EdDSA'], typ: 'stackey-grant+jwt', issuer: pinned.id, audience: node.id,
    currentDate: new Date(clock() * 1000),
  });
  if (checked.payload.sub !== principal) denied('invalid_grant', 'Grant signer verification failed.');
  store.transaction(() => {
    guard?.(store);
    const current = clock();
    if (current >= now + ttl) denied('grant_expired', 'Grant expired before acceptance.');
    if (store.db.prepare('SELECT 1 FROM grants WHERE pairing_id = ?').get(pairingId)) {
      throw new AppError('already_approved', 'This pairing already has a grant; create a new pairing for a new task.');
    }
    store.db.prepare('INSERT INTO grants(grant_id, pairing_id, principal, signed_grant, created_at, expires_at, version, wallet_id, action, connection_id, resource, max_calls, max_amount_minor) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)')
      .run(grantId, pairingId, principal, signed, now, now + ttl, walletId, action, connectionId, resource, maxCalls, maxAmount);
    event(store, 'grant_approved', principal, grantId, current);
  });
  return { grant_id: grantId, pairing_id: pairingId, principal, owner: owner.id,
    wallet_id: walletId, connection_id: connectionId, resource, actions: [action], max_calls: maxCalls, max_amount_minor: maxAmount,
    expires_at: now + ttl, status: 'active', source: scope ? 'external_provider' : 'local_synthetic' };
}

export function grantForPairing(store: Store, pairingId: string): Grant | undefined {
  return store.db.prepare('SELECT * FROM grants WHERE pairing_id = ?').get(pairingId) as unknown as Grant | undefined;
}
export function requireGrant(store: Store, grantId: string, principal: string, now: number): Grant {
  const vault = store.db.prepare("SELECT value FROM settings WHERE key='vault_dir'").get();
  if (vault) {
    const state = store.db.prepare("SELECT value FROM settings WHERE key='vault_unlocked'").get();
    const expiry = store.db.prepare("SELECT value FROM settings WHERE key='vault_unlock_until'").get();
    if (state?.value !== '1' || Number(expiry?.value ?? 0) <= now) throw new AppError('node_locked','Unlock the bound vault first.',403,3,'node_locked');
  }
  const row = store.db.prepare('SELECT * FROM grants WHERE grant_id = ? AND principal = ?').get(grantId, principal) as unknown as Grant | undefined;
  if (!row) denied('permission_denied', 'No matching grant is available.');
  if (row.revoked_at !== null) denied('grant_revoked', 'Owner revoked this grant.');
  if (row.expires_at <= now) denied('grant_expired', 'This grant has expired.');
  return row;
}

export async function verifyGrant(store: Store, node: Identity, row: Grant, now: number): Promise<void> {
  const owner = await ownerKey(store);
  try {
    const { payload } = await jwtVerify(row.signed_grant, await importJWK(owner.key, 'EdDSA'), {
      algorithms: ['EdDSA'], typ: 'stackey-grant+jwt', issuer: owner.id, audience: node.id,
      subject: row.principal, currentDate: new Date(now * 1000), requiredClaims: ['iat', 'exp'],
    });
    if (payload.grant_id !== row.grant_id || payload.pairing_id !== row.pairing_id ||
      payload.subject !== row.principal || payload.iat !== row.created_at || payload.exp !== row.expires_at ||
      payload.wallet_id !== row.wallet_id || payload.connection_id !== row.connection_id || payload.resource !== row.resource ||
      payload.policy_version !== row.version || payload.delegation_allowed !== false ||
      JSON.stringify(payload.actions) !== JSON.stringify([row.action]) ||
      (row.action !== ACTION && (payload.max_calls !== row.max_calls || payload.max_amount_minor !== row.max_amount_minor || payload.currency !== 'usd' || !providerAction(row.action)))) throw new Error('Invalid grant binding');
  } catch { denied('invalid_grant', 'Owner grant could not be verified.'); }
}

export async function revokeGrant(store: Store, node: Identity, owner: Identity, grantId: string, clock = seconds, guard?: (store: Store) => void) {
  const pinned = await ownerKey(store);
  if (owner.id !== pinned.id) denied('owner_mismatch', 'Owner signer does not match this Node.');
  const row = store.db.prepare('SELECT * FROM grants WHERE grant_id = ?').get(grantId) as unknown as Grant | undefined;
  if (!row) throw new AppError('grant_not_found', 'Grant was not found.');
  const now = clock();
  const signed = await new SignJWT({ grant_id: grantId, version: row.version, action: 'revoke' })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'stackey-revocation+jwt' }).setIssuer(owner.id)
    .setAudience(node.id).setIssuedAt(now).setExpirationTime(now + 30)
    .sign(await importJWK(owner.privateJwk, 'EdDSA'));
  await jwtVerify(signed, await importJWK(pinned.key, 'EdDSA'), {
    algorithms: ['EdDSA'], typ: 'stackey-revocation+jwt', issuer: pinned.id, audience: node.id,
    currentDate: new Date(clock() * 1000),
  });
  store.transaction(() => {
    guard?.(store);
    const current = clock();
    if (current >= now + 30) denied('invalid_owner_proof', 'Owner confirmation expired before acceptance.');
    const changed = store.db.prepare('UPDATE grants SET revoked_at = ?, version = version + 1, signed_revocation = ? WHERE grant_id = ? AND version = ? AND revoked_at IS NULL')
      .run(current, signed, grantId, row.version);
    if (changed.changes) event(store, 'grant_revoked', row.principal, grantId, current);
  });
  return { grant_id: grantId, status: 'revoked' };
}

export interface ProofTime { nonce: string; jti: string; iat: number; exp: number }
export function proofTime(input: unknown, now: number): ProofTime {
  const value = record(input);
  if (!Number.isInteger(value.iat) || !Number.isInteger(value.exp) ||
      (value.iat as number) > now || now - (value.iat as number) > 30 ||
      (value.exp as number) <= now || (value.exp as number) - (value.iat as number) > 30) {
    denied('invalid_proof', 'Request proof is expired or invalid.');
  }
  return { nonce: textField(value.nonce, 64), jti: textField(value.jti, 64), iat: value.iat as number, exp: value.exp as number };
}

// Call only while holding the write transaction, after all asynchronous checks.
export function consumeProof(store: Store, proof: ProofTime, now: number): void {
  proofTime(proof, now);
  const row = store.db.prepare('SELECT * FROM challenges WHERE nonce = ?').get(proof.nonce);
  if (!row || row.consumed_at !== null || (row.expires_at as number) <= now ||
      store.db.prepare('SELECT 1 FROM request_proofs WHERE jti = ?').get(proof.jti)) {
    denied('proof_replayed', 'Request nonce or proof is unavailable. Obtain a fresh challenge.');
  }
  store.db.prepare('UPDATE challenges SET consumed_at = ? WHERE nonce = ?').run(now, proof.nonce);
  store.db.prepare('INSERT INTO request_proofs VALUES (?, ?)').run(proof.jti, now);
}
