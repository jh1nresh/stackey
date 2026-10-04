import { calculateJwkThumbprint } from 'jose';
import { resolve } from 'node:path';
import { vaultRequest } from './vault-client.js';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { AppError, envelope, endpoint, MAX_BODY, publicError, record, textField } from './contracts.js';
import { loadIdentity } from './identity.js';
import { startNode } from './node.js';
import { ACTION, CONNECTION, RESOURCE, WALLET } from './orders.js';
import { issueInvitation } from './pairing.js';
import { approvePairing, revokeGrant, seconds, verifyGrant, requireGrant, type Grant } from './policy.js';
import { Store } from './store.js';

const assets = new Map<string, readonly [string, string]>([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/wallet.js', ['wallet.js', 'text/javascript; charset=utf-8']],
  ['/wallet.css', ['wallet.css', 'text/css; charset=utf-8']],
] as const);

async function body(request: IncomingMessage) {
  if (request.headers['content-type'] !== 'application/json') {
    throw new AppError('invalid_content_type', 'Use application/json.', 415);
  }
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk); size += buffer.length;
    if (size > MAX_BODY) throw new AppError('request_too_large', 'Request exceeds 16 KiB.', 413);
    chunks.push(buffer);
  }
  let value: unknown;
  try { value = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new AppError('invalid_json', 'Request body must be JSON.'); }
  return record(value);
}

// An explicit CLI launch is the local management bootstrap. This authority is
// never served by the agent listener, persisted in the browser, or sent to an agent.
export async function startWallet(dir: string, ownerDir: string | { vaultDir: string }, port = 45821, nodePort = 45820, clock = seconds, publicEndpoint?: string) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new AppError('invalid_port', 'Invalid wallet port.');
  const identity = await loadIdentity(dir, 'node');
  const vaultDir = typeof ownerDir === 'string' ? undefined : resolve(ownerDir.vaultDir);
  const legacyOwner = typeof ownerDir === 'string' ? await loadIdentity(ownerDir, 'owner') : undefined;
  const vault = vaultDir ? await vaultRequest(vaultDir, 'status') : undefined;
  const ownerId: string = legacyOwner?.id ?? vault.owner;
  const store = new Store(dir);
  const pinned = store.db.prepare('SELECT value FROM settings WHERE key = ?').get('owner_public_jwk');
  if (!pinned || await calculateJwkThumbprint(JSON.parse(String(pinned.value))) !== ownerId ||
      (vault && store.db.prepare("SELECT value FROM settings WHERE key='bound_vault_id'").get()?.value !== vault.vault_id)) {
    store.close();
    throw new AppError('owner_mismatch', 'Initialize this Node with the matching local owner first.', 403);
  }
  let node;
  try { node = await startNode(dir, nodePort, undefined, publicEndpoint); }
  catch (error) { store.close(); throw error; }
  const token = randomBytes(32).toString('base64url');
  const expected = Buffer.from('Bearer ' + token);
  const expiresAt = clock() + 3600;
  let origin = '';
  let windowStart = clock(); let mutations = 0;
  const server = createServer(async (request, response) => {
    response.setHeader('cache-control', 'no-store');
    response.setHeader('referrer-policy', 'no-referrer');
    response.setHeader('x-content-type-options', 'nosniff');
    response.setHeader('x-frame-options', 'DENY');
    response.setHeader('content-security-policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    response.setHeader('content-type', 'application/json');
    try {
      if (request.headers.host !== new URL(origin).host ||
          (request.headers.origin !== undefined && request.headers.origin !== origin) ||
          (request.headers['sec-fetch-site'] !== undefined && !['same-origin', 'none'].includes(String(request.headers['sec-fetch-site'])))) {
        throw new AppError('untrusted_browser', 'Open the wallet from its local launch URL.', 403);
      }
      const asset = assets.get(request.url ?? '');
      if (request.method === 'GET' && asset) {
        response.setHeader('content-type', asset[1]);
        response.end(readFileSync(new URL('./wallet/' + asset[0], import.meta.url))); return;
      }
      const auth = Buffer.from(request.headers.authorization ?? '');
      if (auth.length !== expected.length || !timingSafeEqual(auth, expected) || clock() >= expiresAt) {
        throw new AppError('wallet_locked', 'Reopen the launch URL; restart the wallet if its one-hour session expired.', 401);
      }
      const url = new URL(request.url ?? '/', origin);
      if (request.method === 'GET' && url.pathname === '/api/state') {
        const after = url.searchParams.get('after');
        const page = store.listPairings(after === null ? undefined : textField(after, 64));
        let vaultStatus = vaultDir ? 'locked' : 'unavailable';
        if (vaultDir) {
          try { const current = await vaultRequest(vaultDir, 'status');
            if (current.vault_id === vault.vault_id && current.owner === ownerId) vaultStatus = 'unlocked';
          } catch { /* Keep metadata and effective permissions fail-closed. */ }
        }
        const pairings = await Promise.all(page.pairings.map(async ({ public_jwk: _key, status: _status, ...pairing }) => {
          const grant = store.db.prepare('SELECT * FROM grants WHERE pairing_id = ?').get(pairing.pairing_id) as unknown as Grant | undefined;
          let status = !grant ? 'approval_required' : grant.revoked_at !== null ? 'revoked' : grant.expires_at <= clock() ? 'expired' : 'active';
          if (status === 'active') {
            try { requireGrant(store, grant!.grant_id, pairing.principal, clock()); await verifyGrant(store, identity, grant!, clock()); }
            catch (error) { status = error instanceof AppError && error.code === 'node_locked' ? 'locked' : 'invalid'; }
            if (vaultDir && vaultStatus !== 'unlocked') status = 'locked';
            if (store.db.prepare("SELECT value FROM settings WHERE key='vault_unlocked'").get()?.value === '0') status = 'locked';
          }
          return { ...pairing, grant_id: grant?.grant_id ?? null, expires_at: grant?.expires_at ?? null,
            wallet_id: grant?.wallet_id ?? null, status, actions: status === 'active' ? [grant!.action] : [],
            credential_access: false, resource: grant?.resource ?? null, delegation_allowed: false };
        }));
        const events = store.db.prepare('SELECT sequence, kind, object_id, created_at FROM events ORDER BY sequence DESC LIMIT 20').all();
        response.end(JSON.stringify(envelope('ok', { pairings, next_cursor: page.next_cursor, events,
          node_id: identity.id, owner: ownerId, vault_status: vaultStatus, endpoint: node.endpoint, session_expires_at: expiresAt,
          pending_count: store.db.prepare('SELECT count(*) AS n FROM pairings p LEFT JOIN grants g ON g.pairing_id = p.pairing_id WHERE g.grant_id IS NULL').get()!.n,
          wallet_id: WALLET, connection_id: CONNECTION, resource: RESOURCE, action: ACTION,
          demo_ready: !!store.db.prepare("SELECT 1 FROM settings WHERE key = 'demo_ready' AND value = '1'").get(), source: 'local_synthetic' }))); return;
      }
      if (request.method === 'GET' && url.pathname === '/api/credentials') {
        if (!vaultDir) throw new AppError('vault_unavailable', 'Start this wallet with an unlocked vault.', 403);
        const after = url.searchParams.get('after');
        const result = await vaultRequest(vaultDir, 'wallet.inventory', { vault_id: vault.vault_id,
          ...(after === null ? {} : { after: textField(after, 64) }) });
        if (clock() >= expiresAt) throw new AppError('wallet_locked', 'Wallet session expired.', 401);
        response.end(JSON.stringify(envelope('ok', result))); return;
      }
      if (request.method !== 'POST' || !['/api/invitations', '/api/approve', '/api/revoke', '/api/credentials/reveal', '/api/remote'].includes(request.url ?? '')) {
        throw new AppError('route_not_available', 'Route is not available.', 404);
      }
      if (request.headers.origin !== origin) throw new AppError('untrusted_browser', 'Same-origin confirmation is required.', 403);
      if (clock() - windowStart >= 60) { windowStart = clock(); mutations = 0; }
      if (++mutations > 30) throw new AppError('rate_limited', 'Too many changes. Retry in one minute.', 429);
      const input = await body(request);
      // Slow bodies cannot extend a management session.
      if (clock() >= expiresAt) throw new AppError('wallet_locked', 'Wallet session expired. Restart the wallet.', 401);
      let result: unknown;
      if (request.url === '/api/remote') {
        if (input.confirmed !== true) throw new AppError('confirmation_required','Confirm the remote Agent origin.');
        const remote = endpoint(input.endpoint);
        node.setPublicEndpoint(remote);
        result = { endpoint: node.endpoint, source: 'remote_agent_origin' };
      } else if (request.url === '/api/credentials/reveal') {
        if (!vaultDir) throw new AppError('vault_unavailable', 'Start this wallet with an unlocked vault.', 403);
        if (input.confirmed !== true) throw new AppError('confirmation_required', 'Explicitly reveal this credential.');
        result = await vaultRequest(vaultDir, 'credential.reveal', { vault_id: vault.vault_id,
          credential_id: textField(input.credential_id, 64), confirmed: true });
        if (clock() >= expiresAt) throw new AppError('wallet_locked', 'Wallet session expired.', 401);
      } else if (request.url === '/api/invitations') {
        const now = clock();
        result = { invitation: await issueInvitation(store, identity, 300, now), expires_at: now + 300 };
      } else if (request.url === '/api/approve') {
        if (input.confirmed !== true) throw new AppError('confirmation_required', 'Confirm the full fingerprint and scope.');
        result = vaultDir ? await vaultRequest(vaultDir, 'grant.approve', { _node_dir: resolve(dir),
          pairing_id: textField(input.pairing_id,36), principal: textField(input.principal,64),
          action: textField(input.action,64), ttl: Number(input.ttl), wallet_id: WALLET }) : await approvePairing(store, identity, legacyOwner!, textField(input.pairing_id, 36),
          textField(input.principal, 64), textField(input.action, 64), Number(input.ttl), clock);
      } else {
        if (input.confirmed !== true) throw new AppError('confirmation_required', 'Confirm revocation.');
        result = vaultDir ? await vaultRequest(vaultDir, 'grant.revoke', { _node_dir: resolve(dir), grant_id: textField(input.grant_id,36) }) : await revokeGrant(store, identity, legacyOwner!, textField(input.grant_id, 36), clock);
      }
      response.end(JSON.stringify(envelope('ok', result)));
    } catch (error) {
      const safe = publicError(error);
      if (!response.destroyed) { response.writeHead(safe.httpStatus); response.end(JSON.stringify(safe.body)); }
    }
  });
  server.requestTimeout = 10_000; server.headersTimeout = 10_000; server.keepAliveTimeout = 1000;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', () => { server.off('error', reject); resolve(); });
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing address');
    origin = 'http://127.0.0.1:' + address.port;
  } catch (error) { server.close(); await node.close(); store.close(); throw error; }
  let closing: Promise<void> | undefined;
  return { endpoint: origin, launchUrl: origin + '/#' + token, nodeEndpoint: node.endpoint,
    close() {
      closing ??= (async () => {
        await new Promise<void>((resolve, reject) => {
          server.close(error => error ? reject(error) : resolve()); server.closeIdleConnections();
        });
        await node.close(); store.close();
      })();
      return closing;
    } };
}
