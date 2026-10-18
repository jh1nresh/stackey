import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { AppError, displayName, envelope, record, textField } from './contracts.js';
import { backupStatusFields, defaultRecoveryPath, NOT_BACKED_UP_NUDGE, vaultExists, withBackupStatus } from './backup-state.js';
import { loadIdentity, privateDirectory, readPrivateJson, replacePrivateJson, writePrivateJson } from './identity.js';
import { issueInvitation } from './pairing.js';
import { grantForPairing, listedGrantStatus, seconds, type Grant } from './policy.js';
import { Store } from './store.js';
import { initializeVault } from './vault.js';
import { vaultRequest } from './vault-client.js';
import { CREDENTIAL_GET_ACTION } from './credential-get.js';
import { credentialForConnection, listAudit, recordAudit } from './website-sessions.js';

export const SIMPLE_ORIGIN = 'https://handoff.stackey.test';
export const PAIR_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const PAIR_CODE_RE = /^[A-HJ-NP-Z2-9]{6}$/;
const DEFAULT_PORT = 45820;
const UNLOCK_TTL = 3600;

export interface AccessRequestRow {
  request_id: string; pairing_id: string; principal: string; agent_name: string;
  connection_id: string; credential_id: string; credential_name: string;
  created_at: number; expires_at: number; resolved_at: number | null; decision: string | null;
}

export function isPairingCode(value: string): boolean {
  return PAIR_CODE_RE.test(value);
}

function newPairingCode(): string {
  const bytes = randomBytes(6);
  let code = '';
  for (const byte of bytes) code += PAIR_CODE_ALPHABET[byte % PAIR_CODE_ALPHABET.length];
  return code;
}

export function savePairingCode(store: Store, invitation: string, ttl: number, now = seconds()): { code: string; expires_at: number } {
  if (!Number.isInteger(ttl) || ttl < 30 || ttl > 900) {
    throw new AppError('invalid_ttl', 'Invitation lifetime must be 30–900 seconds.');
  }
  const expires_at = now + ttl;
  for (let attempt = 0; attempt < 8; attempt++) {
    const code = newPairingCode();
    try {
      store.db.prepare('INSERT INTO pairing_codes(code, invitation, expires_at) VALUES (?, ?, ?)').run(code, invitation, expires_at);
      return { code, expires_at };
    } catch {
      /* unique collision */
    }
  }
  throw new AppError('internal_error', 'Could not allocate a pairing code.');
}

export function redeemPairingCode(store: Store, code: string, now = seconds()): string {
  const normalized = textField(code, 6).toUpperCase();
  if (!isPairingCode(normalized)) throw new AppError('pairing_code_invalid', 'Pairing code is invalid or expired.', 403, 5, 'permission_denied');
  return store.transaction(() => {
    const row = store.db.prepare('SELECT * FROM pairing_codes WHERE code=?').get(normalized) as
      | { invitation: string; expires_at: number; consumed_at: number | null } | undefined;
    if (!row || row.consumed_at !== null || row.expires_at <= now) {
      throw new AppError('pairing_code_invalid', 'Pairing code is invalid or expired.', 403, 5, 'permission_denied');
    }
    store.db.prepare('UPDATE pairing_codes SET consumed_at=? WHERE code=? AND consumed_at IS NULL').run(now, normalized);
    return row.invitation;
  });
}

export function rememberCredentialLabel(store: Store, credentialId: string, connectionId: string, name: string): void {
  store.db.prepare('INSERT INTO credential_labels(credential_id, connection_id, name) VALUES (?, ?, ?) ON CONFLICT(credential_id) DO UPDATE SET connection_id=excluded.connection_id, name=excluded.name')
    .run(credentialId, connectionId, name);
}

export function selectTargetFromStore(store: Store, pairingId: string): { connection_id: string; credential_id: string; credential_name: string } {
  const grant = grantForPairing(store, pairingId);
  if (grant) {
    const labeled = store.db.prepare('SELECT * FROM credential_labels WHERE connection_id=?').get(grant.connection_id) as
      | { credential_id: string; connection_id: string; name: string } | undefined;
    if (labeled) return { connection_id: labeled.connection_id, credential_id: labeled.credential_id, credential_name: labeled.name };
    const linked = credentialForConnection(store, grant.connection_id);
    if (linked !== '-') return { connection_id: grant.connection_id, credential_id: linked, credential_name: 'credential' };
  }
  const labeled = store.db.prepare('SELECT * FROM credential_labels ORDER BY name, credential_id').get() as
    | { credential_id: string; connection_id: string; name: string } | undefined;
  if (!labeled) throw new AppError('no_credential', 'Add a credential first with stackey add <name>.');
  return { connection_id: labeled.connection_id, credential_id: labeled.credential_id, credential_name: labeled.name };
}

function pairingName(store: Store, pairingId: string, principal: string): string {
  const row = store.db.prepare('SELECT display_name FROM pairings WHERE pairing_id=? AND principal=?').get(pairingId, principal);
  return row ? String(row.display_name) : 'Agent';
}

export function createAccessRequest(store: Store, pairingId: string, principal: string, connection: {
  connection_id: string; credential_id: string; credential_name: string;
}, now = seconds(), ttl = 120): AccessRequestRow {
  const open = store.db.prepare(`SELECT * FROM access_requests WHERE pairing_id=? AND principal=? AND resolved_at IS NULL AND expires_at > ? ORDER BY created_at DESC`).get(pairingId, principal, now) as AccessRequestRow | undefined;
  if (open) return open;
  const row: AccessRequestRow = {
    request_id: randomUUID(), pairing_id: pairingId, principal, agent_name: pairingName(store, pairingId, principal),
    connection_id: connection.connection_id, credential_id: connection.credential_id, credential_name: connection.credential_name,
    created_at: now, expires_at: now + ttl, resolved_at: null, decision: null,
  };
  store.db.prepare(`INSERT INTO access_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`)
    .run(row.request_id, row.pairing_id, row.principal, row.agent_name, row.connection_id, row.credential_id, row.credential_name, row.created_at, row.expires_at);
  return row;
}

export function getAccessRequest(store: Store, requestId: string, principal: string): AccessRequestRow {
  const row = store.db.prepare('SELECT * FROM access_requests WHERE request_id=? AND principal=?').get(requestId, principal) as AccessRequestRow | undefined;
  if (!row) throw new AppError('access_request_not_found', 'That approval request was not found.', 404, 2, 'invalid_request');
  return row;
}

export function listPendingAccessRequests(store: Store, now = seconds()): AccessRequestRow[] {
  return store.db.prepare(`SELECT * FROM access_requests WHERE resolved_at IS NULL AND expires_at > ? ORDER BY created_at, request_id`).all(now) as unknown as AccessRequestRow[];
}

export function resolveAccessRequest(store: Store, requestId: string, decision: 'approved' | 'denied', now = seconds()): AccessRequestRow {
  const changed = store.db.prepare(`UPDATE access_requests SET resolved_at=?, decision=? WHERE request_id=? AND resolved_at IS NULL`).run(now, decision, requestId);
  const row = store.db.prepare('SELECT * FROM access_requests WHERE request_id=?').get(requestId) as AccessRequestRow | undefined;
  if (!row || !changed.changes) throw new AppError('access_request_not_found', 'That approval request was not found.', 404, 2, 'invalid_request');
  return row;
}

function cliPath(): string {
  return fileURLToPath(new URL('./cli.js', import.meta.url));
}

function processAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (error) { return (error as NodeJS.ErrnoException).code !== 'ESRCH'; }
}

async function waitUntil(check: () => Promise<boolean>, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await delay(50);
  }
  throw new AppError('node_unreachable', 'Node did not confirm the request.', 503, 4, 'node_unreachable');
}

function spawnDaemon(args: string[]): number {
  const child = spawn(process.execPath, [cliPath(), ...args], {
    detached: true, stdio: 'ignore', env: process.env,
  });
  if (!child.pid) throw new AppError('node_unreachable', 'Node did not confirm the request.', 503, 4, 'node_unreachable');
  child.unref();
  return child.pid;
}

function writeDaemon(dataDir: string, pid: number, endpoint: string, unlockPid?: number): void {
  const pointer = join(dataDir, 'daemon.json');
  const state: Record<string, unknown> = { pid, endpoint };
  if (unlockPid !== undefined) state.unlock_pid = unlockPid;
  try { writePrivateJson(pointer, state); } catch { replacePrivateJson(pointer, state); }
}

function daemonState(dataDir: string): { pid: number; endpoint: string; unlock_pid?: number } | undefined {
  const path = join(dataDir, 'daemon.json');
  if (!existsSync(path)) return undefined;
  try {
    const saved = record(readPrivateJson(path));
    const pid = saved.pid;
    if (!Number.isInteger(pid) || !processAlive(pid as number)) return undefined;
    const unlock = saved.unlock_pid;
    return {
      pid: pid as number, endpoint: textField(saved.endpoint, 100),
      ...(Number.isInteger(unlock) && processAlive(unlock as number) ? { unlock_pid: unlock as number } : {}),
    };
  } catch { return undefined; }
}

export function stopSimpleRuntime(dataDir: string): void {
  const path = join(dataDir, 'daemon.json');
  if (!existsSync(path)) return;
  try {
    const saved = record(readPrivateJson(path));
    for (const pid of [saved.pid, saved.unlock_pid]) {
      if (!Number.isInteger(pid)) continue;
      try { process.kill(pid as number, 'SIGTERM'); } catch { /* already gone */ }
    }
    for (const pid of [saved.pid, saved.unlock_pid]) {
      if (!Number.isInteger(pid)) continue;
      try { process.kill(pid as number, 'SIGKILL'); } catch { /* already gone */ }
    }
  } catch { /* pointer unreadable */ }
}

export async function resolveNodeEndpoint(dataDir: string, port = DEFAULT_PORT): Promise<string> {
  const existing = daemonState(dataDir);
  if (existing) return existing.endpoint;
  if (existsSync(join(dataDir, 'pairings.sqlite'))) {
    const store = new Store(dataDir);
    try { return store.getEndpoint(); }
    catch { /* Node has not advertised an endpoint yet */ }
    finally { store.close(); }
  }
  const fallback = `http://127.0.0.1:${port}`;
  if (await nodeReady(fallback)) return fallback;
  throw new AppError('node_unreachable', 'Node did not confirm the request.', 503, 4, 'node_unreachable');
}

async function nodeReady(endpoint: string): Promise<boolean> {
  try {
    const response = await fetch(endpoint + '/v1/challenges', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ request_id: randomUUID() }), redirect: 'error', signal: AbortSignal.timeout(1000),
    });
    return response.ok || response.status === 400 || response.status === 403;
  } catch { return false; }
}

export async function ensureSimpleRuntime(vaultDir: string, dataDir: string, port = DEFAULT_PORT): Promise<{
  created_vault: boolean; started_node: boolean; unlocked: boolean; endpoint: string; node_id: string;
}> {
  privateDirectory(dataDir);
  privateDirectory(vaultDir);
  let created_vault = false;
  if (!vaultExists(vaultDir)) {
    await initializeVault(vaultDir, defaultRecoveryPath(vaultDir));
    created_vault = true;
  }
  if (!existsSync(join(dataDir, 'identity.json'))) await loadIdentity(dataDir, 'node', true);
  const store = new Store(dataDir); store.close();

  const node_id = (await loadIdentity(dataDir, 'node')).id;
  const endpoint = `http://127.0.0.1:${port}`;
  let started_node = false;
  const existing = daemonState(dataDir);
  let nodePid = existing?.pid;
  let liveEndpoint = existing?.endpoint ?? endpoint;
  if (!(existing && await nodeReady(existing.endpoint)) && !(await nodeReady(endpoint))) {
    nodePid = spawnDaemon(['node', 'start', '--data-dir', dataDir, '--port', String(port)]);
    await waitUntil(() => nodeReady(endpoint));
    liveEndpoint = endpoint;
    started_node = true;
  } else if (existing && await nodeReady(existing.endpoint)) {
    liveEndpoint = existing.endpoint;
  }

  let unlocked = false;
  let unlockPid = existing?.unlock_pid;
  try {
    await vaultRequest(vaultDir, 'status');
    unlocked = true;
  } catch {
    const recovery = defaultRecoveryPath(vaultDir);
    const args = ['vault', 'unlock', '--vault-dir', vaultDir, '--data-dir', dataDir, '--ttl', String(UNLOCK_TTL)];
    if (existsSync(recovery)) args.push('--recovery-file', recovery);
    unlockPid = spawnDaemon(args);
    await waitUntil(async () => {
      try { await vaultRequest(vaultDir, 'status'); return true; } catch { return false; }
    });
    unlocked = true;
  }
  if (nodePid !== undefined) writeDaemon(dataDir, nodePid, liveEndpoint, unlockPid);

  await vaultRequest(vaultDir, 'node.bind', { _node_dir: dataDir });

  const live = new Store(dataDir);
  try {
    const row = live.db.prepare("SELECT value FROM settings WHERE key='endpoint'").get();
    return { created_vault, started_node, unlocked, endpoint: row ? String(row.value) : endpoint, node_id };
  } finally { live.close(); }
}

export async function simpleInit(vaultDir: string, dataDir: string, port = DEFAULT_PORT, json = false): Promise<void> {
  const result = await ensureSimpleRuntime(vaultDir, dataDir, port);
  const backup = backupStatusFields(vaultDir);
  const data = withBackupStatus(vaultDir, {
    ...result,
    vault_dir: vaultDir,
    data_dir: dataDir,
    next_step: 'stackey add <name> to store a credential, then stackey connect to pair an agent.',
  });
  if (json) {
    process.stdout.write(JSON.stringify(envelope('ok', data)) + '\n');
    return;
  }
  const lines = [
    result.created_vault ? 'Created a local vault. The recovery phrase is saved privately; run stackey backup when you can.' : 'Using the existing local vault.',
    `Node is on ${result.endpoint}.`,
    result.unlocked ? 'Vault is unlocked.' : 'Unlock the vault to continue.',
    backup.backup_nudge ?? '',
    '',
    'Next:  stackey add GITHUB_TOKEN',
    'Then:  stackey connect',
  ].filter(line => line !== '');
  process.stdout.write(lines.join('\n') + '\n');
}

export async function readHiddenSecret(prompt = 'Secret: '): Promise<string> {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== 'function') {
    throw new AppError('invalid_arguments', 'Enter the secret in a terminal, or pass --secret-file.');
  }
  process.stderr.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  const chars: string[] = [];
  try {
    await new Promise<void>((resolve, reject) => {
      const onData = (chunk: Buffer) => {
        const text = chunk.toString('utf8');
        for (const char of text) {
          if (char === '\n' || char === '\r') { process.stdin.off('data', onData); resolve(); return; }
          if (char === '\u0003') { process.stdin.off('data', onData); reject(new AppError('invalid_arguments', 'Cancelled.')); return; }
          if (char === '\u007f' || char === '\b') { chars.pop(); continue; }
          if (char >= ' ') chars.push(char);
        }
      };
      process.stdin.on('data', onData);
    });
  } finally {
    process.stdin.setRawMode(false);
    process.stdin.pause();
    process.stderr.write('\n');
  }
  const secret = chars.join('');
  if (!secret) throw new AppError('invalid_arguments', 'Secret is required.');
  return secret;
}

export async function simpleAdd(vaultDir: string, dataDir: string, name: string, secret: string, json = false, port = DEFAULT_PORT): Promise<void> {
  await ensureSimpleRuntime(vaultDir, dataDir, port);
  const labeled = displayName(name);
  const imported = await vaultRequest(vaultDir, 'credential.import', {
    wallet_id: 'wallet_demo', name: labeled, kind: 'api_key', value: textField(secret, 16384), request_id: randomUUID(),
  });
  const connected = await vaultRequest(vaultDir, 'connection.add', {
    wallet_id: 'wallet_demo', name: labeled, provider: 'credential',
    config: { origin: SIMPLE_ORIGIN, credential_id: imported.id }, request_id: randomUUID(),
  });
  const labels = new Store(dataDir);
  try { rememberCredentialLabel(labels, String(imported.id), String(connected.id), labeled); }
  finally { labels.close(); }
  const data = { credential_id: imported.id, connection_id: connected.id, name: labeled, kind: 'api_key' };
  if (json) { process.stdout.write(JSON.stringify(envelope('ok', data)) + '\n'); return; }
  process.stdout.write(`Saved ${labeled}. An agent can request it after stackey connect; you will be asked to approve.\n`);
}

export async function simpleOwnerConnect(vaultDir: string, dataDir: string, ttl = 300, json = false, port = DEFAULT_PORT): Promise<void> {
  await ensureSimpleRuntime(vaultDir, dataDir, port);
  const identity = await loadIdentity(dataDir, 'node');
  const store = new Store(dataDir);
  try {
    const invitation = await issueInvitation(store, identity, ttl);
    const issued = savePairingCode(store, invitation, ttl);
    const endpoint = store.getEndpoint();
    const snippet = `stackey connect ${issued.code}`;
    const data = {
      code: issued.code, expires_at: issued.expires_at, endpoint, snippet,
      env: `STACKEY_PAIRING_CODE=${issued.code}`,
      next_step: 'Paste the snippet into the agent. No long pairing IDs to copy.',
    };
    if (json) { process.stdout.write(JSON.stringify(envelope('ok', data)) + '\n'); return; }
    process.stdout.write([
      'Give this one line to the agent:',
      '',
      `  ${snippet}`,
      '',
      `Code ${issued.code} expires in ${ttl} seconds. No long pairing IDs to copy.`,
    ].join('\n') + '\n');
  } finally { store.close(); }
}

export async function redeemPairingCodeAt(origin: string, code: string): Promise<string> {
  let response: Response;
  try {
    response = await fetch(origin + '/v1/pair-codes', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code }), redirect: 'error', signal: AbortSignal.timeout(5000),
    });
  } catch { throw new AppError('node_unreachable', 'Node did not confirm the request.', 503, 4, 'node_unreachable'); }
  const raw = await response.text();
  let body: Record<string, unknown>;
  try { body = record(JSON.parse(raw)); } catch { throw new AppError('pairing_code_invalid', 'Pairing code is invalid or expired.', 403, 5, 'permission_denied'); }
  if (!response.ok) {
    const error = record(body.error ?? {});
    throw new AppError(typeof error.code === 'string' ? error.code : 'pairing_code_invalid',
      'Pairing code is invalid or expired.', response.status, 5, 'permission_denied');
  }
  return textField(record(body.data).invitation, 8192);
}

export async function simpleApprove(vaultDir: string, dataDir: string, options: { yes?: boolean; json?: boolean; input?: NodeJS.ReadableStream; port?: number } = {}): Promise<void> {
  await ensureSimpleRuntime(vaultDir, dataDir, options.port ?? DEFAULT_PORT);
  const store = new Store(dataDir);
  try {
    const pending = listPendingAccessRequests(store);
    if (pending.length === 0) throw new AppError('no_pending_request', 'There is no pending agent request to approve.');
    const request = pending[0]!;
    const prompt = `${request.agent_name} wants ${request.credential_name} once — approve? [y/N] `;
    let approved = options.yes === true;
    if (!approved && !options.json) {
      if (options.input) {
        approved = await readYes(options.input, prompt);
      } else if (process.stdin.isTTY) {
        approved = await readYes(process.stdin, prompt);
      } else {
        process.stdout.write([
          prompt.trim(),
          ...pending.slice(1).map(row => `${row.agent_name} wants ${row.credential_name} once`),
          'Confirm the first request with stackey approve --yes.',
        ].join('\n') + '\n');
        return;
      }
    }
    if (options.json && options.yes !== true && !approved) {
      process.stdout.write(JSON.stringify(envelope('approval_required', {
        pending: pending.map(row => ({
          request_id: row.request_id, agent: row.agent_name, credential: row.credential_name,
        })),
        prompt,
      })) + '\n');
      return;
    }
    if (!approved) {
      resolveAccessRequest(store, request.request_id, 'denied');
      recordAudit(store, {
        result: 'permission_denied', reason: 'owner_denied', agent_id: request.principal,
        credential_id: request.credential_id, started_at: seconds(),
      });
      if (options.json) { process.stdout.write(JSON.stringify(envelope('ok', { decision: 'denied', request_id: request.request_id })) + '\n'); return; }
      process.stdout.write('Denied.\n');
      return;
    }
    const current = grantForPairing(store, request.pairing_id);
    await vaultRequest(vaultDir, 'grant.approve', {
      _node_dir: dataDir,
      pairing_id: request.pairing_id, principal: request.principal, action: CREDENTIAL_GET_ACTION,
      ttl: 300, wallet_id: 'wallet_demo', connection_id: request.connection_id, max_calls: 1, max_amount_minor: 0,
      ...(current ? { replace_grant_id: current.grant_id } : {}),
    });
    resolveAccessRequest(store, request.request_id, 'approved');
    if (options.json) { process.stdout.write(JSON.stringify(envelope('ok', { decision: 'approved', agent: request.agent_name, credential: request.credential_name })) + '\n'); return; }
    process.stdout.write(`Approved. ${request.agent_name} may fetch ${request.credential_name} once.\n`);
  } finally { store.close(); }
}

async function readYes(input: NodeJS.ReadableStream, prompt: string): Promise<boolean> {
  process.stderr.write(prompt);
  const rl = createInterface({ input, terminal: false });
  try {
    const line = await new Promise<string>(resolve => rl.once('line', resolve));
    return /^\s*y(es)?\s*$/i.test(line);
  } finally { rl.close(); }
}

function denialInPlainWords(result: string): string {
  if (result === 'budget_exceeded') return 'grant was spent';
  if (result === 'grant_expired') return 'grant expired';
  if (result === 'grant_revoked') return 'grant was revoked';
  if (result === 'permission_denied') return 'permission denied';
  if (result === 'agent_not_paired') return 'agent is not paired';
  if (result === 'node_locked') return 'vault was locked';
  return result;
}

export async function simpleOwnerStatus(vaultDir: string, dataDir: string, json = false): Promise<void> {
  let unlocked = false;
  try { await vaultRequest(vaultDir, 'status'); unlocked = true; } catch { unlocked = false; }
  const backup = backupStatusFields(vaultDir);
  let credentials: Array<{ name: string; kind: string }> = [];
  if (unlocked) {
    try {
      const listed = await vaultRequest(vaultDir, 'credential.list', { wallet_id: 'wallet_demo' });
      credentials = ((listed.credentials as Array<{ name: string; kind: string }>) ?? []).map(row => ({ name: row.name, kind: row.kind }));
    } catch { /* vault may still be racing */ }
  }
  const store = existsSync(join(dataDir, 'pairings.sqlite')) ? new Store(dataDir) : undefined;
  try {
    const now = seconds();
    const agents = store ? store.listPairings().pairings.map(row => ({ name: row.display_name, pairing_id: row.pairing_id, principal: row.principal })) : [];
    const pending = store ? listPendingAccessRequests(store, now) : [];
    const denials = store ? listAudit(store).entries.filter(row =>
      ['budget_exceeded', 'grant_expired', 'grant_revoked', 'permission_denied', 'agent_not_paired', 'node_locked'].includes(String(row.result))
    ).slice(-5) : [];
    const grants = store ? store.db.prepare('SELECT * FROM grants').all() as unknown as Grant[] : [];
    const data = {
      vault: unlocked ? 'unlocked' : 'locked',
      backup_status: backup.backup_status ?? 'not_backed_up',
      backup_nudge: backup.backup_nudge,
      credentials,
      agents: agents.map(agent => {
        const grant = grants.find(row => row.pairing_id === agent.pairing_id && row.superseded_at == null);
        const waiting = pending.find(row => row.pairing_id === agent.pairing_id);
        return {
          name: agent.name,
          status: waiting ? 'pending' : grant ? listedGrantStatus(store!, grant, now) : 'connected',
          wants: waiting?.credential_name,
        };
      }),
      pending_requests: pending.map(row => ({ agent: row.agent_name, credential: row.credential_name })),
      recent_denials: denials.map(row => ({
        agent: row.agent_id,
        reason: denialInPlainWords(String(row.reason ?? row.result)),
        at: typeof row.started_at === 'number' ? new Date(row.started_at * 1000).toLocaleString() : String(row.started_at),
      })),
    };
    if (json) { process.stdout.write(JSON.stringify(envelope('ok', data)) + '\n'); return; }
    if (!unlocked) {
      process.stdout.write([
        'Vault locked — run `stackey` to unlock',
        data.backup_nudge ?? NOT_BACKED_UP_NUDGE,
      ].join('\n') + '\n');
      return;
    }
    const lines = [
      `Vault is ${data.vault}.`,
      data.backup_nudge ?? (data.backup_status === 'backed_up' ? 'Backup is recorded.' : NOT_BACKED_UP_NUDGE),
      '',
      'Credentials',
      credentials.length ? credentials.map(row => `  ${row.name}`).join('\n') : '  (none — run stackey add <name>)',
      '',
      'Agents',
      agents.length ? data.agents.map(agent => {
        if (agent.status === 'pending') return `  ${agent.name} wants ${agent.wants} once — run stackey approve`;
        return `  ${agent.name} — ${agent.status}`;
      }).join('\n') : '  (none — run stackey connect)',
    ];
    if (data.recent_denials.length) {
      lines.push('', 'Recent denials');
      for (const row of data.recent_denials) lines.push(`  ${row.reason} (${row.at})`);
    }
    process.stdout.write(lines.join('\n') + '\n');
  } finally { store?.close(); }
}

