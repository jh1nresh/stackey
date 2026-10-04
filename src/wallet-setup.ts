import { randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { AppError, envelope, publicError, record } from './contracts.js';
import { loadIdentity, privateDirectory, writePrivateJson } from './identity.js';
import { initializeVault, recovery, restoreVault } from './vault.js';
import { unlockVault, type RunningVault } from './vault-session.js';
import { vaultRequest } from './vault-client.js';
import { startWallet } from './wallet.js';
import { setupHtml, setupCss, setupJs } from './wallet-setup-ui.js';

const now = () => Math.floor(Date.now() / 1000);
const maximumBody = 6 * 1024 * 1024;
async function readBody(request: IncomingMessage) {
  if (request.headers['content-type'] !== 'application/json') throw new AppError('invalid_request', 'Use JSON.', 415);
  const chunks: Buffer[] = []; let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > maximumBody) throw new AppError('request_too_large', 'Backup exceeds the size limit.', 413);
    chunks.push(Buffer.from(chunk));
  }
  try { return record(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
  catch { throw new AppError('invalid_request', 'Invalid request.'); }
}
function exact(input: Record<string, unknown>, keys: string[]) {
  if (Object.keys(input).sort().join(',') !== [...keys].sort().join(',')) throw new AppError('invalid_request', 'Unexpected fields.');
}
function phrase(value: unknown) {
  if (typeof value !== 'string' || value.length > 512) throw new AppError('invalid_recovery', 'Enter your 24-word recovery phrase.');
  const normalized = value.trim().toLowerCase().split(/\s+/).join(' ');
  if (normalized.split(' ').length !== 24) throw new AppError('invalid_recovery', 'Enter all 24 words in order.');
  return normalized;
}

// Separate, explicit Owner bootstrap. No existing Node, wallet or credentials are changed.
export async function startWalletSetup(directory: string, port = 0, clock = now) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new AppError('invalid_port', 'Invalid setup port.');
  const root = resolve(directory);
  privateDirectory(dirname(root));
  try { mkdirSync(root, { mode: 0o700 }); }
  catch { throw new AppError('output_exists', 'Choose a new setup directory. Existing directories are never overwritten.'); }
  const token = randomBytes(32).toString('base64url');
  const expected = Buffer.from('Bearer ' + token); const expiresAt = clock() + 1800;
  let origin = '', queue = Promise.resolve(), busy = false, attempts = 0, rateStart = clock();
  let draft: { dir: string; id: string; positions: number[]; expires: number } | undefined;
  let completed: { vault_id: string; owner: string; restored: boolean } | undefined;
  let vault: RunningVault | undefined;
  let wallet: Awaited<ReturnType<typeof startWallet>> | undefined;
  let closing: Promise<void> | undefined;
  const destination = join(root, 'wallet');
  function clearDraft() {
    if (!draft) return;
    const dir = draft.dir; draft = undefined;
    for (const file of ['vault/vault.json', 'recovery.json', 'upload.json']) if (existsSync(join(dir, file))) unlinkSync(join(dir, file));
    if (existsSync(join(dir, 'vault'))) rmdirSync(join(dir, 'vault'));
    rmdirSync(dir);
  }
  function checkDraft() {
    if (draft && draft.expires <= clock()) clearDraft();
    if (!draft) throw new AppError('draft_expired', 'Start again. The recovery preview expired.');
    return draft;
  }
  async function openWallet() {
    if (wallet) return wallet.launchUrl;
    const nodeDir = join(destination, 'node'), vaultDir = join(destination, 'vault');
    await loadIdentity(nodeDir, 'node', true);
    vault = await unlockVault(vaultDir, join(destination, 'recovery.json'), nodeDir, 3600);
    try {
      await vaultRequest(vaultDir, 'node.bind', { _node_dir: nodeDir });
      wallet = await startWallet(nodeDir, { vaultDir }, 0, 0);
      return wallet.launchUrl;
    } catch (error) { await vault.close(); vault = undefined; throw error; }
  }
  function commit(result: { vault_id: string; owner: string }, restored: boolean) {
    const pending = checkDraft();
    if (existsSync(destination)) throw new AppError('output_exists', 'Destination already exists. Nothing was replaced.');
    renameSync(pending.dir, destination); draft = undefined;
    completed = { vault_id: result.vault_id, owner: result.owner, restored };
    return { ...completed, directory: destination, grants_restored: false };
  }
  async function execute(path: string, input: Record<string, unknown>) {
    if (completed && !['/api/open', '/api/backup'].includes(path)) throw new AppError('setup_complete', 'This wallet is already saved.');
    if (path === '/api/create') {
      exact(input, ['confirmed']);
      if (input.confirmed !== true) throw new AppError('confirmation_required', 'Confirm the recovery requirements.');
      if (draft) throw new AppError('draft_exists', 'Continue or cancel your current setup.');
      draft = { dir: mkdtempSync(join(root, '.draft-')), id: randomUUID(), positions: [], expires: clock() + 600 };
      try {
        await initializeVault(join(draft.dir, 'vault'), join(draft.dir, 'recovery.json'));
        const positions = new Set<number>(); while (positions.size < 3) positions.add(randomInt(24));
        draft.positions = [...positions].sort((a, b) => a - b);
        return { draft_id: draft.id, positions: draft.positions, expires_at: draft.expires };
      } catch (error) { clearDraft(); throw error; }
    }
    if (path === '/api/phrase') {
      exact(input, ['draft_id', 'confirmed']); const pending = checkDraft();
      if (input.draft_id !== pending.id || input.confirmed !== true) throw new AppError('confirmation_required', 'Explicitly reveal this recovery phrase.');
      return { words: (await recovery(join(pending.dir, 'recovery.json'))).split(' ') };
    }
    if (path === '/api/confirm') {
      exact(input, ['draft_id', 'answers', 'confirmed']); const pending = checkDraft();
      if (input.draft_id !== pending.id || input.confirmed !== true || !Array.isArray(input.answers) || input.answers.length !== 3) throw new AppError('confirmation_required', 'Confirm your recovery backup.');
      const mnemonic = await recovery(join(pending.dir, 'recovery.json')); const words = mnemonic.split(' ');
      const answers = input.answers as unknown[];
      if (pending.positions.some((position, i) => typeof answers[i] !== 'string' || String(answers[i]).trim().toLowerCase() !== words[position])) throw new AppError('words_mismatch', 'The words do not match. Check your backup and try again.');
      const saved = record(JSON.parse(readFileSync(join(pending.dir, 'vault/vault.json'), 'utf8')));
      return commit({ vault_id: String(saved.vault_id), owner: String(saved.owner) }, false);
    }
    if (path === '/api/cancel') { exact(input, []); clearDraft(); return { cancelled: true }; }
    if (path === '/api/restore') {
      exact(input, ['mnemonic', 'backup', 'confirmed']);
      if (input.confirmed !== true) throw new AppError('confirmation_required', 'Confirm restoration into a new wallet.');
      if (draft) throw new AppError('draft_exists', 'Cancel the pending creation first.');
      const mnemonic = phrase(input.mnemonic);
      if (typeof input.backup !== 'string' || Buffer.byteLength(input.backup) > 4 * 1024 * 1024) throw new AppError('invalid_backup', 'Choose an encrypted Stackey backup under 4 MiB.');
      draft = { dir: mkdtempSync(join(root, '.draft-')), id: randomUUID(), positions: [], expires: clock() + 600 };
      try {
        writeFileSync(join(draft.dir, 'upload.json'), input.backup, { mode: 0o600, flag: 'wx' });
        const result = await restoreVault(join(draft.dir, 'vault'), join(draft.dir, 'upload.json'), mnemonic);
        writePrivateJson(join(draft.dir, 'recovery.json'), { format: 'stackey-recovery', version: 1, mnemonic });
        unlinkSync(join(draft.dir, 'upload.json'));
        return commit(result, true);
      } catch (error) { clearDraft(); throw error; }
    }
    if (path === '/api/open') { exact(input, []); if (!completed) throw new AppError('not_ready', 'Finish setup first.'); return { wallet_url: await openWallet() }; }
    if (path === '/api/backup') {
      exact(input, []); if (!completed) throw new AppError('not_ready', 'Finish setup first.');
      return { backup: readFileSync(join(destination, 'vault/vault.json'), 'utf8') };
    }
    throw new AppError('route_not_available', 'Route is unavailable.', 404);
  }
  const server = createServer(async (request, response) => {
    response.setHeader('content-type', 'application/json'); response.setHeader('cache-control', 'no-store');
    response.setHeader('referrer-policy', 'no-referrer'); response.setHeader('x-content-type-options', 'nosniff');
    response.setHeader('x-frame-options', 'DENY');
    response.setHeader('content-security-policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    try {
      if (request.headers.host !== new URL(origin).host || (request.headers.origin !== undefined && request.headers.origin !== origin) || (request.headers['sec-fetch-site'] !== undefined && !['same-origin', 'none'].includes(String(request.headers['sec-fetch-site'])))) throw new AppError('untrusted_browser', 'Use the local setup URL.', 403);
      const assets: Record<string, [string, string]> = { '/': [setupHtml, 'text/html; charset=utf-8'], '/setup.js': [setupJs, 'text/javascript; charset=utf-8'], '/setup.css': [setupCss, 'text/css; charset=utf-8'] };
      const asset = assets[request.url ?? ''];
      if (request.method === 'GET' && asset) { response.setHeader('content-type', asset[1]); response.end(asset[0]); return; }
      const auth = Buffer.from(request.headers.authorization ?? '');
      if (auth.length !== expected.length || !timingSafeEqual(auth, expected) || clock() >= expiresAt || closing) throw new AppError('setup_locked', 'Setup session expired. Restart setup with a new directory.', 401);
      if (busy) throw new AppError('busy', 'Wait for the current operation.', 409);
      if (request.method === 'GET' && request.url === '/api/state') {
        if (draft && draft.expires <= clock()) clearDraft();
        response.end(JSON.stringify(envelope('ok', { stage: completed ? 'complete' : draft ? 'backup' : 'welcome', draft_id: draft?.id, positions: draft?.positions, draft_expires_at: draft?.expires, expires_at: expiresAt, completed, directory: completed ? destination : root }))); return;
      }
      if (request.method !== 'POST' || request.headers.origin !== origin) throw new AppError('untrusted_browser', 'Same-origin confirmation required.', 403);
      if (clock() - rateStart >= 60) { rateStart = clock(); attempts = 0; }
      if (++attempts > 20) throw new AppError('rate_limited', 'Too many attempts. Wait one minute.', 429);
      const input = await readBody(request);
      // Serialize state transitions and recheck time after the upload and queue.
      queue = queue.then(async () => {
        busy = true;
        try {
          if (clock() >= expiresAt || closing) throw new AppError('setup_locked', 'Setup session expired.', 401);
          const data = await execute(request.url ?? '', input);
          if (clock() >= expiresAt) throw new AppError('setup_locked', 'Setup session expired.', 401);
          response.end(JSON.stringify(envelope('ok', data)));
        } catch (error) { const safe = publicError(error); response.writeHead(safe.httpStatus); response.end(JSON.stringify(safe.body)); }
        finally { busy = false; }
      });
      await queue;
    } catch (error) { const safe = publicError(error); response.writeHead(safe.httpStatus); response.end(JSON.stringify(safe.body)); }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 500;
  await new Promise<void>((accept, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => { server.off('error', reject); accept(); }); });
  const address = server.address(); if (!address || typeof address === 'string') throw new Error('Missing listener');
  origin = 'http://127.0.0.1:' + address.port;
  const timer = setInterval(() => { if (!busy && draft && (clock() >= expiresAt || clock() >= draft.expires)) clearDraft(); }, 1000); timer.unref();
  return { endpoint: origin, launchUrl: origin + '/#' + token, async close() {
    closing ??= (async () => { clearInterval(timer); await queue; clearDraft(); await wallet?.close(); await vault?.close(); await new Promise<void>((accept, reject) => { server.close(error => error ? reject(error) : accept()); server.closeIdleConnections(); }); })();
    return closing;
  } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { values } = parseArgs({ options: { dir: { type: 'string' }, port: { type: 'string' } }, strict: true });
    if (!values.dir) throw new AppError('invalid_arguments', 'Use --dir <new-private-directory> [--port 45823].');
    const setup = await startWalletSetup(values.dir, Number(values.port ?? 45823));
    process.stdout.write(JSON.stringify({ setup_url: setup.launchUrl }) + '\n');
    const stop = () => { void setup.close(); }; process.once('SIGTERM', stop); process.once('SIGINT', stop);
  } catch (error) { const safe = publicError(error); process.stdout.write(JSON.stringify(safe.body) + '\n'); process.exitCode = safe.exitCode; }
}
