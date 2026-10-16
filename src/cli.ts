#!/usr/bin/env node
import { existsSync, lstatSync, unlinkSync, rmdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';
import { connect, localStatus } from './client.js';
import { AppError, envelope, publicError, record, textField, vaultReply } from './contracts.js';
import { loadIdentity, privateDirectory, readPrivateJson, writePrivateJson } from './identity.js';
import { startNode } from './node.js';
import { issueInvitation } from './pairing.js';
import { Store } from './store.js';
import { capabilities, liveStatus, operation, runOrders, takeCredential } from './agent-client.js';
import { CREDENTIAL_GET_ACTION, CREDENTIAL_GET_TTL_MAX } from './credential-get.js';
import { onboardLink } from './link-onboarding.js';
import { providerAction, providerSchema } from './providers.js';
import { ACTION, CONNECTION, initializeDemo, ORDER_SCHEMA } from './orders.js';
import { approvePairing, initializeOwner, revokeGrant, seconds } from './policy.js';

import { backupStatusFields, defaultRecoveryPath, withBackupStatus } from './backup-state.js';
import { runPhraseBackup } from './backup-phrase.js';
import { backupToIcloud, findIcloudBackup, readBackupPassword, restoreFromIcloud } from './icloud-backup.js';
import { backupVault, initializeVault, recovery, restoreVault } from './vault.js';
import { unlockVault } from './vault-session.js';
import { sessionPath, vaultRequest } from './vault-client.js';
import { listAudit } from './website-sessions.js';

const help = `Stackey — local agent authorization demo

  stackey setup [--vault-dir .stackey/vault] [--recovery-out .stackey/recovery.json]
  stackey backup [--vault-dir .stackey/vault] [--recovery-file <private-file>]
  stackey backup --icloud --password-file <private-JSON-file> [--vault-dir .stackey/vault]
  stackey restore --password-file <private-JSON-file> [--backup-file <icloud-file>] [--vault-dir <new-dir>]
  stackey vault init --recovery-out <new-private-file> [--vault-dir .stackey/vault]
  stackey vault unlock [--recovery-file <private-file>] [--vault-dir ...] [--data-dir ...] [--ttl 900]
      # macOS: Touch ID / Keychain unlock by default; --recovery-file is fallback
  stackey vault status | lock [--vault-dir ...]
  stackey vault recover-session [--vault-dir ...]
  stackey vault backup --out <new-private-file> [--vault-dir ...]
  stackey vault restore --backup-file <private-file> --recovery-file <private-file> [--vault-dir <new-dir>]
  stackey wallet list | create --name <name> [--vault-dir ...] [--request-id <uuid>]
  stackey credential list --wallet <id> [--vault-dir ...]
  stackey credential import --wallet <id> --name <name> --kind password|api_key|private_key|website_login --secret-file <private-JSON-file> [--vault-dir ...] [--request-id <uuid>]
  stackey credential get [--state-dir ...] [--operation-id ...]
  stackey credential remove <credential-id> [--vault-dir ...]
  stackey credential origin-add <credential-id> --origin https://host [--vault-dir ...] [--data-dir ...]
  stackey credential revoke <credential-id> [--vault-dir ...] [--data-dir ...]
  stackey audit [--data-dir ...] [--after <audit-id>]
  stackey connection list --wallet <id> [--vault-dir ...]
  stackey connection add --wallet <id> --name <name> --provider demo|supabase|vercel|stripe|website|credential --config-file <private-JSON-file> [--vault-dir ...] [--request-id <uuid>]
  stackey link login | finish | cancel --wallet <id> [--vault-dir ...]
  stackey node init [--data-dir .stackey/node]
  stackey node start [--data-dir .stackey/node] [--port 45820]
  stackey node invite --out <private-file> [--ttl 300] [--data-dir ...]
  stackey node pairings [--data-dir ...] [--after <next_cursor>]
  stackey node owner-init [--owner-dir .stackey/owner] [--data-dir ...]
  stackey node demo-init [--data-dir ...]
  stackey node approve <pairing-id> --principal <full-fingerprint> --action demo.orders.read [--ttl 900] [--owner-dir ...] [--data-dir ...]
  stackey node revoke <grant-id> [--owner-dir ...] [--data-dir ...]
  stackey node grants [--data-dir ...] [--after <next_cursor>]
  stackey node events [--data-dir ...] [--after <next_cursor>]
  stackey connect --invite-file <private-file> [--state-dir .stackey/agent] [--name Agent]
  stackey connect <invitation> [--state-dir ...] [--name Agent]
  stackey status [--live] [--state-dir ...]
  stackey capabilities [--state-dir ...]
  stackey run demo.orders.read --schema
  stackey run demo.orders.read --from 2026-09-26 --to 2026-10-02 [--cursor ...] [--operation-id ...] [--state-dir ...]
  stackey node approve <pairing-id> --principal <fingerprint> --action <provider-action> --connection <id> --wallet <id> --vault-dir ... [--max-calls 1] [--max-amount-minor 50]
      # credential.get defaults to 300 seconds; other actions default to 900
      # approve credential.get again with --replace-grant <current-grant-id>; same pairing and connection
  stackey run supabase.orders.read --from YYYY-MM-DD --to YYYY-MM-DD [--cursor ...]
  stackey run vercel.ai.generate --prompt <text> [--operation-id ...]
  stackey run stripe.payments.read [--cursor ...]
  stackey run stripe.mpp.pay [--operation-id ...]
  stackey run website.session.login [--operation-id ...]
  stackey run credential.get [--operation-id ...]
  stackey operation <operation-id> [--state-dir ...]

All results are JSON. --json is accepted for compatibility.
Loopback only. Credentials stay in the vault. An agent receives a secret only through stackey credential get after a short-lived per-agent grant. Stripe adapters are test mode only.
Provider operations return operation_pending; poll the same operation ID.
After Link approval, repeat the same MPP operation ID to resume, never a new one.
Owner mutations that time out return result_unknown; retry the same --request-id or list first.
Private state belongs to the execution environment, not an individual Bot.
`;

const output = (value: unknown) => process.stdout.write(JSON.stringify(value) + '\n');
function outputAgentBody(body: unknown) {
  try {
    const envelope = record(body);
    const result = record(record(envelope.data).result);
    if (typeof result.value === 'string' && Object.keys(result).length === 1) {
      output({ value: result.value });
      return;
    }
  } catch { /* not a one-shot credential handoff */ }
  output(body);
}

async function main() {
  if (process.argv.slice(2).includes('--help') || process.argv.length === 2) {
    process.stdout.write(help); return;
  }
  let parsed;
  try {
    const args = process.argv.slice(2);
    // Public SHA-256 fingerprints are base64url and may begin with '-'.
    // Preserve the documented separate argument form without treating a valid
    // fingerprint as a CLI option; identity verification still happens at approval.
    for (let i = 0; i < args.length && args[i] !== '--'; i++) {
      if (args[i] === '--principal' && /^-[A-Za-z0-9_-]{42}$/.test(args[i + 1] ?? '')) {
        args.splice(i, 2, `--principal=${args[i + 1]}`);
      }
    }
    parsed = parseArgs({ args, options: {
      'data-dir': { type: 'string' }, 'state-dir': { type: 'string' },
      'owner-dir': { type: 'string' }, principal: { type: 'string' }, action: { type: 'string' },
      live: { type: 'boolean' }, schema: { type: 'boolean' }, from: { type: 'string' }, to: { type: 'string' },
      cursor: { type: 'string' }, 'operation-id': { type: 'string' },
      'invite-file': { type: 'string' }, out: { type: 'string' },
      'vault-dir': { type: 'string' }, 'recovery-out': { type: 'string' }, 'recovery-file': { type: 'string' },
      'backup-file': { type: 'string' }, 'secret-file': { type: 'string' }, wallet: { type: 'string' },
      connection: { type: 'string' }, 'max-calls': { type: 'string' }, 'max-amount-minor': { type: 'string' }, prompt: { type: 'string' },
      kind: { type: 'string' }, provider: { type: 'string' }, 'config-file': { type: 'string' },
      origin: { type: 'string' },
      icloud: { type: 'boolean' },
      'password-file': { type: 'string' },
      'request-id': { type: 'string' },
      'replace-grant': { type: 'string' },
      port: { type: 'string' }, ttl: { type: 'string' }, name: { type: 'string' },
      after: { type: 'string' },
      json: { type: 'boolean' },
    }, allowPositionals: true, strict: true });
  } catch { throw new AppError('invalid_arguments', 'Invalid arguments; use --help.'); }
  const { values, positionals } = parsed;
  const command = positionals[0];
  const dataDir = resolve(values['data-dir'] ?? '.stackey/node');
  const stateDir = resolve(values['state-dir'] ?? '.stackey/agent');
  const ownerDir = resolve(values['owner-dir'] ?? '.stackey/owner');
  const vaultDir = resolve(values['vault-dir'] ?? '.stackey/vault');
  if (values['replace-grant'] !== undefined &&
      (command !== 'node' || positionals[1] !== 'approve' || !values['vault-dir'] || values.action !== CREDENTIAL_GET_ACTION)) {
    throw new AppError('invalid_arguments', '--replace-grant requires node approve credential.get with --vault-dir.');
  }
  if (command === 'link') {
    const sub = positionals[1];
    if (positionals.length !== 2 || !['login', 'finish', 'cancel'].includes(sub ?? '')) throw new AppError('invalid_arguments', 'Use link login, finish or cancel.');
    const result = await onboardLink(vaultDir, textField(values.wallet, 64), sub as 'login' | 'finish' | 'cancel');
    output(envelope(String(result.status), result)); return;
  }
  if (command === 'backup' && positionals.length === 1) {
    if (values.icloud) {
      if (!values['password-file']) throw new AppError('backup_password_required', 'Provide a backup password via --password-file (private JSON).');
      output(envelope('ok', vaultReply(await backupToIcloud(vaultDir, readBackupPassword(resolve(values['password-file']))))));
      return;
    }
    const recoveryFile = values['recovery-file'] === undefined ? undefined : resolve(textField(values['recovery-file']));
    const result = await runPhraseBackup(vaultDir, { input: process.stdin, human: process.stderr }, recoveryFile);
    output(envelope('ok', vaultReply(result)));
    return;
  }
  if (command === 'restore' && positionals.length === 1) {
    if (!values['password-file']) throw new AppError('backup_password_required', 'Provide a backup password via --password-file (private JSON).');
    const backupFile = values['backup-file'] === undefined ? findIcloudBackup() : resolve(textField(values['backup-file']));
    output(envelope('ok', vaultReply(await restoreFromIcloud(vaultDir, readBackupPassword(resolve(values['password-file'])), backupFile))));
    return;
  }
  if (command === 'setup' && positionals.length === 1) {
    const recoveryOut = resolve(values['recovery-out'] ?? defaultRecoveryPath(vaultDir));
    const created = await initializeVault(vaultDir, recoveryOut);
    output(envelope('ok', withBackupStatus(vaultDir, {
      ...created,
      next_step: 'Run stackey backup after writing down the recovery phrase. The phrase is not shown here.',
    })));
    return;
  }
  if (command === 'vault') {
    if (positionals.length !== 2) throw new AppError('invalid_arguments', 'Use vault --help.');
    const subcommand = positionals[1];
    if (subcommand === 'init') {
      output(envelope('ok', withBackupStatus(vaultDir, await initializeVault(vaultDir, resolve(textField(values['recovery-out']))))));
      return;
    }
    if (subcommand === 'unlock') {
      const recoveryFile = values['recovery-file'] === undefined ? undefined : resolve(textField(values['recovery-file']));
      const vault = await unlockVault(vaultDir, recoveryFile, dataDir, values.ttl === undefined ? 900 : Number(values.ttl));
      output(envelope('ok', withBackupStatus(vaultDir, { status:'unlocked',vault_id:vault.vaultId,owner:vault.owner,expires_at:vault.expiresAt })));
      const stop = () => { void vault.close().catch(error => { const safe=publicError(error); output(safe.body); process.exitCode=safe.exitCode; }); };
      process.once('SIGINT',stop); process.once('SIGTERM',stop); return;
    }
    if (subcommand === 'status' || subcommand === 'lock') {
      try { output(envelope('ok', withBackupStatus(vaultDir, await vaultRequest(vaultDir,subcommand)))); }
      catch(error) {
        if(error instanceof AppError && error.code==='node_locked') output(envelope('ok', withBackupStatus(vaultDir, {status:'locked'})));
        else throw error;
      }
      return;
    }
    if (subcommand === 'backup') { output(envelope('ok',backupVault(vaultDir,resolve(textField(values.out))))); return; }
    if (subcommand === 'restore') { output(envelope('ok',await restoreVault(vaultDir,resolve(textField(values['backup-file'])),await recovery(resolve(textField(values['recovery-file'])))))); return; }
    if (subcommand === 'recover-session') {
      const path=sessionPath(vaultDir); const state=record(readPrivateJson(path));
      const pid=state.pid; if(!Number.isInteger(pid)||(pid as number)<=0) throw new AppError('invalid_session','Invalid session process.');
      let alive=true; try { process.kill(pid as number,0); } catch(error) { alive=(error as NodeJS.ErrnoException).code!=='ESRCH'; }
      if(alive) throw new AppError('session_active','Session process still exists; lock it first.');
      const socket=textField(state.socket,100); const directory=dirname(socket);
      if(!directory.startsWith(join(tmpdir(),'stackey-vault-'))||join(directory,'owner.sock')!==socket) throw new AppError('unsafe_session','Invalid session socket.');
      const stat=lstatSync(directory); if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid?.()||(stat.mode&0o077)!==0) throw new AppError('unsafe_session','Unsafe session directory.');
      if(existsSync(socket)){ const socketStat=lstatSync(socket); if(!socketStat.isSocket()||socketStat.uid!==process.getuid?.()) throw new AppError('unsafe_session','Unsafe session socket.'); unlinkSync(socket); }
      rmdirSync(directory); unlinkSync(path); output(envelope('ok',{status:'locked',stale_session_removed:true})); return;
    }
    throw new AppError('unknown_command','Use vault --help.');
  }
  if (command === 'credential' && positionals[1] === 'get') {
    if (positionals.length !== 2) throw new AppError('invalid_arguments', 'Unexpected wallet arguments.');
    output(await takeCredential(stateDir, values['operation-id']));
    return;
  }
  if (['wallet','credential','connection'].includes(command ?? '')) {
    const subcommand=positionals[1]; let args:Record<string,unknown>;
    if(command==='wallet' && subcommand==='list') args={};
    else if(command==='wallet' && subcommand==='create') args={name:textField(values.name,64)};
    else if(command==='credential' && subcommand==='import') args={wallet_id:textField(values.wallet,64),name:textField(values.name,64),kind:textField(values.kind,32),value:textField(record(readPrivateJson(resolve(textField(values['secret-file'])))).value,16384)};
    else if(command==='credential' && subcommand==='remove' && positionals.length===3) args={credential_id:textField(positionals[2],64)};
    else if(command==='credential' && subcommand==='revoke' && positionals.length===3) args={credential_id:textField(positionals[2],64),_node_dir:dataDir};
    else if(command==='credential' && subcommand==='origin-add' && positionals.length===3) args={credential_id:textField(positionals[2],64),origin:textField(values.origin,250),_node_dir:dataDir};
    else if(subcommand==='list' && ['credential','connection'].includes(command!)) args={wallet_id:textField(values.wallet,64)};
    else if(command==='connection' && subcommand==='add') args={wallet_id:textField(values.wallet,64),name:textField(values.name,64),provider:textField(values.provider,32),config:record(readPrivateJson(resolve(textField(values['config-file']))))};
    else throw new AppError('unknown_command','Use --help for wallet commands.');
    const extra = command==='credential' && ['remove','revoke','origin-add'].includes(subcommand ?? '') ? 3 : 2;
    if(positionals.length!==extra) throw new AppError('invalid_arguments','Unexpected wallet arguments.');
    if(subcommand==='list' && values.after!==undefined) args.after=textField(values.after,64);
    if(['wallet.create','credential.import','connection.add'].includes(`${command}.${subcommand}`)) args.request_id=values['request-id']??randomUUID();
    const vaultCommand = command==='credential' && subcommand==='origin-add' ? 'credential.origin.add' : `${command}.${subcommand}`;
    output(envelope('ok',await vaultRequest(vaultDir,vaultCommand,args))); return;
  }
  if (command === 'node') {
    if (values['vault-dir'] && ['owner-init','approve','revoke','demo-init'].includes(positionals[1] ?? '')) {
      const sub=positionals[1];
      if (positionals.length !== (sub==='approve'||sub==='revoke'?3:2)) throw new AppError('invalid_arguments','Unexpected Node arguments.');
      const args:Record<string,unknown>={_node_dir:dataDir};
      const action=sub==='owner-init'?'node.bind':sub==='demo-init'?'demo.init':sub==='approve'?'grant.approve':'grant.revoke';
      if(sub==='approve') Object.assign(args,{pairing_id:textField(positionals[2],36),principal:textField(values.principal,64),action:textField(values.action,64),ttl:values.ttl===undefined?(values.action===CREDENTIAL_GET_ACTION?CREDENTIAL_GET_TTL_MAX:900):Number(values.ttl),wallet_id:values.wallet??'wallet_demo',...(values.connection?{connection_id:values.connection,max_calls:Number(values['max-calls']??1),max_amount_minor:Number(values['max-amount-minor']??0)}:{})});
      if(values['replace-grant']!==undefined) args.replace_grant_id=textField(values['replace-grant'],36);
      if(sub==='revoke') args.grant_id=textField(positionals[2],36);
      output(envelope('ok',await vaultRequest(vaultDir,action,args))); return;
    }
    const subcommand = positionals[1];
    if (positionals.length !== (subcommand === 'approve' || subcommand === 'revoke' ? 3 : 2)) {
      throw new AppError('invalid_arguments', 'Unexpected Node arguments; use --help.');
    }
    if (['owner-init', 'demo-init', 'approve', 'revoke', 'grants', 'events'].includes(subcommand ?? '')) {
      const nodeIdentity = await loadIdentity(dataDir, 'node');
      const store = new Store(dataDir);
      try {
        if (subcommand === 'owner-init') {
          const owner = await loadIdentity(ownerDir, 'owner', true);
          await initializeOwner(store, owner);
          output(envelope('ok', { owner: owner.id, owner_dir: ownerDir })); return;
        }
        if (subcommand === 'demo-init') {
          initializeDemo(store);
          output(envelope('ok', { source: 'local_synthetic', connection_id: CONNECTION, rows: 21 })); return;
        }
        if (subcommand === 'approve') {
          const owner = await loadIdentity(ownerDir, 'owner');
          output(envelope('ok', await approvePairing(store, nodeIdentity, owner,
            textField(positionals[2], 36), textField(values.principal, 64), textField(values.action, 64),
            values.ttl === undefined ? 900 : Number(values.ttl)))); return;
        }
        if (subcommand === 'revoke') {
          const owner = await loadIdentity(ownerDir, 'owner');
          output(envelope('ok', await revokeGrant(store, nodeIdentity, owner, textField(positionals[2], 36)))); return;
        }
        if (subcommand === 'grants') {
          let timestamp = -1; let id = '';
          if (values.after !== undefined) {
            const row = store.db.prepare('SELECT created_at, grant_id FROM grants WHERE grant_id = ?').get(textField(values.after, 64));
            if (!row) throw new AppError('invalid_cursor', 'Grant cursor was not found.');
            timestamp = row.created_at as number; id = row.grant_id as string;
          }
          const rows = store.db.prepare(`SELECT grant_id, pairing_id, principal, created_at, expires_at, version, wallet_id, action, connection_id, max_calls, max_amount_minor, superseded_at,
            CASE WHEN revoked_at IS NOT NULL THEN 'revoked' WHEN expires_at <= ? THEN 'expired' ELSE 'active' END AS status
            FROM grants WHERE (created_at, grant_id) > (?, ?) ORDER BY created_at, grant_id LIMIT 201`).all(seconds(), timestamp, id);
          const page = rows.slice(0, 200);
          output(envelope('ok', { grants: page, next_cursor: rows.length > 200 ? page[199]!.grant_id : null })); return;
        }
        const after = values.after === undefined ? 0 : Number(values.after);
        if (!Number.isSafeInteger(after) || after < 0) throw new AppError('invalid_cursor', 'Event cursor must be a nonnegative sequence number.');
        const rows = store.db.prepare('SELECT * FROM events WHERE sequence > ? ORDER BY sequence LIMIT 201').all(after);
        const page = rows.slice(0, 200);
        output(envelope('ok', { events: page, next_cursor: rows.length > 200 ? String(page[199]!.sequence) : null })); return;
      } finally { store.close(); }
    }
    if (subcommand === 'init') {
      privateDirectory(dataDir);
      if (existsSync(join(dataDir, 'identity.json'))) throw new AppError('already_initialized', 'Node identity already exists.');
      const identity = await loadIdentity(dataDir, 'node', true);
      const store = new Store(dataDir); store.close();
      output(envelope('ok', { node_id: identity.id, data_dir: dataDir })); return;
    }
    if (subcommand === 'start') {
      const port = values.port === undefined ? 45820 : Number(values.port);
      const node = await startNode(dataDir, port);
      output(envelope('ok', { node_id: node.nodeId, endpoint: node.endpoint, mode: 'local_pairing_only' }));
      const stop = () => { void node.close().catch(error => {
        const safe = publicError(error); output(safe.body); process.exitCode = safe.exitCode;
      }); };
      process.once('SIGINT', stop); process.once('SIGTERM', stop);
      return;
    }
    if (subcommand === 'invite') {
      if (!values.out) throw new AppError('missing_output', 'Use --out to write the invitation to a private file.');
      const file = resolve(values.out);
      const parent = resolve(file, '..');
      privateDirectory(parent);
      if (existsSync(file)) throw new AppError('output_exists', 'Invitation output already exists; choose a new filename.');
      const identity = await loadIdentity(dataDir, 'node');
      const store = new Store(dataDir);
      try {
        const ttl = values.ttl === undefined ? 300 : Number(values.ttl);
        const invitation = await issueInvitation(store, identity, ttl);
        writePrivateJson(file, { invitation });
        output(envelope('ok', { invitation_file: file, expires_in_seconds: ttl }));
      } finally { store.close(); }
      return;
    }
    if (subcommand === 'pairings') {
      await loadIdentity(dataDir, 'node');
      const store = new Store(dataDir);
      try { output(envelope('ok', store.listPairings(values.after === undefined ? undefined : textField(values.after, 64)))); }
      finally { store.close(); }
      return;
    }
  }
  if (command === 'audit' && positionals.length === 1) {
    await loadIdentity(dataDir, 'node');
    const store = new Store(dataDir);
    try { output(envelope('ok', listAudit(store, values.after === undefined ? undefined : textField(values.after, 36)))); }
    finally { store.close(); }
    return;
  }
  if (command === 'connect') {
    if (positionals.length > 2 || (values['invite-file'] && positionals[1])) {
      throw new AppError('invalid_arguments', 'Supply exactly one invitation source.');
    }
    const invitation = values['invite-file'] ?
      textField(record(readPrivateJson(resolve(values['invite-file']))).invitation, 8192) :
      textField(positionals[1], 8192);
    output(await connect(invitation, stateDir, values.name ?? 'Agent')); return;
  }
  if (command === 'status' && positionals.length === 1) {
    const pairing = await (values.live ? liveStatus(stateDir) : localStatus(stateDir));
    const backup = backupStatusFields(vaultDir);
    output(Object.keys(backup).length === 0 ? pairing : { ...pairing, data: { ...record(pairing.data), ...backup } });
    return;
  }
  if (command === 'capabilities' && positionals.length === 1) {
    output(await capabilities(stateDir)); return;
  }
  if (command === 'run' && positionals.length === 2) {
    const action = textField(positionals[1], 64);
    if (values.schema) {
      if (action !== ACTION && !providerAction(action)) throw new AppError('action_not_available', 'Unsupported action.');
      output(envelope('ok', action===ACTION?ORDER_SCHEMA:providerSchema(action))); return;
    }
    outputAgentBody(await runOrders(stateDir, action, action==='vercel.ai.generate'?{prompt:values.prompt}:action==='stripe.mpp.pay'||action==='website.session.login'||action===CREDENTIAL_GET_ACTION?{}:action==='stripe.payments.read'?(values.cursor?{cursor:values.cursor}:{}):{ from: values.from, to: values.to,
      ...(values.cursor === undefined ? {} : { cursor: values.cursor }) }, values['operation-id'])); return;
  }
  if (command === 'operation' && positionals.length === 2) {
    outputAgentBody(await operation(stateDir, textField(positionals[1], 36))); return;
  }
  throw new AppError('unknown_command', 'Command is not available; use --help.');
}

main().catch(error => {
  const safe = publicError(error); output(safe.body); process.exitCode = safe.exitCode;
});
