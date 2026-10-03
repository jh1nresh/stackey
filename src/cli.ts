#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { connect, localStatus } from './client.js';
import { AppError, envelope, publicError, record, textField } from './contracts.js';
import { loadIdentity, privateDirectory, readPrivateJson, writePrivateJson } from './identity.js';
import { startNode } from './node.js';
import { issueInvitation } from './pairing.js';
import { Store } from './store.js';
import { capabilities, liveStatus, operation, runOrders } from './agent-client.js';
import { ACTION, CONNECTION, initializeDemo, ORDER_SCHEMA } from './orders.js';
import { approvePairing, initializeOwner, revokeGrant, seconds } from './policy.js';

const help = `Stackey — local agent authorization demo

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
  stackey operation <operation-id> [--state-dir ...]

All results are JSON. --json is accepted for compatibility.
Loopback only. Orders are synthetic local data; Supabase, payments and secret storage are not integrated.
Private state belongs to the execution environment, not an individual Bot.
`;

const output = (value: unknown) => process.stdout.write(JSON.stringify(value) + '\n');

async function main() {
  if (process.argv.slice(2).includes('--help') || process.argv.length === 2) {
    process.stdout.write(help); return;
  }
  let parsed;
  try {
    parsed = parseArgs({ options: {
      'data-dir': { type: 'string' }, 'state-dir': { type: 'string' },
      'owner-dir': { type: 'string' }, principal: { type: 'string' }, action: { type: 'string' },
      live: { type: 'boolean' }, schema: { type: 'boolean' }, from: { type: 'string' }, to: { type: 'string' },
      cursor: { type: 'string' }, 'operation-id': { type: 'string' },
      'invite-file': { type: 'string' }, out: { type: 'string' },
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
  if (command === 'node') {
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
          const rows = store.db.prepare(`SELECT grant_id, pairing_id, principal, created_at, expires_at, version,
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
    output(await (values.live ? liveStatus(stateDir) : localStatus(stateDir))); return;
  }
  if (command === 'capabilities' && positionals.length === 1) {
    output(await capabilities(stateDir)); return;
  }
  if (command === 'run' && positionals.length === 2) {
    const action = textField(positionals[1], 64);
    if (values.schema) {
      if (action !== ACTION) throw new AppError('action_not_available', 'Only demo.orders.read is implemented.');
      output(envelope('ok', ORDER_SCHEMA)); return;
    }
    output(await runOrders(stateDir, action, { from: values.from, to: values.to,
      ...(values.cursor === undefined ? {} : { cursor: values.cursor }) }, values['operation-id'])); return;
  }
  if (command === 'operation' && positionals.length === 2) {
    output(await operation(stateDir, textField(positionals[1], 36))); return;
  }
  throw new AppError('unknown_command', 'Command is not available; use --help.');
}

main().catch(error => {
  const safe = publicError(error); output(safe.body); process.exitCode = safe.exitCode;
});
