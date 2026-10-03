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

const help = `Stackey — local pairing milestone

  stackey node init [--data-dir .stackey/node]
  stackey node start [--data-dir .stackey/node] [--port 45820]
  stackey node invite --out <private-file> [--ttl 300] [--data-dir ...]
  stackey node pairings [--data-dir ...] [--after <next_cursor>]
  stackey connect --invite-file <private-file> [--state-dir .stackey/agent] [--name Agent]
  stackey connect <invitation> [--state-dir ...] [--name Agent]
  stackey status [--state-dir ...]

All results are JSON. --json is accepted for compatibility.
Only loopback pairing is implemented; no grants, secrets, sessions or service operations.
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
  if (command === 'node') {
    if (positionals.length !== 2) throw new AppError('invalid_arguments', 'Expected one Node subcommand.');
    const subcommand = positionals[1];
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
    output(await localStatus(stateDir)); return;
  }
  throw new AppError('unknown_command', 'Command is not available; use --help.');
}

main().catch(error => {
  const safe = publicError(error); output(safe.body); process.exitCode = safe.exitCode;
});
