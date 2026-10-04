import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';

// Follow only the Agent entry point's runtime imports. Never package workspace
// state, Owner CLI, Vault implementation, recovery material, or the wallet UI.
const work = mkdtempSync(join(tmpdir(), 'stackey-package-'));
try {
  const root = join(work, 'stackey-agent');
  const seen = new Set();
  function collect(file) {
    if (seen.has(file)) return;
    seen.add(file);
    if (['cli.js', 'vault.js', 'vault-session.js', 'wallet.js', 'wallet-setup.js'].includes(file)) throw new Error('Owner module in Agent package');
    const source = readFileSync(join('dist/src', file), 'utf8');
    const target = join(root, 'src', file);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, source);
    for (const match of source.matchAll(/(?:from\s*|import\s*)['"]\.\/([^'"]+\.js)['"]/g)) collect(match[1]);
  }
  collect('cloud-agent.js');
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'stackey-agent', type: 'module', engines: { node: '>=22.18.0' } }));
  for (const name of ['jose', 'oauth4webapi']) cpSync(join('node_modules', name), join(root, 'node_modules', name), { recursive: true });
  execFileSync('tar', ['-czf', resolve('dist/agent-package.tgz'), '-C', work, 'stackey-agent']);
} finally { rmSync(work, { recursive: true }); }
