import assert from 'node:assert/strict';

// Flags from @stripe/link-cli@0.25.1 packages/cli/src/commands/spend-request/{index,schema}.tsx.
// request-approval registers only args.id. interval / max-attempts are retrieve options.
export const createFlags = new Set([
  '--idempotency-key', '--payment-method-id', '--credential-type', '--network-id',
  '--execution-method', '--merchant-account-id', '--amount', '--currency',
  '--merchant-name', '--merchant-url', '--context', '--line-item', '--total',
  '--request-approval', '--no-request-approval', '--test', '--approve',
  '--output-file', '--force', '--approval-detail', '--metadata', '--expires-at',
  '--recurring-interval', '--recurring-interval-count',
]);
const retrieveFlags = new Set([
  '--timeout', '--interval', '--max-attempts', '--include', '--output-file', '--force',
]);
const booleanFlags = new Set([
  '--request-approval', '--no-request-approval', '--test', '--approve', '--force',
]);

function flagsOf(args: string[]): { flags: string[]; positionals: string[] } {
  const flags: string[] = []; const positionals: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const token = args[index]!;
    if (!token.startsWith('--')) { positionals.push(token); continue; }
    flags.push(token);
    if (!booleanFlags.has(token) && args[index + 1] && !args[index + 1]!.startsWith('--')) index++;
  }
  return { flags, positionals };
}

export function assertLinkSpendRequestArgs(args: string[]): void {
  assert.equal(args[0], 'spend-request');
  const subcommand = args[1];
  const { flags, positionals } = flagsOf(args.slice(2));
  if (subcommand === 'create') {
    assert.equal(positionals.length, 0);
    for (const flag of flags) assert.ok(createFlags.has(flag), `create rejects ${flag}`);
    return;
  }
  if (subcommand === 'retrieve') {
    assert.equal(positionals.length, 1);
    for (const flag of flags) assert.ok(retrieveFlags.has(flag), `retrieve rejects ${flag}`);
    return;
  }
  if (subcommand === 'request-approval') {
    assert.deepEqual(args.slice(1), ['request-approval', positionals[0]]);
    assert.equal(positionals.length, 1);
    assert.equal(flags.length, 0, 'request-approval accepts only the spend-request id');
    return;
  }
  assert.fail(`unexpected spend-request subcommand ${subcommand}`);
}
