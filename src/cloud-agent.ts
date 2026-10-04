import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { connect, localStatus } from './client.js';
import { capabilities, liveStatus, operation, runOrders } from './agent-client.js';
import { AppError, publicError, textField } from './contracts.js';
import { ACTION } from './orders.js';
import { orderReport } from './order-report.js';

async function main() {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: {
    'state-dir': { type: 'string' }, name: { type: 'string' }, live: { type: 'boolean' },
    from: { type: 'string' }, to: { type: 'string' }, cursor: { type: 'string' }, 'operation-id': { type: 'string' },
  } });
  const dir = resolve(values['state-dir'] ?? '.stackey/cloud-agent');
  const [command, argument] = positionals;
  let result: unknown;
  if (command === 'connect' && positionals.length === 2) result = await connect(textField(argument, 8192), dir, values.name ?? 'Cloud Agent');
  else if (command === 'status' && positionals.length === 1) result = await (values.live ? liveStatus(dir) : localStatus(dir));
  else if (command === 'capabilities' && positionals.length === 1) result = await capabilities(dir);
  else if (command === 'report' && positionals.length === 1) {
    process.stdout.write(await orderReport(dir, { from: values.from, to: values.to })); return;
  } else if (command === 'run' && argument === ACTION && positionals.length === 2) result = await runOrders(dir, textField(argument, 64), {
    from: values.from, to: values.to, ...(values.cursor ? { cursor: values.cursor } : {}),
  }, values['operation-id']);
  else if (command === 'operation' && positionals.length === 2) result = await operation(dir, textField(argument, 36));
  else throw new AppError('unknown_command', 'Use connect, status --live, capabilities, report --from YYYY-MM-DD --to YYYY-MM-DD, run demo.orders.read, or operation.');
  process.stdout.write(JSON.stringify(result) + '\n');
}
main().catch(error => { const safe = publicError(error); process.stdout.write(JSON.stringify(safe.body) + '\n'); process.exitCode = safe.exitCode; });
