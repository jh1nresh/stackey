import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { AppError, record } from './contracts.js';

export function linkResult(stdout: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(stdout);
  // Official Link CLI generator commands return a JSON array, ordinary commands
  // return an object. All Stackey calls disable polling and accept one result.
  if (Array.isArray(parsed)) {
    if (parsed.length !== 1) throw new Error('Expected one non-polling result.');
    return record(parsed[0]);
  }
  return record(parsed);
}
export async function runLinkCli(auth: string, args: string[], token?: string): Promise<Record<string, unknown>> {
  const packagePath = createRequire(import.meta.url).resolve('@stripe/link-cli/package.json');
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(dirname(packagePath), 'dist/cli.js'), '--auth', auth, ...args, '--format', 'json'],
      { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env.PATH ?? '', ...(token ? { LINK_ACCESS_TOKEN: token, LINK_NO_REFRESH: '1' } : {}), NO_UPDATE_NOTIFIER: '1' } });
    let stdout = ''; let size = 0; const timer = setTimeout(() => child.kill('SIGTERM'), 12000);
    child.stdout.on('data', chunk => { size += chunk.length; if (size > 65536) child.kill('SIGTERM'); else stdout += chunk.toString(); });
    child.stderr.on('data', () => {});
    child.on('error', () => { clearTimeout(timer); reject(new AppError('link_unavailable', 'Link CLI could not start.', 502, 4, 'result_unknown')); });
    child.on('close', code => { clearTimeout(timer);
      try { if (code !== 0 || size > 65536) throw new Error(); resolve(linkResult(stdout)); }
      catch { reject(new AppError('link_result_unknown', 'Link did not confirm this request. Check its status before creating another payment.', 502, 4, 'result_unknown')); }
    });
  });
}
