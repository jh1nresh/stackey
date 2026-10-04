import { AppError, record } from './contracts.js';
import { runOrders } from './agent-client.js';
import { ACTION, orderParams } from './orders.js';

export function renderReport(input: unknown): string {
  const result = record(input);
  if (result.source !== 'local_synthetic' || result.complete !== true || !Array.isArray(result.rows)) {
    throw new AppError('incomplete_report', 'A complete synthetic order result is required.');
  }
  const days = new Map<string, { count: number; failed: number; revenue: Map<string, number>; losses: Map<string, number> }>();
  for (const raw of result.rows) {
    const row = record(raw);
    if (typeof row.created_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T/.test(row.created_at) ||
        !['USD', 'TWD'].includes(String(row.currency)) || !Number.isSafeInteger(row.amount_minor) || Number(row.amount_minor) < 0 ||
        !['paid', 'payment_failed'].includes(String(row.payment_status))) throw new AppError('invalid_report', 'Invalid demo order.');
    const date = row.created_at.slice(0, 10), currency = String(row.currency), amount = Number(row.amount_minor);
    const day = days.get(date) ?? { count: 0, failed: 0, revenue: new Map(), losses: new Map() };
    day.count++;
    if (row.payment_status === 'paid') day.revenue.set(currency, (day.revenue.get(currency) ?? 0) + amount);
    else { day.failed++; day.losses.set(currency, (day.losses.get(currency) ?? 0) + amount); }
    days.set(date, day);
  }
  const money = (amount: number, currency: string) => `${currency} ${(amount / 100).toFixed(2)}`;
  const list = (values: Map<string, number>) => [...values].sort().map(([c, n]) => money(n, c)).join(' + ') || '—';
  const ordered = [...days].sort(([a], [b]) => a.localeCompare(b));
  const count = ordered.reduce((n, [, d]) => n + d.count, 0), failed = ordered.reduce((n, [, d]) => n + d.failed, 0);
  const lines = ['# Daily sales report', '', `Synthetic demo orders · ${result.from} → ${result.to} · UTC`, '',
    'Revenue includes paid orders only. Currencies are kept separate; no exchange rate is assumed.', '',
    '| Date | Paid revenue | Failed / orders | Failure rate | Failed payment amount |',
    '| --- | --- | --- | --- | --- |'];
  for (const [date, d] of ordered) lines.push(`| ${date} | ${list(d.revenue)} | ${d.failed}/${d.count} | ${(d.failed / d.count * 100).toFixed(1)}% | ${list(d.losses)} |`);
  lines.push('', `**Payment failure rate: ${failed}/${count} (${count ? (failed / count * 100).toFixed(1) : '0.0'}%).**`);
  for (const currency of ['USD', 'TWD']) {
    const peak = Math.max(0, ...ordered.map(([, d]) => d.revenue.get(currency) ?? 0));
    if (peak) lines.push(`Highest ${currency} revenue: ${ordered.filter(([, d]) => d.revenue.get(currency) === peak).map(([date]) => date).join(', ')} — ${money(peak, currency)}.`);
  }
  if (!count) lines.push('No orders in this date range.');
  if (count && failed / count >= 0.2) lines.push('', '**Alert:** Payment failure rate exceeds the demo alert threshold of 20%. Investigate the payment gateway and error logs; this is a signal, not a confirmed cause.');
  if (ordered.length > 1 && ordered.every(([, d]) => d.failed === 1 && d.losses.get('USD') === 1200 && d.losses.size === 1)) lines.push('Recurring pattern: one USD 12.00 failed payment every day. These fixture values are synthetic.');
  lines.push('', 'Access: generated from an owner-approved, time-limited demo.orders.read grant. No store API key or vault credential was given to the agent.',
    'Revocation blocks future reads. It cannot erase this report or data already read.');
  return lines.join('\n') + '\n';
}

export async function orderReport(dir: string, input: unknown): Promise<string> {
  const params = orderParams(input), rows: unknown[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 100; page++) {
    const response = record(await runOrders(dir, ACTION, { ...params, ...(cursor ? { cursor } : {}) }));
    const result = record(record(response.data).result);
    if (!Array.isArray(result.rows)) throw new AppError('invalid_report', 'Invalid order result.');
    rows.push(...result.rows);
    if (result.complete === true) return renderReport({ ...result, from: params.from, to: params.to, rows });
    if (typeof result.next_cursor !== 'string' || result.next_cursor === cursor) throw new AppError('incomplete_report', 'Pagination could not be completed.');
    cursor = result.next_cursor;
  }
  throw new AppError('incomplete_report', 'Report page limit reached.');
}
