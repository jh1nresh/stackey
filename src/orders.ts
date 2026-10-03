import { AppError, record, textField } from './contracts.js';
import type { Store } from './store.js';

export const ACTION = 'demo.orders.read';
export const RESOURCE = 'demo:store/orders';
export const WALLET = 'wallet_demo';
export const CONNECTION = 'connection_local_demo';
export const ORDER_SCHEMA = {
  action: ACTION, source: 'local_synthetic', resource: RESOURCE,
  parameters: { from: 'YYYY-MM-DD (UTC, inclusive)', to: 'YYYY-MM-DD (UTC, inclusive)', cursor: 'optional order ID from next_cursor' },
  limits: { max_days: 31, page_size: 100 },
  result: { fields: ['id', 'created_at', 'currency', 'amount_minor', 'payment_status'], amount_unit: 'minor', timezone: 'UTC' },
};

export function initializeDemo(store: Store): void {
  store.transaction(() => {
    const insert = store.db.prepare('INSERT OR IGNORE INTO demo_orders VALUES (?, ?, ?, ?, ?)');
    for (let day = 0; day < 7; day++) {
      const date = `2026-${day < 5 ? '09' : '10'}-${String(day < 5 ? 26 + day : day - 4).padStart(2, '0')}`;
      insert.run(`demo-${day}-usd`, date + 'T09:00:00.000Z', 'USD', 1000 + day * 100, 'paid');
      insert.run(`demo-${day}-twd`, date + 'T10:00:00.000Z', 'TWD', 30000 + day * 1000, 'paid');
      insert.run(`demo-${day}-failed`, date + 'T11:00:00.000Z', 'USD', 1200, 'payment_failed');
    }
    store.db.prepare('INSERT INTO settings VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run('demo_ready', '1');
  });
}

export function requireDemo(store: Store): void {
  if (!store.db.prepare('SELECT 1 FROM settings WHERE key = ? AND value = ?').get('demo_ready', '1')) {
    throw new AppError('connection_unavailable', 'Owner must initialize the local synthetic demo first.', 403, 3, 'permission_denied');
  }
}

export interface OrderParams { from: string; to: string; cursor?: string }
export function orderParams(input: unknown): OrderParams {
  const value = record(input);
  if (Object.keys(value).some(key => !['from', 'to', 'cursor'].includes(key))) {
    throw new AppError('invalid_parameters', 'Only from, to and cursor are accepted.');
  }
  const date = (raw: unknown) => {
    const result = textField(raw, 10);
    const ms = Date.parse(result + 'T00:00:00.000Z');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(result) || !Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 10) !== result) {
      throw new AppError('invalid_date', 'Use a valid YYYY-MM-DD date.');
    }
    return result;
  };
  const from = date(value.from); const to = date(value.to);
  const days = (Date.parse(to) - Date.parse(from)) / 86_400_000 + 1;
  if (days < 1 || days > 31) throw new AppError('invalid_range', 'Date range must contain 1–31 days.');
  return value.cursor === undefined ? { from, to } : { from, to, cursor: textField(value.cursor, 64) };
}

export function readOrders(store: Store, params: OrderParams) {
  requireDemo(store);
  const from = params.from + 'T00:00:00.000Z';
  const end = new Date(Date.parse(params.to + 'T00:00:00.000Z') + 86_400_000).toISOString();
  let timestamp = ''; let id = '';
  if (params.cursor !== undefined) {
    const row = store.db.prepare('SELECT created_at, id FROM demo_orders WHERE id = ? AND created_at >= ? AND created_at < ?')
      .get(params.cursor, from, end);
    if (!row) throw new AppError('invalid_cursor', 'Order cursor is not in this date range.');
    timestamp = row.created_at as string; id = row.id as string;
  }
  const rows = store.db.prepare(`SELECT id, created_at, currency, amount_minor, payment_status FROM demo_orders
    WHERE created_at >= ? AND created_at < ? AND (created_at, id) > (?, ?)
    ORDER BY created_at, id LIMIT 101`).all(from, end, timestamp, id);
  const page = rows.slice(0, 100);
  return { source: 'local_synthetic', resource: RESOURCE, timezone: 'UTC', ...params,
    amount_unit: 'minor', rows: page, complete: rows.length <= 100,
    next_cursor: rows.length > 100 ? page[99]!.id : null };
}
