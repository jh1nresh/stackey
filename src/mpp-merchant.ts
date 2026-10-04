import { createHmac } from 'node:crypto';
import Stripe from 'stripe';
import { Mppx, stripe } from 'mppx/server';
import { AppError, record, textField } from './contracts.js';

export function createMerchant(key: string, profile: string, client = new Stripe(key, { maxNetworkRetries: 0, timeout: 10000 })) {
  if (!/^sk_test_/.test(key) || !/^profile_test_[A-Za-z0-9]+$/.test(profile)) throw new AppError('test_mode_required', 'MPP merchant requires a Stripe test key and test business profile.');
  const mpp = Mppx.create({ methods: [stripe.spt({ client, networkId: profile, currency: 'usd', decimals: 2, paymentMethodTypes: ['card'] })],
    secretKey: createHmac('sha256', key).update('stackey/mpp-challenge/v1').digest('base64') });
  return async (request: Request) => {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/api/paid-report' || request.headers.get('content-type') !== 'application/json') return Response.json({ error: 'invalid_request' }, { status: 400 });
    const reader = request.body?.getReader();
    if (!reader) return Response.json({ error: 'invalid_request' }, { status: 400 });
    const chunks: Uint8Array[] = []; let size = 0;
    while (true) { const part = await reader.read(); if (part.done) break; size += part.value.length;
      if (size > 1024) { await reader.cancel(); return Response.json({ error: 'request_too_large' }, { status: 413 }); }
      chunks.push(part.value);
    }
    const raw = Buffer.concat(chunks).toString();
    let operation: string;
    try { const body = record(JSON.parse(raw)); operation = textField(body.operation_id, 36);
      if (Object.keys(body).join(',') !== 'operation_id' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(operation)) throw new Error();
    } catch { return Response.json({ error: 'invalid_operation' }, { status: 400 }); }
    // Fixed price, task-bound challenge, short expiration and Stripe's SDK
    // idempotency key. No card numbers, customer details or custom destinations.
    const paidRequest = new Request(request, { body: raw });
    const paid = await mpp.charge({ amount: '0.50', externalId: operation, expires: new Date(Date.now() + 600000), scope: '/api/paid-report', description: 'Stackey synthetic report — test mode' })(paidRequest);
    if (paid.status === 402) return paid.challenge;
    return paid.withReceipt(Response.json({ operation_id: operation, source: 'synthetic_demo',
      report: 'Synthetic store: 21 orders over seven days; 14 paid and 7 failed. Paid totals: USD 91.00 and TWD 2,310.00. Every day has one failed payment; inspect the payment method before retrying.' }, { headers: { 'cache-control': 'no-store' } }));
  };
}
