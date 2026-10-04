import { createGateway, generateText } from 'ai';
import Stripe from 'stripe';
import { AppError, record, textField } from './contracts.js';
import { orderParams } from './orders.js';
import type { Connection, VaultData } from './vault.js';

import { exactFields, integer } from './provider-contracts.js';
export { PROVIDER_ACTIONS, providerAction, resourceFor, exactFields, integer, providerParams, type ProviderAction } from './provider-contracts.js';
export function connectionConfig(provider: Connection['provider'], raw: unknown, data: VaultData, walletId: string) {
  const config = record(raw);
  if (provider === 'demo') { exactFields(config, []); return config; }
  const fields = provider === 'supabase' ? ['project_ref', 'credential_id'] : provider === 'vercel' ? ['model', 'credential_id'] :
    config.mode === 'mpp' ? ['mode', 'endpoint', 'network_id', 'credential_id', 'payment_method_id', 'amount_minor'] : ['mode', 'credential_id'];
  exactFields(config, fields);
  const credential = data.credentials.find(c => c.id === config.credential_id && c.wallet_id === walletId && c.kind === 'api_key');
  if (!credential) throw new AppError('credential_not_found', 'Select an API credential in this wallet.');
  if (provider === 'supabase' && !/^[a-z]{20}$/.test(textField(config.project_ref, 20))) throw new AppError('invalid_project', 'Use a Supabase project reference.');
  if (provider === 'vercel' && !/^[a-z0-9-]+\/[A-Za-z0-9._-]+$/.test(textField(config.model, 120))) throw new AppError('invalid_model', 'Use a fixed AI Gateway model ID.');
  if (provider === 'stripe') {
    if (config.mode !== 'payments' && config.mode !== 'mpp') throw new AppError('invalid_mode', 'Use payments or mpp.');
    if (config.mode === 'payments' && !/^(?:sk|rk)_test_/.test(credential.value)) throw new AppError('test_mode_required', 'Only Stripe test keys are accepted.');
    if (config.mode === 'mpp') {
      const endpoint = new URL(textField(config.endpoint, 250));
      if (endpoint.protocol !== 'https:' || !/^[a-z0-9-]+\.vercel\.app$/.test(endpoint.hostname) || endpoint.port || endpoint.username || endpoint.password || endpoint.pathname !== '/api/paid-report' || endpoint.search || endpoint.hash || endpoint.href !== config.endpoint) {
        throw new AppError('invalid_merchant', 'Use a fixed Vercel HTTPS /api/paid-report endpoint.');
      }
      if (!/^profile_test_[A-Za-z0-9]+$/.test(textField(config.network_id, 100)) || !/^pm_[A-Za-z0-9]+$/.test(textField(config.payment_method_id, 100))) throw new AppError('test_mode_required', 'Select a Stripe test profile and payment method.');
      integer(config.amount_minor, 50, 1000);
    }
  }
  return { ...config };
}
export function supports(connection: Connection, action: string) {
  return connection.provider === 'supabase' && action === 'supabase.orders.read' ||
    connection.provider === 'vercel' && action === 'vercel.ai.generate' ||
    connection.provider === 'stripe' && (connection.config.mode === 'mpp' ? action === 'stripe.mpp.pay' : action === 'stripe.payments.read');
}
export function providerSchema(action: string) {
  return { action, parameters: action === 'supabase.orders.read' ? { from: 'YYYY-MM-DD', to: 'YYYY-MM-DD', cursor: 'optional opaque cursor returned by the previous page' } :
    action === 'vercel.ai.generate' ? { prompt: 'text, at most 4000 characters' } : action === 'stripe.payments.read' ? { cursor: 'optional returned PaymentIntent ID' } : {},
    limits: action === 'supabase.orders.read' ? { page_size: 100 } : action === 'stripe.payments.read' ? { page_size: 10 } : action === 'vercel.ai.generate' ? { max_output_tokens: 1024 } : { currency: 'USD', test_mode: true },
    requires_owner_grant: true, credentials_exported: false };
}
export type ProviderFetch = typeof fetch;
export async function boundedJson(response: Response) {
  if (!response.ok) throw new AppError('provider_rejected', 'Provider rejected this request.', 502, 4, 'result_unknown');
  const reader = response.body?.getReader(); if (!reader) throw new AppError('invalid_provider_response', 'Provider returned an empty response.');
  const chunks: Uint8Array[] = []; let size = 0;
  while (true) { const part = await reader.read(); if (part.done) break; size += part.value.length;
    if (size > 65536) { await reader.cancel(); throw new AppError('invalid_provider_response', 'Provider response exceeds its limit.'); } chunks.push(part.value); }
  return JSON.parse(Buffer.concat(chunks).toString()) as unknown;
}
export async function executeProvider(connection: Connection, action: string, params: Record<string, unknown>, secret: string, transport: ProviderFetch = fetch) {
  if (!supports(connection, action)) throw new AppError('action_not_allowed', 'Connection does not support this action.');
  if (action === 'supabase.orders.read') {
    const range = orderParams(params);
    const url = new URL(`https://${connection.config.project_ref}.supabase.co/rest/v1/stackey_demo_orders`);
    url.searchParams.set('select', 'id,created_at,currency,amount_minor,payment_status');
    url.searchParams.append('created_at', `gte.${range.from}T00:00:00.000Z`);
    url.searchParams.append('created_at', `lt.${new Date(Date.parse(range.to) + 86400000).toISOString()}`);
    url.searchParams.set('order', 'created_at.asc,id.asc'); url.searchParams.set('limit', '101');
    if (range.cursor) {
      if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\|[A-Za-z0-9_-]{1,30}$/.test(range.cursor)) throw new AppError('invalid_cursor', 'Use the returned Supabase cursor.');
      const [date, id] = range.cursor.split('|');
      if (date! < range.from || date! >= new Date(Date.parse(range.to) + 86400000).toISOString()) throw new AppError('invalid_cursor', 'Cursor is outside the date range.');
      url.searchParams.set('or', `(created_at.gt.${date},and(created_at.eq.${date},id.gt.${id}))`);
    }
    const response = await transport(url, { headers: { apikey: secret, ...(secret.startsWith('eyJ') ? { authorization: `Bearer ${secret}` } : {}) }, redirect: 'error', signal: AbortSignal.timeout(10000) });
    const raw = await boundedJson(response);
    if (!Array.isArray(raw) || raw.length > 101) throw new AppError('invalid_provider_response', 'Expected a bounded orders page.');
    const rows = raw.map(value => {
      const row = record(value); exactFields(row, ['id', 'created_at', 'currency', 'amount_minor', 'payment_status']);
      const id = textField(row.id, 30); const created = textField(row.created_at, 40); const timestamp = new Date(created).toISOString();
      if (!/^[A-Za-z0-9_-]+$/.test(id) || timestamp < range.from || timestamp >= new Date(Date.parse(range.to) + 86400000).toISOString() || !/^[A-Z]{3}$/.test(textField(row.currency, 3)) || !['paid', 'payment_failed'].includes(String(row.payment_status))) throw new AppError('invalid_provider_response', 'Invalid order fields.');
      return { id, created_at: timestamp, currency: row.currency, amount_minor: integer(row.amount_minor, 0, 1000000000), payment_status: row.payment_status };
    });
    const page = rows.slice(0, 100); const last = page.at(-1);
    return { source: 'supabase', timezone: 'UTC', amount_unit: 'minor', rows: page, complete: rows.length <= 100,
      next_cursor: rows.length > 100 && last ? last.created_at + '|' + last.id : null };
  }
  if (action === 'vercel.ai.generate') {
    const gateway = createGateway({ apiKey: secret, fetch: transport });
    const result = await generateText({ model: gateway(String(connection.config.model)), prompt: textField(params.prompt, 4000), maxOutputTokens: 1024, maxRetries: 0, abortSignal: AbortSignal.timeout(15000) });
    return { source: 'vercel_ai_gateway', model: connection.config.model, text: textField(result.text, 16000),
      usage: { input_tokens: result.usage.inputTokens ?? null, output_tokens: result.usage.outputTokens ?? null } };
  }
  if (action === 'stripe.payments.read') {
    if (!/^(?:sk|rk)_test_/.test(secret)) throw new AppError('test_mode_required', 'Only Stripe test keys are accepted.');
    const stripe = new Stripe(secret, { maxNetworkRetries: 0, timeout: 10000, httpClient: Stripe.createFetchHttpClient(transport) });
    const result = await stripe.paymentIntents.list({ limit: 10, ...(params.cursor ? { starting_after: String(params.cursor) } : {}) });
    if (result.data.some(pi => pi.livemode)) throw new AppError('test_mode_required', 'Live payment data is not supported.');
    return { source: 'stripe_test', rows: result.data.map(pi => ({ id: pi.id, created_at: new Date(pi.created * 1000).toISOString(), currency: pi.currency.toUpperCase(), amount_minor: pi.amount, status: pi.status, failure_code: pi.last_payment_error?.code ?? null })),
      complete: !result.has_more, next_cursor: result.has_more ? result.data.at(-1)?.id ?? null : null };
  }
  throw new AppError('action_not_available', 'MPP execution requires the payment adapter.');
}
