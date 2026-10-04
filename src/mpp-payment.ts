import { join } from 'node:path';
import { mkdtempSync, unlinkSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { Challenge, Credential, Receipt } from 'mppx';
import { AppError, record, textField } from './contracts.js';
import { writePrivateJson } from './identity.js';
import { runLinkCli } from './link-cli.js';
import { boundedJson, type ProviderFetch } from './providers.js';
import type { Connection } from './vault.js';

export type LinkCall = (token: string, args: string[]) => Promise<Record<string, unknown>>;
// Fixed vendor executable and argv; no shell, arbitrary commands, inherited API keys,
// default Link session, or output files containing payment credentials.
export const linkCall: LinkCall = async (token, args) => {
  const directory = mkdtempSync(join(tmpdir(), 'stackey-link-'));
  const auth = join(directory, 'auth.json'); writePrivateJson(auth, {});
  try { return await runLinkCli(auth, args, token); }
  finally { unlinkSync(auth); rmdirSync(directory); }
};

export interface PaymentContinuation { spend_request_id: string; challenge: string; approval_url: string | null }
export interface PaymentResult { state: 'approval_required' | 'completed'; result: Record<string, unknown> }
export async function payMpp(connection: Connection, token: string, operationId: string, maxAmount: number,
  check: () => void, previous?: PaymentContinuation, transport: ProviderFetch = fetch, link: LinkCall = linkCall): Promise<PaymentResult> {
  const endpoint = String(connection.config.endpoint); const amount = Number(connection.config.amount_minor);
  if (amount > maxAmount) throw new AppError('budget_exceeded', 'Payment exceeds the owner-approved USD budget.', 403, 3, 'permission_denied');
  const body = JSON.stringify({ operation_id: operationId });
  const send = (authorization?: string) => transport(endpoint, { method: 'POST', body,
    headers: { 'content-type': 'application/json', ...(authorization ? { authorization } : {}) },
    redirect: 'error', signal: AbortSignal.timeout(10000) });
  let continuation = previous;
  if (!continuation) {
    check(); const response = await send();
    if (response.status !== 402) { await response.body?.cancel(); throw new AppError('invalid_payment_challenge', 'Expected a Stripe test MPP challenge.'); }
    const challenges = Challenge.fromResponseList(response); await response.body?.cancel();
    const challenge = challenges.find(c => c.method === 'stripe' && c.intent === 'charge');
    if (!challenge || challenge.realm !== new URL(endpoint).hostname || challenge.request.currency !== 'usd' || challenge.request.amount !== String(amount) || record(challenge.request.methodDetails).networkId !== connection.config.network_id ||
      !challenge.expires || !Number.isFinite(Date.parse(challenge.expires)) || Date.parse(challenge.expires) <= Date.now() || Date.parse(challenge.expires) > Date.now() + 900000 || challenge.request.externalId !== operationId) {
      throw new AppError('invalid_payment_challenge', 'Merchant, currency, test profile, operation or amount differs from the approved purchase.');
    }
    check();
    const requested = await link(token, ['spend-request', 'create', '--idempotency-key', `stackey-${operationId}`,
      '--credential-type', 'shared_payment_token', '--network-id', String(connection.config.network_id), '--amount', String(amount),
      '--currency', 'usd', '--payment-method-id', String(connection.config.payment_method_id), '--test', '--no-request-approval',
      '--context', `Stackey sandbox purchase for operation ${operationId}: one fixed paid report from ${new URL(endpoint).hostname}. Test mode only; no recurring payment or card data is requested.`]);
    const id = textField(requested.id, 100);
    if (requested.status !== undefined && !['created', 'pending_approval', 'requires_action', 'approved'].includes(String(requested.status))) {
      throw new AppError('payment_not_approved', 'Link declined or closed this payment request.');
    }
    const approvalUrl = (value: unknown) => {
      if (value === undefined || value === null) return null;
      const url = textField(value, 1000);
      const target = new URL(url);
      if (target.protocol !== 'https:' || !(target.hostname === 'link.com' || target.hostname.endsWith('.link.com'))) throw new AppError('invalid_link_response', 'Unexpected approval destination.');
      return url;
    };
    let url = approvalUrl(requested.approval_url);
    // Fail-closed: create never pays. 0.25.1 create defaults requestApproval to
    // true, so pass --no-request-approval and request approval by id only.
    check();
    const submitted = await link(token, ['spend-request', 'request-approval', id]);
    if (submitted.approval_url !== undefined) url = approvalUrl(submitted.approval_url);
    continuation = { spend_request_id: id, challenge: Challenge.serialize(challenge), approval_url: url };
    return { state: 'approval_required', result: { ...continuation, source: 'stripe_mpp_test', amount_minor: amount, currency: 'USD' } };
  }
  const challenge = Challenge.deserialize(continuation.challenge);
  if (challenge.method !== 'stripe' || challenge.intent !== 'charge' || challenge.realm !== new URL(endpoint).hostname || challenge.request.amount !== String(amount) || challenge.request.currency !== 'usd' || challenge.request.externalId !== operationId || record(challenge.request.methodDetails).networkId !== connection.config.network_id) throw new AppError('invalid_payment_challenge', 'Saved challenge no longer matches this purchase.');
  if (!challenge.expires || !Number.isFinite(Date.parse(challenge.expires)) || Date.parse(challenge.expires) <= Date.now()) throw new AppError('payment_expired', 'Payment challenge expired. No new payment is created automatically.');
  check();
  const approved = await link(token, ['spend-request', 'retrieve', continuation.spend_request_id, '--include', 'shared_payment_token', '--interval', '0', '--max-attempts', '1']);
  if (approved.status !== 'approved') {
    if (!['created', 'pending_approval', 'requires_action'].includes(String(approved.status))) throw new AppError('payment_not_approved', 'Link declined or closed this payment request.');
    return { state: 'approval_required', result: { ...continuation, source: 'stripe_mpp_test', amount_minor: amount, currency: 'USD' } };
  }
  if (approved.amount !== amount || approved.currency !== 'usd' || approved.network_id !== connection.config.network_id || approved.credential_type !== 'shared_payment_token' || approved.test === false || approved.livemode === true) throw new AppError('invalid_link_response', 'Link approval does not match the test purchase.');
  const spt = textField(record(approved.shared_payment_token).id, 500);
  check();
  const paid = await send(Credential.serialize({ challenge, payload: { spt, externalId: operationId } }));
  const receipt = Receipt.fromResponse(paid);
  if (receipt.method !== 'stripe' || receipt.status !== 'success' || receipt.externalId !== operationId) throw new AppError('invalid_payment_receipt', 'Merchant did not confirm the bound Stripe payment.');
  const result = record(await boundedJson(paid));
  return { state: 'completed', result: { source: 'stripe_mpp_test', amount_minor: amount, currency: 'USD',
    receipt: { method: receipt.method, status: receipt.status, reference: receipt.reference, externalId: receipt.externalId, timestamp: receipt.timestamp },
    report: textField(result.report, 16000) } };
}
