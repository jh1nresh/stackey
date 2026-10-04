import { AppError, record, textField } from './contracts.js';
import { orderParams } from './orders.js';

export const PROVIDER_ACTIONS = ['supabase.orders.read', 'vercel.ai.generate', 'stripe.payments.read', 'stripe.mpp.pay'] as const;
export type ProviderAction = typeof PROVIDER_ACTIONS[number];
export const providerAction = (action: string): action is ProviderAction => PROVIDER_ACTIONS.includes(action as ProviderAction);
export const resourceFor = (action: string, connection: string) => `connection:${connection}/${action}`;
export function exactFields(value: Record<string, unknown>, required: string[], optional: string[] = []) {
  if (required.some(k => !(k in value)) || Object.keys(value).some(k => !required.includes(k) && !optional.includes(k))) {
    throw new AppError('invalid_parameters', 'Missing or unexpected parameters.');
  }
}
export function integer(value: unknown, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) throw new AppError('invalid_limit', 'Limit is outside the permitted range.');
  return value as number;
}
export function providerParams(action: string, raw: unknown) {
  if (action === 'supabase.orders.read') return { ...orderParams(raw) };
  const params = record(raw);
  if (action === 'vercel.ai.generate') { exactFields(params, ['prompt']); return { prompt: textField(params.prompt, 4000) }; }
  if (action === 'stripe.payments.read') {
    exactFields(params, [], ['cursor']);
    if (params.cursor !== undefined && !/^pi_[A-Za-z0-9]+$/.test(textField(params.cursor, 100))) throw new AppError('invalid_cursor', 'Use the returned Stripe cursor.');
    return params.cursor === undefined ? {} : { cursor: params.cursor as string };
  }
  if (action === 'stripe.mpp.pay') { exactFields(params, []); return {}; }
  throw new AppError('action_not_available', 'Unsupported action.');
}
