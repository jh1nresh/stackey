import { AppError, textField } from './contracts.js';
import type { Connection } from './vault.js';

export const WEBSITE_LOGIN_ACTION = 'website.session.login';
export const HUMAN_REASONS = ['email_otp', 'passkey', 'captcha', 'device_confirmation'] as const;
export type WebsiteHumanReason = typeof HUMAN_REASONS[number];
export interface WebsiteLoginInput { origin: string; username: string; password: string }
export interface WebsiteLoginOutcome {
  state: 'completed' | 'human_required';
  reason?: WebsiteHumanReason;
}
export type WebsiteLoginExecutor = (input: WebsiteLoginInput) => Promise<WebsiteLoginOutcome>;

export function websiteOrigin(value: unknown): string {
  const raw = textField(value, 250);
  let url: URL;
  try { url = new URL(raw); } catch { throw new AppError('invalid_origin', 'Use a fixed HTTPS website origin.'); }
  const host = url.hostname.replace(/\.+$/u, '').toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash ||
      (url.pathname !== '/' && url.pathname !== '') || raw !== url.origin ||
      host === 'localhost' || host.endsWith('.localhost') ||
      !host.includes('.') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    throw new AppError('invalid_origin', 'Use a fixed HTTPS website origin.');
  }
  return url.origin;
}

export function websiteUsername(value: unknown): string {
  const name = textField(value, 128);
  if (name.trim() !== name || /[\u0000-\u001f\u007f]/u.test(name)) {
    throw new AppError('invalid_name', 'Username must be 1–128 characters without control characters.');
  }
  return name;
}

export const refuseWebsiteLogin: WebsiteLoginExecutor = async () => {
  throw new AppError('executor_unavailable', 'Website login is not enabled. This Node has no login executor.', 403, 3, 'permission_denied');
};

interface OutcomeSnapshot { state?: string; reason?: string }

function snapshotOutcome(value: unknown): OutcomeSnapshot {
  if (value === null || typeof value !== 'object') {
    throw new AppError('invalid_provider_response', 'Login executor returned an invalid state.');
  }
  const snapshot: OutcomeSnapshot = {};
  const state = Reflect.get(value, 'state');
  if (typeof state === 'string') snapshot.state = state;
  const reason = Reflect.get(value, 'reason');
  if (typeof reason === 'string') snapshot.reason = reason;
  return snapshot;
}

function containsSecret(snapshot: OutcomeSnapshot, secret: string): boolean {
  return !!secret && (snapshot.state === secret || snapshot.reason === secret);
}

function sanitize(origin: string, snapshot: OutcomeSnapshot) {
  if (snapshot.state !== 'completed' && snapshot.state !== 'human_required') {
    throw new AppError('invalid_provider_response', 'Login executor returned an invalid state.');
  }
  if (snapshot.state === 'completed') {
    return { source: 'website_login', origin, outcome: 'authenticated' as const };
  }
  if (!snapshot.reason || !HUMAN_REASONS.includes(snapshot.reason as WebsiteHumanReason)) {
    throw new AppError('invalid_provider_response', 'Login executor returned an invalid human reason.');
  }
  return { source: 'website_login', origin, outcome: 'human_required' as const, reason: snapshot.reason as WebsiteHumanReason };
}

export async function executeWebsiteLogin(
  connection: Connection,
  secret: string,
  params: Record<string, unknown>,
  check: () => void,
  executor: WebsiteLoginExecutor,
): Promise<{ state: 'completed'; result: ReturnType<typeof sanitize> }> {
  if (connection.provider !== 'website') throw new AppError('action_not_allowed', 'Connection does not support this action.');
  if (Object.keys(params).length !== 0) throw new AppError('invalid_parameters', 'Website login accepts no agent parameters.');
  const origin = websiteOrigin(connection.config.origin);
  const username = websiteUsername(connection.config.username);
  check();
  let snapshot: OutcomeSnapshot;
  try {
    snapshot = snapshotOutcome(await executor({ origin, username, password: secret }));
  } catch {
    if (executor === refuseWebsiteLogin) {
      throw new AppError('executor_unavailable', 'Website login is not enabled. This Node has no login executor.', 403, 3, 'permission_denied');
    }
    throw new AppError('executor_failed', 'Website login executor failed.', 502, 4, 'failed');
  }
  check();
  if (containsSecret(snapshot, secret)) {
    throw new AppError('secret_leak_blocked', 'Login result attempted to expose vault material.');
  }
  return { state: 'completed', result: sanitize(origin, snapshot) };
}
