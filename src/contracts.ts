import { createHash, randomUUID } from 'node:crypto';

export const INVITE_TYPE = 'stackey-invitation+jwt';
export const PROOF_TYPE = 'stackey-pairing-proof+jwt';
export const RECEIPT_TYPE = 'stackey-pairing-receipt+jwt';
export const MAX_BODY = 16_384;

export class AppError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly httpStatus = 400,
    readonly exitCode = 2,
    readonly status = 'invalid_request',
  ) { super(message); }
}

export function invalid(code: string, message: string): never {
  throw new AppError(code, message);
}

export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    invalid('invalid_format', 'Expected an object.');
  }
  return value as Record<string, unknown>;
}

export function textField(value: unknown, max = 4096): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    invalid('invalid_format', 'Invalid or oversized text field.');
  }
  return value;
}

export function displayName(value: unknown): string {
  const name = textField(value, 64);
  if (name.trim() !== name || /[\u0000-\u001f\u007f]/u.test(name)) {
    invalid('invalid_name', 'Name must be 1–64 characters without control characters.');
  }
  return name;
}

export function digest(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

// Step one deliberately supports literal IPv4 loopback only. No remote URLs,
// redirects, credentials, custom paths or DNS-based localhost resolution.
export function endpoint(value: unknown): string {
  const raw = textField(value, 100);
  let url: URL;
  try { url = new URL(raw); } catch { invalid('invalid_endpoint', 'Invalid Node endpoint.'); }
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' ||
      !url.port || url.username || url.password || url.pathname !== '/' ||
      url.search || url.hash || raw !== url.origin) {
    invalid('invalid_endpoint', 'This milestone only supports http://127.0.0.1:<port>.');
  }
  return url.origin;
}

export function envelope(status: string, data: unknown) {
  return { schema_version: 1, request_id: randomUUID(), status, data };
}

export function publicError(error: unknown) {
  const safe = error instanceof AppError ? error :
    new AppError('internal_error', 'Operation failed; no sensitive details were logged.', 500, 1, 'failed');
  return {
    exitCode: safe.exitCode,
    httpStatus: safe.httpStatus,
    body: { schema_version: 1, request_id: randomUUID(), status: safe.status,
      error: { code: safe.code, message: safe.message } },
  };
}
