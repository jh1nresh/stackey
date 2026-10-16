import { createHash, randomUUID } from 'node:crypto';
import { scrubValue } from './redact.js';

export const INVITE_TYPE = 'stackey-invitation+jwt';
export const PROOF_TYPE = 'stackey-pairing-proof+jwt';
export const RECEIPT_TYPE = 'stackey-pairing-receipt+jwt';
export const MAX_BODY = 16_384;
export const INTERNAL_ERROR_MESSAGE = 'Operation failed; no sensitive details were logged.';

export const PUBLIC_ERROR_MESSAGES: Record<string, string> = Object.freeze({
  action_not_allowed: 'This action is not allowed for the current grant.',
  action_not_available: 'Unsupported action.',
  agent_not_paired: 'Connect this agent state directory first.',
  already_approved: 'This pairing already has a grant; create a new pairing for a new task.',
  already_initialized: 'Node identity already exists.',
  already_paired: 'This state directory already has a pairing; use status or a separate environment.',
  browser_request_denied: 'Browser-origin requests are not supported.',
  budget_exceeded: 'Grant call or payment budget is exhausted.',
  command_not_available: 'Vault command is not available.',
  connection_unavailable: 'Granted connection is unavailable.',
  credential_not_found: 'Credential was not found.',
  executor_failed: 'Website login executor failed.',
  executor_unavailable: 'Website login is not enabled. This Node has no login executor.',
  grant_expired: 'This grant has expired.',
  grant_not_found: 'Grant was not found.',
  grant_revoked: 'Owner revoked this grant.',
  internal_error: INTERNAL_ERROR_MESSAGE,
  invalid_arguments: 'Invalid arguments; use --help.',
  invalid_budget: 'MPP requires a positive USD minor-unit budget.',
  invalid_challenge: 'Expected one UUID request_id.',
  invalid_content_type: 'Use application/json.',
  invalid_cursor: 'Cursor is invalid.',
  invalid_date: 'Use a valid YYYY-MM-DD date.',
  invalid_endpoint: 'Invalid Node endpoint.',
  invalid_format: 'Invalid or oversized text field.',
  invalid_grant: 'Owner grant could not be verified.',
  invalid_identity: 'Local identity does not match its public fingerprint.',
  invalid_invitation: 'Invalid invitation format.',
  invalid_json: 'Request body must be JSON.',
  invalid_kind: 'Use password, api_key, private_key or website_login.',
  invalid_limit: 'Limit is outside the permitted range.',
  invalid_link_response: 'Unexpected Link approval destination.',
  invalid_link_state: 'Missing Link wallet binding.',
  invalid_merchant: 'Use a fixed Vercel HTTPS /api/paid-report endpoint.',
  invalid_mode: 'Use payments or mpp.',
  invalid_model: 'Use a fixed AI Gateway model ID.',
  invalid_name: 'Name must be 1–64 characters without control characters.',
  invalid_node_receipt: 'Node identity or pairing receipt could not be verified; check its pairing list.',
  invalid_node_response: 'Node response could not be verified.',
  invalid_operation_id: 'Use a UUID operation ID.',
  invalid_origin: 'Use a fixed HTTPS website origin.',
  invalid_owner_proof: 'Owner confirmation expired before acceptance.',
  invalid_parameters: 'Missing or unexpected parameters.',
  invalid_payment_challenge: 'Expected a Stripe test MPP challenge.',
  invalid_payment_receipt: 'Merchant did not confirm the bound Stripe payment.',
  invalid_port: 'Invalid Node port.',
  invalid_project: 'Use a Supabase project reference.',
  invalid_proof: 'Registered agent key and a valid request proof are required.',
  invalid_provider: 'Use a supported provider.',
  invalid_provider_response: 'Invalid provider state.',
  invalid_public_key: 'Expected a public key.',
  invalid_range: 'Date range must contain 1–31 days.',
  invalid_request: 'Request is invalid.',
  invalid_request_id: 'Use a UUID request_id.',
  invalid_response: 'Vault returned an invalid response.',
  invalid_session: 'Session is expired or no longer authorized.',
  invalid_session_proof: 'A valid Node session and matching DPoP proof are required.',
  invalid_state: 'Local state is invalid.',
  invalid_ttl: 'Lifetime is outside the permitted range.',
  invalid_vault: 'Vault format, recovery material or integrity check failed.',
  invalid_wallet: 'Invalid wallet ID.',
  invitation_used: 'Invitation has already been used.',
  link_busy: 'Another Link onboarding command is active.',
  link_login_expired: 'Link login expired. Cancel onboarding and start a fresh login.',
  link_not_started: 'Run stackey link login first.',
  link_result_unknown: 'Link did not confirm this request. Check its status before creating another payment.',
  link_unavailable: 'Link CLI could not start.',
  missing_output: 'Use --out to write the invitation to a private file.',
  node_locked: 'Unlock the bound vault first.',
  node_mismatch: 'CLI Node directory differs from the unlocked vault session.',
  node_not_initialized: 'Initialize the Node first.',
  node_not_started: 'Start the Node before issuing invitations.',
  node_unreachable: 'Node did not confirm the request.',
  operation_conflict: 'Operation ID belongs to different parameters.',
  operation_not_found: 'Operation was not found.',
  operation_result_unknown: 'Operation result could not be confirmed. Poll the same operation ID.',
  output_exists: 'Output already exists; choose a new filename.',
  owner_mismatch: 'This Node already has a different owner.',
  owner_not_initialized: 'Initialize the local owner first.',
  pairing_rejected: 'Node rejected the pairing request; no service access was granted.',
  pairing_result_unknown: 'Pairing could not be confirmed. Check the Node pairing list before attempting another invitation.',
  payment_expired: 'Payment challenge expired. No new payment is created automatically.',
  payment_not_approved: 'Link declined or closed this payment request.',
  permission_denied: 'Permission denied.',
  policy_changed: 'Policy changed during verification; request current status again.',
  principal_mismatch: 'Pairing and full principal fingerprint must match.',
  proof_replayed: 'Request nonce or proof is unavailable. Obtain a fresh challenge.',
  provider_rejected: 'Provider rejected this request.',
  rate_limited: 'Request limit reached; retry later.',
  receipt_not_saved: 'Node accepted the pairing, but local state could not be saved. Check its pairing list.',
  request_too_large: 'Request exceeds 16 KiB.',
  result_unknown: 'Result could not be confirmed. Retry the same request or list existing items first.',
  route_not_available: 'Route is not available.',
  secret_leak_blocked: 'Login result attempted to expose vault material.',
  session_active: 'Session process still exists; lock it first.',
  session_exists: 'A vault session or stale session file exists. Lock the active session or use vault recover-session.',
  test_mode_required: 'Only Stripe test mode is accepted.',
  unknown_command: 'Command is not available; use --help.',
  unsafe_database: 'Pairing database must be a private regular file.',
  unsafe_session: 'Vault session socket must be private.',
  unsafe_state_directory: 'Use a private directory owned by this process user.',
  unsafe_state_file: 'State file must be a private regular file.',
  unsafe_vault_file: 'Use a private regular vault file.',
  vault_full: 'Vault is limited to 4 MiB.',
  wallet_mismatch: 'Finish or cancel Link onboarding with the original wallet.',
  wallet_not_found: 'Select an existing wallet.',
});

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

export function isPublicErrorCode(code: string): boolean {
  return Object.hasOwn(PUBLIC_ERROR_MESSAGES, code);
}

export function publicErrorMessage(code: string): string {
  return isPublicErrorCode(code) ? PUBLIC_ERROR_MESSAGES[code]! : INTERNAL_ERROR_MESSAGE;
}

export function publicError(error: unknown, secret?: string) {
  const raw = error instanceof AppError ? error :
    new AppError('internal_error', INTERNAL_ERROR_MESSAGE, 500, 1, 'failed');
  const known = isPublicErrorCode(raw.code);
  const code = known ? raw.code : 'internal_error';
  const body = vaultReply({
    schema_version: 1,
    request_id: randomUUID(),
    status: known ? raw.status : 'failed',
    error: { code, message: publicErrorMessage(code) },
  }, secret);
  return {
    exitCode: known ? raw.exitCode : 1,
    httpStatus: known ? raw.httpStatus : 500,
    body: body as { schema_version: 1; request_id: string; status: string; error: { code: string; message: string } },
  };
}

export function vaultReply(data: unknown, secret?: string): unknown {
  return scrubValue(data, secret);
}
