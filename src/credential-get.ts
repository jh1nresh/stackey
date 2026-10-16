import { AppError } from './contracts.js';
import type { Connection } from './vault.js';
import { websiteOrigin } from './website-login.js';

export const CREDENTIAL_GET_ACTION = 'credential.get';
export const CREDENTIAL_GET_TTL_MIN = 60;
export const CREDENTIAL_GET_TTL_MAX = 300;

export function credentialGetOrigin(connection: Connection): string {
  if (connection.provider !== 'credential') {
    throw new AppError('action_not_allowed', 'Connection does not support this action.');
  }
  return websiteOrigin(connection.config.origin);
}

export function credentialHandoff(secret: string): { state: 'completed'; result: { value: string } } {
  if (!secret) throw new AppError('credential_not_found', 'Select a credential in this wallet.');
  return { state: 'completed', result: { value: secret } };
}
