import { existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { AppError, record, textField } from './contracts.js';
import { privateDirectory, readPrivateJson, writePrivateJson } from './identity.js';
import { runLinkCli } from './link-cli.js';
import { vaultRequest } from './vault-client.js';

type Vendor = typeof runLinkCli;
type Owner = typeof vaultRequest;
function approval(value: Record<string, unknown>) {
  const url = textField(value.verification_url, 2000); const target = new URL(url);
  if (target.protocol !== 'https:' || !(target.hostname === 'link.com' || target.hostname.endsWith('.link.com')) || target.username || target.password) throw new AppError('invalid_link_response', 'Unexpected Link approval destination.');
  return { status: 'approval_required', verification_url: url, phrase: textField(value.phrase, 200), next_step: 'Approve this connection in Link, then run stackey link finish with the same wallet.' };
}
export async function onboardLink(dir: string, wallet: string, command: 'login' | 'finish' | 'cancel', vendor: Vendor = runLinkCli, owner: Owner = vaultRequest) {
  // Owner-only IPC first: agents cannot use this command to obtain a secret.
  await owner(dir, 'credential.list', { wallet_id: wallet });
  const directory = privateDirectory(join(privateDirectory(dir), 'link-onboarding'));
  const auth = join(directory, 'auth.json'); const binding = join(directory, 'wallet.json'); const lock = join(directory, 'lock.json');
  try { writePrivateJson(lock, {}); } catch { throw new AppError('link_busy', 'Another Link onboarding command is active.'); }
  try {
    if (existsSync(binding) && record(readPrivateJson(binding)).wallet_id !== wallet) throw new AppError('wallet_mismatch', 'Finish or cancel Link onboarding with the original wallet.');
    if (command === 'cancel') {
      if (existsSync(auth)) { readPrivateJson(auth); await vendor(auth, ['auth', 'logout']); if (existsSync(auth)) unlinkSync(auth); }
      if (existsSync(binding)) unlinkSync(binding);
      return { status: 'cancelled' };
    }
    if (!existsSync(auth)) {
      if (command !== 'login') throw new AppError('link_not_started', 'Run stackey link login first.');
      if (!existsSync(binding)) writePrivateJson(binding, { wallet_id: wallet });
      writePrivateJson(auth, { auth: null, pendingDeviceAuth: null });
      const result = await vendor(auth, ['auth', 'login', '--client-name', 'Stackey', '--scope', 'payment_methods.agentic', '--interval', '0']);
      return approval(result);
    }
    if (!existsSync(binding)) throw new AppError('invalid_link_state', 'Missing Link wallet binding.');
    const state = record(readPrivateJson(auth));
    if (!state.auth) await vendor(auth, ['auth', 'status', '--interval', '0', '--max-attempts', '1']);
    const updated = record(readPrivateJson(auth));
    if (!updated.auth) {
      if (!updated.pendingDeviceAuth) throw new AppError('link_login_expired', 'Link login expired. Cancel onboarding and start a fresh login.');
      const pending = record(updated.pendingDeviceAuth);
      if (!Number.isFinite(Number(pending.expires_at)) || Number(pending.expires_at) <= Date.now()) throw new AppError('link_login_expired', 'Link login expired. Cancel onboarding and start a fresh login.');
      return approval({ verification_url: pending.verification_url, phrase: pending.phrase });
    }
    if (command === 'login') return { status: 'authenticated', next_step: 'Run stackey link finish to import the credential into the unlocked vault.' };
    const tokens = record(updated.auth);
    const expires = Number(tokens.expires_at);
    if (!Number.isFinite(expires) || expires <= Date.now()) throw new AppError('link_login_expired', 'Link access token expired. Cancel onboarding and log in again.');
    const credential = await owner(dir, 'credential.import', { wallet_id: wallet, name: 'Link Agent Wallet', kind: 'api_key', value: textField(tokens.access_token, 16384) });
    // Refresh tokens are deliberately not retained in this milestone. Relogin
    // when the short-lived access token expires; no plaintext auth remains.
    unlinkSync(auth); unlinkSync(binding);
    return { status: 'connected', credential, access_expires_at: Math.floor(expires / 1000), refresh_supported: false };
  } finally { unlinkSync(lock); }
}
