'use strict';
const $ = id => document.getElementById(id);
let token = location.hash.slice(1);
history.replaceState(null, '', '/');
// Reopening a launch URL in the same tab can be a fragment-only navigation.
window.addEventListener('hashchange', () => { if (location.hash) location.reload(); });
let state;
let credentials = [];
let selectedCredential;
let revealVersion = 0;
let revealTimer;
let credentialRefresh = false;
let selected;
let invitationExpiry = 0;
let sessionExpiry = 0;
let pageCount = 1;
let refreshing = false;
let mutationPending = false;
let online = false;
const labels = { approval_required: 'Pending', active: 'Active', expired: 'Expired', revoked: 'Revoked', locked: 'Vault locked', invalid: 'Invalid grant' };
const kinds = { grant_approved: 'Read-only access approved', grant_revoked: 'Access revoked', operation_completed: 'Demo orders read' };
class WalletError extends Error {}
const errorMessages = {
  node_locked: 'Vault locked. Unlock it in your terminal, then refresh.',
  vault_unavailable: 'This launch has no vault attached. Start wallet with --vault-dir.',
  credential_not_found: 'This credential no longer exists. Refresh the vault.',
  wallet_locked: 'Wallet locked. Reopen the launch URL, or restart the wallet if it has expired.',
  untrusted_browser: 'Use the local wallet launch URL shown in your terminal.',
  rate_limited: 'Too many requests. Please try again in one minute.',
  confirmation_required: 'Verify the full fingerprint and permissions, then check the confirmation box.',
  principal_mismatch: 'The agent fingerprint does not match this request. Refresh and verify it again.',
  already_approved: 'This pairing already has a grant. Refresh the list. A new task needs a new invitation and pairing.',
  connection_unavailable: 'Demo resources are not ready. Run node demo-init in your terminal first.',
  owner_mismatch: 'The owner identity does not match. Restart with the original owner directory.',
  owner_not_initialized: 'No wallet owner is configured. Run node owner-init in your terminal first.',
  action_not_available: 'This preview only supports read-only access to demo orders.',
  invalid_ttl: 'Invalid duration. Choose 1, 5, or 15 minutes.',
  grant_not_found: 'Grant not found. Refresh and try again.',
  grant_expired: 'This grant has expired. Create a new invitation and pairing.',
  grant_revoked: 'This grant has been revoked.',
  invalid_cursor: 'This list position is no longer valid. Reopen the wallet.',
  invalid_owner_proof: 'This confirmation has expired. Review and confirm again.',
  request_too_large: 'The request is too large. Please try again.',
  invalid_json: 'Invalid request format. Refresh and try again.',
  invalid_format: 'Invalid input. Check the values and try again.',
  invalid_content_type: 'Unsupported request format. Reopen the wallet.',
  route_not_available: 'This action is unavailable. Refresh the wallet.',
};
const errorText = error => error instanceof WalletError ? error.message : 'Connection failed. Check that the local wallet is running and try again.';
const date = seconds => new Date(seconds * 1000).toLocaleString('en-US', { hour12: false });
function notice(message) { $('notice').textContent = message; $('notice').hidden = !message; }
function connection(ready) {
  online = ready;
  $('connection').textContent = ready ? 'Local · Online' : 'Offline';
  $('connection').className = ready ? 'connection online' : 'connection';
  $('invite').disabled = !ready || mutationPending;
  if ($('invite-from-agents')) $('invite-from-agents').disabled = !ready || mutationPending;
  $('copy-address').disabled = !ready;
  $('refresh').disabled = !token || mutationPending;
  document.querySelectorAll('[data-agent-action]').forEach(button => { button.disabled = !ready || mutationPending; });
}
function lock() {
  token = ''; invitationExpiry = 0;
  hideSecret(); credentials = []; $('credentials').replaceChildren();
  $('agents').replaceChildren(element('p', 'Unlock to check current agent permissions.', 'muted'));
  $('agent-summary').textContent = 'Wallet locked';
  $('credential-state').textContent = 'Reopen your wallet to view credentials.';
  $('invite-command').value = '';
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
  connection(false);
  $('connection').textContent = 'Wallet locked';
  $('resource-state').textContent = 'Reopen your wallet to view resource status.';
  $('resource-asset').hidden = true;
  $('resource-count').textContent = '—';
  $('request-alert').hidden = true;
  notice('Reopen the full wallet launch URL from your terminal. Restart the wallet if more than one hour has passed.');
}
async function api(path, data) {
  const response = await fetch(path, { method: data === undefined ? 'GET' : 'POST',
    headers: { authorization: 'Bearer ' + token, ...(data === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }), signal: AbortSignal.timeout(10000), cache: 'no-store', redirect: 'error' });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401) lock();
    throw new WalletError(errorMessages[result.error?.code] || 'The operation failed. Refresh to check its status.');
  }
  return result.data;
}
function element(tag, text, className) {
  const el = document.createElement(tag); el.textContent = text;
  if (className) el.className = className;
  return el;
}
const actionLabels = {
  'demo.orders.read': 'Read demo orders',
  'supabase.orders.read': 'Read Supabase orders',
  'vercel.ai.generate': 'Generate text via AI Gateway',
  'stripe.payments.read': 'Read Stripe test payments',
  'stripe.mpp.pay': 'Pay an approved sandbox MPP request',
};
const actionText = agent => agent.actions?.length ? agent.actions.map(action => actionLabels[action] || action).join(', ') : 'No actions allowed';
function render() {
  $('node-id').textContent = state.node_id;
  $('full-address').textContent = 'stackey:' + state.owner + '/' + state.wallet_id;
  $('short-address').textContent = 'stackey:' + state.owner.slice(0, 4) + '…' + state.owner.slice(-4);
  $('vault-status').textContent = state.vault_status === 'unlocked' ? 'Unlocked · Local' : state.vault_status === 'locked' ? 'Locked' : 'Not connected';
  $('agent-summary').textContent = state.pairings.some(a => a.actions?.length) ? state.pairings.find(a => a.actions?.length).display_name + ' · ' + actionText(state.pairings.find(a => a.actions?.length)) : 'No agents can act right now';
  $('resource-asset').hidden = !state.demo_ready;
  $('request-alert').hidden = !state.pending_count;
  $('request-alert').textContent = state.pending_count + ' connection request(s) awaiting approval →';
  $('endpoint').textContent = state.endpoint;
  $('resource-state').textContent = state.demo_ready ? 'Read-only test data. This connection does not grant access to your credentials.' : 'Not ready. Run node demo-init in your terminal first.';
  if (!state.pairings.length) {
    const empty = element('div', '', 'empty');
    empty.append(element('h3', 'No agents yet'), element('p', 'Invite an agent, then review its requested access.'));
    const inviteButton = element('button', 'Invite your first agent', 'secondary');
    inviteButton.id = 'invite-from-agents'; inviteButton.addEventListener('click', () => $('invite').click());
    empty.append(inviteButton); $('agents').replaceChildren(empty);
  }
  if (state.pairings.length) {
    $('agents').replaceChildren();
    for (const agent of state.pairings) {
      const row = element('article', '', 'agent');
      const info = element('div', '', 'agent-info');
      const title = element('h3', agent.display_name);
      title.append(element('span', labels[agent.status] || 'Status unknown', 'status' + (agent.status === 'approval_required' ? ' pending' : '')));
      info.append(title, element('p', agent.principal, 'fingerprint'));
      const permissions = element('dl', '', 'permission-list');
      permissions.append(element('dt', 'Can do now'), element('dd', actionText(agent)));
      permissions.append(element('dt', 'Account access'), element('dd', 'None · No credential access'));
      if (agent.wallet_id) permissions.append(element('dt', 'Wallet / resource'), element('dd', agent.wallet_id + ' / ' + agent.resource));
      permissions.append(element('dt', 'Cannot do'), element('dd', agent.actions?.some(action => action !== 'demo.orders.read') ? 'Reveal vault secrets, create credentials, or delegate access' : 'Reveal passwords, create credentials, log in, write data, or delegate access'));
      if (agent.expires_at) permissions.append(element('dt', 'Grant expires'), element('dd', date(agent.expires_at)));
      info.append(permissions);
      row.append(info);
      if (agent.status === 'approval_required' || agent.status === 'active' || agent.status === 'locked') {
        const approve = agent.status === 'approval_required';
        const button = element('button', approve ? 'Review request' : 'Revoke access', 'secondary');
        button.dataset.agentAction = '';
        button.addEventListener('click', () => {
          selected = { ...agent };
          if (approve) {
            $('approval-name').textContent = agent.display_name;
            $('approval-principal').textContent = agent.principal;
            $('confirmed').checked = false;
            $('grant-ttl').value = '300';
            $('approve').disabled = true;
            $('approval-error').textContent = state.demo_ready ? '' : 'Resources are not ready. Run node demo-init, then refresh.';
            $('approval-dialog').showModal();
          } else {
            $('revoke-name').textContent = agent.display_name + ' · ' + agent.principal;
            $('revoke-error').textContent = '';
            $('revoke-dialog').showModal();
          }
        });
        row.append(button);
      }
      $('agents').append(row);
    }
  }
  $('more').hidden = !state.next_cursor;
  $('events').replaceChildren();
  if (!state.events.length) $('events').append(element('li', 'No activity yet', 'muted'));
  for (const event of state.events) {
    const row = element('li', '');
    const time = element('time', date(event.created_at)); time.dateTime = new Date(event.created_at * 1000).toISOString();
    row.append(element('span', kinds[event.kind] || 'Resource activity'), time);
    $('events').append(row);
  }
}
async function refresh() {
  if (!token || refreshing) return;
  refreshing = true;
  try {
    let next = await api('/api/state');
    sessionExpiry = next.session_expires_at;
    for (let page = 1; page < pageCount && next.next_cursor; page++) {
      const extra = await api('/api/state?after=' + encodeURIComponent(next.next_cursor));
      next.pairings.push(...extra.pairings); next.next_cursor = extra.next_cursor;
    }
    const changed = !online || JSON.stringify(state) !== JSON.stringify(next);
    state = next;
    if (changed) render();
    connection(true); notice('');
    await refreshCredentials();
  } catch (error) {
    hideSecret();
    $('agents').replaceChildren(element('p', 'Permissions could not be verified. Refresh to check current access.', 'muted'));
    $('agent-summary').textContent = 'Permissions unavailable';
    connection(false);
    if (token) notice('Could not refresh the wallet. ' + errorText(error));
  } finally { refreshing = false; }
}
async function mutate(button, action, errorId) {
  if (mutationPending) return;
  mutationPending = true; button.disabled = true; connection(online);
  try { await action(); }
  catch (error) {
    if (errorId) $(errorId).textContent = errorText(error);
    else if (token) notice('The operation was not confirmed. ' + errorText(error));
  } finally {
    mutationPending = false; button.disabled = false; connection(online);
    $('approve').disabled = !$('confirmed').checked || !state?.demo_ready || !token;
  }
}
$('invite').addEventListener('click', () => mutate($('invite'), async () => {
  const invite = await api('/api/invitations', {});
  invitationExpiry = invite.expires_at;
  const cloud = state.endpoint.startsWith('https://');
  const agentDir = '.stackey-agent-' + crypto.randomUUID();
  const entry = cloud ? 'stackey-agent/src/cloud-agent.js' : 'dist/src/cli.js';
  const prefix = cloud ? "curl --fail --silent --show-error --max-time 30 -H 'Authorization: Bearer " + invite.invitation + "' '" + state.endpoint + "/v1/agent-package' -o stackey-agent.tgz\ntar -xzf stackey-agent.tgz\n" : '';
  $('invite-command').value = prefix + "node " + entry + " connect '" + invite.invitation + "' --state-dir '" + agentDir + "' --name 'Grok Demo Agent'\n" +
    "# After the owner approves in the wallet, run:\n# node " + entry + " report --from 2026-09-26 --to 2026-10-02 --state-dir '" + agentDir + "'\n" +
    "# After the owner revokes, run the same report again: the read will be denied.";
  $('invite-command-label').textContent = cloud ? 'Run on the cloud agent’s computer · Node 22.18+' : 'Run from this project’s terminal';
  $('invite-hint').textContent = 'Connecting only requests approval. Wait for the owner before running the report. No password or seed phrase is shared. Do not share your wallet launch URL.';
  $('copy-status').textContent = '';
  tick(); $('invite-dialog').showModal();
}));
$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('invite-command').value); $('copy-status').textContent = state?.endpoint.startsWith('https://') ? 'Copied. Paste it to your cloud agent.' : 'Copied. Share it with an agent on this computer.'; }
  catch { $('invite-command').focus(); $('invite-command').select(); $('copy-status').textContent = 'Please copy the selected connection command manually.'; }
});
$('confirmed').addEventListener('change', () => { $('approve').disabled = !$('confirmed').checked || !state?.demo_ready || mutationPending; });
$('approve').addEventListener('click', () => mutate($('approve'), async () => {
  $('approval-error').textContent = '';
  await api('/api/approve', { pairing_id: selected.pairing_id, principal: selected.principal, action: 'demo.orders.read', ttl: Number($('grant-ttl').value), confirmed: $('confirmed').checked });
  $('approval-dialog').close(); await refresh();
}, 'approval-error'));
$('revoke').addEventListener('click', () => mutate($('revoke'), async () => {
  $('revoke-error').textContent = '';
  await api('/api/revoke', { grant_id: selected.grant_id, confirmed: true });
  $('revoke-dialog').close(); await refresh();
}, 'revoke-error'));
$('refresh').addEventListener('click', refresh);
$('invite-from-agents').addEventListener('click', () => $('invite').click());
$('account').addEventListener('click', () => $('account-dialog').showModal());
$('copy-address').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('full-address').textContent);
    $('address-status').textContent = 'Wallet address copied';
  } catch {
    $('address-status').textContent = 'You can copy the address from account details.';
    $('account-dialog').showModal();
  }
});
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => {
  hideSecret();
  const view = button.dataset.view;
  for (const name of ['assets', 'agents', 'activity']) $('view-' + name).hidden = name !== view;
  document.querySelectorAll('.tab-bar [data-view]').forEach(tab => {
    if (tab.dataset.view === view) tab.setAttribute('aria-current', 'page');
    else tab.removeAttribute('aria-current');
  });
}));
$('more').addEventListener('click', async () => { if (!refreshing) { pageCount++; await refresh(); } });
document.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click', () => $(button.dataset.close).close()));
$('invite-dialog').addEventListener('close', () => { $('invite-command').value = ''; invitationExpiry = 0; });
function tick() {
  if (state?.pairings.some(a => a.status === 'active' && a.expires_at <= Date.now() / 1000)) {
    state.pairings.forEach(a => { if (a.status === 'active' && a.expires_at <= Date.now() / 1000) { a.status = 'expired'; a.actions = []; } }); render(); connection(online);
  }
  if (token && sessionExpiry && Date.now() >= sessionExpiry * 1000) lock();
  if (!invitationExpiry) return;
  const remaining = Math.max(0, invitationExpiry - Math.floor(Date.now() / 1000));
  $('invite-expiry').textContent = remaining ? 'Time left ' + Math.floor(remaining / 60) + ':' + String(remaining % 60).padStart(2, '0') + ' · Single use' : 'Invitation expired. Close this dialog and create a new one.';
  $('copy').disabled = remaining === 0;
  if (!remaining) $('invite-command').value = '';
}
const credentialKinds = { password: 'Password', api_key: 'API key', private_key: 'Private key' };
function hideSecret() {
  revealVersion++; clearTimeout(revealTimer);
  $('credential-secret').value = '••••••••••••';
  $('hide-secret').disabled = true;
  $('reveal-secret').disabled = !token || state?.vault_status !== 'unlocked';
  $('reveal-secret').textContent = 'Reveal secret';
}
async function refreshCredentials() {
  if (credentialRefresh) return;
  if (state.vault_status !== 'unlocked') {
    hideSecret(); credentials = []; $('credentials').replaceChildren(); $('resource-count').textContent = '—';
    $('credential-state').textContent = state.vault_status === 'locked' ? 'Unlock the vault in your terminal to view saved credentials.' : 'Start wallet with --vault-dir to connect your encrypted vault.';
    return;
  }
  credentialRefresh = true;
  try {
    let result = await api('/api/credentials'); const rows = [...result.credentials];
    while (result.next_cursor) { result = await api('/api/credentials?after=' + encodeURIComponent(result.next_cursor)); rows.push(...result.credentials); }
    if (!token) return;
    $('resource-count').textContent = String(rows.length);
    $('credential-state').textContent = rows.length ? 'Secrets stay hidden until you reveal one.' : 'No credentials saved yet. Import a credential with the local CLI to see it here.';
    if (JSON.stringify(rows) === JSON.stringify(credentials)) return;
    credentials = rows; $('credentials').replaceChildren();
    if (selectedCredential && !rows.some(c => c.id === selectedCredential.id)) { hideSecret(); $('credential-dialog').close(); }
    for (const credential of rows) {
      const row = element('button', '', 'credential-card'); row.type = 'button';
      const icon = element('span', credential.kind === 'password' ? 'Aa' : credential.kind === 'api_key' ? '{}' : '↗', 'credential-icon');
      const info = element('span', '', 'credential-info');
      info.append(element('strong', credential.name), element('span', credentialKinds[credential.kind] + ' · ' + credential.wallet_name), element('span', '••••••••••••', 'masked-secret'));
      row.append(icon, info, element('span', 'View', 'credential-view'));
      row.addEventListener('click', () => {
        selectedCredential = credential; hideSecret();
        $('credential-title').textContent = credentialKinds[credential.kind];
        $('credential-name').textContent = credential.name;
        $('credential-meta').textContent = credentialKinds[credential.kind] + ' / ' + credential.wallet_name;
        $('credential-error').textContent = ''; $('credential-dialog').showModal();
      });
      $('credentials').append(row);
    }
  } catch (error) {
    hideSecret(); credentials = []; $('credentials').replaceChildren(); $('resource-count').textContent = '—';
    $('credential-state').textContent = errorText(error);
  } finally { credentialRefresh = false; }
}
$('reveal-secret').addEventListener('click', async () => {
  const version = ++revealVersion; const id = selectedCredential?.id;
  $('reveal-secret').disabled = true; $('credential-error').textContent = '';
  try {
    const result = await api('/api/credentials/reveal', { credential_id: id, confirmed: true });
    if (version !== revealVersion || !token || document.hidden || !$('credential-dialog').open) return;
    $('credential-secret').value = result.value;
    $('hide-secret').disabled = false;
    $('reveal-secret').textContent = 'Visible for 30 seconds';
    revealTimer = setTimeout(hideSecret, 30000);
  } catch (error) { if (version === revealVersion) { hideSecret(); $('credential-error').textContent = errorText(error); } }
});
$('hide-secret').addEventListener('click', hideSecret);
$('credential-dialog').addEventListener('close', hideSecret);
window.addEventListener('blur', hideSecret);
window.addEventListener('pagehide', hideSecret);
document.addEventListener('visibilitychange', () => { if (document.hidden) hideSecret(); });
if (token) void refresh(); else lock();
setInterval(() => { if (!document.hidden && !mutationPending) void refresh(); }, 5000);
setInterval(tick, 1000);
