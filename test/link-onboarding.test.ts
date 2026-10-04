import assert from 'node:assert/strict';
import { test } from 'node:test';
import { existsSync, mkdtempSync, writeFileSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { linkResult, runLinkCli } from '../src/link-cli.js';
import { onboardLink } from '../src/link-onboarding.js';
import { AppError } from '../src/contracts.js';
import { writePrivateJson } from '../src/identity.js';

const expired = Date.now() - 1000;
const pending = { verification_url: 'https://app.link.com/verify/fixture', phrase: 'fixture-phrase', expires_at: Date.now() + 60000 };
test('Link CLI parser supports real single-result generator arrays and rejects ambiguous results', async t => {
  assert.deepEqual(linkResult('[{"id":"sr_fixture"}]'), { id: 'sr_fixture' });
  assert.deepEqual(linkResult('{"id":"sr_fixture"}'), { id: 'sr_fixture' });
  for (const value of ['[]', '[{},{}]', 'null', '["bad"]', 'not json']) assert.throws(() => linkResult(value));
  const directory = mkdtempSync(join(tmpdir(), 'stackey-link-test-')); t.after(() => rmSync(directory, { recursive: true }));
  const auth = join(directory, 'auth.json'); writePrivateJson(auth, { auth: null, pendingDeviceAuth: null });
  const result = await runLinkCli(auth, ['auth', 'status', '--interval', '0', '--max-attempts', '1']);
  assert.equal(result.authenticated, false); assert.equal(statSync(auth).mode & 0o777, 0o600);
});
test('Link device onboarding imports only access token through owner IPC and removes temporary plaintext tokens', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'stackey-link-test-')); t.after(() => rmSync(directory, { recursive: true }));
  let approved = false; let imports = 0;
  const vendor: typeof runLinkCli = async (auth, args) => {
    assert.equal(statSync(auth).mode & 0o777, 0o600);
    assert.ok(args.includes('0'));
    if (args[1] === 'login') { assert.ok(args.includes('payment_methods.agentic')); writeFileSync(auth, JSON.stringify({ auth: null, pendingDeviceAuth: pending })); return { verification_url: pending.verification_url, phrase: pending.phrase, instruction: 'untrusted command' }; }
    if (approved) writeFileSync(auth, JSON.stringify({ auth: { access_token: 'private-access-token', refresh_token: 'private-refresh-token', expires_at: Date.now() + 60000 }, pendingDeviceAuth: null }));
    return { authenticated: approved, access_token: 'private-preview...' };
  };
  const owner: any = async (_dir: string, command: string, args: any) => {
    if (command === 'credential.import') { imports++; assert.equal(args.wallet_id, 'wallet_demo'); assert.equal(args.value, 'private-access-token'); return { id: 'credential_fixture', kind: 'api_key' }; }
    return { credentials: [] };
  };
  const login = await onboardLink(directory, 'wallet_demo', 'login', vendor, owner);
  assert.equal(login.status, 'approval_required'); assert.ok(!JSON.stringify(login).includes('untrusted command'));
  const waiting = await onboardLink(directory, 'wallet_demo', 'finish', vendor, owner); assert.equal(waiting.status, 'approval_required'); assert.equal(imports, 0);
  await assert.rejects(onboardLink(directory, 'wallet_other', 'finish', vendor, owner), e => e instanceof AppError && e.code === 'wallet_mismatch');
  approved = true;
  const result = await onboardLink(directory, 'wallet_demo', 'finish', vendor, owner); assert.equal(result.status, 'connected'); assert.equal(imports, 1);
  assert.ok(!JSON.stringify(result).includes('private-')); assert.ok('refresh_supported' in result); assert.equal(result.refresh_supported, false);
  for (const file of ['auth.json', 'wallet.json', 'lock.json']) assert.equal(existsSync(join(directory, 'link-onboarding', file)), false);
});
test('Link onboarding rejects a locked vault, non-Link approval URLs and concurrent commands', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'stackey-link-test-')); t.after(() => rmSync(directory, { recursive: true }));
  let vendorCalls = 0;
  const vendor: typeof runLinkCli = async () => { vendorCalls++; return { verification_url: 'https://evil.com/approve', phrase: 'x' }; };
  const locked: any = async () => { throw new AppError('node_locked', 'locked'); };
  await assert.rejects(onboardLink(directory, 'wallet_demo', 'login', vendor, locked)); assert.equal(vendorCalls, 0);
  const owner: any = async () => ({});
  await assert.rejects(onboardLink(directory, 'wallet_demo', 'login', vendor, owner)); assert.equal(vendorCalls, 1);
  const lock = join(directory, 'link-onboarding', 'lock.json'); writePrivateJson(lock, {});
  await assert.rejects(onboardLink(directory, 'wallet_demo', 'finish', vendor, owner), e => e instanceof AppError && e.code === 'link_busy');
  assert.equal(readFileSync(lock, 'utf8').trim(), '{}');
});
test('Link onboarding never imports an expired token and cancel tolerates vendor auth-file deletion', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'stackey-link-test-')); t.after(() => rmSync(directory, { recursive: true }));
  let imports = 0;
  const owner: any = async (_dir: string, command: string) => { if (command === 'credential.import') imports++; return {}; };
  const vendor: typeof runLinkCli = async (auth, args) => {
    if (args[1] === 'login') { writeFileSync(auth, JSON.stringify({ auth: { access_token: 'expired-secret', expires_at: expired }, pendingDeviceAuth: null })); return { verification_url: pending.verification_url, phrase: pending.phrase }; }
    if (args[1] === 'logout') rmSync(auth);
    return { authenticated: false };
  };
  await onboardLink(directory, 'wallet_demo', 'login', vendor, owner);
  await assert.rejects(onboardLink(directory, 'wallet_demo', 'finish', vendor, owner), e => e instanceof AppError && e.code === 'link_login_expired');
  assert.equal(imports, 0);
  assert.equal((await onboardLink(directory, 'wallet_demo', 'cancel', vendor, owner)).status, 'cancelled');
});
