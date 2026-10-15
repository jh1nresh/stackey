import assert from 'node:assert/strict';
import { test } from 'node:test';
import { adapterFor, classifyLoginPage, GOOGLE_ADAPTER, GITHUB_ADAPTER, PRODUCTION_ADAPTERS } from '../src/website-adapters.js';

test('production adapters are exact GitHub and Google account origins', () => {
  assert.equal(GITHUB_ADAPTER.origin, 'https://github.com');
  assert.equal(GITHUB_ADAPTER.entryUrl.startsWith('https://github.com/'), true);
  assert.equal(GOOGLE_ADAPTER.origin, 'https://accounts.google.com');
  assert.equal(GOOGLE_ADAPTER.entryUrl.startsWith('https://accounts.google.com/'), true);
  assert.equal(GOOGLE_ADAPTER.entryUrl.includes('continue=https%3A%2F%2Faccounts.google.com%2F'), true);
  assert.equal(adapterFor('https://github.com', PRODUCTION_ADAPTERS), GITHUB_ADAPTER);
  assert.equal(adapterFor('https://accounts.google.com', PRODUCTION_ADAPTERS), GOOGLE_ADAPTER);
  assert.equal(adapterFor('https://evil.example.test', PRODUCTION_ADAPTERS), undefined);
});

test('GitHub and Google 2FA pages classify as human steps, never success', () => {
  assert.equal(classifyLoginPage('https://github.com', 'https://github.com/login'), 'login');
  assert.equal(classifyLoginPage('https://github.com', 'https://github.com/sessions/two-factor'), 'email_otp');
  assert.equal(classifyLoginPage('https://github.com', 'https://github.com/sessions/two-factor/webauthn'), 'passkey');
  assert.equal(classifyLoginPage('https://github.com', 'https://github.com/sessions/verified-device'), 'device_confirmation');
  assert.equal(classifyLoginPage('https://github.com', 'https://github.com/'), 'success');
  assert.equal(classifyLoginPage('https://accounts.google.com', 'https://accounts.google.com/v3/signin/identifier'), 'login');
  assert.equal(classifyLoginPage('https://accounts.google.com', 'https://accounts.google.com/signin/challenge/totp'), 'email_otp');
  assert.equal(classifyLoginPage('https://accounts.google.com', 'https://accounts.google.com/challenge/sk'), 'passkey');
  assert.equal(classifyLoginPage('https://accounts.google.com', 'https://accounts.google.com/challenge/az'), 'device_confirmation');
  assert.equal(classifyLoginPage('https://github.com', 'https://evil.example.test/login'), 'other');
});
