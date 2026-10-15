import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AppError } from '../src/contracts.js';
import { assertPublicHost, isPrivateOrLocalAddress } from '../src/website-dns.js';

test('private, loopback, link-local and mapped addresses fail closed', () => {
  for (const host of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.4.4', '169.254.1.1',
    '100.64.0.1', '0.0.0.0', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:10.1.2.3']) {
    assert.equal(isPrivateOrLocalAddress(host), true, host);
  }
  assert.equal(isPrivateOrLocalAddress('140.82.112.4'), false);
  assert.equal(isPrivateOrLocalAddress('8.8.8.8'), false);
});

test('runner DNS lookup that rebinds to loopback is origin_not_allowed', async () => {
  await assert.rejects(assertPublicHost('github.com', async () => ['127.0.0.1']),
    error => error instanceof AppError && error.code === 'origin_not_allowed');
  await assert.rejects(assertPublicHost('accounts.google.com', async () => ['::1']),
    error => error instanceof AppError && error.code === 'origin_not_allowed');
  const publicAddrs = await assertPublicHost('github.com', async () => ['140.82.112.4']);
  assert.deepEqual(publicAddrs, ['140.82.112.4']);
});
