import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { AppError, INTERNAL_ERROR_MESSAGE, PUBLIC_ERROR_MESSAGES, publicError, publicErrorMessage, vaultReply } from '../src/contracts.js';
import { scrubText, secretForms, writeScrubbed } from '../src/redact.js';

test('publicError maps AppError codes through a fixed table and never returns thrown text', () => {
  const canary = `CANARY-pw-${randomUUID()}`;
  const leaked = publicError(new AppError('executor_failed', `could not type ${canary}`, 502, 4, 'failed'));
  assert.equal(leaked.body.error.code, 'executor_failed');
  assert.equal(leaked.body.error.message, PUBLIC_ERROR_MESSAGES.executor_failed);
  assert.equal(leaked.body.error.message.includes(canary), false);
  assert.equal(JSON.stringify(leaked).includes(canary), false);

  const unknown = publicError(new AppError('login_failed', `site said ${canary}`));
  assert.equal(unknown.body.error.code, 'internal_error');
  assert.equal(unknown.body.error.message, INTERNAL_ERROR_MESSAGE);
  assert.equal(JSON.stringify(unknown).includes(canary), false);
  assert.equal(JSON.stringify(unknown).includes('login_failed'), false);

  const generic = publicError(new Error(`stack contains ${canary}`));
  assert.equal(generic.body.error.code, 'internal_error');
  assert.equal(generic.httpStatus, 500);
  assert.equal(JSON.stringify(generic).includes(canary), false);
  assert.equal(publicErrorMessage('missing_code'), INTERNAL_ERROR_MESSAGE);

  const ttl = publicError(new AppError('invalid_ttl', 'Grant lifetime must be 60–300 seconds.'));
  assert.equal(ttl.body.error.message, 'Grant lifetime must be 60–300 seconds.');
  const noisyTtl = publicError(new AppError('invalid_ttl', `Grant lifetime must be 60–300 seconds. ${canary}`));
  assert.equal(noisyTtl.body.error.message, PUBLIC_ERROR_MESSAGES.invalid_ttl);
  assert.equal(JSON.stringify(noisyTtl).includes(canary), false);
});

test('vaultReply and the scrubber replace the secret and its encodings, not public tokens', () => {
  const canary = `CANARY-pw-${randomUUID()}`;
  const forms = secretForms(canary);
  assert.ok(forms.includes(canary));
  assert.ok(forms.includes(Buffer.from(canary, 'utf8').toString('base64url')));
  const dirty = {
    origin: 'https://dashboard.example.test',
    outcome: 'authenticated',
    html: `<form value="${canary}">`,
    nested: { b64: Buffer.from(canary, 'utf8').toString('base64') },
  };
  const clean = vaultReply(dirty, canary) as typeof dirty;
  assert.equal(clean.origin, 'https://dashboard.example.test');
  assert.equal(clean.outcome, 'authenticated');
  assert.equal(String(clean.html).includes(canary), false);
  assert.equal(String(clean.nested.b64).includes(canary), false);
  assert.equal(JSON.stringify(clean).includes(canary), false);
  assert.equal(scrubText(`typed ${canary} here`, canary).includes(canary), false);
  const publicReply = vaultReply({ source: 'website_login', origin: 'https://dashboard.example.test', outcome: 'authenticated' }, 'test') as Record<string, string>;
  assert.equal(publicReply.origin, 'https://dashboard.example.test');
  assert.equal(publicReply.outcome, 'authenticated');
  assert.equal((vaultReply({ html: 'test' }, 'test') as { html: string }).html, '[redacted]');
  const chunks: string[] = [];
  writeScrubbed({ write(chunk: string) { chunks.push(chunk); return true; } } as unknown as NodeJS.WritableStream, `log ${canary}\n`, canary);
  assert.equal(chunks.join('').includes(canary), false);
});
