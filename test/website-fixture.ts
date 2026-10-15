import type { Page, Route } from 'playwright';
import type { SiteAdapter } from '../src/website-adapters.js';

export const FIXTURE_ORIGIN = 'https://login.stackey.test';
export const FIXTURE_HOSTS = ['login.stackey.test', 'evil.example.test'];

export function fixtureAdapter(path = '/login'): SiteAdapter {
  return {
    origin: FIXTURE_ORIGIN,
    entryUrl: `${FIXTURE_ORIGIN}${path}`,
    twoStep: false,
    username: '#login',
    password: '#password',
    submit: 'button[type=submit]',
  };
}

function html(body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Stackey fixture</title></head><body>${body}</body></html>`;
}

function form(action: string): string {
  return html(`<form method="post" action="${action}">
    <input id="login" name="login" autocomplete="username">
    <input id="password" name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>`);
}

function formData(route: Route): URLSearchParams {
  const raw = route.request().postData() ?? '';
  try { return new URLSearchParams(raw); } catch { return new URLSearchParams(); }
}

export async function installFixtureRoutes(page: Page, secret: string): Promise<void> {
  await page.route('https://evil.example.test/**', async route => {
    await route.fulfill({ status: 200, contentType: 'text/html', body: html('<p>phish</p>') });
  });
  await page.route('https://login.stackey.test/**', async route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (route.request().method() === 'GET' && path === '/login') {
      await route.fulfill({ status: 200, contentType: 'text/html', body: form('/session') });
      return;
    }
    if (route.request().method() === 'GET' && path === '/login-echo') {
      await route.fulfill({ status: 200, contentType: 'text/html', body: form('/echo') });
      return;
    }
    if (route.request().method() === 'GET' && path === '/login-mfa') {
      await route.fulfill({ status: 200, contentType: 'text/html', body: form('/mfa') });
      return;
    }
    if (route.request().method() === 'GET' && path === '/login-redirect') {
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: html('<meta http-equiv="refresh" content="0;url=https://evil.example.test/phish"><script>location.replace("https://evil.example.test/phish")</script>'),
      });
      return;
    }
    if (route.request().method() === 'GET' && path === '/login-500') {
      await route.fulfill({ status: 500, contentType: 'text/html', body: html('<p>crash</p>') });
      return;
    }
    if (route.request().method() === 'POST' && path === '/session') {
      const password = formData(route).get('password');
      if (password !== secret) {
        await route.fulfill({ status: 401, contentType: 'text/html', body: html('<p>invalid</p>') });
        return;
      }
      await route.fulfill({
        status: 302,
        headers: { location: `${FIXTURE_ORIGIN}/app`, 'set-cookie': 'session=ok; Path=/; Secure; HttpOnly' },
        body: '',
      });
      return;
    }
    if (route.request().method() === 'GET' && path === '/app') {
      await route.fulfill({ status: 200, contentType: 'text/html', body: html('<p>logged-in</p>') });
      return;
    }
    if (route.request().method() === 'POST' && path === '/echo') {
      const password = formData(route).get('password') ?? '';
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: html(`<p>invalid password ${password}</p>`),
      });
      return;
    }
    if (route.request().method() === 'POST' && path === '/mfa') {
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: html('<form action="/otp"><input name="otp" id="otp" autocomplete="one-time-code"><button type="submit">Verify</button></form>'),
      });
      return;
    }
    await route.fulfill({ status: 404, contentType: 'text/html', body: html('<p>missing</p>') });
  });
}
