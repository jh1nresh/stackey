import type { WebsiteHumanReason } from './website-login.js';

export interface SiteAdapter {
  origin: string;
  entryUrl: string;
  twoStep: boolean;
  username: string;
  password: string;
  submit: string;
  identifierNext?: string;
}

export const GITHUB_ADAPTER: SiteAdapter = {
  origin: 'https://github.com',
  entryUrl: 'https://github.com/login',
  twoStep: false,
  username: '#login_field',
  password: '#password',
  submit: 'input[type=submit][name=commit], button[type=submit]',
};

export const GOOGLE_ADAPTER: SiteAdapter = {
  origin: 'https://accounts.google.com',
  entryUrl: 'https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Faccounts.google.com%2F&flowName=GlifWebSignIn',
  twoStep: true,
  username: 'input[type=email], #identifierId',
  password: 'input[type=password], input[name=Passwd]',
  submit: '#passwordNext, button:has-text("Next")',
  identifierNext: '#identifierNext, button:has-text("Next")',
};

export const PRODUCTION_ADAPTERS: SiteAdapter[] = [GITHUB_ADAPTER, GOOGLE_ADAPTER];

export function adapterFor(origin: string, adapters: SiteAdapter[]): SiteAdapter | undefined {
  return adapters.find(adapter => adapter.origin === origin);
}

export function classifyLoginPage(origin: string, href: string): 'login' | 'success' | WebsiteHumanReason | 'other' {
  let url: URL;
  try { url = new URL(href); } catch { return 'other'; }
  const pageOrigin = `${url.protocol}//${url.hostname}`;
  if (pageOrigin !== origin) return 'other';
  const path = `${url.pathname}${url.search}`.toLowerCase();

  if (origin === 'https://github.com') {
    if (/webauthn|u2f|passkey/.test(path)) return 'passkey';
    if (/\/sessions\/two-factor|\/two-factor\/sms|\/two-factor\/app|\/two-factor\/mobile/.test(path)) return 'email_otp';
    if (/verified-device|verified-email|sudo|device_verification/.test(path)) return 'device_confirmation';
    if (/captcha|arkose|challenge/.test(path)) return 'captcha';
    if (path === '/login' || path.startsWith('/login/') || path.startsWith('/session')) return 'login';
    if (path === '/' || path.startsWith('/dashboard') || path.startsWith('/settings') || path.startsWith('/notifications')) return 'success';
    return 'other';
  }

  if (origin === 'https://accounts.google.com') {
    if (/\/challenge\/totp|\/challenge\/ipp|smsauth|\/challenge\/ootp/.test(path)) return 'email_otp';
    if (/\/challenge\/sk|\/challenge\/pk|passkey|webauthn/.test(path)) return 'passkey';
    if (/\/challenge\/az|\/challenge\/dp|device.?confirm|\/signin\/challenge\/iap/.test(path)) return 'device_confirmation';
    if (/recaptcha|captcha|\/challenge\/bcd/.test(path)) return 'captcha';
    if (/\/identifier|\/challenge\/pwd|\/signin\/v2\/sl\/pwd|flowentry=servicelogin/.test(path)) return 'login';
    if (/managedaccounts|\/b\/0|checkcookie|\/signin\/oauth\/legacy|\/lifecycle/.test(path) || path === '/' || path === '') return 'success';
    return 'other';
  }

  if (/two-factor|totp|one-time|otp|\/mfa\b/.test(path)) return 'email_otp';
  if (/webauthn|passkey|u2f/.test(path)) return 'passkey';
  if (/captcha|recaptcha|arkose/.test(path)) return 'captcha';
  if (/device|confirm.?login/.test(path)) return 'device_confirmation';
  if (/\/login|\/signin|\/session/.test(path)) return 'login';
  if (/\/app|\/home|\/dashboard|logged-in/.test(path)) return 'success';
  return 'other';
}
