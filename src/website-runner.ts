import { existsSync } from 'node:fs';
import { chromium, type Browser, type BrowserContext, type Locator, type Page } from 'playwright';
import { AppError } from './contracts.js';
import { adapterFor, classifyLoginPage, PRODUCTION_ADAPTERS, type SiteAdapter } from './website-adapters.js';
import { assertPublicHost, type HostLookup } from './website-dns.js';
import { refuseWebsiteLogin, type WebsiteHumanReason, type WebsiteLoginExecutor, type WebsiteLoginInput, type WebsiteLoginOutcome } from './website-login.js';

export const WEBSITE_RUNNER_ENV = 'STACKEY_WEBSITE_RUNNER';
const ACTION_TIMEOUT = 15_000;

export interface PlaywrightRunnerOptions {
  adapters?: SiteAdapter[];
  lookup?: HostLookup;
  headed?: boolean;
  humanWaitMs?: number;
  allowPrivateHosts?: string[];
  ignoreHTTPSErrors?: boolean;
  preparePage?: (page: Page) => Promise<void>;
  allowNonDarwin?: boolean;
}

function denied(): never {
  throw new AppError('origin_not_allowed', 'Website origin is not on this credential allowlist.', 403, 3, 'permission_denied');
}

function hrefOrigin(href: string): string | undefined {
  try {
    const url = new URL(href);
    if (url.protocol === 'about:' || url.protocol === 'blob:' || href === 'about:blank') return;
    return url.origin;
  } catch { return; }
}

function assertPageOrigin(page: Page, origin: string): void {
  const current = hrefOrigin(page.url());
  if (current && current !== origin) denied();
}

async function assertFillFrame(locator: Locator, origin: string): Promise<void> {
  assertPageOrigin(locator.page(), origin);
  let frameUrl: string;
  try {
    frameUrl = await locator.evaluate(el => el.ownerDocument.defaultView?.location.origin ?? '');
  } catch {
    denied();
  }
  if (frameUrl !== origin) denied();
}

async function humanReason(page: Page, origin: string): Promise<WebsiteHumanReason | undefined> {
  const classified = classifyLoginPage(origin, page.url());
  if (classified === 'email_otp' || classified === 'passkey' || classified === 'captcha' || classified === 'device_confirmation') {
    return classified;
  }
  const otp = await page.locator('input[autocomplete="one-time-code"], input[name=otp], input#otp, input[name=totp]').count();
  if (otp > 0) return 'email_otp';
  if (/webauthn|passkey/i.test(page.url())) return 'passkey';
  const captcha = await page.locator('iframe[src*="recaptcha"], iframe[src*="hcaptcha"], iframe[title*="captcha" i]').count();
  if (captcha > 0) return 'captcha';
  return;
}

async function isSuccess(page: Page, origin: string): Promise<boolean> {
  if (classifyLoginPage(origin, page.url()) === 'success') return true;
  if (origin === 'https://github.com') {
    const cookies = await page.context().cookies(origin);
    return cookies.some(cookie => cookie.name === 'logged_in' && cookie.value === 'yes');
  }
  if (origin === 'https://accounts.google.com') {
    const cookies = await page.context().cookies();
    return cookies.some(cookie => cookie.name === 'SID' || cookie.name === 'LSID') &&
      classifyLoginPage(origin, page.url()) !== 'login';
  }
  const cookies = await page.context().cookies(origin);
  return cookies.some(cookie => cookie.name === 'session' && cookie.value.length > 0);
}

function launchChrome(headed: boolean, privateHosts: string[]) {
  const args = ['--disable-dev-shm-usage', '--mute-audio', '--disable-gpu', '--no-sandbox', '--disable-setuid-sandbox'];
  if (privateHosts.length) {
    args.push(`--host-resolver-rules=${privateHosts.map(host => `MAP ${host} 127.0.0.1`).join(',')}`);
  }
  const common = { headless: !headed, args, timeout: 30_000 };
  if (existsSync('/usr/local/bin/google-chrome') || existsSync('/Applications/Google Chrome.app')) {
    return chromium.launch({ ...common, channel: 'chrome' as const });
  }
  return chromium.launch(common);
}

export function createPlaywrightExecutor(options: PlaywrightRunnerOptions = {}): WebsiteLoginExecutor {
  const adapters = options.adapters ?? PRODUCTION_ADAPTERS;
  const headed = options.headed === true;
  const humanWaitMs = options.humanWaitMs ?? 0;
  const allowPrivate = new Set(options.allowPrivateHosts ?? []);
  return async (input: WebsiteLoginInput): Promise<WebsiteLoginOutcome> => {
    const adapter = adapterFor(input.origin, adapters);
    if (!adapter) denied();
    const host = new URL(adapter.entryUrl).hostname;
    if (!allowPrivate.has(host)) await assertPublicHost(host, options.lookup);
    delete process.env.DEBUG;
    delete process.env.PWDEBUG;
    let browser: Browser | undefined;
    let context: BrowserContext | undefined;
    try {
      browser = await launchChrome(headed, [...allowPrivate]);
      context = await browser.newContext({
        ignoreHTTPSErrors: options.ignoreHTTPSErrors === true,
        javaScriptEnabled: true,
        locale: 'en-US',
        viewport: { width: 1280, height: 800 },
        serviceWorkers: 'block',
      });
      context.setDefaultTimeout(ACTION_TIMEOUT);
      context.setDefaultNavigationTimeout(ACTION_TIMEOUT);
      const page = await context.newPage();
      page.removeAllListeners('console');
      page.removeAllListeners('pageerror');
      if (options.preparePage) await options.preparePage(page);
      await page.goto(adapter.entryUrl, { waitUntil: 'domcontentloaded' });
      if (hrefOrigin(page.url()) && hrefOrigin(page.url()) !== input.origin) denied();
      const leftOrigin = page.waitForURL(url => {
        const current = hrefOrigin(url.toString());
        return !!current && current !== input.origin;
      }, { timeout: ACTION_TIMEOUT }).then(() => 'off' as const);
      const firstField = page.locator(adapter.username).first().waitFor({ state: 'visible' }).then(() => 'ready' as const);
      if (await Promise.race([leftOrigin, firstField]) === 'off') denied();
      assertPageOrigin(page, input.origin);
      const before = await humanReason(page, input.origin);
      if (before) return await finishHuman(page, context, before, humanWaitMs, input.origin);
      if (adapter.twoStep) {
        const identifier = page.locator(adapter.username).first();
        await identifier.waitFor({ state: 'visible' });
        await assertFillFrame(identifier, input.origin);
        await identifier.fill(input.username);
        const next = page.locator(adapter.identifierNext ?? adapter.submit).first();
        await next.click();
        await page.waitForLoadState('domcontentloaded');
        assertPageOrigin(page, input.origin);
        const mid = await humanReason(page, input.origin);
        if (mid) return await finishHuman(page, context, mid, humanWaitMs, input.origin);
      }
      const user = page.locator(adapter.username).first();
      const secret = page.locator(adapter.password).first();
      if (!adapter.twoStep) {
        await user.waitFor({ state: 'visible' });
        await assertFillFrame(user, input.origin);
        await user.fill(input.username);
      }
      await secret.waitFor({ state: 'visible' });
      await assertFillFrame(secret, input.origin);
      await secret.fill(input.password);
      await page.locator(adapter.submit).first().click();
      await page.waitForLoadState('domcontentloaded');
      assertPageOrigin(page, input.origin);
      const after = await humanReason(page, input.origin);
      if (after) return await finishHuman(page, context, after, humanWaitMs, input.origin);
      if (await isSuccess(page, input.origin)) {
        const jar = JSON.stringify(await context.cookies());
        return { state: 'completed', jar };
      }
      throw new AppError('executor_failed', 'Website login executor failed.', 502, 4, 'failed');
    } finally {
      await context?.close().catch(() => undefined);
      await browser?.close().catch(() => undefined);
    }
  };
}

async function finishHuman(
  page: Page, context: BrowserContext, reason: WebsiteHumanReason, waitMs: number, origin: string,
): Promise<WebsiteLoginOutcome> {
  if (waitMs > 0) {
    const deadline = Date.now() + waitMs;
    while (Date.now() < deadline) {
      if (hrefOrigin(page.url()) && hrefOrigin(page.url()) !== origin) denied();
      if (await isSuccess(page, origin)) {
        return { state: 'completed', jar: JSON.stringify(await context.cookies()) };
      }
      const current = await humanReason(page, origin);
      if (!current && classifyLoginPage(origin, page.url()) === 'success') {
        return { state: 'completed', jar: JSON.stringify(await context.cookies()) };
      }
      await page.waitForTimeout(1000);
    }
  }
  return { state: 'human_required', reason };
}

export function websiteRunnerFromEnv(): WebsiteLoginExecutor {
  if (process.env[WEBSITE_RUNNER_ENV] !== '1') return refuseWebsiteLogin;
  if (process.platform !== 'darwin' && process.env.STACKEY_WEBSITE_RUNNER_ALLOW_LINUX !== '1') return refuseWebsiteLogin;
  return createPlaywrightExecutor({
    headed: process.env.STACKEY_WEBSITE_HEADED !== '0',
    humanWaitMs: 240_000,
  });
}
