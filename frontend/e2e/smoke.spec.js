import { test, expect } from './fixtures/auth.fixture.js';
import { trackPageErrors } from './fixtures/navigationErrors.js';

// The Vite dev server reports a lazy route module whose load a full navigation cancelled as a page error (E2E-002).
const LAZY_MODULE_CANCELLED = /dynamically imported module|Importing a module script failed/;

test.describe('End-to-End Smoke & Navigation Stability', () => {
  test('public showcase routes render cleanly without console errors or page errors', async ({ page }) => {
    const consoleErrors = [];
    const pageErrors = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push({ url: page.url(), text: msg.text() });
    });
    page.on('pageerror', (err) => {
      pageErrors.push({ url: page.url(), error: err.message });
    });

    const publicRoutes = ['/', '/about', '/features', '/login', '/register'];

    for (const route of publicRoutes) {
      await page.goto(route);
      await page.waitForLoadState('domcontentloaded');

      // Assert basic navigation elements exist
      await expect(page.locator('.sentinel-navbar')).toBeVisible();

      // Filter out non-fatal expected browser notices (e.g., favicon 404s, font downloads in offline/headless environments)
      const fatalConsole = consoleErrors.filter(e => !e.text.includes('favicon') && !e.text.includes('404') && !e.text.includes('downloadable font'));
      expect(fatalConsole).toEqual([]);
      expect(pageErrors).toEqual([]);
    }
  });

  test('analyst dashboard routes render smoothly without uncaught errors', async ({ page, loginAs }) => {
    const pageErrors = trackPageErrors(page);

    await loginAs('analyst');

    const analystRoutes = [
      { path: '/dashboard', heading: 'Tactical Command' },
      { path: '/dashboard/threats', heading: /Threat Logs/i },
      { path: '/dashboard/honeypot', heading: /Honeypot Analytics/i },
      { path: '/dashboard/campaigns', heading: /Attack Campaigns/i },
      { path: '/dashboard/attack-time-machine', heading: /Attack Time Machine/i },
      { path: '/dashboard/deception-arena', heading: /Deception Arena/i },
      { path: '/dashboard/ai', heading: /AI Analytics Engine/i },
      { path: '/dashboard/ai-trust-meter', heading: /AI Trust Meter/i },
    ];

    for (const { path, heading } of analystRoutes) {
      if (!page.url().endsWith(path)) {
        await page.goto(path);
      }
      await expect(page).toHaveURL(new RegExp(`${path}$`));
      await expect(page.locator('.dashboard-main').getByText(heading).first()).toBeVisible({ timeout: 10000 });
      const fatalErrors = pageErrors.fatal().filter((e) => !LAZY_MODULE_CANCELLED.test(e.error));
      expect(fatalErrors).toEqual([]);
    }
  });

  test('admin governance routes render smoothly without uncaught errors', async ({ page, loginAs }) => {
    const pageErrors = trackPageErrors(page);

    await loginAs('admin');

    const adminRoutes = [
      { path: '/dashboard/users', heading: /User Management/i },
      { path: '/settings', heading: /System Settings/i },
    ];

    for (const { path, heading } of adminRoutes) {
      if (!page.url().endsWith(path)) {
        await page.goto(path);
      }
      await expect(page).toHaveURL(new RegExp(`${path}$`));
      await expect(page.locator('.dashboard-main').getByText(heading).first()).toBeVisible({ timeout: 10000 });
      const fatalErrors = pageErrors.fatal().filter((e) => !LAZY_MODULE_CANCELLED.test(e.error));
      expect(fatalErrors).toEqual([]);
    }
  });

  // TEST-009: deep links in quick succession cancel the previous page's pollers and Socket.IO requests. The app must
  // handle those cancellations itself: no 'unhandledrejection' or 'error' event inside the page.
  test('rapid deep-link navigation leaves no unhandled errors in the app', async ({ page, loginAs }) => {
    const inPage = [];
    await page.exposeFunction('__reportPageEvent', (e) => inPage.push(e));
    await page.addInitScript(() => {
      window.addEventListener('unhandledrejection', (e) => window.__reportPageEvent({ type: 'unhandledrejection', path: location.pathname, reason: String(e.reason?.message || e.reason) }));
      window.addEventListener('error', (e) => window.__reportPageEvent({ type: 'error', path: location.pathname, reason: String(e.message) }));
    });
    const pageErrors = trackPageErrors(page);
    await loginAs('analyst');
    for (let round = 0; round < 2; round++) {
      for (const path of ['/dashboard', '/dashboard/threats', '/dashboard/honeypot', '/dashboard/campaigns', '/dashboard/ai']) {
        await page.goto(path);
        await page.waitForTimeout(150 + 150 * round);
      }
    }
    await expect(page.locator('.dashboard-main')).toBeVisible();
    expect(inPage.filter((e) => !LAZY_MODULE_CANCELLED.test(e.reason))).toEqual([]);
    expect(pageErrors.fatal().filter((e) => !LAZY_MODULE_CANCELLED.test(e.error))).toEqual([]);
  });
});
