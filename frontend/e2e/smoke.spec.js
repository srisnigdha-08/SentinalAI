import { test, expect } from './fixtures/auth.fixture.js';

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
    const pageErrors = [];
    page.on('pageerror', (err) => {
      pageErrors.push({ url: page.url(), error: err.message });
    });

    await loginAs('analyst');

    const analystRoutes = [
      { path: '/dashboard', heading: 'Tactical Command' },
      { path: '/dashboard/threats', heading: /Threat Logs/i },
      { path: '/dashboard/honeypot', heading: /Honeypot Analytics/i },
      { path: '/dashboard/campaigns', heading: /Attack Campaigns/i },
      { path: '/dashboard/ai', heading: /AI Analytics Engine/i },
    ];

    for (const { path, heading } of analystRoutes) {
      if (!page.url().endsWith(path)) {
        await page.goto(path);
      }
      await expect(page).toHaveURL(new RegExp(`${path}$`));
      await expect(page.locator('.dashboard-main').getByText(heading).first()).toBeVisible({ timeout: 10000 });
      const fatalErrors = pageErrors.filter(e => !e.error.includes('dynamically imported module') && !e.error.includes('Importing a module script failed') && !e.error.includes('socket.io'));
      expect(fatalErrors).toEqual([]);
    }
  });

  test('admin governance routes render smoothly without uncaught errors', async ({ page, loginAs }) => {
    const pageErrors = [];
    page.on('pageerror', (err) => {
      pageErrors.push({ url: page.url(), error: err.message });
    });

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
      const fatalErrors = pageErrors.filter(e => !e.error.includes('dynamically imported module') && !e.error.includes('Importing a module script failed') && !e.error.includes('socket.io'));
      expect(fatalErrors).toEqual([]);
    }
  });
});
