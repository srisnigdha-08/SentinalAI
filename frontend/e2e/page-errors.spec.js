import { test, expect } from './fixtures/auth.fixture.js';
import { trackPageErrors } from './fixtures/navigationErrors.js';

// TEST-009 negative controls: the page-error tracker the smoke tests rely on must still report genuine failures. Each
// test induces one on a real dashboard page and expects the tracker to flag it.

const fatalMatching = async (tracker, pattern) => {
  await expect.poll(() => tracker.fatal().some((e) => pattern.test(e.error)), { timeout: 10000 }).toBe(true);
};

test.describe('Page-error tracker still reports genuine failures (TEST-009)', () => {
  test('a JavaScript exception in the page', async ({ page, loginAs }) => {
    await loginAs('analyst');
    const tracker = trackPageErrors(page);
    await page.evaluate(() => { setTimeout(() => { throw new Error('negative-control exception'); }, 0); });
    await fatalMatching(tracker, /negative-control exception/);
  });

  test('an unhandled promise rejection in the page', async ({ page, loginAs }) => {
    await loginAs('analyst');
    const tracker = trackPageErrors(page);
    await page.evaluate(() => { Promise.reject(new Error('negative-control rejection')); });
    await fatalMatching(tracker, /negative-control rejection/);
  });

  test('an API request that fails at the network level', async ({ page, loginAs }) => {
    await loginAs('analyst');
    const tracker = trackPageErrors(page);
    await page.route('**/api/alerts/unread-count', (route) => route.abort('connectionrefused'));
    await page.locator('.sentinel-sidebar').getByRole('link', { name: 'Threat Logs' }).click(); // client-side: no unload
    await page.locator('.sentinel-sidebar').getByRole('link', { name: 'Dashboard' }).click();
    await fatalMatching(tracker, /request failed: GET .*\/api\/alerts\/unread-count/);
  });

  test('a Socket.IO transport that cannot connect', async ({ page, loginAs }) => {
    await loginAs('analyst');
    await expect.poll(() => page.evaluate(() => window.__socket?.connected), { timeout: 10000 }).toBe(true);
    const tracker = trackPageErrors(page);
    await page.route('**/socket.io/**', (route) => route.abort('connectionrefused'));
    await page.evaluate(() => window.__socket.io.engine.close()); // force a new transport through the refusing route
    await fatalMatching(tracker, /request failed: .*\/socket\.io\//);
  });
});
