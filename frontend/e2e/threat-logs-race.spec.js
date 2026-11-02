import { test, expect } from './fixtures/auth.fixture.js';

// UI-003: Threat Logs fired overlapping list requests (mount, filter change + page reset) and applied whichever
// response arrived last, so a slow, older request could overwrite the table with the previous filter's rows.
test('a slow response for an older filter does not overwrite the current filter’s results', async ({ loginAs, page }) => {
  await page.route(/\/api\/threats(\?|$)/, async (route) => {
    const url = new URL(route.request().url());
    if (route.request().method() === 'GET' && !url.searchParams.get('severity')) {
      await new Promise((r) => setTimeout(r, 2500)); // the unfiltered (older) request is slow
    }
    await route.continue();
  });
  await loginAs('analyst');
  await page.goto('/dashboard/threats');

  // Change the filter while the unfiltered requests are still in flight.
  await page.locator('select').filter({ hasText: 'All Severities' }).selectOption('CRITICAL');

  const rows = page.locator('.sentinel-table-scroll table tbody tr');
  await expect.poll(async () => (await rows.allTextContents()).length).toBeGreaterThan(0);
  await page.waitForTimeout(4000); // let the slow, stale responses arrive
  const texts = await rows.allTextContents();
  expect(texts.length).toBeGreaterThan(0);
  expect(texts.every((t) => t.includes('CRITICAL'))).toBe(true);
});
