import { test, expect } from './fixtures/auth.fixture.js';

// Batch 13: time from navigation until each main view shows its data, and no uncaught JavaScript errors.
// Budgets are deliberately generous (dev server, unbundled modules): they catch gross regressions and hangs,
// not milliseconds. Measured values are printed for the performance record.

// Views are opened from the sidebar, i.e. client-side navigation as a user does it. (A full page load per view would
// discard the previous document mid-load; Firefox and WebKit then report its cancelled lazy modules as page errors.)
const VIEWS = [
  { name: 'Threat Logs', link: 'Threat Logs', ready: (p) => p.locator('.sentinel-table-scroll table tbody tr').first() },
  { name: 'Honeypot Analytics', link: 'Honeypot', ready: (p) => p.getByText('Attacker Sessions') },
  { name: 'AI Analytics', link: 'AI Analytics', ready: (p) => p.getByText('Predictions by Attack Class') },
  { name: 'Dashboard', link: 'Dashboard', ready: (p) => p.getByText('Live Attack Feed') },
];
const sidebarLink = (page, name) => page.locator('.sentinel-sidebar').getByRole('link', { name: new RegExp(name) });
const BUDGET_MS = 8000;

test.describe('Page performance and runtime errors', () => {
  test('main views render their data within budget with no uncaught errors', async ({ loginAs, page, browserName }) => {
    await loginAs('analyst');
    await page.waitForLoadState('networkidle');
    // Errors are collected for the measured views. On the Vite dev server, Firefox can report a cancelled lazy-module
    // load during the fixture's fast sign-in sequence; a real sign-in shows no error (checked 2026-11-03).
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    const timings = {};
    for (const v of VIEWS) {
      const t0 = Date.now();
      await sidebarLink(page, v.link).click();
      await expect(v.ready(page)).toBeVisible({ timeout: BUDGET_MS });
      timings[v.name] = Date.now() - t0;
    }
    console.log(`[perf] ${browserName} view ready ms: ${JSON.stringify(timings)}`);
    expect(errors).toEqual([]);
    for (const [name, ms] of Object.entries(timings)) expect(ms, name).toBeLessThan(BUDGET_MS);
  });

  test('explanation modal opens and renders its chart within budget', async ({ loginAs, page, browserName }) => {
    const errors = [];
    await page.route(/\/api\/threats(\?|$)/, async (route) => {
      if (route.request().method() !== 'GET') return route.continue();
      const res = await route.fetch();
      const body = await res.json();
      if (Array.isArray(body.data) && body.data.length) body.data[0] = { ...body.data[0], predictionId: 'p1' };
      await route.fulfill({ response: res, json: body });
    });
    const contributions = Array.from({ length: 53 }, (_, i) => ({ feature: `feature_${i}`, contribution: (i % 2 ? -1 : 1) / (i + 1), value: i }));
    await page.route('**/api/threats/*/explanation', (route) => route.fulfill({ status: 200, json: { success: true, data: {
      predictedClass: 'DDoS', explainedClass: 'DDoS', confidence: 0.97, threatScore: 0.97, modelVersion: 'xgb_cicids_v1',
      predictedAt: new Date().toISOString(), contributions } } }));
    await loginAs('analyst');
    await page.waitForLoadState('networkidle');
    page.on('pageerror', (e) => errors.push(e.message)); // from here on (see above)
    await sidebarLink(page, 'Threat Logs').click();
    await expect(page.getByRole('button', { name: 'Explain' })).toHaveCount(1);
    const t0 = Date.now();
    await page.getByRole('button', { name: 'Explain' }).click();
    await expect(page.getByTestId('explanation').locator('.recharts-bar-rectangle')).toHaveCount(10);
    const ms = Date.now() - t0;
    console.log(`[perf] ${browserName} explanation modal ready ms: ${ms}`);
    expect(errors).toEqual([]);
    expect(ms).toBeLessThan(BUDGET_MS);
  });
});
