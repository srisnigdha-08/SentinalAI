import { test, expect } from './fixtures/auth.fixture.js';
import { trackPageErrors } from './fixtures/navigationErrors.js';

const LAZY_MODULE_CANCELLED = /dynamically imported module|Importing a module script failed/;
const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
// The AI engine is not started in the browser suite, so its proxy endpoints answer 503 by design; every other
// failed API response or console error is reported.
const ENGINE_DEPENDENT = /\/api\/(ai\/engine\/|honeypot\/deception\/recommendation)/;
const consoleErrors = (page) => {
  const out = [];
  const engine503 = [];
  page.on('response', (r) => {
    if (r.url().includes('/api/') && r.status() >= 500) (r.status() === 503 && ENGINE_DEPENDENT.test(r.url()) ? engine503 : out).push(`${r.status()} ${r.url()}`);
  });
  page.on('console', (m) => {
    if (m.type() === 'error' && !/Failed to load resource: the server responded with a status of 503/.test(m.text())) out.push(`${page.url()} :: ${m.text()}`);
  });
  return out;
};

// Cross-feature integration: the three investigation features and the original pages coexist for every role,
// in the sidebar, at desktop and phone widths, without console/page errors or page-level horizontal scroll.
// Read-only: it only navigates. Screenshots go to test-results/integration/.
const PAGES = [
  { path: '/dashboard', heading: /Dashboard|Tactical Command|Security Monitoring|Command/i, nav: /Dashboard/ },
  { path: '/dashboard/threats', heading: /Threat Logs/i, nav: /Threat Logs/ },
  { path: '/dashboard/honeypot', heading: /Honeypot Analytics/i, nav: /Honeypot/ },
  { path: '/dashboard/attack-time-machine', heading: /Attack Time Machine/i, nav: /Attack Time Machine/ },
  { path: '/dashboard/deception-arena', heading: /Deception Arena/i, nav: /Deception Arena/ },
  { path: '/dashboard/campaigns', heading: /Attack Campaigns/i, nav: /Campaigns/ },
  { path: '/dashboard/ai', heading: /AI Analytics Engine/i, nav: /AI Analytics/ },
  { path: '/dashboard/ai-trust-meter', heading: /AI Trust Meter/i, nav: /AI Trust Meter/ },
];

for (const role of ['viewer', 'analyst', 'admin']) {
  test(`${role}: every page is in the sidebar and opens from it without errors`, async ({ page, loginAs }) => {
    const errors = trackPageErrors(page);
    await loginAs(role);
    const sidebar = page.locator('.sentinel-sidebar');
    for (const p of PAGES) {
      await sidebar.getByRole('link', { name: p.nav }).click();
      await expect(page).toHaveURL(new RegExp(`${escapeRegExp(p.path)}$`));
      await expect(page.locator('.dashboard-main').getByText(p.heading).first()).toBeVisible();
      await expect(sidebar.getByRole('link', { name: p.nav })).toHaveAttribute('aria-current', 'page');
    }
    expect(errors.fatal().filter((e) => !LAZY_MODULE_CANCELLED.test(e.error))).toEqual([]);
  });
}

for (const [label, size] of [['desktop', { width: 1366, height: 900 }], ['phone', { width: 375, height: 812 }]]) {
  test(`${label}: all pages fit the viewport and render without errors`, async ({ page, loginAs }) => {
    await page.setViewportSize(size);
    const errors = trackPageErrors(page);
    const logged = consoleErrors(page);
    await loginAs('analyst');
    for (const p of PAGES) {
      await page.goto(p.path);
      await expect(page.locator('.dashboard-main').getByText(p.heading).first()).toBeVisible();
      await page.waitForLoadState('networkidle');
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(overflow, `${p.path} overflows by ${overflow}px`).toBeLessThanOrEqual(0);
      // Nothing visible may stick out past the viewport, except inside deliberate horizontal scroll areas.
      const sticking = await page.evaluate(() => [...document.querySelectorAll('.dashboard-main *')]
        .filter((el) => !el.closest('.sentinel-table-scroll, pre, .recharts-wrapper') && el.offsetParent !== null)
        .filter((el) => el.getBoundingClientRect().right > window.innerWidth + 1)
        .slice(0, 3).map((el) => `${el.tagName.toLowerCase()}${el.dataset.testid ? `[${el.dataset.testid}]` : ''}`));
      expect(sticking, `${p.path}: elements past the viewport`).toEqual([]);
      await page.screenshot({ path: `test-results/integration/${label}${p.path.replace(/\//g, '_')}.png`, fullPage: true });
    }
    expect(errors.fatal().filter((e) => !LAZY_MODULE_CANCELLED.test(e.error))).toEqual([]);
    expect(logged).toEqual([]);
  });
}

test('deep links survive a reload and browser history across the new features', async ({ page, loginAs }) => {
  await loginAs('analyst');
  for (const url of ['/dashboard/attack-time-machine?q=cowrie', '/dashboard/ai-trust-meter?state=INSUFFICIENT', '/dashboard/deception-arena?status=COMPLETED']) {
    await page.goto(url);
    await expect(page.locator('.sentinel-sidebar')).toBeVisible();
    await page.waitForLoadState('networkidle');
    await page.reload();
    await expect(page.locator('.sentinel-sidebar')).toBeVisible();
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(new RegExp(url.split('?')[1]));
  }
  // Wait for each page to settle: a full reload restores the session with a refresh-token rotation, and
  // navigating away while that request is in flight trips the existing refresh-replay protection (logout).
  await page.goBack();
  await expect(page).toHaveURL(/ai-trust-meter\?state=INSUFFICIENT/);
  await expect(page.getByRole('heading', { name: /AI Trust Meter/i })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await page.goBack();
  await expect(page).toHaveURL(/attack-time-machine\?q=cowrie/);
  await expect(page.getByRole('heading', { name: /Attack Time Machine/i })).toBeVisible();
});
