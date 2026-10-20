import { test, expect } from './fixtures/auth.fixture.js';

test.describe('Responsive Design & Viewport Fluidity', () => {
  const VIEWPORTS = [
    { name: 'Desktop (1280px)', width: 1280, height: 800, expectedKpiCols: 4 },
    { name: 'Tablet (768px)', width: 768, height: 1024, expectedKpiCols: 2 },
    { name: 'Mobile (375px)', width: 375, height: 667, expectedKpiCols: 1 },
  ];

  for (const vp of VIEWPORTS) {
    test(`dashboard layout and KPI grid adapt gracefully at ${vp.name}`, async ({ page, loginAs }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height });
      await loginAs('analyst');
      await page.goto('/dashboard');
      await expect(page).toHaveURL(/\/dashboard$/);

      // 1. Assert no horizontal page overflow
      const overflowCheck = await page.evaluate(() => {
        return document.documentElement.scrollWidth <= window.innerWidth + 1 &&
               document.body.scrollWidth <= window.innerWidth + 1;
      });
      expect(overflowCheck).toBe(true);

      // 2. Assert KPI grid computed columns match breakpoint expectation
      const kpiGrid = page.locator('.dashboard-kpis');
      await expect(kpiGrid).toBeVisible();

      const computedCols = await kpiGrid.evaluate((el) => {
        const style = window.getComputedStyle(el);
        const template = style.getPropertyValue('grid-template-columns');
        return template.split(' ').filter(Boolean).length;
      });
      expect(computedCols).toBe(vp.expectedKpiCols);

      // 3. Assert tables are enclosed in .sentinel-table-scroll
      const scrollContainers = page.locator('.sentinel-table-scroll');
      const count = await scrollContainers.count();
      expect(count).toBeGreaterThan(0);
      for (let i = 0; i < count; i++) {
        const overflowX = await scrollContainers.nth(i).evaluate((el) => {
          return window.getComputedStyle(el).overflowX;
        });
        expect(['auto', 'scroll']).toContain(overflowX);
      }
    });

    test(`threat logs table remains fully scrollable without root overflow at ${vp.name}`, async ({ page, loginAs }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height });
      await loginAs('analyst');
      await page.goto('/dashboard/threats');
      await expect(page).toHaveURL(/\/dashboard\/threats$/);

      // Assert root has no horizontal scroll blowout
      const noRootBlowout = await page.evaluate(() => {
        return document.documentElement.scrollWidth <= window.innerWidth + 1;
      });
      expect(noRootBlowout).toBe(true);

      // Assert threat table scroll container
      const tableScroll = page.locator('.sentinel-table-scroll');
      await expect(tableScroll).toBeVisible();
    });
  }
});
