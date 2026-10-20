import { test, expect, SEEDED_USERS } from './fixtures/auth.fixture.js';

test.describe('Dashboard Operations & Error Boundaries', () => {
  test('KPIs, panels, and charts render accurately for analyst', async ({ page, analystPage, dashboardPage }) => {
    // Already logged in via analystPage fixture and at /dashboard
    await expect(page).toHaveURL(/\/dashboard$/);

    // 1. Assert Analyst KPI Cards
    await expect(page.getByText('Threats Today', { exact: true })).toBeVisible();
    await expect(page.getByText('Threats Blocked', { exact: true })).toBeVisible();
    await expect(page.getByText('Avg Threat Score', { exact: true })).toBeVisible();
    await expect(page.getByText('Active Honeypots', { exact: true })).toBeVisible();

    // 2. Assert Key Panels
    await expect(page.getByText('Active Threat Queue')).toBeVisible();
    await expect(page.getByText('Threat Activity — Today (IST)')).toBeVisible();
    await expect(page.getByText('Live Attack Feed')).toBeVisible();
    await expect(page.getByText(/Attack Vector Distribution/i)).toBeVisible();

    // 3. Assert Active Threat Queue has rows
    const queueRows = page.locator('.sentinel-table-scroll table tbody tr');
    await expect(queueRows.first()).toBeVisible();
  });

  test('blocking an IP displays SUCCESS toast (not error) and refreshes queue', async ({ page, analystPage }) => {
    await expect(page).toHaveURL(/\/dashboard$/);

    // Wait for the table rows to load
    const blockButton = page.getByRole('button', { name: 'Block IP' }).first();
    await expect(blockButton).toBeVisible();

    // Track reload network request
    const reloadPromise = page.waitForResponse(
      (resp) => resp.url().includes('/api/threats') && resp.request().method() === 'GET' && resp.status() === 200
    );

    // Click Block IP
    await blockButton.click();

    // Assert SUCCESS toast appears (and no error toast)
    const successToast = page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: /added to deny-list/i });
    await expect(successToast.first()).toBeVisible();

    const errorToast = page.locator('.hot-toast-bar, [role="alert"]').filter({ hasText: /Block failed/i });
    await expect(errorToast).toHaveCount(0);

    // Queue refreshed
    await reloadPromise;
  });

  test('panel-level error boundary isolates render crash while keeping rest of dashboard operational', async ({ page, loginPage }) => {
    // Intercept threat list endpoint and return malformed data where attackType is an object (invalid React child)
    await page.route('**/api/threats?*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            success: true,
            data: [
              {
                _id: 'crash-threat-1',
                severity: 'CRITICAL',
                sourceIP: '192.0.2.1',
                attackType: { unrenderable: 'object child' },
                targetService: 'SSH:22',
                createdAt: new Date().toISOString(),
                aiScore: 0.99,
              },
            ],
            total: 1,
            page: 1,
            limit: 8,
          }),
        });
      } else {
        await route.continue();
      }
    });

    // Login as analyst
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    await page.waitForURL('**/dashboard');

    // 1. Assert that the crashed panel displays the ErrorBoundary fallback
    const crashAlert = page.locator('[role="alert"]').filter({ hasText: /COMPONENT RENDER ANOMALY/i });
    await expect(crashAlert.first()).toBeVisible();
    await expect(crashAlert.first().getByRole('button', { name: /Retry Module/i })).toBeVisible();

    // 2. Assert that other panels and modules remain fully intact and operational
    await expect(page.getByText('Threat Activity — Today (IST)')).toBeVisible();
    await expect(page.getByText('Live Attack Feed')).toBeVisible();
    await expect(page.locator('.sentinel-navbar')).toBeVisible();
    await expect(page.locator('.sentinel-sidebar')).toBeVisible();

    // 3. User can still interact with navigation
    await page.locator('.sentinel-sidebar').getByRole('link', { name: /Threat Logs/i }).click();
    await expect(page).toHaveURL(/\/dashboard\/threats$/);
  });
});
