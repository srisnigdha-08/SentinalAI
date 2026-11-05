import { test, expect } from './fixtures/auth.fixture.js';

test.describe('Error State Resilience & Retry Workflows', () => {
  test('Campaigns: 500 failure shows role="alert" banner with Retry, omits "No security events", and recovers upon Retry', async ({ page, loginAs }) => {
    let mockError = true;
    await page.route('**/api/campaigns', async (route) => {
      if (mockError && route.request().method() === 'GET') {
        await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'Database timeout' }) });
      } else {
        await route.continue();
      }
    });

    await loginAs('analyst');
    await page.goto('/dashboard/campaigns');
    await expect(page).toHaveURL(/\/dashboard\/campaigns$/);

    // 1. Assert role="alert" banner and Retry button are visible
    const alertBanner = page.locator('[role="alert"]').filter({ hasText: /Campaign telemetry is unavailable/i });
    await expect(alertBanner).toBeVisible();
    const retryBtn = alertBanner.getByRole('button', { name: /Retry/i });
    await expect(retryBtn).toBeVisible();

    // 2. CRITICAL AUDIT RULE: Campaigns must NOT show "No security events" on failure
    await expect(page.getByText(/No live security events detected/i)).not.toBeVisible();

    // 3. Remove mock and click Retry
    mockError = false;
    await retryBtn.click();

    // 4. Alert disappears and data renders
    await expect(alertBanner).not.toBeVisible();
    await expect(page.getByText('Active Attack Campaigns')).toBeVisible();
  });

  test('HoneypotAnalytics: 500 failure shows role="alert" banner with Retry and recovers upon Retry', async ({ page, loginAs }) => {
    let mockError = true;
    await page.route('**/api/honeypot/analytics', async (route) => {
      if (mockError && route.request().method() === 'GET') {
        await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'Honeypot collector offline' }) });
      } else {
        await route.continue();
      }
    });

    await loginAs('analyst');
    await page.goto('/dashboard/honeypot');
    await expect(page).toHaveURL(/\/dashboard\/honeypot$/);

    // 1. Assert role="alert" banner and Retry button are visible
    const alertBanner = page.locator('[role="alert"]').filter({ hasText: /Honeypot telemetry is unavailable/i });
    await expect(alertBanner).toBeVisible();
    const retryBtn = alertBanner.getByRole('button', { name: /Retry/i });
    await expect(retryBtn).toBeVisible();

    // 2. Remove mock and click Retry
    mockError = false;
    await retryBtn.click();

    // 3. Alert disappears and honeypot panels render
    await expect(alertBanner).not.toBeVisible();
    await expect(page.getByText('Honeypot Analytics')).toBeVisible();
  });

  test('AIAnalytics: 500 failure shows role="alert" banner with Retry and recovers upon Retry', async ({ page, loginAs }) => {
    let mockError = true;
    await page.route('**/api/ai/stats', async (route) => {
      if (mockError && route.request().method() === 'GET') {
        await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'AI inference service down' }) });
      } else {
        await route.continue();
      }
    });

    await loginAs('analyst');
    await page.goto('/dashboard/ai');
    await expect(page).toHaveURL(/\/dashboard\/ai$/);

    // 1. Assert role="alert" banner and Retry button are visible
    const alertBanner = page.locator('[role="alert"]').filter({ hasText: /AI analytics telemetry is unavailable/i });
    await expect(alertBanner).toBeVisible();
    const retryBtn = alertBanner.getByRole('button', { name: /Retry/i });
    await expect(retryBtn).toBeVisible();

    // 2. Remove mock and click Retry
    mockError = false;
    await retryBtn.click();

    // 3. Alert disappears and AI engine panels render
    await expect(alertBanner).not.toBeVisible();
    await expect(page.getByText('AI Analytics Engine')).toBeVisible();
  });

  test('UserManagement: 500 failure shows role="alert" banner with Retry and recovers upon Retry', async ({ page, loginAs }) => {
    let mockError = true;
    await page.route('**/api/users', async (route) => {
      if (mockError && route.request().method() === 'GET') {
        await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'User directory unavailable' }) });
      } else {
        await route.continue();
      }
    });

    // Requires admin
    await loginAs('admin');
    await page.goto('/dashboard/users');
    await expect(page).toHaveURL(/\/dashboard\/users$/);

    // 1. Assert role="alert" banner and Retry button are visible
    const alertBanner = page.locator('[role="alert"]').filter({ hasText: /Failed to load user list/i });
    await expect(alertBanner).toBeVisible();
    const retryBtn = alertBanner.getByRole('button', { name: /Retry/i });
    await expect(retryBtn).toBeVisible();

    // 2. Remove mock and click Retry
    mockError = false;
    await retryBtn.click();

    // 3. Alert disappears and user table renders
    await expect(alertBanner).not.toBeVisible();
    await expect(page.locator('.sentinel-table-scroll table')).toBeVisible();
  });

  test('Settings: 500 failure shows role="alert" banner with Retry and recovers upon Retry', async ({ page, loginAs }) => {
    let mockError = true;
    await page.route('**/api/threats/settings', async (route) => {
      if (mockError && route.request().method() === 'GET') {
        await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'Firewall rules query failure' }) });
      } else {
        await route.continue();
      }
    });

    // Requires admin
    await loginAs('admin');
    await page.goto('/settings');
    await expect(page).toHaveURL(/\/settings$/);

    // 1. Assert role="alert" banner and Retry button are visible
    const alertBanner = page.locator('[role="alert"]').filter({ hasText: /System configuration is unavailable/i });
    await expect(alertBanner).toBeVisible();
    const retryBtn = alertBanner.getByRole('button', { name: /Retry/i });
    await expect(retryBtn).toBeVisible();

    // 2. Remove mock and click Retry
    mockError = false;
    await retryBtn.click();

    // 3. Alert disappears and settings panels render
    await expect(alertBanner).not.toBeVisible();
    await expect(page.getByText(/System Settings/i)).toBeVisible();
  });
});
