import { test, expect, SEEDED_USERS } from './fixtures/auth.fixture.js';

test.describe('Role-Based Access Control (RBAC)', () => {
  test('viewer role permissions, sidebar isolation, and admin route protection', async ({ page, loginPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.viewer.email, SEEDED_USERS.viewer.password);
    await expect(page).toHaveURL(/\/dashboard$/);

    const sidebar = page.locator('.sentinel-sidebar');

    // 1. Sidebar items match viewer role
    await expect(sidebar.getByRole('link', { name: /Dashboard/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Threat Logs/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Honeypot/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Campaigns/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /AI Analytics/i })).toBeVisible();

    // Admin-only links must NOT be present
    await expect(sidebar.getByRole('link', { name: /Users/i })).not.toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Settings/i })).not.toBeVisible();

    // Verify viewer badge
    await expect(sidebar).toContainText('VIEWER // OBSERVE');

    // 2. Direct navigation to /settings is blocked with redirect and error toast
    await page.goto('/settings');
    await expect(page).toHaveURL(/\/dashboard$/);
    const toast = page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: /Access denied|Insufficient permissions/i });
    await expect(toast.first()).toBeVisible();

    // 3. Direct navigation to /dashboard/users is blocked with redirect and error toast
    await page.goto('/dashboard/users');
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(toast.first()).toBeVisible();

    // 4. On dashboard, viewer sees observation mode instead of block button
    await expect(page.getByText('OBSERVATION MODE').first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Block IP' })).not.toBeVisible();
  });

  test('analyst role can triage and contain but cannot access admin management', async ({ page, loginPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    await expect(page).toHaveURL(/\/dashboard$/);

    const sidebar = page.locator('.sentinel-sidebar');

    // 1. Sidebar items match analyst role
    await expect(sidebar.getByRole('link', { name: /Dashboard/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Threat Logs/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Users/i })).not.toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Settings/i })).not.toBeVisible();
    await expect(sidebar).toContainText('ANALYST // DEFEND');

    // 2. Analyst can view Block IP action on Dashboard
    await expect(page.getByRole('button', { name: 'Block IP' }).first()).toBeVisible();

    // 3. Analyst can see Triage and Block buttons on Threat Logs
    await page.goto('/dashboard/threats');
    await expect(page).toHaveURL(/\/dashboard\/threats$/);
    await expect(page.getByRole('button', { name: 'Triage' }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Block' }).first()).toBeVisible();

    // 4. Analyst cannot open /dashboard/users
    await page.goto('/dashboard/users');
    await expect(page).toHaveURL(/\/dashboard$/);
    const toast = page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: /Access denied|Insufficient permissions/i });
    await expect(toast.first()).toBeVisible();
  });

  test('admin role has full access to all navigation links, management screens, and controls', async ({ page, loginPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.admin.email, SEEDED_USERS.admin.password);
    await expect(page).toHaveURL(/\/dashboard$/);

    const sidebar = page.locator('.sentinel-sidebar');

    // 1. Sidebar contains all links
    await expect(sidebar.getByRole('link', { name: /Dashboard/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Threat Logs/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Users/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Settings/i })).toBeVisible();
    await expect(sidebar).toContainText('ADMIN // CONTROL');

    // 2. Admin can access /settings directly
    await page.goto('/settings');
    await expect(page).toHaveURL(/\/settings$/);
    await expect(page.getByText('Host Containment & Response Policy Engine')).toBeVisible();

    // 3. Admin can access /dashboard/users directly
    await page.goto('/dashboard/users');
    await expect(page).toHaveURL(/\/dashboard\/users$/);
    await expect(page.getByRole('button', { name: /\+ Provision Operator/i })).toBeVisible();
  });
});
