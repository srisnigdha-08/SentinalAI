import { test, expect } from './fixtures/auth.fixture.js';

test.describe('Operator Account Governance & RBAC (User Management)', () => {
  test('admin can provision a new operator, verify in table, and delete operator', async ({ page, loginAs }) => {
    const operatorName = 'Forensic Analyst AutoTest';
    const operatorEmail = `autotest.analyst.${Date.now()}@sentinel.test`;
    const operatorPassword = 'OperatorPassword123!';

    await loginAs('admin');
    await page.goto('/dashboard/users');
    await expect(page).toHaveURL(/\/dashboard\/users$/);
    await expect(page.getByText('User Management')).toBeVisible();

    // 1. Open provision form
    await page.getByRole('button', { name: /\+ Provision Operator/i }).click();
    await expect(page.getByText('Administrator-only enrollment')).toBeVisible();

    // 2. Fill form
    await page.getByLabel('Full name').fill(operatorName);
    await page.getByLabel('Email').fill(operatorEmail);
    await page.getByLabel('Initial password').fill(operatorPassword);
    await page.getByLabel('Department').fill('Threat Intelligence');
    await page.getByLabel('Role').selectOption('analyst');

    // 3. Submit account creation
    await page.getByRole('button', { name: 'Provision account' }).click();

    // 4. Assert success toast
    const successToast = page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: /Account provisioned/i });
    await expect(successToast.first()).toBeVisible();

    // 5. Assert new operator appears in the table
    const table = page.locator('.sentinel-table-scroll table');
    await expect(table.getByText(operatorEmail)).toBeVisible();
    await expect(table.getByText(operatorName)).toBeVisible();

    // 6. Delete operator (handling window.confirm dialog)
    page.once('dialog', async (dialog) => {
      expect(dialog.message()).toContain(`Delete ${operatorName}?`);
      await dialog.accept();
    });

    const operatorRow = table.locator('tbody tr').filter({ hasText: operatorEmail });
    await operatorRow.getByRole('button', { name: 'Remove' }).click();

    // Assert deletion toast
    const deleteToast = page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: new RegExp(`${operatorName} removed`, 'i') });
    await expect(deleteToast.first()).toBeVisible();

    // Assert row removed from table
    await expect(table.getByText(operatorEmail)).not.toBeVisible();
  });

  test('non-admin (analyst or viewer) cannot access /dashboard/users and receives redirect', async ({ page, loginAs }) => {
    await loginAs('analyst');

    // Direct navigation attempt to /dashboard/users
    await page.goto('/dashboard/users');

    // Should be redirected back to /dashboard
    await expect(page).toHaveURL(/\/dashboard$/);

    // Sidebar should not display Users link for analyst
    await expect(page.locator('.sentinel-sidebar').getByRole('link', { name: /Users/i })).toHaveCount(0);
  });
});
