import { test, expect } from './fixtures/auth.fixture.js';

test.describe('Settings & Manual Containment (Admin)', () => {
  test.beforeEach(async ({ loginAs, page }) => {
    // Only Admin has permissions: settings:read, settings:write, containment:manage
    await loginAs('admin');
    await page.goto('/settings');
    await expect(page).toHaveURL(/\/settings$/);
    await expect(page.getByText('System Settings')).toBeVisible();
  });

  test('toggle the AI autonomous auto-blocking engine', async ({ page }) => {
    // Locate the toggle button
    const toggleBtn = page.getByRole('button', { name: /ACTIVE \/ ON|DISABLED \/ OFF/i });
    await expect(toggleBtn).toBeVisible();

    const initialText = await toggleBtn.innerText();
    const isInitiallyOn = initialText.includes('ACTIVE');

    // Click toggle button
    await toggleBtn.click();

    // Verify toast notification and new state
    if (isInitiallyOn) {
      await expect(page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: /Autonomous Auto-Blocking Disabled/i })).toBeVisible();
      await expect(toggleBtn).toContainText('DISABLED / OFF');
    } else {
      await expect(page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: /Autonomous Auto-Blocking Enabled/i })).toBeVisible();
      await expect(toggleBtn).toContainText('ACTIVE / ON');
    }

    // Toggle back to original state to restore baseline
    await toggleBtn.click();
    await expect(toggleBtn).toContainText(isInitiallyOn ? 'ACTIVE / ON' : 'DISABLED / OFF');
  });

  test('validate IP format in manual containment form (rejects 999.1.1.1 and abc)', async ({ page }) => {
    const ipInput = page.getByPlaceholder('e.g. 185.220.101.47');
    const enforceBtn = page.getByRole('button', { name: 'Enforce IP Block' });

    // 1. Test invalid octet > 255
    await ipInput.fill('999.1.1.1');
    await enforceBtn.click();

    const toastInvalid = page.locator('.hot-toast-bar, [role="status"], [role="alert"]').filter({ hasText: /Please enter a valid IPv4 or IPv6 address/i });
    await expect(toastInvalid.first()).toBeVisible();
    await expect(page.getByRole('dialog')).toHaveCount(0);

    // 2. Test non-IP string
    await ipInput.fill('abc');
    await enforceBtn.click();
    await expect(toastInvalid.first()).toBeVisible();
    await expect(page.getByRole('dialog')).toHaveCount(0);
  });

  test('add valid IP to blocklist, verify in table, and unblock IP', async ({ page }) => {
    const validIP = '198.51.100.42';
    const reasonText = 'Automated E2E containment verification';

    const ipInput = page.getByPlaceholder('e.g. 185.220.101.47');
    const reasonInput = page.getByPlaceholder('e.g. Manual block of scanner IP');
    const enforceBtn = page.getByRole('button', { name: 'Enforce IP Block' });

    await ipInput.fill(validIP);
    await reasonInput.fill(reasonText);
    await enforceBtn.click();

    // Verification modal appears
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('heading', { name: 'CONTAINMENT VERIFICATION' })).toBeVisible();

    // Confirm containment inside modal
    await dialog.getByRole('button', { name: 'Confirm Containment' }).click();

    // Assert success toast
    const successToast = page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: new RegExp(`Simulated containment recorded for ${validIP}`, 'i') });
    await expect(successToast.first()).toBeVisible();

    // Assert row appears in honeypot blocklist table
    const blocklistTable = page.locator('.sentinel-table-scroll table').filter({ hasText: 'Enforced IP' });
    await expect(blocklistTable.getByText(validIP)).toBeVisible();

    // Unblock the IP
    const row = blocklistTable.locator('tbody tr').filter({ hasText: validIP });
    const unblockBtn = row.getByRole('button', { name: 'Unblock IP' });
    await expect(unblockBtn).toBeVisible();
    await unblockBtn.click();

    // Assert unblock toast
    const unblockToast = page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: new RegExp(`IP ${validIP} unblocked successfully`, 'i') });
    await expect(unblockToast.first()).toBeVisible();

    // Assert IP removed from table
    await expect(blocklistTable.getByText(validIP)).not.toBeVisible();
  });

  test('audit log entries appear in Security & Compliance Audit Trail panel', async ({ page }) => {
    // Assert Audit panel is visible
    const auditPanel = page.locator('[data-sentinel-panel]').filter({ hasText: 'Security & Compliance Audit Trail' });
    await expect(auditPanel).toBeVisible();

    // Assert audit table rows are populated from seed
    const auditTable = auditPanel.locator('table');
    await expect(auditTable).toBeVisible();
    const rows = auditTable.locator('tbody tr');
    await expect(rows.first()).toBeVisible();
  });
});
