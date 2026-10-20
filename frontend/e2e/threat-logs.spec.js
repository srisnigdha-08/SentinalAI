import { test, expect, SEEDED_USERS } from './fixtures/auth.fixture.js';

test.describe('Threat Logs Telemetry, Triage & Containment', () => {
  test.beforeEach(async ({ loginAs, page }) => {
    // Analyst has permissions: threats:read, threats:triage, threats:block
    await loginAs('analyst');
    await page.goto('/dashboard/threats');
    await expect(page).toHaveURL(/\/dashboard\/threats$/);
  });

  test('filters, severity badges, and disabled CSV export render correctly', async ({ page }) => {
    // 1. Export CSV button is disabled
    const exportBtn = page.getByRole('button', { name: /Export CSV/i });
    await expect(exportBtn).toBeVisible();
    await expect(exportBtn).toBeDisabled();

    // 2. Filter controls are present
    const searchInput = page.getByPlaceholder('Search IP, type...');
    await expect(searchInput).toBeVisible();

    const sevSelect = page.locator('select').filter({ hasText: 'All Severities' });
    await expect(sevSelect).toBeVisible();

    const typeSelect = page.locator('select').filter({ hasText: 'All Types' });
    await expect(typeSelect).toBeVisible();

    // 3. Severity badges exist in table
    const table = page.locator('.sentinel-table-scroll table');
    await expect(table).toBeVisible();
    const badges = table.locator('tbody tr td span').filter({ hasText: /CRITICAL|HIGH|MEDIUM|LOW/ });
    await expect(badges.first()).toBeVisible();

    // 4. Test filtering by severity
    await Promise.all([
      page.waitForResponse(resp => resp.url().includes('/api/threats') && resp.status() === 200),
      sevSelect.selectOption('CRITICAL'),
    ]);

    const rows = table.locator('tbody tr');
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
    // All displayed severities should be CRITICAL
    for (let i = 0; i < count; i++) {
      await expect(rows.nth(i).locator('td').filter({ hasText: 'CRITICAL' })).toBeVisible();
    }
  });

  test('open Triage modal, update incident status and notes, and assert PATCH payload', async ({ page }) => {
    const triageBtn = page.getByRole('button', { name: 'Triage' }).first();
    await expect(triageBtn).toBeVisible();
    await triageBtn.click();

    // Verify Modal opens
    const modalDialog = page.getByRole('dialog');
    await expect(modalDialog).toBeVisible();
    await expect(modalDialog.getByText(/INCIDENT TRIAGE & NOTES/i)).toBeVisible();

    // Intercept PATCH request to verify payload
    let patchPayload = null;
    await page.route('**/api/threats/*/triage', async (route) => {
      if (route.request().method() === 'PATCH') {
        patchPayload = JSON.parse(route.request().postData() || '{}');
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            success: true,
            data: {
              threat: {
                _id: 'mock-triage-id',
                status: patchPayload.status,
                triageNotes: patchPayload.triageNotes,
              },
            },
          }),
        });
      } else {
        await route.continue();
      }
    });

    // Update status to INVESTIGATING
    await page.locator('#triage-status').selectOption('INVESTIGATING');

    // Add forensic note
    const noteText = 'Automated triage verification note: high anomalous entropy detected.';
    await page.locator('#triage-notes').fill(noteText);

    // Click Save Triage
    await page.getByRole('button', { name: 'Save Triage' }).click();

    // Assert success toast appears
    const successToast = page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: /Threat triage updated successfully/i });
    await expect(successToast.first()).toBeVisible();

    // Assert Modal closed
    await expect(modalDialog).not.toBeVisible();

    // Assert PATCH payload matches expectations
    expect(patchPayload).not.toBeNull();
    expect(patchPayload.status).toBe('INVESTIGATING');
    expect(patchPayload.triageNotes).toBe(noteText);
  });

  test('open Containment modal, specify TTL and justification, and assert POST payload with safety guarantee', async ({ page }) => {
    const blockBtn = page.getByRole('button', { name: 'Block' }).first();
    await expect(blockBtn).toBeVisible();
    await blockBtn.click();

    // Verify Modal opens
    const modalDialog = page.getByRole('dialog');
    await expect(modalDialog).toBeVisible();
    await expect(modalDialog.getByText(/CONTAINMENT VERIFICATION/i)).toBeVisible();

    // Safety intercept on POST /api/containment/actions
    let containmentPayload = null;
    await page.route('**/api/containment/actions', async (route) => {
      if (route.request().method() === 'POST') {
        containmentPayload = JSON.parse(route.request().postData() || '{}');
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            success: true,
            data: {
              actionId: 'action-test-uuid',
              status: 'CONTAINED',
              target: containmentPayload.target,
              durationSeconds: containmentPayload.durationSeconds,
            },
          }),
        });
      } else {
        await route.continue();
      }
    });

    // Select TTL (e.g., 24 Hours)
    await page.locator('#containment-duration').selectOption('86400');

    // Enter operator reason
    const reasonText = 'E2E automated active containment response check';
    await page.locator('#containment-reason').fill(reasonText);

    // Confirm containment
    await page.getByRole('button', { name: 'Confirm Containment' }).click();

    // Assert success toast appears
    const successToast = page.locator('.hot-toast-bar, [role="status"]').filter({ hasText: /Simulated containment recorded/i });
    await expect(successToast.first()).toBeVisible();

    // Assert Modal closed
    await expect(modalDialog).not.toBeVisible();

    // Assert POST payload matches
    expect(containmentPayload).not.toBeNull();
    expect(containmentPayload.actionType).toBe('block_ip');
    expect(containmentPayload.durationSeconds).toBe(86400);
    expect(containmentPayload.isPermanent).toBe(false);
    expect(containmentPayload.reason).toBe(reasonText);
    expect(typeof containmentPayload.target).toBe('string');
  });
});
