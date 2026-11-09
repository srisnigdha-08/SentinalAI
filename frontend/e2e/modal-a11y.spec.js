import { test, expect } from './fixtures/auth.fixture.js';

test.describe('Modal Accessibility & Focus Trap (WAI-ARIA)', () => {
  test.beforeEach(async ({ loginAs, page }) => {
    await loginAs('analyst');
    await page.goto('/dashboard/threats');
    await expect(page).toHaveURL(/\/dashboard\/threats$/);
    await expect(page.locator('.sentinel-table-scroll table tbody tr').first()).toBeVisible();
  });

  test('Triage modal satisfies WAI-ARIA dialog attributes, focus trapping, scroll locking, Escape closing, and focus restoration', async ({ page }) => {
    const triageBtn = page.getByRole('button', { name: 'Triage' }).first();
    await triageBtn.focus();
    await triageBtn.press('Enter');

    // 1. Assert role="dialog" and aria-modal="true"
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAttribute('aria-modal', 'true');

    // 2. Assert body scroll lock is applied
    const isScrollLocked = await page.evaluate(() => document.body.style.overflow === 'hidden');
    expect(isScrollLocked).toBe(true);

    // 3. Assert initial focus is placed inside dialog
    await expect.poll(async () => {
      return page.evaluate(() => {
        const active = document.activeElement;
        const dialogEl = document.querySelector('[role="dialog"]');
        return Boolean(dialogEl && dialogEl.contains(active));
      });
    }).toBe(true);

    // 4. Assert Focus Trap (Tab and Shift+Tab)
    const focusableSelectors = 'button:not([disabled]), select:not([disabled]), textarea:not([disabled]), input:not([disabled])';
    const focusableElements = dialog.locator(focusableSelectors);
    const count = await focusableElements.count();
    expect(count).toBeGreaterThan(1);

    const firstElement = focusableElements.first();
    const lastElement = focusableElements.last();

    // Focus last element and press Tab -> should wrap to first element
    await lastElement.focus();
    await page.keyboard.press('Tab');
    const isFirstFocused = await firstElement.evaluate((el) => el === document.activeElement);
    expect(isFirstFocused).toBe(true);

    // Press Shift+Tab from first element -> should wrap to last element
    await page.keyboard.press('Shift+Tab');
    const isLastFocused = await lastElement.evaluate((el) => el === document.activeElement);
    expect(isLastFocused).toBe(true);

    // 5. Assert Escape key closes the modal
    await page.keyboard.press('Escape');
    await expect(dialog).not.toBeVisible();

    // 6. Assert body scroll is restored
    const isScrollRestored = await page.evaluate(() => document.body.style.overflow !== 'hidden');
    expect(isScrollRestored).toBe(true);

    // 7. Assert focus returns to triggering button
    await expect(triageBtn).toBeFocused();
  });

  test('Containment modal satisfies WAI-ARIA dialog attributes, focus trapping, scroll locking, Escape closing, and focus restoration', async ({ page }) => {
    const blockBtn = page.getByRole('button', { name: 'Block' }).first();
    await blockBtn.focus();
    await blockBtn.press('Enter');

    // 1. Assert role="dialog" and aria-modal="true"
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAttribute('aria-modal', 'true');

    // 2. Assert body scroll lock is applied
    const isScrollLocked = await page.evaluate(() => document.body.style.overflow === 'hidden');
    expect(isScrollLocked).toBe(true);

    // 3. Assert initial focus inside dialog
    await expect.poll(async () => {
      return page.evaluate(() => {
        const active = document.activeElement;
        const dialogEl = document.querySelector('[role="dialog"]');
        return Boolean(dialogEl && dialogEl.contains(active));
      });
    }).toBe(true);

    // 4. Assert Focus Trap (Tab and Shift+Tab)
    const focusableSelectors = 'button:not([disabled]), select:not([disabled]), input:not([disabled])';
    const focusableElements = dialog.locator(focusableSelectors);
    const count = await focusableElements.count();
    expect(count).toBeGreaterThan(1);

    const firstElement = focusableElements.first();
    const lastElement = focusableElements.last();

    // Focus last element and press Tab -> wraps to first
    await lastElement.focus();
    await page.keyboard.press('Tab');
    const isFirstFocused = await firstElement.evaluate((el) => el === document.activeElement);
    expect(isFirstFocused).toBe(true);

    // Press Shift+Tab -> wraps to last
    await page.keyboard.press('Shift+Tab');
    const isLastFocused = await lastElement.evaluate((el) => el === document.activeElement);
    expect(isLastFocused).toBe(true);

    // 5. Assert Escape key closes the modal
    await page.keyboard.press('Escape');
    await expect(dialog).not.toBeVisible();

    // 6. Assert body scroll is restored
    const isScrollRestored = await page.evaluate(() => document.body.style.overflow !== 'hidden');
    expect(isScrollRestored).toBe(true);

    // 7. Assert focus returns to triggering button
    await expect(blockBtn).toBeFocused();
  });
});
