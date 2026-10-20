import { test, expect, SEEDED_USERS } from './fixtures/auth.fixture.js';

test.describe('MustChangePassword Workflow', () => {
  test('mustChangePassword user is forced to /change-password from any protected route', async ({ page, loginPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.mustChange.email, SEEDED_USERS.mustChange.password);
    await expect(page).toHaveURL(/\/change-password$/);

    // Attempting to navigate directly to /dashboard or /dashboard/threats redirects back to /change-password
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/change-password$/);

    await page.goto('/dashboard/threats');
    await expect(page).toHaveURL(/\/change-password$/);
  });

  test('form validation enforces length (8-128), mismatch, and difference from current', async ({ page, loginPage, changePasswordPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.mustChange.email, SEEDED_USERS.mustChange.password);
    await expect(page).toHaveURL(/\/change-password$/);

    // 1. Missing current password
    await changePasswordPage.changePassword('', 'NewPass123!', 'NewPass123!');
    await expect(changePasswordPage.errorAlert).toContainText(/Current password is required/i);

    // 2. Short new password (< 8 chars)
    await changePasswordPage.changePassword(SEEDED_USERS.mustChange.password, 'Short1', 'Short1');
    await expect(changePasswordPage.errorAlert).toContainText(/at least 8 characters/i);

    // 3. Passwords mismatch
    await changePasswordPage.changePassword(SEEDED_USERS.mustChange.password, 'ValidPassword123!', 'MismatchPassword123!');
    await expect(changePasswordPage.errorAlert).toContainText(/do not match/i);

    // 4. Same as current password
    await changePasswordPage.changePassword(SEEDED_USERS.mustChange.password, SEEDED_USERS.mustChange.password, SEEDED_USERS.mustChange.password);
    await expect(changePasswordPage.errorAlert).toContainText(/different from current password/i);
  });

  test('double-submit guard sends exactly one PUT request', async ({ page, loginPage, changePasswordPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.mustChange.email, SEEDED_USERS.mustChange.password);
    await expect(page).toHaveURL(/\/change-password$/);

    let putRequestCount = 0;
    await page.route('**/api/auth/update-password', async (route) => {
      putRequestCount++;
      await new Promise((r) => setTimeout(r, 600));
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            token: 'mock-token',
            user: { ...SEEDED_USERS.mustChange, mustChangePassword: false },
          },
        }),
      });
    });

    const newPass = 'ValidNewPassword123!';
    await changePasswordPage.currentPasswordInput.fill(SEEDED_USERS.mustChange.password);
    await changePasswordPage.newPasswordInput.fill(newPass);
    await changePasswordPage.confirmPasswordInput.fill(newPass);

    const submitBtn = changePasswordPage.submitButton;
    await Promise.all([
      submitBtn.click({ clickCount: 1 }),
      submitBtn.click({ clickCount: 1 }).catch(() => {}),
    ]);

    await expect(page).toHaveURL(/\/dashboard$/);
    expect(putRequestCount).toBe(1);
  });

  test('successful password change transitions operator to /dashboard with cleared restriction', async ({ page, loginPage, changePasswordPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.mustChange.email, SEEDED_USERS.mustChange.password);
    await expect(page).toHaveURL(/\/change-password$/);

    const newPass = 'UpdatedSecurePassword123!';
    await changePasswordPage.changePassword(SEEDED_USERS.mustChange.password, newPass, newPass);
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.locator('.sentinel-sidebar')).toContainText(SEEDED_USERS.mustChange.email);
  });
});
