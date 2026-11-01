import { test, expect, SEEDED_USERS } from './fixtures/auth.fixture.js';
import { restoreSeededUser } from './global-setup.js';

test.describe('MustChangePassword Workflow', () => {
  // The last test changes the seeded password; the next browser project needs the original back.
  test.afterAll(async () => {
    await restoreSeededUser('mustChange');
  });

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

test.describe('Voluntary password change (SEC-001 remediation path)', () => {
  // Changes the seeded analyst's password; later specs and browser projects need the original back.
  test.afterAll(async () => {
    await restoreSeededUser('analyst');
  });

  test('a signed-in user opens Change password from the sidebar, changes it, and only the new password works', async ({ page, loginPage, changePasswordPage }) => {
    const analyst = SEEDED_USERS.analyst;
    await loginPage.goto();
    await loginPage.login(analyst.email, analyst.password);
    await expect(page).toHaveURL(/\/dashboard$/);

    await page.getByRole('button', { name: 'CHANGE PASSWORD' }).click();
    await expect(page).toHaveURL(/\/change-password$/);
    await expect(page.getByText('CHANGE PASSWORD', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toBeVisible(); // not "Cancel & Sign Out"

    const newPass = 'VoluntaryRotation123!';
    await changePasswordPage.changePassword(analyst.password, newPass, newPass);
    await expect(page).toHaveURL(/\/dashboard$/);

    await page.getByRole('button', { name: 'LOGOUT', exact: true }).click();
    await loginPage.goto();
    await loginPage.login(analyst.email, analyst.password); // the old password
    await expect(page.locator('.hot-toast-bar, [role="status"], [role="alert"]').filter({ hasText: /Login failed|Invalid credentials|Unauthorized/i }).first()).toBeVisible();
    await expect(page).toHaveURL(/\/login/);
    await loginPage.login(analyst.email, newPass);
    await expect(page).toHaveURL(/\/dashboard$/);
  });
});
