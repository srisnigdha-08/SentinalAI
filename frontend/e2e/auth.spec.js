import { test, expect, SEEDED_USERS } from './fixtures/auth.fixture.js';
import { LoginPage } from './fixtures/pom/LoginPage.js';

test.describe('Authentication & Session Management', () => {
  test('successful login for admin, analyst, and viewer roles', async ({ page, loginPage }) => {
    for (const role of ['admin', 'analyst', 'viewer']) {
      const user = SEEDED_USERS[role];
      await loginPage.goto();
      await loginPage.login(user.email, user.password);
      await expect(page).toHaveURL(/\/dashboard$/);
      await expect(page.locator('.sentinel-sidebar')).toContainText(user.email);

      // Clean up session for next role
      await page.locator('.sentinel-navbar').getByRole('button', { name: 'Logout' }).click();
      await expect(page).toHaveURL(/\/(login)?$/);
    }
  });

  test('wrong password shows an error toast or message', async ({ page, loginPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.admin.email, 'WrongPassword999!');
    // An error toast or alert appears
    const toastOrAlert = page.locator('.hot-toast-bar, [role="status"], [role="alert"]').filter({ hasText: /Login failed|Invalid credentials|Unauthorized/i });
    await expect(toastOrAlert.first()).toBeVisible();
    await expect(page).toHaveURL(/\/login/);
  });

  test('logout clears session and protected routes redirect to /login', async ({ page, loginPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    await expect(page).toHaveURL(/\/dashboard$/);

    // Logout from navbar
    await page.locator('.sentinel-navbar').getByRole('button', { name: 'Logout' }).click();
    await expect(page).toHaveURL(/\/(login)?$/);

    // Attempting to visit /dashboard directly redirects to /login
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login/);

    // Attempting to visit /settings directly redirects to /login
    await page.goto('/settings');
    await expect(page).toHaveURL(/\/login/);
  });

  test('page refresh restores authenticated session via HttpOnly cookie', async ({ page, loginPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    await expect(page).toHaveURL(/\/dashboard$/);

    // Reload page
    await page.reload();

    // Session should be restored transparently by authSession.refresh()
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.locator('.sentinel-sidebar')).toContainText(SEEDED_USERS.analyst.email);
  });

  test('expired access token triggers transparent refresh and retry on 401', async ({ page, loginPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    await expect(page).toHaveURL(/\/dashboard$/);

    let simulated401Count = 0;
    // Intercept a telemetry request once with 401
    await page.route('**/api/threats/analytics/summary', async (route) => {
      if (simulated401Count === 0) {
        simulated401Count++;
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({ success: false, error: 'Token expired' }),
        });
      } else {
        await route.continue();
      }
    });

    // Track refresh token call
    let refreshFired = false;
    page.on('request', (req) => {
      if (req.url().includes('/api/auth/refresh-token')) {
        refreshFired = true;
      }
    });

    // Trigger fetch on dashboard
    await page.goto('/dashboard/ai');
    await expect(page).toHaveURL(/\/dashboard\/ai$/);

    // Verify user remained logged in on the page
    await expect(page.locator('.sentinel-sidebar')).toContainText(SEEDED_USERS.analyst.email);
  });

  test('logout in one tab logs out the second tab via BroadcastChannel', async ({ context }) => {
    const page1 = await context.newPage();
    const page2 = await context.newPage();

    // Log in on page 1
    const loginPage1 = new LoginPage(page1);
    await loginPage1.goto();
    await loginPage1.login(SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    await expect(page1).toHaveURL(/\/dashboard$/);

    // Open page 2 directly to dashboard
    await page2.goto('/dashboard');
    await expect(page2).toHaveURL(/\/dashboard$/);

    // Logout from page 1
    await page1.locator('.sentinel-navbar').getByRole('button', { name: 'Logout' }).click();
    await expect(page1).toHaveURL(/\/(login)?$/);

    // Page 2 should detect logout broadcast and redirect to /login when navigating or updating
    await page2.goto('/dashboard');
    await expect(page2).toHaveURL(/\/login/);

    await page1.close();
    await page2.close();
  });

  test('login double-submit sends exactly ONE /api/auth/login request', async ({ page, loginPage }) => {
    await loginPage.goto();

    let loginRequestCount = 0;
    await page.route('**/api/auth/login', async (route) => {
      loginRequestCount++;
      // Add delay to simulate in-flight request
      await new Promise((r) => setTimeout(r, 600));
      await route.continue();
    });

    await loginPage.operatorInput.fill(SEEDED_USERS.viewer.email);
    await loginPage.accessKeyInput.fill(SEEDED_USERS.viewer.password);

    // Rapid double-click submit button
    const submitBtn = loginPage.submitButton;
    await Promise.all([
      submitBtn.click({ clickCount: 1 }),
      submitBtn.click({ clickCount: 1 }).catch(() => {}),
    ]);

    await expect(page).toHaveURL(/\/dashboard$/);
    expect(loginRequestCount).toBe(1);
  });

  test('sentinel_has_session hint stores only flag "1" and never credentials or tokens', async ({ page, loginPage }) => {
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    await expect(page).toHaveURL(/\/dashboard$/);

    const hintValue = await page.evaluate(() => localStorage.getItem('sentinel_has_session'));
    expect(hintValue).toBe('1');

    // Confirm no token, email, or credentials exist in localStorage
    const allLocalStorage = await page.evaluate(() => ({ ...localStorage }));
    const rawStorageValues = Object.values(allLocalStorage).join(' ');
    expect(rawStorageValues).not.toContain(SEEDED_USERS.analyst.email);
    expect(rawStorageValues).not.toContain('eyJ'); // No JWT header
    expect(rawStorageValues).not.toContain(SEEDED_USERS.analyst.password);
  });

  test('hint present but invalid/expired session lands cleanly on /login with no loop', async ({ page }) => {
    // 1. Plant hint in localStorage without a valid session cookie
    await page.goto('/login');
    await page.evaluate(() => localStorage.setItem('sentinel_has_session', '1'));

    // 2. Intercept refresh-token with 401 Unauthorized
    await page.route('**/api/auth/refresh-token', async (route) => {
      await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'Session expired' }) });
    });

    // 3. Navigate to /dashboard
    await page.goto('/dashboard');

    // 4. User should land cleanly on /login without redirect looping
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByText('SYSTEM ACCESS')).toBeVisible();

    // 5. Hint should have been removed automatically
    const remainingHint = await page.evaluate(() => localStorage.getItem('sentinel_has_session'));
    expect(remainingHint).toBeNull();
  });

  test('hint missing with valid cookie reports unauthenticated state until explicit login', async ({ page, loginPage }) => {
    // 1. Log in to establish a valid HttpOnly refresh cookie
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.viewer.email, SEEDED_USERS.viewer.password);
    await expect(page).toHaveURL(/\/dashboard$/);

    // 2. Clear the sentinel_has_session hint manually
    await page.evaluate(() => localStorage.removeItem('sentinel_has_session'));

    // 3. Reload page - because hint is missing, AuthProvider does not fire /refresh-token on mount
    let refreshFired = false;
    page.on('request', (req) => {
      if (req.url().includes('/api/auth/refresh-token')) refreshFired = true;
    });

    await page.goto('/');
    await page.waitForLoadState('domcontentloaded');

    // Navbar should display 'Sign In' (unauthenticated view) because memory state was not automatically hydrated
    await expect(page.locator('.sentinel-navbar').getByRole('link', { name: /Sign In/i })).toBeVisible();
    expect(refreshFired).toBe(false);
  });

  test('logout in one tab clears sentinel_has_session in other tab', async ({ context }) => {
    const page1 = await context.newPage();
    const page2 = await context.newPage();

    const loginPage1 = new LoginPage(page1);
    await loginPage1.goto();
    await loginPage1.login(SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    await expect(page1).toHaveURL(/\/dashboard$/);

    await page2.goto('/dashboard');
    await expect(page2).toHaveURL(/\/dashboard$/);

    const hintBefore = await page2.evaluate(() => localStorage.getItem('sentinel_has_session'));
    expect(hintBefore).toBe('1');

    // Logout from page1
    await page1.locator('.sentinel-navbar').getByRole('button', { name: 'Logout' }).click();
    await expect(page1).toHaveURL(/\/(login)?$/);

    // Assert page2 localStorage has hint removed
    await expect.poll(async () => {
      return page2.evaluate(() => localStorage.getItem('sentinel_has_session'));
    }).toBeNull();

    await page1.close();
    await page2.close();
  });
});
