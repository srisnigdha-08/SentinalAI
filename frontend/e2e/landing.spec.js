import { test, expect } from './fixtures/auth.fixture.js';

test.describe('Public Landing Page', () => {
  test('unauthenticated visit to / generates ZERO 401 responses, renders showcase counters, and produces no console errors', async ({ page }) => {
    const error401Responses = [];
    const consoleErrors = [];

    page.on('response', (response) => {
      if (response.status() === 401) {
        error401Responses.push(response.url());
      }
    });

    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.goto('/');

    // 1. Assert ZERO 401 responses were captured
    expect(error401Responses).toEqual([]);

    // 2. Assert hero section and title are visible
    await expect(page.getByText(/AUTONOMOUS CYBER DEFENCE PLATFORM/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /Launch SOC Console/i })).toBeVisible();

    // 3. Assert showcase metric counter labels are visible
    await expect(page.getByText('Threats Blocked')).toBeVisible();
    await expect(page.getByText('Attacks Analyzed')).toBeVisible();
    await expect(page.getByText('Honeypot Sessions')).toBeVisible();
    await expect(page.getByText('AI Accuracy')).toBeVisible();

    // 3b. Assert "Sample data" disclosure label is visible for unauthenticated visitors
    await expect(page.getByText(/Sample data/i)).toBeVisible();

    // 4. Assert counters animate to non-zero values
    await expect.poll(async () => {
      const texts = await page.locator('div[style*="fontFamily: Orbitron"], div[style*="font-family: Orbitron"]').allTextContents();
      return texts.some((t) => t.includes('2,341') || t.includes('14,823') || t.includes('94%') || parseInt(t.replace(/\D/g, ''), 10) > 0);
    }, { timeout: 5000 }).toBe(true);

    // 5. Assert no fatal console errors occurred
    const fatalErrors = consoleErrors.filter(err => !err.includes('favicon') && !err.includes('404'));
    expect(fatalErrors).toEqual([]);
  });

  test('clicking Launch SOC Console redirects unauthenticated visitor to /login', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: /Launch SOC Console/i }).click();
    await expect(page).toHaveURL(/\/login/);
  });
});
