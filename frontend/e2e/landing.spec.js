import { test, expect } from './fixtures/auth.fixture.js';

test.describe('Public Landing Page', () => {
  test('unauthenticated visit to / generates ZERO 401 responses, renders capability tiles (no invented figures), and produces no console errors', async ({ page }) => {
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

    // 3. Anonymous visitors see capability descriptions, not sample statistics
    const tiles = page.getByTestId('capability-tile');
    await expect(tiles).toHaveCount(4);
    for (const label of ['Explainable Detection', 'Recorded Traffic Replay', 'MITRE Mapping', 'Simulated Containment']) {
      await expect(tiles.filter({ hasText: label })).toHaveCount(1);
    }

    // 4. No invented counters: the old sample figures and the operator-only counter labels are gone
    await expect(page.getByText(/Sample data/i)).toHaveCount(0);
    await expect(page.getByText('Test-split Accuracy')).toHaveCount(0);
    const tileText = (await tiles.allTextContents()).join(' ');
    for (const figure of ['2,341', '14,823', '312', '94%']) expect(tileText).not.toContain(figure);

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
