import { test, expect } from './fixtures/auth.fixture.js';

// XAI-001 UI: the per-threat explanation. The seeded test database has no stored predictions, so the threat list is
// given one predictionId and the explanation endpoint is mocked here; the real stored-vector path (engine re-scoring
// and reproduction check) is covered by backend tests and the integration harness.

const EXPLANATION = {
  threatId: 'x',
  predictionId: 'p1',
  predictedAt: '2026-11-03T10:00:00.000Z',
  modelVersion: 'xgb_cicids_v1',
  featureSchemaVersion: 'v2.1_53feat',
  predictedClass: 'DDoS',
  explainedClass: 'DDoS',
  threatScore: 0.9731,
  confidence: 0.9731,
  baseValue: -0.2,
  reproduced: true,
  contributions: [
    { feature: 'init_win_bytes_forward', contribution: 2.1, value: 8192 },
    { feature: 'bwd_packet_len_max', contribution: 0.9, value: 1460 },
    { feature: 'flow_duration', contribution: -0.4, value: 1200 },
  ],
};

async function withOnePredictionLinkedThreat(page) {
  await page.route(/\/api\/threats(\?|$)/, async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const res = await route.fetch();
    const body = await res.json();
    if (Array.isArray(body.data) && body.data.length) body.data[0] = { ...body.data[0], predictionId: 'p1' };
    await route.fulfill({ response: res, json: body });
  });
}

test.describe('Threat explanation (SHAP)', () => {
  test('analyst opens an explanation: class, confidence, score, model, chart and guidance', async ({ loginAs, page }) => {
    await withOnePredictionLinkedThreat(page);
    let calls = 0;
    await page.route('**/api/threats/*/explanation', (route) => {
      calls += 1;
      return route.fulfill({ status: 200, json: { success: true, data: EXPLANATION } });
    });
    await loginAs('analyst');
    await page.goto('/dashboard/threats');

    const explainButtons = page.getByRole('button', { name: 'Explain' });
    await expect(explainButtons).toHaveCount(1); // only the threat with a stored prediction offers it
    await explainButtons.first().click();

    const dialog = page.getByRole('dialog');
    const panel = dialog.getByTestId('explanation');
    await expect(panel).toBeVisible();
    await expect(panel.getByText('xgb_cicids_v1', { exact: true })).toBeVisible();
    await expect(panel.getByText('97.3%', { exact: true })).toBeVisible();
    await expect(panel.getByText('0.9731', { exact: true })).toBeVisible();
    await expect(panel.getByText(/chose DDoS with 97\.3% confidence/)).toBeVisible();
    await expect(panel.getByText(/explain the XGBoost classifier only/)).toBeVisible();
    await expect(panel.locator('.recharts-bar-rectangle')).toHaveCount(3);
    // React.StrictMode mounts effects twice in development (2 requests, the first response is ignored); the point
    // is that the modal does not keep re-fetching once it has rendered.
    const settled = calls;
    expect(settled).toBeLessThanOrEqual(2);
    await page.waitForTimeout(1000);
    expect(calls).toBe(settled);

    await dialog.getByRole('button', { name: /close/i }).first().click();
    await expect(dialog).not.toBeVisible();
  });

  test('a refused explanation shows its reason and no chart', async ({ loginAs, page }) => {
    await withOnePredictionLinkedThreat(page);
    await page.route('**/api/threats/*/explanation', (route) =>
      route.fulfill({
        status: 409,
        json: { success: false, error: 'x', code: 409, errors: { reason: 'MODEL_VERSION_MISMATCH' } },
      }));
    await loginAs('analyst');
    await page.goto('/dashboard/threats');
    await page.getByRole('button', { name: 'Explain' }).first().click();

    const err = page.getByRole('dialog').getByTestId('explanation-error');
    await expect(err).toContainText('different model');
    await expect(page.getByRole('dialog').getByTestId('explanation')).toHaveCount(0);
    await expect(err.getByRole('button', { name: 'TRY AGAIN' })).toHaveCount(0); // not retryable
  });

  test('viewers are not offered explanations', async ({ loginAs, page }) => {
    await withOnePredictionLinkedThreat(page);
    await loginAs('viewer');
    await page.goto('/dashboard/threats');
    await expect(page.locator('.sentinel-table-scroll table tbody tr').first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Explain' })).toHaveCount(0);
  });
});
