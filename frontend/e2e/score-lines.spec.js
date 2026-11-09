import { test, expect } from './fixtures/auth.fixture.js';
import { SEEDED_USERS } from './global-setup.js';

// THR-002 / THR-003: score colours and the live feed use the alert/block lines the backend scores with
// (GET /api/ai/score-lines: 0.90 / 0.92 by default, the engine's ALERT_THRESHOLD / BLOCK_THRESHOLD when overridden).
// Seeded threats (global-setup.js): 45.95.147.22 scored 0.82 (INVESTIGATING), 194.165.16.78 scored 0.79,
// 212.102.39.212 scored 0.62 (DETECTED). A manual block leaves analyst triage states such as INVESTIGATING alone.
const ORIGIN = 'http://127.0.0.1:3000';
const BLUE = 'rgb(0, 212, 255)';
const AMBER = 'rgb(255, 170, 0)';
const OVERRIDE = { alert: 0.8, block: 0.85 }; // an engine started with ALERT_THRESHOLD=0.80 BLOCK_THRESHOLD=0.85

const overrideLines = (page) =>
  page.route('**/api/ai/score-lines', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, data: OVERRIDE }) })
  );

const scoreCell = (page, ip, pct) =>
  page.locator('.sentinel-table-scroll tbody tr').filter({ hasText: ip }).locator('td', { hasText: new RegExp(`^${pct}%$`) });

async function openThreatLogs(page, loginAs) {
  await loginAs('analyst');
  await page.goto('/dashboard/threats');
  await expect(page.locator('.sentinel-table-scroll tbody tr').first()).toBeVisible();
}

/** Filters Threat Logs to one seeded address: other specs add threats, so it may not be on the first page. */
async function searchThreat(page, ip) {
  const searched = page.waitForResponse((r) => r.url().includes('/api/threats?') && r.url().includes(`search=${ip}`));
  const box = page.getByPlaceholder('Search IP, type...');
  await box.fill(ip);
  await box.press('Enter'); // Threat Logs searches on Enter
  await searched;
  await expect(page.locator('.sentinel-table-scroll tbody tr').filter({ hasText: ip }).first()).toBeVisible();
}

/** A server event delivered through the dashboard's real Socket.IO client (same path as a backend emit). */
const injectEvent = (page, event, payload) =>
  page.evaluate(([e, p]) => window.__socket.onpacket({ type: 2, nsp: '/', data: [e, p] }), [event, payload]);

/**
 * Pages subscribe to socket events only after their own connected state renders, so the first event can arrive before
 * anyone listens. Re-send until `shown` is visible (repeats are harmless: the check is "at least one").
 */
async function injectUntilShown(page, event, payload, shown) {
  await expect(async () => {
    await injectEvent(page, event, payload);
    await expect(shown.first()).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 15000 });
}

async function waitForSocket(page) {
  await expect.poll(() => page.evaluate(() => window.__socket?.connected), { timeout: 10000 }).toBe(true);
}

const prediction = (sourceIP, threatScore) => ({
  _id: `e2e-${sourceIP}-${threatScore}`,
  sourceIP,
  threatScore,
  predictedClass: 'DDoS',
  action: threatScore >= 0.9 ? 'MONITOR' : 'ALLOW',
});

test.describe('Score lines follow the backend (THR-002 / THR-003)', () => {
  test('Threat Logs colours use the backend defaults: 0.82 is below the 0.90 alert line', async ({ page, loginAs }) => {
    const lines = page.waitForResponse((r) => r.url().includes('/api/ai/score-lines') && r.status() === 200);
    await openThreatLogs(page, loginAs);
    // No AI engine runs in the E2E stack: the backend reports its defaults, labelled as such (THR-004)
    expect((await (await lines).json()).data).toEqual({ alert: 0.9, block: 0.92, source: 'default', confirmedAt: null });
    await searchThreat(page, '45.95.147.22');
    await expect(scoreCell(page, '45.95.147.22', 82)).toHaveCSS('color', BLUE);
  });

  test('with an overridden alert line the same threat is coloured as an alert', async ({ page, loginAs }) => {
    await overrideLines(page);
    await openThreatLogs(page, loginAs);
    await searchThreat(page, '45.95.147.22');
    await expect(scoreCell(page, '45.95.147.22', 82)).toHaveCSS('color', AMBER);
    await searchThreat(page, '194.165.16.78');
    await expect(scoreCell(page, '194.165.16.78', 79)).toHaveCSS('color', BLUE);
  });

  test('Live Feed lists AI predictions from the alert line only', async ({ page, loginAs }) => {
    await loginAs('analyst');
    await page.goto('/dashboard');
    const feed = page.locator('[data-sentinel-panel]').filter({ hasText: 'Live Attack Feed' });
    await expect(feed).toBeVisible();
    await waitForSocket(page);
    const ip = (n) => feed.getByText(`198.51.100.${n}`, { exact: true });
    await injectUntilShown(page, 'ai_prediction', prediction('198.51.100.212', 0.95), ip(212)); // listener is live
    // Events are handled in order: once the 0.96 marker is shown, the 0.85 prediction sent before it was processed
    await injectEvent(page, 'ai_prediction', prediction('198.51.100.211', 0.85));
    await injectEvent(page, 'ai_prediction', prediction('198.51.100.215', 0.96));
    await expect(ip(215)).toHaveCount(1);
    await expect(ip(211)).toHaveCount(0);
  });

  test('Live Feed follows an overridden alert line', async ({ page, loginAs }) => {
    await overrideLines(page);
    await loginAs('analyst');
    await page.goto('/dashboard');
    const feed = page.locator('[data-sentinel-panel]').filter({ hasText: 'Live Attack Feed' });
    await waitForSocket(page);
    // 0.82 is below the default 0.90 line: it can only appear once the overridden lines have loaded
    await injectUntilShown(page, 'ai_prediction', prediction('198.51.100.213', 0.82), feed.getByText('198.51.100.213', { exact: true }));
  });

  test('AI Analytics inference log colours a live prediction by the backend lines', async ({ page, loginAs }) => {
    await overrideLines(page);
    await loginAs('analyst');
    await page.goto('/dashboard/ai');
    await waitForSocket(page);
    const line = page.getByText(/\[INFER\] 198\.51\.100\.214 → score=82%/).first();
    await injectUntilShown(page, 'ai_prediction', prediction('198.51.100.214', 0.82), line);
    await expect(line).toHaveCSS('color', AMBER);
  });

  test('block then unblock restores the threat to its own pre-block status', async ({ page, loginAs, request }) => {
    const csrfFor = async () =>
      (await (await request.get('/api/auth/csrf', { headers: { Origin: ORIGIN } })).json()).data.csrfToken;
    const login = await request.post('/api/auth/login', {
      data: { email: SEEDED_USERS.admin.email, password: SEEDED_USERS.admin.password },
      headers: { 'X-CSRF-Token': await csrfFor(), Origin: ORIGIN },
    });
    expect(login.ok()).toBe(true);
    const token = (await login.json()).data.token;
    const headers = async () => ({ Authorization: `Bearer ${token}`, 'X-CSRF-Token': await csrfFor(), Origin: ORIGIN });
    const call = async (path, body) => request.post(path, { data: body, headers: await headers() });
    const ip = '212.102.39.212';
    const blocked = await call('/api/threats/block-ip', { ip, reason: 'E2E score-lines restore check' });
    expect(blocked.status(), await blocked.text()).toBeLessThan(300);
    const row = page.locator('.sentinel-table-scroll tbody tr').filter({ hasText: ip });
    try {
      await openThreatLogs(page, loginAs);
      await searchThreat(page, ip);
      await expect(row.getByText('BLOCKED', { exact: true })).toBeVisible();
    } finally {
      const unblocked = await call('/api/threats/unblock-ip', { ip });
      expect(unblocked.status(), await unblocked.text()).toBeLessThan(300);
      // Block and unblock each raise an alert; mark them read so the shared unread count other specs assert on
      // (realtime alert-bell test) is unchanged by this spec.
      const list = await request.get('/api/alerts?limit=100&isRead=false', { headers: await headers() });
      for (const a of (await list.json()).data || []) {
        if (typeof a.message === 'string' && a.message.includes(ip)) {
          await request.put(`/api/alerts/${a._id}/read`, { headers: await headers() });
        }
      }
    }
    await page.reload();
    await searchThreat(page, ip);
    await expect(row.getByText('DETECTED', { exact: true })).toBeVisible();
  });
});
