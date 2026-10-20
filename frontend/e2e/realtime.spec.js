import { test, expect } from './fixtures/auth.fixture.js';

test.describe('Real-Time Socket Telemetry & Connection Resilience', () => {
  test.beforeEach(async ({ loginAs, page }) => {
    await loginAs('analyst');
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/dashboard$/);

    // Wait until socket is connected
    await expect.poll(async () => {
      return page.evaluate(() => window.__socket?.connected);
    }, { timeout: 10000 }).toBe(true);

    // Wait for initial dashboard widgets to render
    await expect(page.locator('[data-sentinel-panel]').filter({ hasText: 'Live Attack Feed' })).toBeVisible();
  });

  test('new_threat socket emission updates live feed without page reload', async ({ page, request }) => {
    const testThreatIP = '198.51.100.77';
    const testAttackType = 'RCE Attempt';

    // 1. Emit new_threat via test backend helper
    const res = await request.post('http://127.0.0.1:5000/api/test/emit-socket', {
      data: {
        event: 'new_threat',
        data: {
          _id: 'socket-test-threat-' + Date.now(),
          sourceIP: testThreatIP,
          attackType: testAttackType,
          severity: 'CRITICAL',
          targetService: 'HTTPS:8443',
          aiScore: 0.95,
          createdAt: new Date().toISOString(),
        },
      },
    });
    expect(res.ok()).toBe(true);

    // 2. Assert live attack feed displays new threat without page reload
    const liveFeedPanel = page.locator('[data-sentinel-panel]').filter({ hasText: 'Live Attack Feed' });
    await expect(liveFeedPanel.getByText(testThreatIP)).toBeVisible({ timeout: 10000 });
    await expect(liveFeedPanel.getByText(new RegExp(`${testAttackType} detected.*95%`, 'i'))).toBeVisible();
  });

  test('new_alert socket emission updates alert bell unread badge without reload', async ({ page, request }) => {
    const bellBtn = page.getByRole('button', { name: /🔔/i });
    await expect(bellBtn).toBeVisible();

    // 1. Wait for initial alerts count to load
    await expect(bellBtn).toHaveText(/🔔\s*\d+/, { timeout: 10000 });
    const initialText = await bellBtn.innerText();
    const initialCount = parseInt(initialText.replace(/\D/g, '') || '0', 10);

    // 2. Emit new_alert via test backend helper
    const alertTitle = 'Autonomous Containment Triggered';
    const res = await request.post('http://127.0.0.1:5000/api/test/emit-socket', {
      data: {
        event: 'new_alert',
        data: {
          _id: 'socket-test-alert-' + Date.now(),
          title: alertTitle,
          message: 'Anomalous exfiltration vector neutralized automatically',
          severity: 'HIGH',
          createdAt: new Date().toISOString(),
        },
      },
    });
    expect(res.ok()).toBe(true);

    // 3. Assert unread count badge increments by 1 without reload
    const expectedCount = initialCount + 1;
    await expect(bellBtn).toHaveText(new RegExp(`🔔\\s*${expectedCount}`), { timeout: 10000 });

    // 4. Open alert dropdown and verify alert is listed inside navbar dropdown
    await bellBtn.click();
    await expect(page.locator('.sentinel-navbar').getByText(alertTitle)).toBeVisible();
  });

  test('socket disconnect displays ConnectionStatus pill and reconnect clears it', async ({ page }) => {
    // 1. Verify ConnectionStatus pill is initially absent while connected
    const statusPill = page.locator('text=REAL-TIME FEED DISCONNECTED');
    await expect(statusPill).toHaveCount(0);

    // 2. Simulate disconnect
    await page.evaluate(() => {
      window.__socket?.disconnect();
    });

    // 3. Assert ConnectionStatus pill appears
    await expect(statusPill).toBeVisible({ timeout: 5000 });

    // 4. Simulate reconnect
    await page.evaluate(() => {
      window.__socket?.connect();
    });

    // 5. Assert ConnectionStatus pill disappears after reconnection
    await expect(statusPill).not.toBeVisible({ timeout: 10000 });
  });
});
