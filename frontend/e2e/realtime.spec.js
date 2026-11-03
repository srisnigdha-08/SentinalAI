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

  // WS-001: the backend closes sockets when a session re-check fails (e.g. auth store unreachable during a MongoDB
  // outage). Socket.IO does not reconnect after a server-side close, so the dashboard must, and must rejoin its rooms.
  // The server answers join_room with 'connected' once the socket is back in its rooms; only then can it receive
  // room broadcasts (socket.connected alone turns true before the server has processed join_room).
  const countRoomJoins = (page) => page.evaluate(() => {
    window.__roomJoins = 0;
    window.__socket.on('connected', () => { window.__roomJoins += 1; });
  });
  const roomJoins = (page) => page.evaluate(() => window.__roomJoins);

  test('dashboard reconnects by itself after a server-side disconnect and keeps receiving threats', async ({ page, request }) => {
    await countRoomJoins(page);
    // A DISCONNECT packet (type 1) is exactly what the client receives when the server closes the namespace
    await page.evaluate(() => window.__socket.onpacket({ type: 1, nsp: '/' }));
    await expect.poll(() => page.evaluate(() => window.__socket?.connected), { timeout: 3000 }).toBe(false);
    await expect.poll(() => roomJoins(page), { timeout: 10000 }).toBe(1);

    const ip = '198.51.100.88';
    const res = await request.post('http://127.0.0.1:5000/api/test/emit-socket', {
      data: { event: 'new_threat', data: { _id: 'reconnect-' + Date.now(), sourceIP: ip, attackType: 'DDoS', severity: 'CRITICAL', targetService: 'HTTP:80', aiScore: 0.97, createdAt: new Date().toISOString() } },
    });
    expect(res.ok()).toBe(true);
    const liveFeedPanel = page.locator('[data-sentinel-panel]').filter({ hasText: 'Live Attack Feed' });
    await expect(liveFeedPanel.getByText(ip)).toBeVisible({ timeout: 5000 });
  });

  test('signing out while a reconnect is pending cancels it: no new connection is opened', async ({ page }) => {
    await page.evaluate(() => window.__socket.onpacket({ type: 1, nsp: '/' }));
    await expect.poll(() => page.evaluate(() => window.__socket?.connected), { timeout: 3000 }).toBe(false);
    const afterLogout = [];
    let loggedOut = false;
    page.on('request', (r) => { if (loggedOut && r.url().includes('/socket.io/')) afterLogout.push(r.url()); });
    page.on('websocket', (ws) => { if (loggedOut) afterLogout.push(ws.url()); });
    loggedOut = true;
    await page.locator('.sentinel-navbar').getByRole('button', { name: 'Logout' }).click();
    await expect(page).toHaveURL(/\/(login)?$/);
    await page.waitForTimeout(5000); // past the first retry (1.5-2.5 s) and the second
    expect(afterLogout).toEqual([]);
    expect(await page.evaluate(() => window.__socket ?? null)).toBeNull();
  });

  test('rapid repeated server disconnects end in one connection that delivers each threat once', async ({ page, request }) => {
    await countRoomJoins(page);
    await page.evaluate(() => { for (let i = 0; i < 3; i++) window.__socket.onpacket({ type: 1, nsp: '/' }); });
    await expect.poll(() => page.evaluate(() => window.__socket?.connected), { timeout: 3000 }).toBe(false);
    await expect.poll(() => roomJoins(page), { timeout: 15000 }).toBe(1);
    await page.evaluate(() => window.__socket.onpacket({ type: 1, nsp: '/' }));
    await expect.poll(() => roomJoins(page), { timeout: 10000 }).toBe(2);
    await page.waitForTimeout(3000); // a duplicate pending retry would fire within this window
    expect(await roomJoins(page)).toBe(2); // ...and show up as an extra reconnect

    const ip = '198.51.100.89';
    const res = await request.post('http://127.0.0.1:5000/api/test/emit-socket', {
      data: { event: 'new_threat', data: { _id: 'rapid-' + Date.now(), sourceIP: ip, attackType: 'DDoS', severity: 'CRITICAL', targetService: 'HTTP:80', aiScore: 0.97, createdAt: new Date().toISOString() } },
    });
    expect(res.ok()).toBe(true);
    const liveFeedPanel = page.locator('[data-sentinel-panel]').filter({ hasText: 'Live Attack Feed' });
    await expect(liveFeedPanel.getByText(ip)).toBeVisible({ timeout: 5000 });
    await page.waitForTimeout(1000);
    await expect(liveFeedPanel.getByText(ip)).toHaveCount(1);
    expect(await page.evaluate(() => window.__socket.connected)).toBe(true);
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
