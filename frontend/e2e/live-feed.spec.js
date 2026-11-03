import { test, expect } from './fixtures/auth.fixture.js';
import { SEEDED_USERS } from './global-setup.js';

// WS-002: the Live Feed against the real backend. Threats are created through POST /api/threats, so the server emits
// exactly what it emits in production (new_threat and live_feed_event, redacted per role room).

const ORIGIN = 'http://127.0.0.1:3000';
let ipSeq = 0;
const nextIp = () => `198.51.100.${20 + ((Math.floor(Date.now() / 1000) * 7 + ipSeq++) % 200)}`;

async function apiAdmin(request) {
  const csrf = (await (await request.get('/api/auth/csrf', { headers: { Origin: ORIGIN } })).json()).data.csrfToken;
  const login = await request.post('/api/auth/login', {
    data: { email: SEEDED_USERS.admin.email, password: SEEDED_USERS.admin.password },
    headers: { 'X-CSRF-Token': csrf, Origin: ORIGIN },
  });
  expect(login.ok()).toBe(true);
  const token = (await login.json()).data.token;
  return {
    async createThreat(sourceIP) {
      const csrfNow = (await (await request.get('/api/auth/csrf', { headers: { Origin: ORIGIN } })).json()).data.csrfToken;
      const res = await request.post('/api/threats', {
        data: { sourceIP, attackType: 'SQL Injection', severity: 'MEDIUM', targetService: 'HTTP:80' }, // MEDIUM: no alert, so the shared alert count other specs read is untouched
        headers: { Authorization: `Bearer ${token}`, 'X-CSRF-Token': csrfNow, Origin: ORIGIN },
      });
      expect(res.status(), await res.text()).toBe(201);
    },
  };
}

const liveFeed = (page) => page.locator('[data-sentinel-panel]').filter({ hasText: 'Live Attack Feed' });

async function openDashboard(page, loginAs, role) {
  await loginAs(role);
  // The Live Feed issues this request when it mounts; until then nothing listens for its socket events
  const feedLoaded = page.waitForResponse((r) => r.url().includes('/api/threats/recent'));
  await page.goto('/dashboard');
  await feedLoaded;
  await expect(liveFeed(page)).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__socket?.connected), { timeout: 10000 }).toBe(true);
  await page.evaluate(() => {
    window.__roomJoins = 0;
    window.__socket.on('connected', () => { window.__roomJoins += 1; });
  });
}

test.describe('Live Attack Feed against the real backend (WS-002)', () => {
  test('a detected threat appears exactly once', async ({ page, loginAs, request }) => {
    await openDashboard(page, loginAs, 'analyst');
    const ip = nextIp();
    await (await apiAdmin(request)).createThreat(ip);
    await expect(liveFeed(page).getByText(ip, { exact: true })).toHaveCount(1, { timeout: 5000 });
    await page.waitForTimeout(1500); // the second event of a pair arrives within milliseconds
    await expect(liveFeed(page).getByText(ip, { exact: true })).toHaveCount(1);
  });

  test('a threat detected while the live connection was down is shown once it is back', async ({ page, loginAs, request }) => {
    await openDashboard(page, loginAs, 'analyst');
    const ip = nextIp();
    await page.evaluate(() => window.__socket.onpacket({ type: 1, nsp: '/' })); // server-side disconnect
    await expect.poll(() => page.evaluate(() => window.__socket.connected), { timeout: 3000 }).toBe(false);
    await (await apiAdmin(request)).createThreat(ip); // emitted while this dashboard is offline
    await expect.poll(() => page.evaluate(() => window.__roomJoins), { timeout: 10000 }).toBe(1);
    await expect(liveFeed(page).getByText(ip, { exact: true })).toHaveCount(1, { timeout: 5000 });
    await page.waitForTimeout(1500);
    await expect(liveFeed(page).getByText(ip, { exact: true })).toHaveCount(1);
  });

  test('a threat arriving live while the catch-up is in flight does not hide the threats it recovers', async ({ page, loginAs, request }) => {
    await openDashboard(page, loginAs, 'analyst');
    const admin = await apiAdmin(request);
    const missed = nextIp();
    const live = nextIp();
    // Hold the catch-up response so a live event lands before it
    let releaseCatchUp;
    const held = new Promise((r) => { releaseCatchUp = r; });
    await page.route(/\/api\/threats\/recent\?limit=20/, async (route) => { await held; await route.continue(); });
    await page.evaluate(() => window.__socket.onpacket({ type: 1, nsp: '/' }));
    await expect.poll(() => page.evaluate(() => window.__socket.connected), { timeout: 3000 }).toBe(false);
    await admin.createThreat(missed); // emitted while this dashboard is offline
    await expect.poll(() => page.evaluate(() => window.__roomJoins), { timeout: 10000 }).toBe(1);
    await admin.createThreat(live); // delivered live, newer than the missed one
    await expect(liveFeed(page).getByText(live, { exact: true })).toHaveCount(1, { timeout: 5000 });
    releaseCatchUp();
    await expect(liveFeed(page).getByText(missed, { exact: true })).toHaveCount(1, { timeout: 5000 });
    await page.waitForTimeout(1000);
    await expect(liveFeed(page).getByText(live, { exact: true })).toHaveCount(1);
    // newest first: the live (newer) threat stays above the recovered one
    const order = await liveFeed(page).locator('span').allTextContents();
    expect(order.indexOf(live)).toBeLessThan(order.indexOf(missed));
  });

  test('two distinct threats from the same address are both shown', async ({ page, loginAs, request }) => {
    await openDashboard(page, loginAs, 'analyst');
    const admin = await apiAdmin(request);
    const ip = nextIp();
    await admin.createThreat(ip);
    await admin.createThreat(ip); // a second detection, same attack type and score, within 2 s
    await expect(liveFeed(page).getByText(ip, { exact: true })).toHaveCount(2, { timeout: 5000 });
  });

  test('a viewer catching up after a reconnect sees only the redacted address', async ({ page, loginAs, request }) => {
    await openDashboard(page, loginAs, 'viewer');
    // own /24, so the redacted form cannot match an earlier test's threat
    const ip = `198.18.${Math.floor(Date.now() / 1000) % 250}.${10 + (ipSeq++ % 200)}`;
    const redacted = ip.replace(/\.\d+$/, '.xxx');
    await page.evaluate(() => window.__socket.onpacket({ type: 1, nsp: '/' }));
    await expect.poll(() => page.evaluate(() => window.__socket.connected), { timeout: 3000 }).toBe(false);
    await (await apiAdmin(request)).createThreat(ip);
    await expect.poll(() => page.evaluate(() => window.__roomJoins), { timeout: 10000 }).toBe(1);
    await expect(liveFeed(page).getByText(redacted, { exact: true }).first()).toBeVisible({ timeout: 5000 });
    expect(await page.content()).not.toContain(ip);
  });
});
